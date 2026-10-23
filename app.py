import csv
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, Response, abort, flash, redirect, render_template, request, send_file, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(APP_DIR, "scanner.db")
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]
SERVICE_MAP = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt"}
RISK_RULES = {
    21: ("FTP exposed", "Medium", 5.3, "Use SFTP/FTPS, disable anonymous access, and restrict network exposure."),
    23: ("Telnet uses cleartext credentials", "High", 8.1, "Disable Telnet and replace it with SSH."),
    80: ("Unencrypted HTTP service", "Low", 3.1, "Redirect HTTP to HTTPS and enable HSTS after testing."),
    445: ("SMB service exposed", "High", 8.2, "Restrict SMB to trusted networks; patch promptly and disable SMBv1."),
    3389: ("RDP service exposed", "High", 7.5, "Require VPN/MFA, Network Level Authentication, and limit allowed sources."),
    5900: ("VNC service exposed", "High", 8.0, "Do not expose VNC publicly; use strong authentication through a VPN."),
}
app = Flask(__name__)
app.secret_key = os.environ.get("SCANNER_SECRET", "change-me-for-production")
jobs = {}
lock = threading.Lock()

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, target TEXT, resolved_ip TEXT, started TEXT, finished TEXT, status TEXT, summary TEXT, results TEXT);
        ''')

def severity(score):
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score else "Info"

def normalize_target(raw):
    raw = raw.strip()
    host = urlparse(raw).hostname if "://" in raw else raw.split("/")[0]
    if not host or not re.fullmatch(r"[A-Za-z0-9._:-]+", host): raise ValueError("Enter a valid hostname, IPv4, or IPv6 address.")
    return host.strip("[]")

def banner(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.5) as s:
            if port in (80, 8080): s.sendall(b"HEAD / HTTP/1.0\r\nHost: scan.local\r\n\r\n")
            data = s.recv(180).decode("utf-8", "replace").replace("\r", " ").replace("\n", " ").strip()
            return data[:160]
    except OSError: return ""

def http_checks(host, port, secure):
    scheme = "https" if secure else "http"
    url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=True, headers={"User-Agent": "Authorized-Assessment-Scanner/1.0"})
        important = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"]
        missing = [h for h in important if h not in {k.lower() for k in r.headers}]
        if missing:
            findings.append({"title": "Missing HTTP security headers", "severity": "Medium", "cvss": 5.3, "cve": "N/A", "recommendation": "Add: " + ", ".join(missing), "evidence": url})
    except requests.RequestException: pass
    return findings

def tls_check(host, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert(); expires = cert.get("notAfter", "unknown")
                return {"protocol": s.version(), "cipher": s.cipher()[0], "expires": expires}
    except Exception as e: return {"error": str(e)[:100]}

def run_scan(scan_id, target):
    def update(**values):
        with lock: jobs[scan_id].update(values)
    try:
        update(status="Resolving target", progress=8)
        ip = socket.gethostbyname(target)
        update(resolved_ip=ip, status="Scanning common TCP ports", progress=18)
        ports = []
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = {pool.submit(lambda p: p if socket.create_connection((ip, p), timeout=0.7).close() is None else None, p): p for p in TOP_PORTS}
            for i, f in enumerate(as_completed(futures)):
                try:
                    p = f.result()
                    if p: ports.append(p)
                except OSError: pass
                update(progress=18 + int((i + 1) / len(TOP_PORTS) * 52))
        update(status="Collecting service evidence", progress=75)
        services, findings = [], []
        for p in sorted(ports):
            svc = {"port": p, "service": SERVICE_MAP.get(p, "unknown"), "banner": banner(ip, p)}
            services.append(svc)
            if p in RISK_RULES:
                title, sev, score, rec = RISK_RULES[p]
                findings.append({"title": title, "severity": sev, "cvss": score, "cve": "Configuration exposure", "recommendation": rec, "evidence": f"TCP/{p} open"})
            if p in (80, 8080, 443, 8443): findings += http_checks(target, p, p in (443, 8443))
            if p in (443, 8443): svc["tls"] = tls_check(target, p)
        score = round(max([x["cvss"] for x in findings], default=0), 1)
        result = {"target": target, "ip": ip, "ports": services, "findings": findings, "risk_score": score, "risk_level": severity(score), "stats": {"ports": len(services), "findings": len(findings)}}
        update(status="Completed", progress=100, result=result)
        with conn() as c: c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)", (scan_id, target, ip, jobs[scan_id]["started"], datetime.now(timezone.utc).isoformat(), "Completed", json.dumps(result["stats"]), json.dumps(result)))
    except Exception as e:
        update(status="Failed", progress=100, error=str(e))

@app.route("/")
def index():
    with conn() as c: history = c.execute("SELECT id,target,resolved_ip,started,status,summary FROM scans ORDER BY started DESC LIMIT 25").fetchall()
    return render_template("index.html", history=history, jobs=jobs)

@app.post("/scan")
def start_scan():
    if request.form.get("authorized") != "yes":
        flash("You must confirm that you are authorized to assess this target.", "error"); return redirect(url_for("index"))
    try: target = normalize_target(request.form.get("target", ""))
    except ValueError as e: flash(str(e), "error"); return redirect(url_for("index"))
    sid = str(uuid.uuid4())[:8]
    with lock: jobs[sid] = {"id": sid, "target": target, "started": datetime.now(timezone.utc).isoformat(), "status": "Queued", "progress": 0}
    threading.Thread(target=run_scan, args=(sid, target), daemon=True).start()
    return redirect(url_for("scan_detail", scan_id=sid))

@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    job = jobs.get(scan_id)
    if not job:
        with conn() as c: row = c.execute("SELECT results FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row: abort(404)
        job = {"id": scan_id, "status": "Completed", "progress": 100, "result": json.loads(row["results"])}
    return render_template("scan.html", job=job)

@app.route("/scan/<scan_id>/json")
def scan_json(scan_id):
    job = jobs.get(scan_id)
    if not job or "result" not in job: return {"status": job["status"] if job else "not found", "progress": job.get("progress", 0) if job else 0}
    return job["result"]

def get_result(scan_id):
    if scan_id in jobs and "result" in jobs[scan_id]: return jobs[scan_id]["result"]
    with conn() as c: row = c.execute("SELECT results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: abort(404)
    return json.loads(row["results"])

@app.route("/scan/<scan_id>/export/<fmt>")
def export(scan_id, fmt):
    data = get_result(scan_id)
    if fmt == "csv":
        out = io.StringIO(); w = csv.DictWriter(out, fieldnames=["title","severity","cvss","cve","evidence","recommendation"]); w.writeheader(); w.writerows(data["findings"])
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"})
    if fmt == "html": return Response(render_template("report.html", data=data), mimetype="text/html", headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"})
    if fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            b=io.BytesIO(); p=canvas.Canvas(b,pagesize=letter); y=750
            for line in ["Security Assessment Report", f"Target: {data['target']} ({data['ip']})", f"Risk: {data['risk_level']} ({data['risk_score']})", "", "Findings:"] + [f"[{x['severity']}] {x['title']} — {x['recommendation']}" for x in data['findings']]:
                p.drawString(48,y,line[:115]); y-=18
                if y<55: p.showPage(); y=750
            p.save(); b.seek(0); return send_file(b, mimetype="application/pdf", as_attachment=True, download_name=f"scan-{scan_id}.pdf")
        except ImportError: abort(501, "Install reportlab for PDF export.")
    abort(404)

if __name__ == "__main__":
    init_db(); app.run(debug=True, host="127.0.0.1", port=5000)
