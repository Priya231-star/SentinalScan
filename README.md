# SentinelScan

Local, educational vulnerability-assessment dashboard for systems you own or are explicitly authorized to test.

## Quick start

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Included

- Authorization confirmation, hostname/IP validation, common-port discovery, banners, service naming
- Basic TLS and HTTP header checks; rule-based risk scoring and recommendations
- SQLite scan history, progress display, JSON REST result, and HTML/CSV/PDF reports

This tool intentionally uses a small list of common TCP ports and rule-based checks. It is not a replacement for a professional security assessment, does not exploit targets, and should only be used with explicit authorization.
