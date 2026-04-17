# DDoS Detection using Packet Flow Analysis (Flask + SQLite)

## What this does
- Secure login (password hashing via Werkzeug)
- Analyze "packet flow logs" from text input or file upload
- Heuristic DDoS detection + risk scoring
- Dashboard with Chart.js (2+ charts + summary cards)
- History of runs
- PDF report export (ReportLab)
- Evidence integrity: SHA256 hash + chained JSON ledger ("blockchain-inspired")
- Runs on Windows 10/11 with Python 3.12 (no Docker, no GPU, no paid APIs)

## Supported input formats
Best results if your data looks like CSV:
timestamp,src_ip,dst_ip,protocol,length,flags(optional)

Examples:
2026-02-26T10:00:01,192.168.1.10,10.0.0.5,TCP,60,SYN
2026-02-26T10:00:01,192.168.1.11,10.0.0.5,TCP,60,SYN

You can also paste loose logs; the analyzer will try to extract IPs + length.

## Run
1) Create venv, install requirements
2) Start: `python app.py`
3) Open: http://127.0.0.1:5000

Default: You must register your first user from the Register page.