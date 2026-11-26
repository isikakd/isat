# ISAT — Internal Security Assessment Tool

A defensive, information-gathering web application for performing basic
security assessments on a domain or IP address. Built with Python/Flask
and Bootstrap 5.

> **Scope note:** ISAT performs passive information gathering only
> (port status checks, HTTP header inspection, SSL certificate reading,
> DNS/WHOIS lookups). It does **not** perform any offensive/exploitation
> actions.

## Features

- Port scanner (13 common ports, TCP connect scan)
- HTTP security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- SSL/TLS certificate inspection (issuer, validity, expiration)
- DNS record lookup (A, AAAA, MX, TXT, NS) with public-resolver fallback
- WHOIS lookup (registrar, creation/expiration dates, name servers)
- Rule-based risk scoring (0–100, Low/Medium/High)
- Automated security recommendations
- Professional PDF report generation
- Persistent scan history (SQLite)

## Project Structure

```
isat/
├── app/
│   ├── routes/          # HTTP layer (Flask blueprints)
│   ├── services/        # Business logic (scanners, analyzers, scoring)
│   ├── models/          # Database access layer
│   ├── templates/       # Jinja2 templates
│   ├── static/          # CSS / JS
│   └── utils/           # Input validation helpers
├── database/             # SQLite database file (auto-created)
├── reports/              # Generated PDF reports (auto-created)
├── config.py
├── run.py
└── requirements.txt
```

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

The app runs on **http://127.0.0.1:5001** by default.

> **Note (macOS):** Port 5000 is reserved by the AirPlay Receiver service
> on modern macOS versions, which conflicts with Flask's default port.
> This is why the app is configured to run on port 5001 instead.

## Usage

1. Open the dashboard and enter a domain (e.g. `example.com`) or IP address.
2. Click **Start Scan**. A full assessment typically takes 15–30 seconds.
3. Review the Risk Score, Recommendations, and detailed findings.
4. Click **Download PDF Report** to export the assessment.
5. Visit **Scan History** to revisit or re-download past assessments.

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3, Bootstrap 5, vanilla JavaScript
- **Libraries:** requests, dnspython, python-whois, reportlab
- **Database:** SQLite
