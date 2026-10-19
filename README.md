# PhishGuard AI

Flask app that scores a pasted email with built-in rules. Groq, VirusTotal, and Gmail run only when their environment names are set.

## Python

`runtime.txt` pins `python-3.11.7` for Render. A revival check on Python 3.12.3 installed these requirements and booted the app. Python 3.11.7 was not installed on that machine.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000 and register. With no API keys, analysis uses the built-in rules.

If `DATABASE_URL` is unset, the app uses SQLite and creates tables on startup.

## Environment

Set these names in the process environment. Leave them unset to boot with rules only. Do not commit values. `.env.example` lists the same names; the app does not load that file.

- `SECRET_KEY`
- `DATABASE_URL`
- `GROQ_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GMAIL_REDIRECT_URI`
