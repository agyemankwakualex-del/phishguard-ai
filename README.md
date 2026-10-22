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

Set these names in the process environment. Leave the API names unset to boot with rules only. Do not commit values. `.env.example` lists the same names; the app does not load that file.

`SECRET_KEY` is required. If it is missing or blank, startup raises `RuntimeError`. Gmail access and refresh tokens are encrypted with SHA-256 of that key before they are stored. A value that cannot be decrypted, including an older plaintext row or a token saved under a previous key, is treated as disconnected so the user can connect again. Logout is a POST with the CSRF token. Registration rejects a password shorter than 8 characters. A duplicate email or username gets one generic message and does not say which field was taken.

Gmail connect puts a random `state` in the session and on the Google URL. The callback redirects back to settings if that value is missing or does not match.

`GROQ_MODEL` is optional. When it is unset or blank, `analyze_with_ai` calls `openai/gpt-oss-20b`. Groq shut down developer access to `llama-3.1-8b-instant` on 16 August 2026 and lists that model as the replacement. The call sends `response_format` type `json_object`. The prompt still asks for JSON, and a fenced reply is still parsed if the text contains a fence. The model is given the first 6,000 characters of the body (`AI_BODY_LIMIT`). The About page shows this same model name. The Groq client uses a 20 second timeout and does not retry; if that call fails, the scan uses the built-in rules and labels the engine Rules. Set `GROQ_MODEL` to switch models without a code change. `GROQ_API_KEY` still has to be set or analysis stays on the built-in rules.

`GMAIL_REDIRECT_URI` is optional. When it is unset, the Gmail connect and callback routes both use this request's `/gmail/callback` URL, so it is `https` on Vercel. Set it only to force one specific callback.

- `SECRET_KEY` (required)
- `DATABASE_URL`
- `DATABASE_HOSTADDR`
- `GROQ_API_KEY`
- `GROQ_MODEL`
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GMAIL_REDIRECT_URI`

## Rate limit

Failed `POST /login` attempts are rows in `auth_attempts`: 5 per minute for the submitted email, and 5 per minute for the client IP. A successful login is not stored. `POST /register` allows 5 posts per minute for the client IP. The next attempt renders the form again with "Too many attempts. Wait a minute and try again." Rows older than 10 minutes are deleted when a new attempt is checked. `db.create_all` creates the table on startup.

The IP is the `x-real-ip` header. [Vercel sets that to the visitor's public address](https://vercel.com/docs/headers/request-headers), the same value as `x-forwarded-for` (which Vercel overwrites) and `x-vercel-forwarded-for`. If `x-real-ip` is absent, the app uses `x-vercel-forwarded-for`, then `x-forwarded-for`, then `remote_addr`. Counts are in the database, so another serverless instance sees them.

## Gmail

Gmail scanning reads the message body, not the snippet alone. The inbox list loads up to 15 messages with the `gmail.readonly` scope. Each message is fetched in Gmail `full` format. The body prefers `text/plain` and falls back to `text/html` with tags removed. `http` and `https` links from the HTML are kept, and script and style text are not. Analysis receives at most 100,000 characters of that text, through the same path as paste-to-analyze. Link extraction uses that full text and keeps the first 5 unique http(s) URLs in the order they appear. The Groq call only receives the first 6,000 characters of the body. If a message has no readable body, analysis uses the snippet. One message that cannot be read does not stop the scan. The full email body is not stored. History stores the engine that produced the row (`AI`, `Rules`, `AI + VT`, or `Rules + VT`). Rows from before that column existed say `Not recorded`.

## Vercel

Set `DATABASE_URL` to the Supabase transaction pooler URL (port 6543). Serverless functions should not open a direct database connection on each request. The name is `DATABASE_URL`. Do not commit the value.

`DATABASE_HOSTADDR` is optional. Leave it unset for normal runs, including local SQLite. Set it only when Vercel logs show `Errno 16` inside psycopg `conninfo_attempts` (glibc `getaddrinfo` failing before connect). The value is one current public IPv4 address of the Supabase pooler host. That address can rotate and then needs refreshing. Do not commit a value. For a `postgresql+psycopg` URL the app passes it as a psycopg `hostaddr` connect argument and does not put it in `DATABASE_URL`. Those Postgres URLs also use a `NullPool` and psycopg `prepare_threshold=None` with `connect_timeout=10`. SQLite ignores `DATABASE_HOSTADDR`.

Vercel installs from `requirements.txt`. The Postgres driver is `psycopg[binary]`, which SQLAlchemy loads for a `postgresql+psycopg://` URL. Vercel detects the Flask app in `app.py`. Do not add a rewrite that sends every path to `/api/index`. The Python runtime now gives Flask that rewritten destination, so `/`, `/login`, and `/static/...` all miss their routes. There is no UI build step. `python app.py` and the Procfile (`gunicorn app:app`) are unchanged. `postgres://`, `postgresql://`, and `postgresql+psycopg2://` are rewritten to `postgresql+psycopg://` before SQLAlchemy sees the URL. Static files stay in `static/` and Flask serves them at `/static/...`.

For persistence on Vercel, set `DATABASE_URL` to the Supabase pooler URL. If `DATABASE_URL` is unset on Vercel, the app uses `sqlite:////tmp/phishguard.db`. Local runs with no `DATABASE_URL` still use `sqlite:///phishguard.db`. A live check still needs a Vercel deploy.
