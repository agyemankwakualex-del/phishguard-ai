"""
PhishGuard AI - Final Production Backend
Includes: Centralized API Keys, VirusTotal, Gmail, and Profile Route
"""

from flask import Flask, abort, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask import send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone # <--- Added timedelta
import json
import re
import os
import base64
import html
import urllib.parse
import hashlib
import secrets
import requests
from cryptography.fernet import Fernet
import qrcode
from html.parser import HTMLParser
from io import BytesIO
from sqlalchemy.pool import NullPool

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
_secret_key = (os.environ.get('SECRET_KEY') or '').strip()
if not _secret_key:
    raise RuntimeError('SECRET_KEY is not set. Set it in the environment before starting PhishGuard.')
app.secret_key = _secret_key
# Vercel terminates TLS and forwards the public host and scheme.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
# Checks POST, PUT, PATCH, and DELETE. The Google callback stays GET.
csrf = CSRFProtect(app)
HTTP_TIMEOUT = 10

def normalize_database_url(url):
    # Scheme prefix only. User, password, host, port, path, and query stay as given.
    # postgres://, postgresql://, and postgresql+psycopg2:// become postgresql+psycopg://.
    # postgresql+psycopg:// is already the installed psycopg v3 dialect and is left as-is.
    # sqlite:// and every other scheme are untouched. .strip() matches the previous call.
    url = url.strip()
    return re.sub(
        r'^postgres(?:ql)?(?:\+psycopg2)?://',
        'postgresql+psycopg://',
        url,
        count=1,
    )


def engine_options_for_database(scheme, hostaddr):
    # Only the normalized psycopg v3 scheme. SQLite and other schemes stay on
    # Flask-SQLAlchemy's default engine. hostaddr is a connect argument, not a URL part.
    if scheme != 'postgresql+psycopg':
        return {}
    addr = hostaddr.strip() if isinstance(hostaddr, str) else ''
    connect_args = {
        'prepare_threshold': None,
        'connect_timeout': 10,
    }
    if addr:
        connect_args['hostaddr'] = addr
    return {
        'poolclass': NullPool,
        'connect_args': connect_args,
    }


# Database Config (Handles Render PostgreSQL or Local SQLite)
# On Vercel the project directory is not a durable disk. /tmp lasts for one instance.
# Local `python app.py` does not set VERCEL, so an unset DATABASE_URL stays on sqlite:///phishguard.db.
if not os.environ.get('DATABASE_URL') and os.environ.get('VERCEL'):
    os.environ['DATABASE_URL'] = 'sqlite:////tmp/phishguard.db'

database_url = normalize_database_url(os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db'))

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

_database_hostaddr = os.environ.get('DATABASE_HOSTADDR', '')
_database_hostaddr = _database_hostaddr.strip() if isinstance(_database_hostaddr, str) else ''
_engine_options = engine_options_for_database(
    urllib.parse.urlparse(database_url).scheme,
    _database_hostaddr,
)
if _engine_options:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = _engine_options

# SYSTEM-WIDE API KEYS (Loaded from Render Environment)
SYSTEM_GROQ_KEY = os.environ.get('GROQ_API_KEY', '')
SYSTEM_VT_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

# Google OAuth Config
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip().replace('\n', '').replace('\r', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip().replace('\n', '').replace('\r', '')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

def utc_now_naive():
    # Columns are naive DateTime. Store UTC with tzinfo removed so old rows still compare.
    return datetime.now(timezone.utc).replace(tzinfo=None)

# ============================================================
# DATABASE MODELS
# ============================================================

def _token_fernet():
    secret = app.secret_key
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    # Fernet wants 32 url-safe base64 bytes. SHA-256 of SECRET_KEY is those 32 bytes.
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret).digest()))


def encrypt_secret(value):
    value = (value or '').strip()
    if not value:
        return ''
    return _token_fernet().encrypt(value.encode('utf-8')).decode('ascii')


def decrypt_secret(value):
    # Old plaintext rows and a rotated SECRET_KEY both fail here. Caller treats that as disconnected.
    if not value:
        return ''
    try:
        return _token_fernet().decrypt(str(value).encode('ascii')).decode('utf-8')
    except Exception:
        return ''


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    
    # Kept for DB compatibility, but unused in this version
    groq_api_key = db.Column(db.String(256), default='')
    virustotal_api_key = db.Column(db.String(256), default='')
    
    # Gmail tokens are encrypted by the properties below. gmail_email stays plaintext.
    gmail_email = db.Column(db.String(120), default='')
    
    analyses = db.relationship('AnalysisHistory', backref='user', lazy=True)
    
    # Ciphertext lives in the existing columns. Plaintext is only on the properties.
    _gmail_token = db.Column('gmail_token', db.Text, default='')
    _gmail_refresh_token = db.Column('gmail_refresh_token', db.Text, default='')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def gmail_token(self):
        return decrypt_secret(self._gmail_token)

    @gmail_token.setter
    def gmail_token(self, value):
        self._gmail_token = encrypt_secret(value)

    @property
    def gmail_refresh_token(self):
        return decrypt_secret(self._gmail_refresh_token)

    @gmail_refresh_token.setter
    def gmail_refresh_token(self, value):
        self._gmail_refresh_token = encrypt_secret(value)

    def initials(self):
        source = (self.username or '').strip() or (self.email or '?')
        parts = [part for part in re.split(r'[\s._@-]+', source) if part]
        letters = ''.join(part[0] for part in parts[:2])
        return (letters or '?').upper()


class AnalysisHistory(db.Model):
    __tablename__ = 'analysis_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender = db.Column(db.String(200), default='Unknown')
    subject = db.Column(db.String(500), default='')
    risk_level = db.Column(db.String(20), default='LOW')
    risk_score = db.Column(db.Integer, default=0)
    reasons = db.Column(db.Text, default='[]')
    timestamp = db.Column(db.DateTime, default=utc_now_naive)
    # Short code from PhishingAnalyzer.analyze: AI, Rules, AI + VT, Rules + VT.
    # Rows created before this column existed stay 'Not recorded'.
    engine = db.Column(db.String(40), nullable=False, default='Not recorded')
    
    def get_reasons(self):
        try: return json.loads(self.reasons)
        except: return []
    
    def set_reasons(self, reasons_list):
        self.reasons = json.dumps(reasons_list)


class AuthAttempt(db.Model):
    # Shared by every instance. create_all adds this table on startup.
    __tablename__ = 'auth_attempts'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(16), nullable=False)
    ip = db.Column(db.String(64), nullable=False, default='')
    email = db.Column(db.String(120), nullable=False, default='')
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive, index=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_database_target(uri):
    # Scheme, host, port, and whether DATABASE_URL / DATABASE_HOSTADDR are set.
    # Never user, password, path, query, or the hostaddr value.
    env_set = bool(os.environ.get('DATABASE_URL'))
    hostaddr_raw = os.environ.get('DATABASE_HOSTADDR', '')
    hostaddr_set = bool(hostaddr_raw.strip()) if isinstance(hostaddr_raw, str) else False
    try:
        parsed = urllib.parse.urlparse(uri)
        scheme = parsed.scheme if isinstance(parsed.scheme, str) else ''
        host = parsed.hostname
        port = parsed.port
        if not scheme or any(c in scheme for c in ':/@?# \t\r\n'):
            raise ValueError
        if host is not None and any(c in host for c in '@/?# \t\r\n'):
            raise ValueError
        host_text = host or ''
        port_text = '' if port is None else str(port)
    except Exception:
        safe_scheme = ''
        if isinstance(uri, str) and '://' in uri:
            head = uri.split('://', 1)[0]
            if head and len(head) <= 64 and re.fullmatch(r'[A-Za-z][A-Za-z0-9+.-]*', head):
                safe_scheme = head
        if safe_scheme:
            print(f'[phishguard] DATABASE_URL parse failed scheme={safe_scheme}', flush=True)
        else:
            print('[phishguard] DATABASE_URL parse failed', flush=True)
        return
    print(
        f'[phishguard] db scheme={scheme} host={host_text} port={port_text} env_set={env_set} hostaddr_set={hostaddr_set}',
        flush=True,
    )

log_database_target(app.config['SQLALCHEMY_DATABASE_URI'])

def ensure_history_engine_column():
    # create_all does not add a column to a table that already exists.
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    if 'analysis_history' not in inspector.get_table_names():
        return
    names = {column['name'] for column in inspector.get_columns('analysis_history')}
    if 'engine' in names:
        return
    with db.engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE analysis_history ADD COLUMN engine VARCHAR(40) NOT NULL DEFAULT 'Not recorded'"
        ))

with app.app_context():
    db.create_all()
    ensure_history_engine_column()

# ============================================================
# PHISHING ANALYZER CORE
# ============================================================

# Characters of the body sent to Groq. Link extraction still uses the full body.
AI_BODY_LIMIT = 6000
# One call. The SDK's default is 60s and two retries, which would hold a scan much longer.
GROQ_TIMEOUT = 20

ENGINE_LABELS = {
    'AI + VT': 'AI + VirusTotal',
    'AI': 'AI only',
    'Rules + VT': 'Rules + VirusTotal',
    'Rules': 'Rule-based',
    'Not recorded': 'Not recorded',
}


def groq_model_name():
    return (os.environ.get('GROQ_MODEL') or 'openai/gpt-oss-20b').strip() or 'openai/gpt-oss-20b'


def engine_label(value):
    key = value or 'Not recorded'
    return ENGINE_LABELS.get(key, key)

class PhishingAnalyzer:
    def __init__(self, groq_key, vt_key):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def extract_links(self, text):
        # First 5 unique http(s) links in order of appearance. A set would not be stable.
        ordered = []
        for url in re.findall(r'https?://[^\s<>"\'}\]]+', text or ''):
            if url not in ordered:
                ordered.append(url)
            if len(ordered) == 5:
                break
        return ordered

    def check_virustotal(self, urls):
        detailed_results = []
        malicious_count = 0

        if not urls:
            return {'malicious_count': 0}, []

        # No key, a 404, or a failed lookup is UNKNOWN. HIGH/MEDIUM/LOW need real stats.
        if not self.virustotal_api_key:
            return {'malicious_count': 0}, [
                {'url': url, 'risk': 'UNKNOWN', 'note': 'Not checked'} for url in urls
            ]

        headers = {"x-apikey": self.virustotal_api_key}

        for url in urls:
            result_entry = {'url': url, 'risk': 'UNKNOWN', 'note': 'Not checked'}
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(api_url, headers=headers, timeout=HTTP_TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    result_entry['note'] = ''
                    if stats['malicious'] > 0:
                        malicious_count += 1
                        result_entry['risk'] = 'HIGH'
                    elif stats['suspicious'] > 0:
                        result_entry['risk'] = 'MEDIUM'
                    else:
                        result_entry['risk'] = 'LOW'
                elif response.status_code == 429:
                    result_entry['risk'] = 'UNKNOWN'
                    result_entry['note'] = 'Rate limited'
                    result_entry['rate_limited'] = True
                elif response.status_code == 404:
                    result_entry['risk'] = 'UNKNOWN'
                    result_entry['note'] = 'Not in VirusTotal'
            except Exception:
                print('VT Error')
            
            detailed_results.append(result_entry)
            
        return {'malicious_count': malicious_count}, detailed_results

    def analyze_with_ai(self, email_data, vt_summary):
        if not self.groq_api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_api_key, timeout=GROQ_TIMEOUT, max_retries=0)
            
            vt_context = ""
            if vt_summary['malicious_count'] > 0:
                vt_context = f"CRITICAL: VirusTotal detected {vt_summary['malicious_count']} MALICIOUS links."

            prompt = f"""You are PhishGuard AI. Analyze this email.
External Intel: {vt_context}

From: {email_data.get('sender', 'Unknown')}
Subject: {email_data.get('subject', '')}
Body: {(email_data.get('body') or '')[:AI_BODY_LIMIT]}

Respond in strictly valid JSON:
{{
    "risk_level": "HIGH" | "MEDIUM" | "LOW",
    "risk_score": <0-100>,
    "reasons": ["Short reason 1", "Short reason 2"],
    "recommendation": "Actionable advice"
}}
If External Intel says malicious, risk MUST be HIGH."""

            model = groq_model_name()
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            
            result_text = response.choices[0].message.content.strip()
            if "```" in result_text: 
                result_text = result_text.split("```")[1].replace('json', '')
            
            result = json.loads(result_text)
            result['ai_powered'] = True
            
            if vt_summary['malicious_count'] > 0:
                result['risk_level'] = 'HIGH'
                result['risk_score'] = max(result.get('risk_score', 0), 90)
                result['reasons'].insert(0, f"VirusTotal found {vt_summary['malicious_count']} malicious links.")
                
            return result
        except Exception as e:
            print(f"AI Error: {e}")
            return None

    def analyze_with_rules(self, email_data, vt_summary):
        score = 0
        reasons = []
        
        if vt_summary['malicious_count'] > 0:
            score += 100
            reasons.append(f"VirusTotal detected {vt_summary['malicious_count']} malicious links")

        full_text = (email_data.get('subject', '') + " " + email_data.get('body', '')).lower()
        
        if 'urgent' in full_text: score += 20; reasons.append("Urgency detected")
        if 'password' in full_text: score += 30; reasons.append("Credential request")
        if not reasons: reasons.append("No common phishing patterns detected")
        
        risk = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        
        return {
            "risk_level": risk,
            "risk_score": min(100, score),
            "reasons": reasons,
            "recommendation": "Be cautious.",
            "ai_powered": False
        }

    def analyze(self, email_data, use_ai=True):
        links = self.extract_links(email_data.get('body', ''))
        vt_summary, detailed_link_results = self.check_virustotal(links)
        vt_used = bool(self.virustotal_api_key) and bool(links)

        result = self.analyze_with_ai(email_data, vt_summary) if use_ai else None
        if not result:
            result = self.analyze_with_rules(email_data, vt_summary)
        name = 'AI' if result.get('ai_powered') else 'Rules'
        result['engine'] = f'{name} + VT' if vt_used else name
        result['engine_label'] = engine_label(result['engine'])
        result['vt_rate_limited'] = any(item.get('rate_limited') for item in detailed_link_results)
        result['vt_unknown'] = any(item.get('risk') == 'UNKNOWN' for item in detailed_link_results)
        body = email_data.get('body') or ''
        if result['engine'].startswith('AI') and len(body) > AI_BODY_LIMIT:
            result['ai_body_note'] = f'AI read the first {AI_BODY_LIMIT:,} characters of this email.'
        else:
            result['ai_body_note'] = ''
        return result, links, detailed_link_results

@app.template_filter('engine_label')
def engine_label_filter(value):
    return engine_label(value)

# ============================================================
# ROUTES
# ============================================================

def client_ip():
    # Vercel sets x-real-ip to the visitor's public address. Docs:
    # https://vercel.com/docs/headers/request-headers
    # x-forwarded-for is that same address (Vercel overwrites it so it cannot be spoofed).
    # x-vercel-forwarded-for stays put when a proxy in front of Vercel rewrites x-forwarded-for.
    # @vercel/functions reads x-real-ip. ProxyFix's remote_addr is only the local fallback.
    for header in ('X-Real-Ip', 'X-Vercel-Forwarded-For', 'X-Forwarded-For'):
        raw = request.headers.get(header) or ''
        ip = raw.split(',')[0].strip()
        if ip:
            return ip[:64]
    return (request.remote_addr or 'unknown')[:64]


def _prune_auth_attempts(now):
    cutoff = now - timedelta(minutes=10)
    AuthAttempt.query.filter(AuthAttempt.created_at < cutoff).delete(synchronize_session=False)


def _recent_attempts(action, now, ip=None, email=None):
    query = AuthAttempt.query.filter(
        AuthAttempt.action == action,
        AuthAttempt.created_at >= now - timedelta(minutes=1),
    )
    if ip is not None:
        query = query.filter(AuthAttempt.ip == ip)
    if email is not None:
        query = query.filter(AuthAttempt.email == email)
    return query.count()


def auth_attempt_blocked(action, ip, email=''):
    now = utc_now_naive()
    _prune_auth_attempts(now)
    db.session.commit()
    if action == 'login':
        if email and _recent_attempts('login', now, email=email) >= 5:
            return True
        if ip and _recent_attempts('login', now, ip=ip) >= 5:
            return True
        return False
    return bool(ip) and _recent_attempts('register', now, ip=ip) >= 5


def record_auth_attempt(action, ip, email=''):
    now = utc_now_naive()
    _prune_auth_attempts(now)
    db.session.add(AuthAttempt(
        action=action,
        ip=ip or '',
        email=(email or '')[:120],
        created_at=now,
    ))
    db.session.commit()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        ip = client_ip()
        if auth_attempt_blocked('register', ip):
            abort(429)
        record_auth_attempt('register', ip)
        password = request.form.get('password', '')
        if password != request.form.get('confirm_password', ''):
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')
        user = User(username=request.form['username'], email=request.form['email'].lower())
        user.set_password(password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('Could not create account with those details.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()[:120]
        ip = client_ip()
        if auth_attempt_blocked('login', ip, email):
            abort(429)
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(request.form.get('password', '')):
            login_user(user, remember=request.form.get('remember') == 'on')
            return redirect(url_for('home'))
        record_auth_attempt('login', ip, email)
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.errorhandler(429)
def too_many_requests(_error):
    flash('Too many attempts. Wait a minute and try again.', 'error')
    template = 'register.html' if request.path.startswith('/register') else 'login.html'
    return render_template(template), 429

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    # 1. Fetch History
    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).all()
    
    # 2. Calculate Stats
    stats = {
        'total': len(history),
        'high_risk': len([h for h in history if h.risk_level == 'HIGH']),
        'medium_risk': len([h for h in history if h.risk_level == 'MEDIUM']),
        'low_risk': len([h for h in history if h.risk_level == 'LOW'])
    }
    
    # 3. Calculate Weekly Activity (Real-Time)
    # Create a dictionary for the last 7 days initialized to 0
    today = utc_now_naive().date()
    dates = [(today - timedelta(days=i)) for i in range(6, -1, -1)] # Last 7 days
    labels = [d.strftime('%a') for d in dates] # Mon, Tue, Wed...
    counts = {d: 0 for d in dates}
    
    # Count actual scans
    for h in history:
        h_date = h.timestamp.date()
        if h_date in counts:
            counts[h_date] += 1
            
    data_values = [counts[d] for d in dates]
    
    return render_template('index.html', 
                         stats=stats, 
                         recent_threats=history[:5],
                         chart_labels=labels,
                         chart_data=data_values)

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_page():
    if request.method == 'POST':
        data = {
            'sender': request.form.get('sender', ''),
            'subject': request.form.get('subject', ''),
            'body': request.form.get('body', '')
        }
        
        # Use System Keys
        analyzer = PhishingAnalyzer(SYSTEM_GROQ_KEY, SYSTEM_VT_KEY)
        result, links, link_results = analyzer.analyze(data, request.form.get('use_ai') == 'on')
        
        entry = AnalysisHistory(
            user_id=current_user.id, 
            sender=data['sender'] or 'Unknown',
            subject=data['subject'] or '(No Subject)', 
            risk_level=result['risk_level'],
            risk_score=result['risk_score'],
            engine=(result.get('engine') or 'Not recorded')[:40],
        )
        entry.set_reasons(result['reasons'])
        db.session.add(entry)
        db.session.commit()
        
        return render_template('results.html', result=result, email=data, links=links, link_results=link_results)
    
    return render_template('analyze.html', ai_body_limit=AI_BODY_LIMIT)

@app.route('/history')
@login_required
def history_page():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).all()
    return render_template('history.html', history=history)

@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    AnalysisHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('History cleared.', 'success')
    return redirect(url_for('history_page'))

@app.route('/settings')
@login_required
def settings_page():
    config = {
        'groq_active': bool(SYSTEM_GROQ_KEY),
        'vt_active': bool(SYSTEM_VT_KEY),
        'gmail_connected': bool((current_user.gmail_token or '').strip()),
        'gmail_email': current_user.gmail_email if (current_user.gmail_token or '').strip() else '',
        'gmail_available': bool(GOOGLE_CLIENT_ID)
    }
    return render_template('settings.html', config=config)

# ============================================================
# NEW FEATURES: VIEW DETAIL & DELETE
# ============================================================

@app.route('/history/view/<int:id>')
@login_required
def view_analysis(id):
    entry = db.session.get(AnalysisHistory, id)
    if entry is None:
        abort(404)
    # Security check: ensure this entry belongs to the current user
    if entry.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('history_page'))
    
    engine = entry.engine or 'Not recorded'
    result = {
        'risk_level': entry.risk_level,
        'risk_score': entry.risk_score,
        'reasons': entry.get_reasons(),
        'recommendation': "Review past analysis." if entry.risk_level == 'LOW' else "Caution advised based on past scan.",
        'ai_powered': engine.startswith('AI'),
        'engine': engine,
        'ai_body_note': '',
    }
    
    # Reconstruct email object
    # Note: We didn't save the full body in the DB to save space, 
    # so we show a placeholder or what we have.
    email_data = {
        'sender': entry.sender,
        'subject': entry.subject,
        'body': "(Email content was not stored permanently for privacy reasons.)", 
        'date': entry.timestamp.strftime('%Y-%m-%d %H:%M')
    }
    
    return render_template('results.html', result=result, email=email_data, links=[], link_results=[])


@app.route('/history/delete/<int:id>', methods=['POST'])
@login_required
def delete_analysis(id):
    entry = db.session.get(AnalysisHistory, id)
    if entry is None:
        abort(404)
    if entry.user_id != current_user.id:
        flash('Unauthorized.', 'error')
        return redirect(url_for('history_page'))
    
    db.session.delete(entry)
    db.session.commit()
    flash('Analysis record deleted.', 'success')
    return redirect(url_for('history_page'))


# =========================================================
# PROFILE PAGE (This is the one that was missing)
# =========================================================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current_pass = request.form.get('current_password') or ''
            new_pass = request.form.get('new_password') or ''
            confirm_pass = request.form.get('confirm_password') or ''
            
            if not current_user.check_password(current_pass):
                flash('Incorrect current password.', 'error')
            elif new_pass != confirm_pass:
                flash('New passwords do not match.', 'error')
            elif len(new_pass) < 8:
                flash('Password must be at least 8 characters.', 'error')
            else:
                current_user.set_password(new_pass)
                db.session.commit()
                flash('Password changed successfully.', 'success')
    return render_template('profile.html')

@app.route('/about')
def about_page():
    return render_template('about.html', ai_body_limit=AI_BODY_LIMIT, groq_model=groq_model_name())

# ============================================================
# GMAIL INTEGRATION (Final Fix)
# ============================================================

# Characters of decoded body passed into analysis. History never stores this text.
GMAIL_BODY_CAP = 100_000


def _decode_gmail_data(data):
    pad = '=' * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(data + pad)
    return raw.decode('utf-8', errors='replace')[:GMAIL_BODY_CAP]


class _GmailHTMLText(HTMLParser):
    """Visible text plus http(s) href/src values. Script and style contents are dropped."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
            return
        if self._skip:
            return
        found = {name: html.unescape(value or '') for name, value in attrs}
        for key in ('href', 'src'):
            value = found.get(key, '').strip()
            if value.lower().startswith(('http://', 'https://')):
                self._parts.append(' ' + value + ' ')

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag in ('p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3'):
            self._parts.append('\n')

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)

    def text(self):
        return ''.join(self._parts)


def _html_to_text(value):
    parser = _GmailHTMLText()
    parser.feed(value)
    parser.close()
    return parser.text()


def _collect_mime_text(part, plain, html_parts):
    if not isinstance(part, dict):
        return
    if sum(len(item) for item in plain) >= GMAIL_BODY_CAP:
        return
    mime = str(part.get('mimeType') or '').split(';', 1)[0].strip().lower()
    data = (part.get('body') or {}).get('data')
    if data:
        if mime == 'text/plain':
            plain.append(_decode_gmail_data(data))
        elif mime == 'text/html':
            html_parts.append(_decode_gmail_data(data))
    for child in part.get('parts') or []:
        _collect_mime_text(child, plain, html_parts)


def gmail_message_body(message):
    """Capped readable body. Uses the snippet when the MIME body is empty or unreadable."""
    snippet = (message.get('snippet') or '').strip()
    try:
        plain, html_parts = [], []
        _collect_mime_text(message.get('payload') or {}, plain, html_parts)
        if any(part.strip() for part in plain):
            text = '\n'.join(part.strip() for part in plain if part.strip())
        elif any(part.strip() for part in html_parts):
            text = _html_to_text('\n'.join(html_parts))
        else:
            text = ''
        text = (text or '').strip() or snippet
    except Exception:
        text = snippet
    return text[:GMAIL_BODY_CAP]


def gmail_headers(message):
    found = {}
    for item in (message.get('payload') or {}).get('headers') or []:
        name = str(item.get('name') or '').lower()
        if name and name not in found:
            found[name] = item.get('value') or ''
    return found

def gmail_redirect_uri():
    # One value for the authorize redirect and the token exchange. They must match.
    override = (os.environ.get('GMAIL_REDIRECT_URI') or '').strip()
    if override:
        return override
    return url_for('gmail_callback', _external=True)


def refresh_gmail_access_token(user):
    refresh_token = (user.gmail_refresh_token or '').strip()
    if not refresh_token or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return False
    response = requests.post('https://oauth2.googleapis.com/token', data={
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    }, timeout=HTTP_TIMEOUT)
    if response.status_code != 200:
        return False
    tokens = response.json()
    access_token = tokens.get('access_token')
    if not access_token:
        return False
    user.gmail_token = access_token
    if tokens.get('refresh_token'):
        user.gmail_refresh_token = tokens['refresh_token']
    db.session.commit()
    return True


def gmail_api_get(user, url, params=None):
    def _get():
        return requests.get(
            url,
            headers={'Authorization': f'Bearer {user.gmail_token}'},
            params=params,
            timeout=HTTP_TIMEOUT,
        )
    response = _get()
    if response.status_code == 401 and refresh_gmail_access_token(user):
        response = _get()
    return response


@app.route('/gmail/connect')
@login_required
def gmail_connect():
    if not GOOGLE_CLIENT_ID: 
        flash('Google Login not configured on server.', 'error')
        return redirect(url_for('settings_page'))
        
    redirect_uri = gmail_redirect_uri()
    
    # 1. SCOPES: We ask for BOTH Read-Only Gmail AND User Email Profile
    scope = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email"
    state = secrets.token_urlsafe(32)
    session['gmail_oauth_state'] = state
    query = urllib.parse.urlencode({
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': scope,
        'access_type': 'offline',
        'prompt': 'consent',
        'state': state,
    })
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{query}')

@app.route('/gmail/callback')
@login_required
def gmail_callback():
    # 2. Get the code from the URL
    code = request.args.get('code')
    
    # 3. SAFETY CHECK: If there is no code, stop immediately.
    if not code:
        flash('Login failed: No authorization code received from Google. Please try again.', 'error')
        return redirect(url_for('settings_page'))

    saved_state = session.pop('gmail_oauth_state', None)
    if not saved_state or request.args.get('state') != saved_state:
        flash('Gmail sign-in could not be verified. Please try again.', 'error')
        return redirect(url_for('settings_page'))

    redirect_uri = gmail_redirect_uri()
    
    data = {
        'code': code, 
        'client_id': GOOGLE_CLIENT_ID, 
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri, 
        'grant_type': 'authorization_code'
    }
    
    try:
        # 4. Exchange Code for Token
        r = requests.post('https://oauth2.googleapis.com/token', data=data, timeout=HTTP_TIMEOUT)
        
        if r.status_code == 200:
            tokens = r.json()
            access_token = tokens.get('access_token') or ''
            if not access_token:
                flash('Failed to connect to Google.', 'error')
                return redirect(url_for('settings_page'))
            current_user.gmail_token = access_token
            refresh_token = tokens.get('refresh_token')
            if refresh_token:
                current_user.gmail_refresh_token = refresh_token
            # Keep the tokens even if the email lookup fails.
            db.session.commit()

            email = ''
            try:
                user_info = requests.get(
                    'https://www.googleapis.com/oauth2/v2/userinfo',
                    headers={'Authorization': f'Bearer {access_token}'},
                    timeout=HTTP_TIMEOUT,
                )
                if user_info.status_code == 200:
                    email = (user_info.json() or {}).get('email') or ''
            except Exception:
                email = ''
            if email:
                current_user.gmail_email = email
                db.session.commit()
                flash('Gmail connected successfully!', 'success')
            else:
                flash('Connected, but could not fetch email address.', 'warning')
        else:
            error_code = ''
            try:
                body = r.json()
                if isinstance(body, dict) and isinstance(body.get('error'), str):
                    error_code = body['error']
            except Exception:
                error_code = ''
            print(f'GOOGLE ERROR: status={r.status_code} error={error_code}')
            flash('Failed to connect to Google.', 'error')
            
    except Exception:
        print('CONNECTION ERROR')
        flash('System error during connection.', 'error')
        
    return redirect(url_for('settings_page'))

def revoke_gmail_token(token):
    token = (token or '').strip()
    if not token:
        return
    try:
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            data={'token': token},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=5,
        )
    except Exception:
        return


@app.route('/gmail/disconnect', methods=['POST'])
@login_required
def gmail_disconnect():
    token = (current_user.gmail_refresh_token or '').strip() or (current_user.gmail_token or '').strip()
    revoke_gmail_token(token)
    current_user.gmail_token = ''
    current_user.gmail_refresh_token = ''
    current_user.gmail_email = ''
    db.session.commit()
    flash('Gmail disconnected.', 'success')
    return redirect(url_for('settings_page'))

@app.route('/gmail/scan')
@login_required
def gmail_scan():
    if not current_user.gmail_token: return redirect(url_for('settings_page'))
    
    try:
        r = gmail_api_get(
            current_user,
            'https://gmail.googleapis.com/gmail/v1/users/me/messages',
            params={'maxResults': 15, 'labelIds': 'INBOX'},
        )
        if r.status_code != 200:
            if r.status_code == 401:
                flash('Token expired. Please reconnect Gmail.', 'error')
            else:
                flash('Error scanning inbox.', 'error')
            return redirect(url_for('settings_page'))
            
        messages = r.json().get('messages', [])
        emails = []
        
        for msg in messages:
            try:
                m_r = gmail_api_get(
                    current_user,
                    f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg["id"]}',
                    params={'format': 'full'},
                )
                if m_r.status_code != 200:
                    continue
                m_data = m_r.json()
                headers_dict = gmail_headers(m_data)
                body = gmail_message_body(m_data)
                emails.append({
                    'id': msg['id'],
                    'sender': headers_dict.get('from', 'Unknown'),
                    'subject': headers_dict.get('subject', 'No Subject'),
                    'body': (m_data.get('snippet') or body)[:240],
                    'date': headers_dict.get('date', '')[:16]
                })
            except Exception as e:
                print(f'Gmail message skipped: {e}')
                continue
        
        return render_template('gmail_scan.html', emails=emails)
    except Exception as e:
        print(e)
        flash('Error scanning inbox.', 'error')
        return redirect(url_for('home'))

@app.route('/gmail/analyze/<msg_id>', methods=['POST'])
@login_required
def gmail_analyze_single(msg_id):
    if not current_user.gmail_token: return jsonify({'error': 'No token'})
    
    try:
        r = gmail_api_get(
            current_user,
            f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}',
            params={'format': 'full'},
        )
        if r.status_code != 200: return jsonify({'error': 'Fetch failed'})
        
        m_data = r.json()
        headers_dict = gmail_headers(m_data)
        body = gmail_message_body(m_data)
        
        # 1. Run Analysis
        analyzer = PhishingAnalyzer(SYSTEM_GROQ_KEY, SYSTEM_VT_KEY)
        result, _, _ = analyzer.analyze({
            'sender': headers_dict.get('from', ''),
            'subject': headers_dict.get('subject', ''),
            'body': body
        })
        
        # 2. SAVE TO DATABASE (This was missing!)
        entry = AnalysisHistory(
            user_id=current_user.id, 
            sender=headers_dict.get('from', 'Unknown')[:200],
            subject=headers_dict.get('subject', '(No Subject)')[:500], 
            risk_level=result['risk_level'],
            risk_score=result['risk_score'],
            engine=(result.get('engine') or 'Not recorded')[:40],
        )
        entry.set_reasons(result['reasons'])
        db.session.add(entry)
        db.session.commit()
        
        # 3. Return result to frontend
        return jsonify(result)
        
    except Exception:
        print('Gmail analyze failed')
        return jsonify({'error': 'Could not analyze this message.'})
    
@app.route('/site-qr')
def site_qr():
    base_url = url_for('home', _external=True)

    # Generate QR
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(base_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to buffer
    buffer = BytesIO()
    img.save(buffer)
    buffer.seek(0)
    
    # FIX: Use 'send_file' directly, not 'flask.send_file'
    return send_file(buffer, mimetype='image/png')
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)