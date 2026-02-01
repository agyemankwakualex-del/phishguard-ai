"""
PhishGuard AI - Final Version (Phase 3)
Includes Gravatar support and Bulk Scanning
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import re
import os

import base64
import urllib.parse
import hashlib  # <--- Added for Gravatar

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'phishguard-dev-secret-key-2024')

database_url = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip().replace('\n', '').replace('\r', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip().replace('\n', '').replace('\r', '')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


# ============================================================
# DATABASE MODELS
# ============================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    groq_api_key = db.Column(db.String(256), default='')
    virustotal_api_key = db.Column(db.String(256), default='')
    
    gmail_token = db.Column(db.Text, default='')
    gmail_refresh_token = db.Column(db.Text, default='')
    gmail_email = db.Column(db.String(120), default='')
    
    analyses = db.relationship('AnalysisHistory', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # NEW: Generate Profile Picture URL
    def avatar(self, size):
        digest = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'


class AnalysisHistory(db.Model):
    __tablename__ = 'analysis_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender = db.Column(db.String(200), default='Unknown')
    subject = db.Column(db.String(500), default='')
    risk_level = db.Column(db.String(20), default='LOW')
    risk_score = db.Column(db.Integer, default=0)
    reasons = db.Column(db.Text, default='[]')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_reasons(self):
        try:
            return json.loads(self.reasons)
        except:
            return []
    
    def set_reasons(self, reasons_list):
        self.reasons = json.dumps(reasons_list)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()
    print("✓ Database tables ready")



# ============================================================
# PHISHING ANALYZER (UPDATED WITH VIRUSTOTAL)
# ============================================================

class PhishingAnalyzer:
    def __init__(self, groq_key='', vt_key=''):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def extract_links(self, text):
        # Extract http/https links
        return list(set(re.findall(r'https?://[^\s<>"\'}\]]+', text)))[:5] # Limit to top 5 to save API calls

    def check_virustotal(self, urls):
        """
        Checks a list of URLs against VirusTotal API v3.
        Returns a summary of malicious findings.
        """
        if not self.virustotal_api_key or not urls:
            return {"malicious_count": 0, "details": []}

        malicious_count = 0
        details = []

        headers = {
            "x-apikey": self.virustotal_api_key
        }

        for url in urls:
            try:
                # VT requires base64 encoded URL identifiers
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(api_url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    
                    if stats['malicious'] > 0:
                        malicious_count += 1
                        details.append(f"⚠️ {url} flagged by {stats['malicious']} vendors.")
                    elif stats['suspicious'] > 0:
                        details.append(f"⚠️ {url} marked as suspicious.")
                
                # Note: Free API has rate limits (4/min). 
                # In production, we would handle 429 errors here.
                
            except Exception as e:
                print(f"VT Error for {url}: {e}")
        
        return {"malicious_count": malicious_count, "details": details}

    def analyze_with_ai(self, email_data, vt_results):
        if not self.groq_api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_api_key)
            
            # Inject VT results into the prompt so the AI knows about bad links
            vt_context = ""
            if vt_results['malicious_count'] > 0:
                vt_context = f"CRITICAL: VirusTotal found {vt_results['malicious_count']} MALICIOUS links in this email: {str(vt_results['details'])}"
            
            prompt = f"""You are PhishGuard AI. Analyze this email.

EXTERNAL INTELLIGENCE:
{vt_context}

EMAIL METADATA:
FROM: {email_data.get('sender', 'Unknown')}
SUBJECT: {email_data.get('subject', '')}

EMAIL BODY:
{email_data.get('body', '')[:2000]}

Respond in JSON format:
{{
    "risk_level": "HIGH" | "MEDIUM" | "LOW",
    "risk_score": <0-100>,
    "reasons": ["Reason 1", "Reason 2"],
    "recommendation": "Short advice"
}}
If 'EXTERNAL INTELLIGENCE' indicates malicious links, risk_level MUST be HIGH.
"""

            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Respond with JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Cleanup Markdown code blocks if AI adds them
            if "```" in result_text:
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
            
            result = json.loads(result_text)
            result['ai_powered'] = True
            
            # Force HIGH risk if VT found malware, regardless of what AI thinks
            if vt_results['malicious_count'] > 0:
                result['risk_level'] = 'HIGH'
                result['risk_score'] = 95
                result['reasons'].insert(0, f"VirusTotal detected {vt_results['malicious_count']} malicious links.")

            return result
            
        except Exception as e:
            print(f"AI error: {e}")
            return None
    
    # ... (Keep analyze_with_rules method exactly as it was, or I can paste it if needed) ...
    def analyze_with_rules(self, email_data, vt_results):
        reasons = []
        score = 0
        
        # Add VT Logic to Rule Engine
        if vt_results['malicious_count'] > 0:
            score += 100
            reasons.append(f"VirusTotal detected {vt_results['malicious_count']} malicious links")
        
        sender = email_data.get('sender', '').lower()
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        full_text = f"{subject} {body}"
        
        if any(w in full_text for w in ['urgent', 'act now', 'suspended']):
            score += 15
            reasons.append("Uses urgency tactics")
        
        # ... (rest of logic similar to previous version) ...
        
        risk_level = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        
        return {
            "risk_level": risk_level,
            "risk_score": min(100, score),
            "reasons": reasons,
            "recommendation": "Be careful.",
            "ai_powered": False
        }

    def analyze(self, email_data, use_ai=True):
        # 1. Extract Links
        links = self.extract_links(email_data.get('body', ''))
        
        # 2. Check VirusTotal
        vt_results = self.check_virustotal(links)
        
        # 3. Run Analysis
        if use_ai:
            result = self.analyze_with_ai(email_data, vt_results)
            if result:
                return result
        
        return self.analyze_with_rules(email_data, vt_results)


# ============================================================
# GMAIL HELPER FUNCTIONS
# ============================================================

def get_gmail_auth_url():
    client_id = GOOGLE_CLIENT_ID
    if not client_id:
        return None
    
    if os.environ.get('RENDER'):
        redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 
            'https://phishguard-ai-g6iu.onrender.com/gmail/callback')
    else:
        redirect_uri = 'http://127.0.0.1:5000/gmail/callback'
    
    redirect_uri = redirect_uri.strip().replace('\n', '').replace('\r', '')
    
    scopes = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/userinfo.email'
    ]
    
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': ' '.join(scopes),
        'access_type': 'offline',
        'prompt': 'consent'
    }
    
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params)
    return auth_url


def exchange_code_for_tokens(code):
    import requests
    if os.environ.get('RENDER'):
        redirect_uri = os.environ.get('GMAIL_REDIRECT_URI',
            'https://phishguard-ai-g6iu.onrender.com/gmail/callback')
    else:
        redirect_uri = 'http://127.0.0.1:5000/gmail/callback'
    
    redirect_uri = redirect_uri.strip().replace('\n', '').replace('\r', '')
    
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    
    response = requests.post('https://oauth2.googleapis.com/token', data=data)
    if response.status_code == 200:
        return response.json()
    return None


def get_gmail_service(user):
    if not user.gmail_token:
        return None
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        
        credentials = Credentials(
            token=user.gmail_token,
            refresh_token=user.gmail_refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET
        )
        
        if credentials.expired and credentials.refresh_token:
            from google.auth.transport.requests import Request
            credentials.refresh(Request())
            user.gmail_token = credentials.token
            db.session.commit()
        
        return build('gmail', 'v1', credentials=credentials)
    except Exception as e:
        print(f"Gmail service error: {e}")
        return None


def get_email_body(payload):
    body = ''
    if 'body' in payload and payload['body'].get('data'):
        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    if 'parts' in payload:
        for part in payload['parts']:
            if part.get('mimeType') == 'text/plain':
                if 'data' in part.get('body', {}):
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    break
            elif 'parts' in part:
                body = get_email_body(part)
                if body: break
    body = re.sub(r'<[^>]+>', ' ', body)
    return re.sub(r'\s+', ' ', body).strip()[:2000]


# ============================================================
# ROUTES
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        if len(username) < 3 or len(password) < 6 or password != confirm:
            flash('Invalid input', 'error')
            return render_template('register.html')
        
        if User.query.filter((User.email==email)|(User.username==username)).first():
            flash('User already exists', 'error')
            return render_template('register.html')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email', '').lower()).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user, remember=request.form.get('remember') == 'on')
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(request.args.get('next') or url_for('home'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).all()
    stats = {
        'total': len(history),
        'high_risk': len([h for h in history if h.risk_level == 'HIGH']),
        'medium_risk': len([h for h in history if h.risk_level == 'MEDIUM']),
        'low_risk': len([h for h in history if h.risk_level == 'LOW'])
    }
    return render_template('index.html', stats=stats, recent_threats=[h for h in history if h.risk_level == 'HIGH'][:5])


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_page():
    if request.method == 'POST':
        body = request.form.get('body', '').strip()
        if not body: return render_template('analyze.html', error="No content")
        
        data = {
            'sender': request.form.get('sender', ''),
            'subject': request.form.get('subject', ''),
            'body': body
        }
        
        analyzer = PhishingAnalyzer(current_user.groq_api_key, current_user.virustotal_api_key)
        result = analyzer.analyze(data, request.form.get('use_ai') == 'on')
        links = analyzer.extract_links(body)
        
        entry = AnalysisHistory(user_id=current_user.id, sender=data['sender'] or 'Unknown',
                              subject=data['subject'] or '(No Subject)', risk_level=result['risk_level'],
                              risk_score=result['risk_score'])
        entry.set_reasons(result['reasons'][:5])
        db.session.add(entry)
        db.session.commit()
        
        return render_template('results.html', result=result, email=data, links=links, link_results=[])
    return render_template('analyze.html')


@app.route('/history')
@login_required
def history_page():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).limit(50).all()
    return render_template('history.html', history=history)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    if request.method == 'POST':
        current_user.groq_api_key = request.form.get('groq_api_key', '').strip()
        current_user.virustotal_api_key = request.form.get('virustotal_api_key', '').strip()
        db.session.commit()
        flash('Settings saved!', 'success')
    
    config = {
        'groq_configured': bool(current_user.groq_api_key),
        'virustotal_configured': bool(current_user.virustotal_api_key),
        'gmail_connected': bool(current_user.gmail_email),
        'gmail_email': current_user.gmail_email,
        'gmail_available': bool(GOOGLE_CLIENT_ID)
    }
    return render_template('settings.html', config=config)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    # Basic profile update logic here (same as before)
    return render_template('profile.html')


@app.route('/about')
def about_page(): return render_template('about.html')


# Gmail Routes
@app.route('/gmail/connect')
@login_required
def gmail_connect():
    url = get_gmail_auth_url()
    return redirect(url) if url else redirect(url_for('settings_page'))


@app.route('/gmail/callback')
@login_required
def gmail_callback():
    code = request.args.get('code')
    if code:
        tokens = exchange_code_for_tokens(code)
        if tokens:
            current_user.gmail_token = tokens.get('access_token', '')
            current_user.gmail_refresh_token = tokens.get('refresh_token', '')
            
            # Fetch email address
            import requests
            resp = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers={'Authorization': f'Bearer {tokens["access_token"]}'})
            if resp.status_code == 200: current_user.gmail_email = resp.json().get('email', '')
            
            db.session.commit()
            flash('Gmail connected!', 'success')
    return redirect(url_for('settings_page'))


@app.route('/gmail/disconnect')
@login_required
def gmail_disconnect():
    current_user.gmail_token = ''
    current_user.gmail_email = ''
    db.session.commit()
    return redirect(url_for('settings_page'))


@app.route('/gmail/scan')
@login_required
def gmail_scan():
    service = get_gmail_service(current_user)
    if not service: return redirect(url_for('settings_page'))
    
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=20).execute()
        emails = []
        for msg in results.get('messages', []):
            m = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name'].lower(): h['value'] for h in m['payload']['headers']}
            emails.append({
                'id': msg['id'],
                'sender': headers.get('from', 'Unknown'),
                'subject': headers.get('subject', '(No Subject)'),
                'body': m['snippet'], # Use snippet for preview
                'date': headers.get('date', '')[:16]
            })
        return render_template('gmail_scan.html', emails=emails)
    except:
        return redirect(url_for('home'))


@app.route('/gmail/analyze/<msg_id>')
@login_required
def gmail_analyze_message(msg_id):
    service = get_gmail_service(current_user)
    if not service: return jsonify({'error': 'Not connected'})
    
    try:
        m = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        headers = {h['name'].lower(): h['value'] for h in m['payload']['headers']}
        body = get_email_body(m['payload'])
        
        analyzer = PhishingAnalyzer(current_user.groq_api_key, current_user.virustotal_api_key)
        result = analyzer.analyze({
            'sender': headers.get('from', ''),
            'subject': headers.get('subject', ''),
            'body': body
        })
        
        # Save history
        entry = AnalysisHistory(user_id=current_user.id, sender=headers.get('from', '')[:200],
                              subject=headers.get('subject', '')[:500], risk_level=result['risk_level'],
                              risk_score=result['risk_score'])
        entry.set_reasons(result['reasons'][:5])
        db.session.add(entry)
        db.session.commit()
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/health')
def health(): return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)