"""
PhishGuard AI - Complete Version with Gmail Integration
Fixed version with proper URL encoding
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

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

# Secret key
app.secret_key = os.environ.get('SECRET_KEY', 'phishguard-dev-secret-key-2024')

# Database
database_url = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth Configuration - strip removes extra spaces/newlines
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip().replace('\n', '').replace('\r', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip().replace('\n', '').replace('\r', '')

# Initialize extensions
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


# Create tables
with app.app_context():
    db.create_all()
    print("✓ Database tables ready")


# ============================================================
# PHISHING ANALYZER
# ============================================================

class PhishingAnalyzer:
    def __init__(self, groq_key='', vt_key=''):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def analyze_with_ai(self, email_data):
        if not self.groq_api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_api_key)
            
            prompt = f"""You are PhishGuard AI, an elite cybersecurity expert. Analyze this email for phishing, social engineering, and fraud.

EMAIL METADATA:
FROM: {email_data.get('sender', 'Unknown')}
SUBJECT: {email_data.get('subject', '')}

EMAIL BODY:
{email_data.get('body', '')[:2000]}

Perform a deep analysis looking for:
1. Header anomalies (mismatched domains, spoofing)
2. Social engineering (urgency, fear, greed, curiosity)
3. Malicious content (suspicious links, credential harvesting)
4. Language patterns (poor grammar, generic greetings)

Respond in strictly valid JSON format:
{{
    "risk_level": "HIGH" | "MEDIUM" | "LOW",
    "risk_score": <integer 0-100>,
    "is_phishing": <boolean>,
    "reasons": [
        "Specific reason 1 (e.g. 'Sender domain @paypal-support.com impersonates PayPal')",
        "Specific reason 2 (e.g. 'Urgency tactic: threatens account suspension in 24h')"
    ],
    "recommendation": "Clear, actionable advice for the user"
}}"""

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
            
            if "```" in result_text:
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
            
            result = json.loads(result_text)
            result['ai_powered'] = True
            return result
            
        except Exception as e:
            print(f"AI error: {e}")
            return None
    
    def analyze_with_rules(self, email_data):
        reasons = []
        score = 0
        
        sender = email_data.get('sender', '').lower()
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        full_text = f"{subject} {body}"
        
        if any(w in full_text for w in ['urgent', 'immediate', 'act now', 'expire', 'suspended']):
            score += 15
            reasons.append("Uses urgency tactics")
        
        if any(w in full_text for w in ['compromised', 'unauthorized', 'verify your', 'security alert']):
            score += 20
            reasons.append("Uses fear tactics")
        
        if any(w in full_text for w in ['won', 'winner', 'prize', 'lottery', 'congratulations']):
            score += 25
            reasons.append("Promises rewards (common scam)")
        
        if any(tld in sender for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz']):
            score += 30
            reasons.append("Suspicious sender domain")
        
        brands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'bank']
        for brand in brands:
            if brand in full_text and brand not in sender:
                score += 30
                reasons.append(f"Possible {brand.title()} impersonation")
                break
        
        if any(w in full_text for w in ['password', 'ssn', 'credit card', 'bank account']):
            score += 25
            reasons.append("Requests sensitive information")
        
        if any(s in full_text for s in ['bit.ly', 'tinyurl', 'goo.gl']):
            score += 15
            reasons.append("Contains shortened URLs")
        
        if any(p in full_text for p in ['kindly', 'dear customer', 'dear user']):
            score += 10
            reasons.append("Uses scam-like phrasing")
        
        risk_level = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        
        if not reasons:
            reasons.append("No obvious phishing indicators")
        
        recommendation = {
            "HIGH": "Do NOT click links or reply. Delete immediately.",
            "MEDIUM": "Be cautious. Verify sender through official channels.",
            "LOW": "Email appears safe, but stay vigilant."
        }[risk_level]
        
        return {
            "risk_level": risk_level,
            "risk_score": min(100, score),
            "is_phishing": score >= 50,
            "reasons": reasons,
            "recommendation": recommendation,
            "ai_powered": False
        }
    
    def analyze(self, email_data, use_ai=True):
        if use_ai:
            result = self.analyze_with_ai(email_data)
            if result:
                return result
        return self.analyze_with_rules(email_data)
    
    def extract_links(self, text):
        return list(set(re.findall(r'https?://[^\s<>"\'}\]]+', text)))[:10]


# ============================================================
# GMAIL HELPER FUNCTIONS
# ============================================================

def get_gmail_auth_url():
    """Generate Google OAuth URL"""
    client_id = GOOGLE_CLIENT_ID
    
    if not client_id:
        return None
    
    # Determine redirect URI
    if os.environ.get('RENDER'):
        redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 
            'https://phishguard-ai-g6iu.onrender.com/gmail/callback')
    else:
        redirect_uri = 'http://127.0.0.1:5000/gmail/callback'
    
    # Clean redirect URI
    redirect_uri = redirect_uri.strip().replace('\n', '').replace('\r', '')
    
    scopes = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/userinfo.email'
    ]
    
    # Build URL with proper encoding
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
    """Exchange authorization code for access tokens"""
    import requests
    
    if os.environ.get('RENDER'):
        redirect_uri = os.environ.get('GMAIL_REDIRECT_URI',
            'https://phishguard-ai-g6iu.onrender.com/gmail/callback')
    else:
        redirect_uri = 'http://127.0.0.1:5000/gmail/callback'
    
    redirect_uri = redirect_uri.strip().replace('\n', '').replace('\r', '')
    
    token_url = 'https://oauth2.googleapis.com/token'
    
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    
    response = requests.post(token_url, data=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Token exchange error: {response.text}")
        return None


def get_gmail_service(user):
    """Get authenticated Gmail API service"""
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
        
        service = build('gmail', 'v1', credentials=credentials)
        return service
        
    except Exception as e:
        print(f"Gmail service error: {e}")
        return None


def get_email_body(payload):
    """Extract email body from Gmail payload"""
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
                if body:
                    break
    
    body = re.sub(r'<[^>]+>', ' ', body)
    body = re.sub(r'\s+', ' ', body).strip()
    
    return body[:2000]


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters")
        if not re.match(r'^[\w.-]+@[\w.-]+\.\w+$', email):
            errors.append("Invalid email address")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters")
        if password != confirm:
            errors.append("Passwords don't match")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered")
        if User.query.filter_by(username=username).first():
            errors.append("Username taken")
        
        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash(f'Welcome, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('home'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


# ============================================================
# MAIN ROUTES
# ============================================================

@app.route('/')
@login_required
def home():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id)\
        .order_by(AnalysisHistory.timestamp.desc()).all()
    
    stats = {
        'total': len(history),
        'high_risk': len([h for h in history if h.risk_level == 'HIGH']),
        'medium_risk': len([h for h in history if h.risk_level == 'MEDIUM']),
        'low_risk': len([h for h in history if h.risk_level == 'LOW'])
    }
    
    recent_threats = [h for h in history if h.risk_level == 'HIGH'][:5]
    
    return render_template('index.html', stats=stats, recent_threats=recent_threats)


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_page():
    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        use_ai = request.form.get('use_ai') == 'on'
        
        if not body:
            return render_template('analyze.html', error="Please enter email content.")
        
        email_data = {'sender': sender, 'subject': subject, 'body': body}
        
        analyzer = PhishingAnalyzer(
            groq_key=current_user.groq_api_key,
            vt_key=current_user.virustotal_api_key
        )
        
        result = analyzer.analyze(email_data, use_ai=use_ai)
        links = analyzer.extract_links(body)
        
        entry = AnalysisHistory(
            user_id=current_user.id,
            sender=sender or 'Unknown',
            subject=subject or '(No Subject)',
            risk_level=result['risk_level'],
            risk_score=result['risk_score']
        )
        entry.set_reasons(result['reasons'][:5])
        db.session.add(entry)
        db.session.commit()
        
        return render_template('results.html', result=result, email=email_data, 
                             links=links, link_results=[])
    
    return render_template('analyze.html')


@app.route('/history')
@login_required
def history_page():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id)\
        .order_by(AnalysisHistory.timestamp.desc()).limit(50).all()
    
    formatted = [{
        'id': h.id,
        'sender': h.sender,
        'subject': h.subject,
        'risk_level': h.risk_level,
        'risk_score': h.risk_score,
        'timestamp': h.timestamp.strftime('%Y-%m-%d %H:%M'),
        'reasons': h.get_reasons()
    } for h in history]
    
    return render_template('history.html', history=formatted)


@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    AnalysisHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    message = None
    
    if request.method == 'POST':
        groq_key = request.form.get('groq_api_key', '').strip()
        vt_key = request.form.get('virustotal_api_key', '').strip()
        
        if groq_key:
            current_user.groq_api_key = groq_key
        if vt_key:
            current_user.virustotal_api_key = vt_key
        
        db.session.commit()
        message = "Settings saved!"
    
    config = {
        'groq_configured': bool(current_user.groq_api_key),
        'virustotal_configured': bool(current_user.virustotal_api_key),
        'gmail_connected': bool(current_user.gmail_email),
        'gmail_email': current_user.gmail_email,
        'gmail_available': bool(GOOGLE_CLIENT_ID)
    }
    
    return render_template('settings.html', config=config, message=message)


@app.route('/about')
@login_required
def about_page():
    return render_template('about.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            new_username = request.form.get('username', '').strip()
            if len(new_username) >= 3:
                existing = User.query.filter_by(username=new_username).first()
                if existing and existing.id != current_user.id:
                    flash('Username taken', 'error')
                else:
                    current_user.username = new_username
                    db.session.commit()
                    flash('Profile updated!', 'success')
        
        elif action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            
            if not current_user.check_password(current_pw):
                flash('Current password incorrect', 'error')
            elif len(new_pw) < 6:
                flash('Password must be 6+ characters', 'error')
            elif new_pw != confirm_pw:
                flash("Passwords don't match", 'error')
            else:
                current_user.set_password(new_pw)
                db.session.commit()
                flash('Password changed!', 'success')
    
    return render_template('profile.html')


# ============================================================
# GMAIL ROUTES
# ============================================================

@app.route('/gmail/connect')
@login_required
def gmail_connect():
    """Start Gmail OAuth flow"""
    auth_url = get_gmail_auth_url()
    
    if not auth_url:
        flash('Gmail integration not configured. Please contact admin.', 'error')
        return redirect(url_for('settings_page'))
    
    return redirect(auth_url)


@app.route('/gmail/callback')
@login_required
def gmail_callback():
    """Handle Gmail OAuth callback"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'Gmail connection cancelled: {error}', 'error')
        return redirect(url_for('settings_page'))
    
    if not code:
        flash('No authorization code received', 'error')
        return redirect(url_for('settings_page'))
    
    tokens = exchange_code_for_tokens(code)
    
    if not tokens:
        flash('Failed to get access token', 'error')
        return redirect(url_for('settings_page'))
    
    current_user.gmail_token = tokens.get('access_token', '')
    current_user.gmail_refresh_token = tokens.get('refresh_token', '')
    
    try:
        import requests
        headers = {'Authorization': f'Bearer {tokens["access_token"]}'}
        resp = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
        if resp.status_code == 200:
            current_user.gmail_email = resp.json().get('email', '')
    except:
        pass
    
    db.session.commit()
    
    flash(f'Gmail connected: {current_user.gmail_email}', 'success')
    return redirect(url_for('settings_page'))


@app.route('/gmail/disconnect')
@login_required
def gmail_disconnect():
    """Disconnect Gmail"""
    current_user.gmail_token = ''
    current_user.gmail_refresh_token = ''
    current_user.gmail_email = ''
    db.session.commit()
    
    flash('Gmail disconnected', 'info')
    return redirect(url_for('settings_page'))


@app.route('/gmail/scan')
@login_required
def gmail_scan():
    """Scan Gmail inbox"""
    if not current_user.gmail_token:
        flash('Please connect Gmail first', 'error')
        return redirect(url_for('settings_page'))
    
    service = get_gmail_service(current_user)
    
    if not service:
        flash('Gmail connection expired. Please reconnect.', 'error')
        current_user.gmail_token = ''
        current_user.gmail_email = ''
        db.session.commit()
        return redirect(url_for('settings_page'))
    
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=20
        ).execute()
        
        messages = results.get('messages', [])
        emails = []
        
        for msg in messages:
            msg_data = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='full'
            ).execute()
            
            headers = msg_data.get('payload', {}).get('headers', [])
            
            subject = ''
            sender = ''
            date = ''
            
            for h in headers:
                name = h.get('name', '').lower()
                if name == 'subject':
                    subject = h.get('value', '')
                elif name == 'from':
                    sender = h.get('value', '')
                elif name == 'date':
                    date = h.get('value', '')[:25]
            
            body = get_email_body(msg_data.get('payload', {}))
            
            emails.append({
                'id': msg['id'],
                'sender': sender[:50] if sender else 'Unknown',
                'subject': subject[:60] if subject else '(No Subject)',
                'body': body[:300],
                'date': date
            })
        
        return render_template('gmail_scan.html', emails=emails)
        
    except Exception as e:
        flash(f'Error fetching emails: {str(e)}', 'error')
        return redirect(url_for('home'))


@app.route('/gmail/analyze/<msg_id>')
@login_required
def gmail_analyze_message(msg_id):
    """Analyze a specific Gmail message"""
    service = get_gmail_service(current_user)
    
    if not service:
        return jsonify({'error': 'Gmail not connected'})
    
    try:
        msg_data = service.users().messages().get(
            userId='me',
            id=msg_id,
            format='full'
        ).execute()
        
        headers = msg_data.get('payload', {}).get('headers', [])
        
        subject = ''
        sender = ''
        
        for h in headers:
            name = h.get('name', '').lower()
            if name == 'subject':
                subject = h.get('value', '')
            elif name == 'from':
                sender = h.get('value', '')
        
        body = get_email_body(msg_data.get('payload', {}))
        
        analyzer = PhishingAnalyzer(
            groq_key=current_user.groq_api_key,
            vt_key=current_user.virustotal_api_key
        )
        
        result = analyzer.analyze({
            'sender': sender,
            'subject': subject,
            'body': body
        })
        
        entry = AnalysisHistory(
            user_id=current_user.id,
            sender=sender[:200] if sender else 'Unknown',
            subject=subject[:500] if subject else '(No Subject)',
            risk_level=result['risk_level'],
            risk_score=result['risk_score']
        )
        entry.set_reasons(result['reasons'][:5])
        db.session.add(entry)
        db.session.commit()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)})


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})


# ============================================================
# RUN
# ============================================================

if __name__ == '__main__':
    print("=" * 50)
    print("  PhishGuard AI")
    print("  http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)