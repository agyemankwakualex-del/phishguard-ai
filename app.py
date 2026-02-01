"""
PhishGuard AI - Final Backend
Integrates Groq AI, VirusTotal, and Gmail with your Custom UI
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
import hashlib
import requests  # <--- REQUIRED for VirusTotal

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

# Security Key
app.secret_key = os.environ.get('SECRET_KEY', 'phishguard-dev-secret-key-2024')

# Database Config (Handles Render PostgreSQL or Local SQLite)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth Config
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip().replace('\n', '').replace('\r', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip().replace('\n', '').replace('\r', '')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error' # Matches your alert-error class

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
    
    # API Keys
    groq_api_key = db.Column(db.String(256), default='')
    virustotal_api_key = db.Column(db.String(256), default='')
    
    # Gmail Tokens
    gmail_token = db.Column(db.Text, default='')
    gmail_refresh_token = db.Column(db.Text, default='')
    gmail_email = db.Column(db.String(120), default='')
    
    analyses = db.relationship('AnalysisHistory', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Gravatar for Profile Pic
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
        try: return json.loads(self.reasons)
        except: return []
    
    def set_reasons(self, reasons_list):
        self.reasons = json.dumps(reasons_list)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# ============================================================
# PHISHING ANALYZER (LOGIC CORE)
# ============================================================

class PhishingAnalyzer:
    def __init__(self, groq_key='', vt_key=''):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def extract_links(self, text):
        # Extract http/https links
        return list(set(re.findall(r'https?://[^\s<>"\'}\]]+', text)))[:5]

    def check_virustotal(self, urls):
        """
        Checks links against VirusTotal.
        Returns a tuple: (summary_dict, detailed_list_for_ui)
        """
        detailed_results = []
        malicious_count = 0
        
        if not self.virustotal_api_key or not urls:
            return {'malicious_count': 0}, []

        headers = {"x-apikey": self.virustotal_api_key}

        for url in urls:
            result_entry = {'url': url, 'risk': 'UNKNOWN'}
            try:
                # Base64 encode URL for VT API v3
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    
                    if stats['malicious'] > 0:
                        malicious_count += 1
                        result_entry['risk'] = 'HIGH'
                    elif stats['suspicious'] > 0:
                        result_entry['risk'] = 'MEDIUM'
                    else:
                        result_entry['risk'] = 'LOW'
                elif response.status_code == 404:
                    result_entry['risk'] = 'LOW' # URL not in database usually means new or safe-ish
                
            except Exception as e:
                print(f"VT Error: {e}")
            
            detailed_results.append(result_entry)
            
        return {'malicious_count': malicious_count}, detailed_results

    def analyze_with_ai(self, email_data, vt_summary):
        if not self.groq_api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_api_key)
            
            # Inject VT findings into prompt
            vt_context = ""
            if vt_summary['malicious_count'] > 0:
                vt_context = f"CRITICAL: VirusTotal detected {vt_summary['malicious_count']} MALICIOUS links."

            prompt = f"""You are PhishGuard AI. Analyze this email.
External Intel: {vt_context}

From: {email_data.get('sender', 'Unknown')}
Subject: {email_data.get('subject', '')}
Body: {email_data.get('body', '')[:2000]}

Respond in strictly valid JSON:
{{
    "risk_level": "HIGH" | "MEDIUM" | "LOW",
    "risk_score": <0-100>,
    "reasons": ["Short reason 1", "Short reason 2"],
    "recommendation": "Actionable advice"
}}
If External Intel says malicious, risk MUST be HIGH."""

            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            result_text = response.choices[0].message.content.strip()
            if "```" in result_text: 
                result_text = result_text.split("```")[1].replace('json', '')
            
            result = json.loads(result_text)
            result['ai_powered'] = True
            
            # Force high risk if VT found malware
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
        
        keywords = {
            'urgent': 15, 'verify': 20, 'account suspended': 30, 
            'password': 25, 'lottery': 25, 'bank': 15
        }
        
        for word, weight in keywords.items():
            if word in full_text:
                score += weight
                reasons.append(f"Contains suspicion keyword: '{word}'")
        
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
        # 1. Extract and Scan Links
        links = self.extract_links(email_data.get('body', ''))
        vt_summary, detailed_link_results = self.check_virustotal(links)
        
        # 2. Analyze Content
        if use_ai:
            result = self.analyze_with_ai(email_data, vt_summary)
            if result:
                return result, links, detailed_link_results
        
        result = self.analyze_with_rules(email_data, vt_summary)
        return result, links, detailed_link_results

# ============================================================
# ROUTES
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user = User(username=request.form['username'], email=request.form['email'].lower())
        user.set_password(request.form['password'])
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Email or username already exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email'].lower()).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=request.form.get('remember') == 'on')
            return redirect(url_for('home'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
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
    return render_template('index.html', stats=stats, recent_threats=history[:5])

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_page():
    if request.method == 'POST':
        data = {
            'sender': request.form.get('sender', ''),
            'subject': request.form.get('subject', ''),
            'body': request.form.get('body', '')
        }
        
        analyzer = PhishingAnalyzer(current_user.groq_api_key, current_user.virustotal_api_key)
        # Unpack the 3 return values
        result, links, link_results = analyzer.analyze(data, request.form.get('use_ai') == 'on')
        
        # Save to DB
        entry = AnalysisHistory(
            user_id=current_user.id, 
            sender=data['sender'] or 'Unknown',
            subject=data['subject'] or '(No Subject)', 
            risk_level=result['risk_level'],
            risk_score=result['risk_score']
        )
        entry.set_reasons(result['reasons'])
        db.session.add(entry)
        db.session.commit()
        
        # Pass link_results to template
        return render_template('results.html', result=result, email=data, links=links, link_results=link_results)
    
    return render_template('analyze.html')

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
    return jsonify({'success': True})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    if request.method == 'POST':
        current_user.groq_api_key = request.form.get('groq_api_key', '').strip()
        current_user.virustotal_api_key = request.form.get('virustotal_api_key', '').strip()
        db.session.commit()
        flash('Settings saved successfully!', 'success')
        
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
    if request.method == 'POST':
        if request.form.get('action') == 'update_profile':
            current_user.username = request.form.get('username')
            db.session.commit()
            flash('Profile updated.', 'success')
        elif request.form.get('action') == 'change_password':
            if current_user.check_password(request.form.get('current_password')):
                if request.form.get('new_password') == request.form.get('confirm_password'):
                    current_user.set_password(request.form.get('new_password'))
                    db.session.commit()
                    flash('Password changed.', 'success')
                else:
                    flash('Passwords do not match.', 'error')
            else:
                flash('Incorrect current password.', 'error')
    return render_template('profile.html')

@app.route('/about')
def about_page(): return render_template('about.html')

# Gmail Integration Functions (Simplified for brevity but functional)
def get_gmail_credentials(user):
    if not user.gmail_token: return None
    from google.oauth2.credentials import Credentials
    creds = Credentials(
        token=user.gmail_token, refresh_token=user.gmail_refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET
    )
    if creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request
        creds.refresh(Request())
        user.gmail_token = creds.token
        db.session.commit()
    return creds

@app.route('/gmail/connect')
@login_required
def gmail_connect():
    if not GOOGLE_CLIENT_ID: return redirect(url_for('settings_page'))
    redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 'http://127.0.0.1:5000/gmail/callback')
    scope = "https://www.googleapis.com/auth/gmail.readonly"
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&access_type=offline&prompt=consent")

@app.route('/gmail/callback')
@login_required
def gmail_callback():
    code = request.args.get('code')
    redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 'http://127.0.0.1:5000/gmail/callback')
    data = {
        'code': code, 'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'
    }
    r = requests.post('https://oauth2.googleapis.com/token', data=data)
    if r.status_code == 200:
        tokens = r.json()
        current_user.gmail_token = tokens['access_token']
        current_user.gmail_refresh_token = tokens.get('refresh_token', current_user.gmail_refresh_token)
        
        # Get Email Address
        user_info = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers={'Authorization': f"Bearer {tokens['access_token']}"})
        if user_info.status_code == 200:
            current_user.gmail_email = user_info.json().get('email')
        
        db.session.commit()
        flash('Gmail connected successfully!', 'success')
    else:
        flash('Failed to connect Gmail.', 'error')
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
    creds = get_gmail_credentials(current_user)
    if not creds: return redirect(url_for('settings_page'))
    
    try:
        from googleapiclient.discovery import build
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=15).execute()
        emails = []
        for msg in results.get('messages', []):
            m = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name'].lower(): h['value'] for h in m['payload']['headers']}
            emails.append({
                'id': msg['id'],
                'sender': headers.get('from', 'Unknown'),
                'subject': headers.get('subject', 'No Subject'),
                'body': m['snippet'],
                'date': headers.get('date', '')[:16]
            })
        return render_template('gmail_scan.html', emails=emails)
    except Exception as e:
        print(e)
        flash('Error scanning Gmail.', 'error')
        return redirect(url_for('home'))

@app.route('/gmail/analyze/<msg_id>')
@login_required
def gmail_analyze_single(msg_id):
    # Same logic as /analyze but fetches body from Gmail
    # Returns JSON for the AJAX in gmail_scan.html
    creds = get_gmail_credentials(current_user)
    if not creds: return jsonify({'error': 'Auth failed'})
    
    from googleapiclient.discovery import build
    service = build('gmail', 'v1', credentials=creds)
    m = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = {h['name'].lower(): h['value'] for h in m['payload']['headers']}
    body = m['snippet'] # Simplified for MVP
    
    analyzer = PhishingAnalyzer(current_user.groq_api_key, current_user.virustotal_api_key)
    result, _, _ = analyzer.analyze({
        'sender': headers.get('from', ''),
        'subject': headers.get('subject', ''),
        'body': body
    })
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)