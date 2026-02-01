"""
PhishGuard AI - Centralized Keys Version
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
import requests

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'phishguard-dev-secret-key-2024')

# Database
database_url = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SYSTEM-WIDE API KEYS (Loaded from Render Environment)
SYSTEM_GROQ_KEY = os.environ.get('GROQ_API_KEY', '')
SYSTEM_VT_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

# Google Config
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip().replace('\n', '').replace('\r', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip().replace('\n', '').replace('\r', '')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'

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
    
    # Gmail Tokens (Still need these per user)
    gmail_token = db.Column(db.Text, default='')
    gmail_refresh_token = db.Column(db.Text, default='')
    gmail_email = db.Column(db.String(120), default='')
    
    analyses = db.relationship('AnalysisHistory', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
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
# PHISHING ANALYZER
# ============================================================

class PhishingAnalyzer:
    def __init__(self, groq_key, vt_key):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def extract_links(self, text):
        return list(set(re.findall(r'https?://[^\s<>"\'}\]]+', text)))[:5]

    def check_virustotal(self, urls):
        detailed_results = []
        malicious_count = 0
        
        if not self.virustotal_api_key or not urls:
            return {'malicious_count': 0}, []

        headers = {"x-apikey": self.virustotal_api_key}

        for url in urls:
            result_entry = {'url': url, 'risk': 'UNKNOWN'}
            try:
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
                    result_entry['risk'] = 'LOW'
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
            
            vt_context = ""
            if vt_summary['malicious_count'] > 0:
                vt_context = f"CRITICAL: VirusTotal detected {vt_summary['malicious_count']} MALICIOUS links."

            prompt = f"""You are PhishGuard AI. Analyze this email.
External Intel: {vt_context}
From: {email_data.get('sender', 'Unknown')}
Subject: {email_data.get('subject', '')}
Body: {email_data.get('body', '')[:2000]}
Respond in JSON:
{{ "risk_level": "HIGH"|"MEDIUM"|"LOW", "risk_score": <0-100>, "reasons": ["Reason 1"], "recommendation": "Advice" }}
"""
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "system", "content": "JSON only."}, {"role": "user", "content": prompt}],
                temperature=0.1
            )
            result_text = response.choices[0].message.content.strip()
            if "```" in result_text: result_text = result_text.split("```")[1].replace('json', '')
            result = json.loads(result_text)
            result['ai_powered'] = True
            
            if vt_summary['malicious_count'] > 0:
                result['risk_level'] = 'HIGH'
                result['risk_score'] = 95
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
        
        return {
            "risk_level": "HIGH" if score > 50 else "LOW",
            "risk_score": min(100, score),
            "reasons": reasons or ["No obvious patterns"],
            "recommendation": "Be cautious.",
            "ai_powered": False
        }

    def analyze(self, email_data, use_ai=True):
        links = self.extract_links(email_data.get('body', ''))
        vt_summary, detailed_link_results = self.check_virustotal(links)
        
        if use_ai:
            result = self.analyze_with_ai(email_data, vt_summary)
            if result: return result, links, detailed_link_results
            
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
        except: flash('User exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email'].lower()).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
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
        # USE SYSTEM KEYS HERE
        analyzer = PhishingAnalyzer(SYSTEM_GROQ_KEY, SYSTEM_VT_KEY)
        result, links, link_results = analyzer.analyze(data, request.form.get('use_ai') == 'on')
        
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
        
        return render_template('results.html', result=result, email=data, links=links, link_results=link_results)
    return render_template('analyze.html')

@app.route('/history')
@login_required
def history_page():
    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).all()
    return render_template('history.html', history=history)

@app.route('/settings')
@login_required
def settings_page():
    # Pass system status to template
    config = {
        'groq_active': bool(SYSTEM_GROQ_KEY),
        'vt_active': bool(SYSTEM_VT_KEY),
        'gmail_connected': bool(current_user.gmail_email),
        'gmail_email': current_user.gmail_email,
        'gmail_available': bool(GOOGLE_CLIENT_ID)
    }
    return render_template('settings.html', config=config)

@app.route('/about')
def about_page(): return render_template('about.html')

# Gmail simplified (Authentication logic remains per user)
@app.route('/gmail/connect')
@login_required
def gmail_connect():
    redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 'http://127.0.0.1:5000/gmail/callback')
    scope = "https://www.googleapis.com/auth/gmail.readonly"
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&access_type=offline&prompt=consent")

@app.route('/gmail/callback')
@login_required
def gmail_callback():
    code = request.args.get('code')
    redirect_uri = os.environ.get('GMAIL_REDIRECT_URI', 'http://127.0.0.1:5000/gmail/callback')
    data = {'code': code, 'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
    r = requests.post('https://oauth2.googleapis.com/token', data=data)
    if r.status_code == 200:
        current_user.gmail_token = r.json()['access_token']
        db.session.commit()
        flash('Gmail connected!', 'success')
    return redirect(url_for('settings_page'))

@app.route('/gmail/disconnect')
@login_required
def gmail_disconnect():
    current_user.gmail_token = ''
    db.session.commit()
    return redirect(url_for('settings_page'))

@app.route('/gmail/scan')
@login_required
def gmail_scan():
    if not current_user.gmail_token: return redirect(url_for('settings_page'))
    # (Mock logic: in production, use actual Gmail API list)
    return render_template('gmail_scan.html', emails=[]) 

@app.route('/gmail/analyze/<msg_id>')
@login_required
def gmail_analyze_single(msg_id):
    # USE SYSTEM KEYS HERE TOO
    analyzer = PhishingAnalyzer(SYSTEM_GROQ_KEY, SYSTEM_VT_KEY)
    # (Mock analysis for demo)
    return jsonify({'risk_level': 'LOW', 'risk_score': 10, 'reasons': ['Safe sender']})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)