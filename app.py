"""
PhishGuard AI - Web Version with User Accounts
Complete version with login, registration, and user-specific data
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pathlib import Path
import json
import re
import os

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
app.secret_key = 'phishguard-secret-key-change-in-production-2024'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    """User account model"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # API Keys (stored per user)
    groq_api_key = db.Column(db.String(256), default='')
    virustotal_api_key = db.Column(db.String(256), default='')
    
    # Gmail tokens (for Part 3)
    gmail_token = db.Column(db.Text, default='')
    gmail_email = db.Column(db.String(120), default='')
    
    # Relationship to analysis history
    analyses = db.relationship('AnalysisHistory', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AnalysisHistory(db.Model):
    """Stores email analysis history for each user"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.Column(db.String(200), default='Unknown')
    subject = db.Column(db.String(500), default='')
    risk_level = db.Column(db.String(20), default='LOW')
    risk_score = db.Column(db.Integer, default=0)
    reasons = db.Column(db.Text, default='[]')  # JSON string
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


# ============================================================
# PHISHING ANALYZER
# ============================================================

class PhishingAnalyzer:
    """Analyzes emails for phishing indicators"""
    
    def __init__(self, groq_key='', vt_key=''):
        self.groq_api_key = groq_key
        self.virustotal_api_key = vt_key
    
    def analyze_with_ai(self, email_data):
        """Use Groq AI to analyze email"""
        if not self.groq_api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_api_key)
            
            prompt = f"""Analyze this email for phishing and social engineering indicators.

FROM: {email_data.get('sender', 'Unknown')}
SUBJECT: {email_data.get('subject', '')}
BODY: {email_data.get('body', '')[:1500]}

Respond in this exact JSON format only:
{{
    "risk_level": "HIGH" or "MEDIUM" or "LOW",
    "risk_score": <number 0-100>,
    "is_phishing": true or false,
    "reasons": ["reason 1", "reason 2", "reason 3"],
    "recommendation": "what the user should do"
}}

Look for:
- Sender domain mismatches or suspicious domains
- Urgency or fear tactics
- Requests for passwords, money, or personal info
- Suspicious links
- Grammar/spelling issues
- Impersonation of known brands

Only respond with JSON."""

            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Clean up response
            if "```" in result_text:
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
            
            result = json.loads(result_text)
            result['ai_powered'] = True
            return result
            
        except Exception as e:
            print(f"AI Analysis error: {e}")
            return None
    
    def analyze_with_rules(self, email_data):
        """Rule-based analysis (fallback)"""
        reasons = []
        score = 0
        
        sender = email_data.get('sender', '').lower()
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        full_text = f"{subject} {body}"
        
        # Urgency check
        urgency_words = ['urgent', 'immediate', 'act now', 'expire', 'suspended', 'locked', 'asap']
        if any(word in full_text for word in urgency_words):
            score += 15
            reasons.append("Uses urgency tactics to pressure you")
        
        # Fear tactics
        fear_words = ['compromised', 'unauthorized', 'security alert', 'verify your', 'unusual activity']
        if any(word in full_text for word in fear_words):
            score += 20
            reasons.append("Uses fear tactics about your account")
        
        # Reward scams
        reward_words = ['won', 'winner', 'prize', 'lottery', 'congratulations', 'free gift']
        if any(word in full_text for word in reward_words):
            score += 25
            reasons.append("Promises rewards or prizes (common scam)")
        
        # Suspicious domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        if any(tld in sender for tld in suspicious_tlds):
            score += 30
            reasons.append("Sender uses suspicious domain")
        
        # Brand impersonation
        brands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'bank']
        for brand in brands:
            if brand in full_text.lower() and brand not in sender:
                score += 30
                reasons.append(f"Possible impersonation of {brand.title()}")
                break
        
        # Credential requests
        cred_words = ['password', 'ssn', 'credit card', 'bank account', 'verify your account']
        if any(word in full_text for word in cred_words):
            score += 25
            reasons.append("Requests sensitive information")
        
        # Suspicious links
        links = re.findall(r'https?://[^\s<>"\'}\]]+', full_text)
        for link in links:
            if any(tld in link.lower() for tld in suspicious_tlds):
                score += 20
                reasons.append("Contains suspicious links")
                break
            if any(short in link.lower() for short in ['bit.ly', 'tinyurl', 'goo.gl']):
                score += 15
                reasons.append("Contains shortened URLs")
                break
        
        # Scam phrases
        scam_phrases = ['kindly', 'dear customer', 'dear user', 'dear valued']
        if any(phrase in full_text for phrase in scam_phrases):
            score += 10
            reasons.append("Uses unusual phrasing common in scams")
        
        # Determine risk level
        if score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        if not reasons:
            reasons.append("No obvious phishing indicators detected")
        
        # Recommendation
        if risk_level == "HIGH":
            recommendation = "Do NOT click any links or reply. Delete immediately."
        elif risk_level == "MEDIUM":
            recommendation = "Be cautious. Verify sender through official channels."
        else:
            recommendation = "Email appears safe, but stay vigilant."
        
        return {
            "risk_level": risk_level,
            "risk_score": min(100, score),
            "is_phishing": score >= 50,
            "reasons": reasons,
            "recommendation": recommendation,
            "ai_powered": False
        }
    
    def check_url_virustotal(self, url):
        """Check URL with VirusTotal"""
        if not self.virustotal_api_key:
            return None
        
        try:
            import requests
            import base64
            
            headers = {"x-apikey": self.virustotal_api_key}
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_bad = malicious + suspicious
                
                if total_bad > 3:
                    risk = "HIGH"
                elif total_bad > 0:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"
                
                return {
                    "url": url,
                    "risk": risk,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "message": f"Flagged by {total_bad} security vendors"
                }
            
            return {"url": url, "risk": "UNKNOWN", "message": "Could not analyze"}
            
        except Exception as e:
            return {"url": url, "risk": "ERROR", "message": str(e)}
    
    def analyze(self, email_data, use_ai=True):
        """Main analysis function"""
        if use_ai:
            ai_result = self.analyze_with_ai(email_data)
            if ai_result:
                return ai_result
        return self.analyze_with_rules(email_data)
    
    def extract_links(self, text):
        """Extract URLs from text"""
        links = re.findall(r'https?://[^\s<>"\'}\]]+', text)
        return list(set(links))[:10]


# ============================================================
# ROUTES - AUTHENTICATION
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if len(username) < 3:
            errors.append("Username must be at least 3 characters")
        
        if not re.match(r'^[\w.-]+@[\w.-]+\.\w+$', email):
            errors.append("Please enter a valid email address")
        
        if len(password) < 6:
            errors.append("Password must be at least 6 characters")
        
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered")
        
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken")
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash(f'Welcome back, {user.username}!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Log out user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ============================================================
# ROUTES - MAIN PAGES
# ============================================================

@app.route('/')
@login_required
def home():
    """Dashboard - requires login"""
    # Get user's analysis history
    history = AnalysisHistory.query.filter_by(user_id=current_user.id)\
        .order_by(AnalysisHistory.timestamp.desc()).all()
    
    # Calculate stats
    total = len(history)
    high_risk = len([h for h in history if h.risk_level == 'HIGH'])
    medium_risk = len([h for h in history if h.risk_level == 'MEDIUM'])
    low_risk = len([h for h in history if h.risk_level == 'LOW'])
    
    stats = {
        'total': total,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk
    }
    
    # Recent threats
    recent_threats = [h for h in history if h.risk_level == 'HIGH'][:5]
    
    return render_template('index.html', stats=stats, recent_threats=recent_threats)


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_page():
    """Analyze email page"""
    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        use_ai = request.form.get('use_ai') == 'on'
        
        if not body:
            return render_template('analyze.html', error="Please enter email content.")
        
        email_data = {
            'sender': sender,
            'subject': subject,
            'body': body
        }
        
        # Create analyzer with user's API keys
        analyzer = PhishingAnalyzer(
            groq_key=current_user.groq_api_key,
            vt_key=current_user.virustotal_api_key
        )
        
        # Analyze
        result = analyzer.analyze(email_data, use_ai=use_ai)
        
        # Extract and check links
        links = analyzer.extract_links(body)
        link_results = []
        
        if links and current_user.virustotal_api_key:
            for link in links[:3]:
                vt_result = analyzer.check_url_virustotal(link)
                if vt_result:
                    link_results.append(vt_result)
                    if vt_result.get('risk') == 'HIGH':
                        result['risk_level'] = 'HIGH'
                        result['risk_score'] = max(result.get('risk_score', 0), 80)
                        if "Dangerous link detected" not in str(result['reasons']):
                            result['reasons'].append("Dangerous link detected by VirusTotal")
        
        # Save to history
        history_entry = AnalysisHistory(
            user_id=current_user.id,
            sender=sender or 'Unknown',
            subject=subject or '(No Subject)',
            risk_level=result['risk_level'],
            risk_score=result['risk_score']
        )
        history_entry.set_reasons(result['reasons'][:5])
        
        db.session.add(history_entry)
        db.session.commit()
        
        return render_template('results.html',
                             result=result,
                             email=email_data,
                             links=links,
                             link_results=link_results)
    
    return render_template('analyze.html')


@app.route('/history')
@login_required
def history_page():
    """View user's analysis history"""
    history = AnalysisHistory.query.filter_by(user_id=current_user.id)\
        .order_by(AnalysisHistory.timestamp.desc()).limit(50).all()
    
    # Format for template
    formatted_history = []
    for item in history:
        formatted_history.append({
            'id': item.id,
            'sender': item.sender,
            'subject': item.subject,
            'risk_level': item.risk_level,
            'risk_score': item.risk_score,
            'timestamp': item.timestamp.strftime('%Y-%m-%d %H:%M'),
            'reasons': item.get_reasons()
        })
    
    return render_template('history.html', history=formatted_history)


@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    """Clear user's analysis history"""
    AnalysisHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    """User settings page"""
    message = None
    
    if request.method == 'POST':
        groq_key = request.form.get('groq_api_key', '').strip()
        vt_key = request.form.get('virustotal_api_key', '').strip()
        
        # Update user's API keys
        if groq_key:
            current_user.groq_api_key = groq_key
        if vt_key:
            current_user.virustotal_api_key = vt_key
        
        db.session.commit()
        message = "Settings saved successfully!"
    
    # Prepare display config
    config = {
        'groq_configured': bool(current_user.groq_api_key),
        'virustotal_configured': bool(current_user.virustotal_api_key),
        'gmail_connected': bool(current_user.gmail_email),
        'gmail_email': current_user.gmail_email
    }
    
    return render_template('settings.html', config=config, message=message)


@app.route('/about')
@login_required
def about_page():
    """About page"""
    return render_template('about.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    """User profile page"""
    message = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            new_username = request.form.get('username', '').strip()
            
            if len(new_username) >= 3:
                existing = User.query.filter_by(username=new_username).first()
                if existing and existing.id != current_user.id:
                    flash('Username already taken', 'error')
                else:
                    current_user.username = new_username
                    db.session.commit()
                    flash('Profile updated!', 'success')
        
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'error')
            elif len(new_password) < 6:
                flash('New password must be at least 6 characters', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'error')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password changed successfully!', 'success')
    
    return render_template('profile.html')


# ============================================================
# API ROUTES
# ============================================================

@app.route('/api/check-link', methods=['POST'])
@login_required
def check_link_api():
    """API to check a single link"""
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'})
    
    if not current_user.virustotal_api_key:
        return jsonify({'error': 'VirusTotal API key not configured'})
    
    analyzer = PhishingAnalyzer(vt_key=current_user.virustotal_api_key)
    result = analyzer.check_url_virustotal(url)
    
    return jsonify(result if result else {'error': 'Could not check URL'})


# ============================================================
# TEMPLATE CONTEXT
# ============================================================

@app.context_processor
def inject_user():
    """Make current_user available in all templates"""
    return dict(current_user=current_user)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        print("✓ Database initialized")


# ============================================================
# RUN THE APP
# ============================================================

if __name__ == '__main__':
    # Create database tables
    init_db()
    
    print("=" * 50)
    print("  PhishGuard AI - Web Version")
    print("  Now with User Accounts!")
    print("=" * 50)
    print()
    print("  Open your browser and go to:")
    print("  http://127.0.0.1:5000")
    print()
    print("  Press Ctrl+C to stop")
    print("=" * 50)
    
    app.run(debug=True, host='127.0.0.1', port=5000)