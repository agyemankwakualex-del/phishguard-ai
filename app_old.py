"""
PhishGuard AI - Web Version
A simple Flask web application for detecting phishing emails
"""

from flask import Flask, render_template, request, jsonify, session
import json
import re
import os
from pathlib import Path
from datetime import datetime

# ============================================================
# FLASK APP SETUP
# ============================================================

app = Flask(__name__)
app.secret_key = 'phishguard-secret-key-change-this-in-production'

# ============================================================
# CONFIGURATION
# ============================================================

CONFIG_FILE = Path("config.json")

def load_config():
    """Load configuration from file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {"groq_api_key": "", "virustotal_api_key": ""}

def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# ============================================================
# PHISHING ANALYZER
# ============================================================

class PhishingAnalyzer:
    """Analyzes emails for phishing indicators"""
    
    def __init__(self):
        self.config = load_config()
    
    def reload_config(self):
        """Reload configuration"""
        self.config = load_config()
    
    def analyze_with_ai(self, email_data):
        """Use Groq AI to analyze email"""
        api_key = self.config.get('groq_api_key', '')
        
        if not api_key:
            return None
        
        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            
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
- Impersonation of known brands (PayPal, Amazon, Apple, etc.)

Be thorough and strict. Only respond with JSON."""

            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Always respond with valid JSON only, no other text."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
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
        
        # Check for urgency
        urgency_words = [
            'urgent', 'immediate', 'act now', 'expire', 'expires',
            'suspended', 'locked', 'asap', 'quickly', 'hurry',
            'limited time', 'within 24 hours', 'within 48 hours'
        ]
        for word in urgency_words:
            if word in full_text:
                score += 15
                reasons.append("Uses urgency tactics to pressure you into acting quickly")
                break
        
        # Check for fear tactics
        fear_words = [
            'compromised', 'unauthorized', 'security alert', 'security warning',
            'verify your', 'confirm your identity', 'unusual activity',
            'suspicious activity', 'account will be closed', 'account suspended'
        ]
        for word in fear_words:
            if word in full_text:
                score += 20
                reasons.append("Uses fear tactics about your account security")
                break
        
        # Check for reward scams
        reward_words = [
            'won', 'winner', 'prize', 'lottery', 'congratulations',
            'selected', 'free gift', 'claim your', 'you have been chosen',
            'million dollars', 'inheritance'
        ]
        for word in reward_words:
            if word in full_text:
                score += 25
                reasons.append("Promises rewards, prizes, or free money (common scam)")
                break
        
        # Check for suspicious domains in sender
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click']
        for tld in suspicious_tlds:
            if tld in sender:
                score += 30
                reasons.append(f"Sender uses suspicious domain ending ({tld})")
                break
        
        # Check for brand impersonation
        brands = {
            'paypal': 'paypal.com',
            'apple': 'apple.com', 
            'google': 'google.com',
            'microsoft': 'microsoft.com',
            'amazon': 'amazon.com',
            'netflix': 'netflix.com',
            'facebook': 'facebook.com',
            'instagram': 'instagram.com',
            'bank': 'bank',
            'wells fargo': 'wellsfargo.com',
            'chase': 'chase.com'
        }
        
        for brand, legit_domain in brands.items():
            if brand in full_text.lower():
                if legit_domain not in sender:
                    score += 30
                    reasons.append(f"Mentions {brand.title()} but sender email doesn't match official domain")
                    break
        
        # Check for credential requests
        credential_words = [
            'password', 'passwd', 'ssn', 'social security',
            'credit card', 'card number', 'cvv', 'bank account',
            'login credentials', 'verify your account', 'update your payment',
            'enter your details'
        ]
        for word in credential_words:
            if word in full_text:
                score += 25
                reasons.append("Requests sensitive information like passwords or financial details")
                break
        
        # Check for suspicious links
        url_pattern = r'https?://[^\s<>"\'}\])]+' 
        links = re.findall(url_pattern, full_text)
        
        for link in links:
            link_lower = link.lower()
            # Check for suspicious TLDs in links
            if any(tld in link_lower for tld in suspicious_tlds):
                score += 20
                reasons.append("Contains links with suspicious domains")
                break
            # Check for URL shorteners
            if any(short in link_lower for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']):
                score += 15
                reasons.append("Contains shortened URLs that hide the real destination")
                break
            # Check for IP addresses in URLs
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
                score += 25
                reasons.append("Contains links with IP addresses instead of domain names (suspicious)")
                break
        
        # Check for common scam phrases
        scam_phrases = [
            'kindly', 'do the needful', 'dear customer', 'dear user',
            'dear valued', 'dear sir/madam', 'dear friend',
            'i am prince', 'i am barrister', 'next of kin',
            'confidential', 'strictly confidential'
        ]
        for phrase in scam_phrases:
            if phrase in full_text:
                score += 15
                reasons.append("Uses unusual phrasing commonly found in scam emails")
                break
        
        # Check for poor grammar indicators
        grammar_issues = [
            'kindly revert', 'aborad', 'recieve', 'beleive',
            'your informations', 'aborad', 'untill'
        ]
        for issue in grammar_issues:
            if issue in full_text:
                score += 10
                reasons.append("Contains grammar or spelling errors typical of scam emails")
                break
        
        # Determine risk level
        if score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        if not reasons:
            reasons.append("No obvious phishing indicators detected")
        
        # Create recommendation
        if risk_level == "HIGH":
            recommendation = "Do NOT click any links or reply to this email. Delete it immediately."
        elif risk_level == "MEDIUM":
            recommendation = "Be cautious. Verify the sender through official channels before taking any action."
        else:
            recommendation = "This email appears safe, but always stay vigilant."
        
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
        api_key = self.config.get('virustotal_api_key', '')
        
        if not api_key:
            return None
        
        try:
            import requests
            import base64
            
            headers = {"x-apikey": api_key}
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
            
            return {"url": url, "risk": "UNKNOWN", "message": "Could not analyze URL"}
            
        except Exception as e:
            return {"url": url, "risk": "ERROR", "message": str(e)}
    
    def analyze(self, email_data, use_ai=True):
        """Main analysis function"""
        
        # Try AI first if enabled
        if use_ai:
            ai_result = self.analyze_with_ai(email_data)
            if ai_result:
                return ai_result
        
        # Fall back to rules
        return self.analyze_with_rules(email_data)
    
    def extract_links(self, text):
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"\'}\])]+' 
        links = re.findall(url_pattern, text)
        return list(set(links))[:10]


# Create global analyzer instance
analyzer = PhishingAnalyzer()

# ============================================================
# WEB ROUTES
# ============================================================

@app.route('/')
def home():
    """Home page / Dashboard"""
    # Get analysis history from session
    history = session.get('history', [])
    
    # Calculate stats
    total = len(history)
    high_risk = len([h for h in history if h.get('risk_level') == 'HIGH'])
    medium_risk = len([h for h in history if h.get('risk_level') == 'MEDIUM'])
    low_risk = len([h for h in history if h.get('risk_level') == 'LOW'])
    
    stats = {
        'total': total,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk
    }
    
    # Get recent threats (high risk)
    recent_threats = [h for h in history if h.get('risk_level') == 'HIGH'][:5]
    
    return render_template('index.html', stats=stats, recent_threats=recent_threats)


@app.route('/analyze', methods=['GET', 'POST'])
def analyze_page():
    """Analyze email page"""
    if request.method == 'POST':
        # Get form data
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        use_ai = request.form.get('use_ai') == 'on'
        
        if not body:
            return render_template('analyze.html', error="Please enter email content to analyze.")
        
        # Prepare email data
        email_data = {
            'sender': sender,
            'subject': subject,
            'body': body
        }
        
        # Reload config to get latest API keys
        analyzer.reload_config()
        
        # Analyze
        result = analyzer.analyze(email_data, use_ai=use_ai)
        
        # Extract and check links
        links = analyzer.extract_links(body)
        link_results = []
        
        if links and analyzer.config.get('virustotal_api_key'):
            for link in links[:3]:  # Check first 3 links
                vt_result = analyzer.check_url_virustotal(link)
                if vt_result:
                    link_results.append(vt_result)
                    # If link is dangerous, boost risk score
                    if vt_result.get('risk') == 'HIGH':
                        result['risk_level'] = 'HIGH'
                        result['risk_score'] = max(result.get('risk_score', 0), 80)
                        if "Dangerous link detected by VirusTotal" not in result['reasons']:
                            result['reasons'].append("Dangerous link detected by VirusTotal")
        
        # Add to history
        history_entry = {
            'sender': sender or 'Unknown',
            'subject': subject or '(No Subject)',
            'risk_level': result['risk_level'],
            'risk_score': result['risk_score'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'reasons': result['reasons'][:3]
        }
        
        history = session.get('history', [])
        history.insert(0, history_entry)
        session['history'] = history[:50]  # Keep last 50
        
        return render_template('results.html', 
                             result=result, 
                             email=email_data, 
                             links=links,
                             link_results=link_results)
    
    return render_template('analyze.html')


@app.route('/history')
def history_page():
    """View analysis history"""
    history = session.get('history', [])
    return render_template('history.html', history=history)


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear analysis history"""
    session['history'] = []
    return jsonify({'success': True})


@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    """Settings page"""
    config = load_config()
    message = None
    
    if request.method == 'POST':
        groq_key = request.form.get('groq_api_key', '').strip()
        vt_key = request.form.get('virustotal_api_key', '').strip()
        
        config['groq_api_key'] = groq_key
        config['virustotal_api_key'] = vt_key
        save_config(config)
        
        # Reload analyzer config
        analyzer.reload_config()
        
        message = "Settings saved successfully!"
    
    # Mask API keys for display
    display_config = {
        'groq_api_key': config.get('groq_api_key', '')[:10] + '...' if config.get('groq_api_key') else '',
        'virustotal_api_key': config.get('virustotal_api_key', '')[:10] + '...' if config.get('virustotal_api_key') else '',
        'groq_configured': bool(config.get('groq_api_key')),
        'virustotal_configured': bool(config.get('virustotal_api_key'))
    }
    
    return render_template('settings.html', config=display_config, message=message)


@app.route('/check-link', methods=['POST'])
def check_link():
    """API endpoint to check a single link"""
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'})
    
    analyzer.reload_config()
    result = analyzer.check_url_virustotal(url)
    
    if result:
        return jsonify(result)
    else:
        return jsonify({'error': 'VirusTotal API key not configured'})


@app.route('/about')
def about_page():
    """About page"""
    return render_template('about.html')


# ============================================================
# RUN THE APP
# ============================================================

if __name__ == '__main__':
    print("=" * 50)
    print("  PhishGuard AI - Web Version")
    print("=" * 50)
    print()
    print("  Starting server...")
    print()
    print("  Open your browser and go to:")
    print("  http://127.0.0.1:5000")
    print()
    print("  Press Ctrl+C to stop the server")
    print("=" * 50)
    
    app.run(debug=True, host='127.0.0.1', port=5000)