"""
Add authentication styles to CSS
"""

import os

CSS_FILE = os.path.join(os.path.dirname(__file__), 'static', 'css', 'style.css')

# Additional CSS for authentication
auth_css = '''

/* ============================================================
   AUTHENTICATION PAGES
   ============================================================ */

.auth-page {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}

.auth-container {
    width: 100%;
    max-width: 420px;
    padding: 20px;
}

.auth-card {
    background-color: #16213e;
    border-radius: 16px;
    padding: 40px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
}

.auth-header {
    text-align: center;
    margin-bottom: 30px;
}

.auth-logo {
    font-size: 48px;
    display: block;
    margin-bottom: 16px;
}

.auth-header h1 {
    font-size: 24px;
    margin-bottom: 8px;
}

.auth-header p {
    color: #6c757d;
    font-size: 14px;
}

.auth-form h2 {
    font-size: 20px;
    margin-bottom: 8px;
    text-align: center;
}

.auth-subtitle {
    color: #6c757d;
    text-align: center;
    margin-bottom: 24px;
}

.auth-footer {
    text-align: center;
    margin-top: 24px;
    color: #6c757d;
    font-size: 14px;
}

.auth-footer a {
    color: #3498db;
    font-weight: 600;
}

.full-width {
    width: 100%;
}

/* ============================================================
   USER MENU (Sidebar)
   ============================================================ */

.user-menu {
    padding: 16px 20px;
    border-top: 1px solid rgba(255,255,255,0.1);
    margin-top: auto;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
}

.user-icon {
    font-size: 24px;
}

.user-name {
    font-weight: 600;
    font-size: 14px;
}

.user-actions {
    display: flex;
    gap: 16px;
}

.user-link {
    font-size: 12px;
    color: #6c757d;
    text-decoration: none;
}

.user-link:hover {
    color: #fff;
}

.user-link.logout {
    color: #e74c3c;
}

/* ============================================================
   WELCOME BANNER
   ============================================================ */

.welcome-banner {
    background: linear-gradient(135deg, #3498db, #2980b9);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}

.welcome-banner h3 {
    margin-bottom: 4px;
}

.welcome-banner p {
    opacity: 0.9;
    font-size: 14px;
}

/* ============================================================
   PROFILE PAGE
   ============================================================ */

.profile-container {
    max-width: 600px;
}

.profile-form {
    max-width: 100%;
}

.stats-mini {
    display: flex;
    gap: 24px;
}

.stat-mini-item {
    text-align: center;
}

.stat-mini-value {
    font-size: 24px;
    font-weight: 700;
    display: block;
    color: #3498db;
}

.stat-mini-label {
    font-size: 12px;
    color: #6c757d;
}

/* ============================================================
   ALERT IMPROVEMENTS
   ============================================================ */

.alert-info {
    background-color: rgba(52, 152, 219, 0.2);
    border-left: 4px solid #3498db;
}

.alert-error {
    background-color: rgba(231, 76, 60, 0.2);
    border-left: 4px solid #e74c3c;
}

.alert-success {
    background-color: rgba(39, 174, 96, 0.2);
    border-left: 4px solid #27ae60;
}
'''

# Append to existing CSS
with open(CSS_FILE, 'a', encoding='utf-8') as f:
    f.write(auth_css)

print("✅ CSS updated with authentication styles!")