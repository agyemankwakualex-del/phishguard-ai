"""
Setup script for authentication templates
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

# Create templates directory if needed
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

# ============================================================
# UPDATED BASE TEMPLATE (with user menu)
# ============================================================

base_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}PhishGuard AI{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <nav class="sidebar">
        <div class="sidebar-header">
            <div class="logo">
                <span class="logo-icon">🛡️</span>
                <div class="logo-text">
                    <h1>PhishGuard AI</h1>
                    <p>Email Security</p>
                </div>
            </div>
        </div>
        
        <ul class="nav-menu">
            <li class="nav-item">
                <a href="{{ url_for('home') }}" class="nav-link {% if request.endpoint == 'home' %}active{% endif %}">
                    <span class="nav-icon">📊</span>
                    <span>Dashboard</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="{{ url_for('analyze_page') }}" class="nav-link {% if request.endpoint == 'analyze_page' %}active{% endif %}">
                    <span class="nav-icon">🔍</span>
                    <span>Analyze Email</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="{{ url_for('history_page') }}" class="nav-link {% if request.endpoint == 'history_page' %}active{% endif %}">
                    <span class="nav-icon">📋</span>
                    <span>History</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="{{ url_for('settings_page') }}" class="nav-link {% if request.endpoint == 'settings_page' %}active{% endif %}">
                    <span class="nav-icon">⚙️</span>
                    <span>Settings</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="{{ url_for('about_page') }}" class="nav-link {% if request.endpoint == 'about_page' %}active{% endif %}">
                    <span class="nav-icon">ℹ️</span>
                    <span>About</span>
                </a>
            </li>
        </ul>
        
        <!-- User Menu -->
        <div class="user-menu">
            <div class="user-info">
                <span class="user-icon">👤</span>
                <span class="user-name">{{ current_user.username }}</span>
            </div>
            <div class="user-actions">
                <a href="{{ url_for('profile_page') }}" class="user-link">Profile</a>
                <a href="{{ url_for('logout') }}" class="user-link logout">Logout</a>
            </div>
        </div>
        
        <div class="sidebar-footer">
            <p>Version 2.0.0</p>
        </div>
    </nav>
    
    <main class="main-content">
        <header class="page-header">
            <h2>{% block page_title %}Dashboard{% endblock %}</h2>
        </header>
        
        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }}">
                    {{ message }}
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="content">
            {% block content %}{% endblock %}
        </div>
    </main>
    
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>
</html>
'''

# ============================================================
# AUTH BASE TEMPLATE (for login/register pages)
# ============================================================

auth_base_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}PhishGuard AI{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <span class="auth-logo">🛡️</span>
                <h1>PhishGuard AI</h1>
                <p>Email Security Assistant</p>
            </div>
            
            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            {% block content %}{% endblock %}
        </div>
    </div>
</body>
</html>
'''

# ============================================================
# LOGIN PAGE
# ============================================================

login_html = '''{% extends "auth_base.html" %}

{% block title %}Login - PhishGuard AI{% endblock %}

{% block content %}
<form method="POST" class="auth-form">
    <h2>Welcome Back</h2>
    <p class="auth-subtitle">Sign in to your account</p>
    
    <div class="form-group">
        <label for="email">Email</label>
        <input type="email" 
               id="email" 
               name="email" 
               placeholder="you@example.com"
               class="form-input"
               required>
    </div>
    
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" 
               id="password" 
               name="password" 
               placeholder="••••••••"
               class="form-input"
               required>
    </div>
    
    <div class="form-options">
        <label class="checkbox-label">
            <input type="checkbox" name="remember">
            <span>Remember me</span>
        </label>
    </div>
    
    <button type="submit" class="submit-button full-width">
        Sign In
    </button>
    
    <p class="auth-footer">
        Don't have an account? 
        <a href="{{ url_for('register') }}">Sign up</a>
    </p>
</form>
{% endblock %}
'''

# ============================================================
# REGISTER PAGE
# ============================================================

register_html = '''{% extends "auth_base.html" %}

{% block title %}Register - PhishGuard AI{% endblock %}

{% block content %}
<form method="POST" class="auth-form">
    <h2>Create Account</h2>
    <p class="auth-subtitle">Start protecting your inbox</p>
    
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" 
               id="username" 
               name="username" 
               placeholder="johndoe"
               class="form-input"
               minlength="3"
               required>
    </div>
    
    <div class="form-group">
        <label for="email">Email</label>
        <input type="email" 
               id="email" 
               name="email" 
               placeholder="you@example.com"
               class="form-input"
               required>
    </div>
    
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" 
               id="password" 
               name="password" 
               placeholder="••••••••"
               class="form-input"
               minlength="6"
               required>
        <small>At least 6 characters</small>
    </div>
    
    <div class="form-group">
        <label for="confirm_password">Confirm Password</label>
        <input type="password" 
               id="confirm_password" 
               name="confirm_password" 
               placeholder="••••••••"
               class="form-input"
               required>
    </div>
    
    <button type="submit" class="submit-button full-width">
        Create Account
    </button>
    
    <p class="auth-footer">
        Already have an account? 
        <a href="{{ url_for('login') }}">Sign in</a>
    </p>
</form>
{% endblock %}
'''

# ============================================================
# PROFILE PAGE
# ============================================================

profile_html = '''{% extends "base.html" %}

{% block title %}Profile - PhishGuard AI{% endblock %}
{% block page_title %}My Profile{% endblock %}

{% block content %}
<div class="profile-container">
    <!-- Profile Info -->
    <div class="card">
        <div class="card-header">
            <h3>👤 Profile Information</h3>
        </div>
        <div class="card-body">
            <form method="POST" class="profile-form">
                <input type="hidden" name="action" value="update_profile">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" 
                           id="username" 
                           name="username" 
                           value="{{ current_user.username }}"
                           class="form-input"
                           minlength="3"
                           required>
                </div>
                
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" 
                           value="{{ current_user.email }}"
                           class="form-input"
                           disabled>
                    <small>Email cannot be changed</small>
                </div>
                
                <div class="form-group">
                    <label>Member Since</label>
                    <input type="text" 
                           value="{{ current_user.created_at.strftime('%B %d, %Y') }}"
                           class="form-input"
                           disabled>
                </div>
                
                <button type="submit" class="submit-button">
                    Save Changes
                </button>
            </form>
        </div>
    </div>
    
    <!-- Change Password -->
    <div class="card">
        <div class="card-header">
            <h3>🔒 Change Password</h3>
        </div>
        <div class="card-body">
            <form method="POST" class="profile-form">
                <input type="hidden" name="action" value="change_password">
                
                <div class="form-group">
                    <label for="current_password">Current Password</label>
                    <input type="password" 
                           id="current_password" 
                           name="current_password" 
                           class="form-input"
                           required>
                </div>
                
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" 
                           id="new_password" 
                           name="new_password" 
                           class="form-input"
                           minlength="6"
                           required>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" 
                           id="confirm_password" 
                           name="confirm_password" 
                           class="form-input"
                           required>
                </div>
                
                <button type="submit" class="submit-button">
                    Change Password
                </button>
            </form>
        </div>
    </div>
    
    <!-- Account Stats -->
    <div class="card">
        <div class="card-header">
            <h3>📊 Account Statistics</h3>
        </div>
        <div class="card-body">
            <div class="stats-mini">
                <div class="stat-mini-item">
                    <span class="stat-mini-value">{{ current_user.analyses|length }}</span>
                    <span class="stat-mini-label">Emails Analyzed</span>
                </div>
                <div class="stat-mini-item">
                    <span class="stat-mini-value">{{ '✓' if current_user.groq_api_key else '✗' }}</span>
                    <span class="stat-mini-label">Groq API</span>
                </div>
                <div class="stat-mini-item">
                    <span class="stat-mini-value">{{ '✓' if current_user.virustotal_api_key else '✗' }}</span>
                    <span class="stat-mini-label">VirusTotal</span>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''

# ============================================================
# UPDATED INDEX (DASHBOARD)
# ============================================================

index_html = '''{% extends "base.html" %}

{% block title %}Dashboard - PhishGuard AI{% endblock %}
{% block page_title %}Dashboard{% endblock %}

{% block content %}
<div class="welcome-banner">
    <h3>👋 Welcome, {{ current_user.username }}!</h3>
    <p>Your email security dashboard</p>
</div>

<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-icon blue">📧</div>
        <div class="stat-info">
            <h3>{{ stats.total }}</h3>
            <p>Emails Analyzed</p>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-icon red">🔴</div>
        <div class="stat-info">
            <h3>{{ stats.high_risk }}</h3>
            <p>High Risk</p>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-icon yellow">🟡</div>
        <div class="stat-info">
            <h3>{{ stats.medium_risk }}</h3>
            <p>Medium Risk</p>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-icon green">🟢</div>
        <div class="stat-info">
            <h3>{{ stats.low_risk }}</h3>
            <p>Safe</p>
        </div>
    </div>
</div>

<div class="dashboard-grid">
    <div class="card">
        <div class="card-header">
            <h3>⚡ Quick Actions</h3>
        </div>
        <div class="card-body">
            <a href="{{ url_for('analyze_page') }}" class="action-button primary">
                🔍 Analyze New Email
            </a>
            <a href="{{ url_for('history_page') }}" class="action-button secondary">
                📋 View History
            </a>
            <a href="{{ url_for('settings_page') }}" class="action-button secondary">
                ⚙️ Configure APIs
            </a>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <h3>⚠️ Recent Threats</h3>
        </div>
        <div class="card-body">
            {% if recent_threats %}
                {% for threat in recent_threats %}
                <div class="threat-item">
                    <div class="threat-badge high">HIGH</div>
                    <div class="threat-info">
                        <strong>{{ threat.sender[:30] }}{% if threat.sender|length > 30 %}...{% endif %}</strong>
                        <p>{{ threat.subject[:40] }}{% if threat.subject|length > 40 %}...{% endif %}</p>
                        <small>{{ threat.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty-state">
                    <span class="empty-icon">✅</span>
                    <p>No threats detected!</p>
                    <small>Analyze an email to get started</small>
                </div>
            {% endif %}
        </div>
    </div>
    
    <div class="card full-width">
        <div class="card-header">
            <h3>💡 Security Tips</h3>
        </div>
        <div class="card-body">
            <div class="tips-grid">
                <div class="tip">
                    <span class="tip-icon">🔗</span>
                    <p><strong>Check Links:</strong> Hover before clicking.</p>
                </div>
                <div class="tip">
                    <span class="tip-icon">📧</span>
                    <p><strong>Verify Sender:</strong> Check email addresses.</p>
                </div>
                <div class="tip">
                    <span class="tip-icon">⏰</span>
                    <p><strong>Beware Urgency:</strong> Scammers rush you.</p>
                </div>
                <div class="tip">
                    <span class="tip-icon">🔒</span>
                    <p><strong>Never Share:</strong> No passwords via email.</p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''

# ============================================================
# SAVE ALL TEMPLATES
# ============================================================

templates = {
    'base.html': base_html,
    'auth_base.html': auth_base_html,
    'login.html': login_html,
    'register.html': register_html,
    'profile.html': profile_html,
    'index.html': index_html,
}

print("📄 Creating authentication templates...")

for filename, content in templates.items():
    filepath = os.path.join(TEMPLATES_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✓ Created: templates/{filename}")

print("\n✅ Authentication templates created!")