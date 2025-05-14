from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from datetime import datetime, timedelta
import bcrypt
import os
import re
import uuid
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from ipaddress import ip_network, ip_address
import json
import socket
import requests
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config.update(
    SECRET_KEY='dev-secret-key-change-in-production',
    SQLALCHEMY_DATABASE_URI='sqlite:///brute_force_sim.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    DEBUG=True  # Enable debug mode
)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Configuration
ADMIN_IPS = ['127.0.0.1']  # Add your IP here
ALLOWED_NETWORKS = ['192.168.0.0/16', '10.0.0.0/8']  # Common local network ranges

def get_client_ip():
    """Get the real client IP, even when behind a proxy"""
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the chain (real client IP)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

# Setup rate limiter with custom key function
def get_rate_limit_key():
    return get_client_ip()

limiter = Limiter(
    app=app,
    key_func=get_rate_limit_key,
    default_limits=["200 per day", "50 per hour"]
)

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

# Password validation
def is_password_complex(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password meets complexity requirements"

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    request_id = db.Column(db.String(36), unique=True, nullable=True)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(36), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)  # Store attempted password for analysis
    user_agent = db.Column(db.String(200), nullable=True)
    headers = db.Column(db.Text, nullable=True)  # Store all request headers
    cookies = db.Column(db.Text, nullable=True)  # Store cookies
    geo_location = db.Column(db.Text, nullable=True)  # Store IP geolocation
    attack_type = db.Column(db.String(50), nullable=True)  # Classify attack type
    success = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom error handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html',
                         error_code=400,
                         error_message="CSRF token validation failed. Please try again.",
                         retry_after=0,
                         auto_refresh=True), 400

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    # Get the retry time in a safer way
    retry_after = 60  # Default to 60 seconds if we can't parse the time
    try:
        description = str(e.description)
        if 'minute' in description:
            retry_after = 60
        elif 'hour' in description:
            retry_after = 3600
        elif 'day' in description:
            retry_after = 86400
        elif 'second' in description:
            # Try to parse the number of seconds
            retry_after = int(''.join(filter(str.isdigit, description)))
    except:
        pass  # Use default retry_after value
        
    return render_template('error.html',
                         error_code=429,
                         error_message="Too Many Requests. Please try again later.",
                         retry_after=retry_after), 429

@app.after_request
def after_request(response):
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf()
    return response

# Routes
@app.route('/')
def index():
    return render_template('dummy_site/index.html')  # New template for the dummy website

@app.route('/admin')
@login_required
def admin():
    return render_template('admin/index.html')

def detect_attack_type(username, password, headers):
    """Detect the type of attack based on patterns"""
    if username.lower() in ['admin', 'administrator', 'root']:
        return 'Common Admin Account'
    if any(p in password.lower() for p in ['123456', 'password', 'admin']):
        return 'Common Password'
    if len(password) > 20:
        return 'Possible SQL Injection'
    if any(sql in password.lower() for sql in ["'", '"', 'or 1=1', 'union']):
        return 'SQL Injection Attempt'
    if any(cmd in password.lower() for cmd in ['|', ';', '>', '$(']):
        return 'Command Injection Attempt'
    return 'Unknown'

def get_ip_info(ip):
    """Get IP geolocation info"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        return response.json() if response.status_code == 200 else None
    except:
        return None

class LoginForm(FlaskForm):
    """Empty form class for CSRF protection"""
    pass

@app.route('/dummy/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def dummy_login():
    """Honeypot login page that logs all attempts"""
    form = LoginForm()
    request_id = str(uuid.uuid4())
    
    if request.method == 'POST':
        if form.validate_on_submit():
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            client_ip = get_client_ip()
            
            # Get geolocation info
            geo_info = get_ip_info(client_ip)
            
            # Log the attempt with enhanced details
            attempt = LoginAttempt(
                request_id=request_id,
                ip_address=client_ip,
                username=username,
                password=password,  # Store password for analysis
                user_agent=request.user_agent.string,
                headers=json.dumps(dict(request.headers)),
                cookies=json.dumps(dict(request.cookies)),
                geo_location=json.dumps(geo_info) if geo_info else None,
                attack_type=detect_attack_type(username, password, dict(request.headers))
            )
            db.session.add(attempt)
            
            # Log additional details about the attacker
            app.logger.warning(
                f'Attack detected:\n'
                f'IP: {client_ip}\n'
                f'Username: {username}\n'
                f'Password: {password}\n'
                f'User-Agent: {request.user_agent.string}\n'
                f'Attack Type: {attempt.attack_type}\n'
                f'Geolocation: {geo_info if geo_info else "Unknown"}'
            )
            
            db.session.commit()
            
            # Always return a failed login (it's a honeypot)
            # But make it look legitimate with different error messages
            if not username:
                flash('Username is required.', 'danger')
            elif not password:
                flash('Password is required.', 'danger')
            elif len(password) < 8:
                flash('Invalid password format.', 'danger')
            else:
                flash('Invalid username or password.', 'danger')
            
            return redirect(url_for('dummy_login'))
        else:
            flash('Invalid form submission. Please try again.', 'danger')
            return redirect(url_for('dummy_login'))
    
    return render_template('dummy_site/login.html', form=form)

def is_ip_allowed(ip):
    """Check if IP is allowed"""
    if ip in ADMIN_IPS:
        return True
    return any(ip_address(ip) in ip_network(network) for network in ALLOWED_NETWORKS)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_ip_allowed(get_client_ip()):
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
@admin_only
@limiter.limit("5 per minute")
def admin_login():
    """Real admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@login_required
@admin_only  # Add IP protection
def admin_dashboard():
    """Enhanced admin dashboard showing attack patterns"""
    # Get recent attempts
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(50).all()
    
    # Calculate statistics
    stats = {
        'total_attempts': LoginAttempt.query.count(),
        'failed_attempts': LoginAttempt.query.filter_by(success=False).count(),
        'unique_ips': db.session.query(LoginAttempt.ip_address).distinct().count(),
        'recent_failures': LoginAttempt.query.filter_by(success=False)
            .filter(LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)).count(),
        'attack_types': db.session.query(
            LoginAttempt.attack_type,
            db.func.count(LoginAttempt.id)
        ).group_by(LoginAttempt.attack_type).all(),
        'common_usernames': db.session.query(
            LoginAttempt.username,
            db.func.count(LoginAttempt.id)
        ).group_by(LoginAttempt.username).order_by(db.func.count(LoginAttempt.id).desc()).limit(5).all(),
        'common_passwords': db.session.query(
            LoginAttempt.password,
            db.func.count(LoginAttempt.id)
        ).group_by(LoginAttempt.password).order_by(db.func.count(LoginAttempt.id).desc()).limit(5).all()
    }
    
    return render_template('admin/dashboard.html', attempts=attempts, stats=stats)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    request_id = str(uuid.uuid4())
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password', '')  # Default to empty string if not provided
        user = User.query.filter_by(username=username).first()
        
        # Log the attempt with request ID and real IP
        attempt = LoginAttempt(
            request_id=request_id,
            ip_address=get_client_ip(),
            username=username,
            password=password,  # Include the password
            success=False,
            user_agent=request.user_agent.string,
            headers=json.dumps(dict(request.headers)),
            cookies=json.dumps(dict(request.cookies)),
            geo_location=json.dumps(get_ip_info(get_client_ip())),
            attack_type=detect_attack_type(username, password, dict(request.headers))
        )
        db.session.add(attempt)
        
        if user:
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('Account is locked. Please try again later.', 'danger')
                app.logger.warning(f'Attempted login to locked account: {username} from IP: {request.remote_addr}')
                db.session.commit()
                return redirect(url_for('login'))
            
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
                # Reset failed attempts on successful login
                user.failed_attempts = 0
                user.request_id = request_id
                attempt.success = True
                db.session.commit()
                login_user(user)
                app.logger.info(f'Successful login: {username} from IP: {request.remote_addr}')
                return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                user.failed_attempts += 1
                if user.failed_attempts >= 5:  # Lock account after 5 failed attempts
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to too many failed attempts.', 'danger')
                    app.logger.warning(f'Account locked: {username} after {user.failed_attempts} failed attempts')
                else:
                    flash('Invalid credentials.', 'danger')
                    app.logger.info(f'Failed login attempt: {username} from IP: {request.remote_addr}')
        else:
            flash('Invalid credentials.', 'danger')
            app.logger.info(f'Failed login attempt for non-existent user: {username} from IP: {request.remote_addr}')
        
        db.session.commit()
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get login attempts for display
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(50).all()
    stats = {
        'total_attempts': LoginAttempt.query.count(),
        'failed_attempts': LoginAttempt.query.filter_by(success=False).count(),
        'unique_ips': db.session.query(LoginAttempt.ip_address).distinct().count(),
        'recent_failures': LoginAttempt.query.filter_by(success=False)
            .filter(LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)).count()
    }
    return render_template('dashboard.html', attempts=attempts, stats=stats)

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f'User logged out: {current_user.username}')
    logout_user()
    return redirect(url_for('index'))

# API endpoints
@app.route('/api/stats')
@login_required
def api_stats():
    stats = {
        'total_attempts': LoginAttempt.query.count(),
        'failed_attempts': LoginAttempt.query.filter_by(success=False).count(),
        'unique_ips': db.session.query(LoginAttempt.ip_address).distinct().count()
    }
    return jsonify(stats)

@app.route('/api/attempt_history')
@login_required
def attempt_history():
    # Get attempts for the last 24 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    
    # Query attempts hour by hour
    hourly_attempts = []
    for hour in range(24):
        hour_start = end_time - timedelta(hours=hour+1)
        hour_end = end_time - timedelta(hours=hour)
        count = LoginAttempt.query.filter(
            LoginAttempt.timestamp.between(hour_start, hour_end)
        ).count()
        hourly_attempts.append(count)
    
    return jsonify({
        'data': list(reversed(hourly_attempts)),  # Reverse to show oldest to newest
        'labels': [f'{i}h ago' for i in range(23, -1, -1)]
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 