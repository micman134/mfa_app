from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import bcrypt
import hashlib
import random
import requests
import json
import logging
from functools import wraps
from sqlalchemy import func, and_, or_
from sqlalchemy.sql import text
from flask_mail import Mail, Message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# MySQL Configuration for your existing mfa_system database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/mfa_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

# Render API Configuration
app.config['RENDER_API_URL'] = 'https://mfa-r6ib.onrender.com'
app.config['RENDER_API_TIMEOUT'] = 5
app.config['USE_RENDER_API'] = True

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Flask-Mail
app.config.from_object('config.DevelopmentConfig')
mail = Mail(app)

# ============================================
# DATABASE MODELS
# ============================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    role = db.Column(db.Enum('admin', 'student', 'supervisor'), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    contact = db.Column(db.String(255), default='')
    dob = db.Column(db.String(255), default='')
    gender = db.Column(db.String(255), default='')
    image = db.Column(db.String(255), default='')
    updated_at = db.Column(db.String(255), default='')
    
    def check_password(self, password_input):
        return bcrypt.checkpw(password_input.encode('utf-8'), self.password.encode('utf-8'))

    def set_password(self, password_input):
        self.password = bcrypt.hashpw(password_input.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def get_id(self):
        return str(self.id)
    
    def is_admin(self):
        return self.role == 'admin'

class AuthLog(db.Model):
    __tablename__ = 'auth_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(255))
    role = db.Column(db.String(50))
    status = db.Column(db.String(50))
    action_taken = db.Column(db.String(50))
    risk_score = db.Column(db.Float)
    matched_rules = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    hour = db.Column(db.Integer)
    minute = db.Column(db.Integer)
    day_of_week = db.Column(db.Integer)
    is_weekend = db.Column(db.Boolean)
    is_business_hours = db.Column(db.Boolean)
    ip_address = db.Column(db.String(45))
    device_fingerprint = db.Column(db.String(64))
    browser = db.Column(db.String(50))
    os = db.Column(db.String(50))
    device_type = db.Column(db.String(20))
    country = db.Column(db.String(100))
    failed_attempts = db.Column(db.Integer, default=0)
    is_known_device = db.Column(db.Boolean, default=False)
    is_known_location = db.Column(db.Boolean, default=False)
    location_mismatch = db.Column(db.Integer, default=0)
    time_anomaly = db.Column(db.Boolean, default=False)
    velocity_check = db.Column(db.Integer, default=0)

class OTPCode(db.Model):
    __tablename__ = 'otp_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RiskRule(db.Model):
    __tablename__ = 'risk_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(100), nullable=False)
    rule_description = db.Column(db.Text)
    rule_category = db.Column(db.Enum('time', 'location', 'device', 'behavior', 'velocity', 'threshold'), default='behavior')
    risk_weight = db.Column(db.Integer, default=10)
    condition_type = db.Column(db.Enum('range', 'equals', 'greater_than', 'less_than', 'contains', 'in_list', 'not_in_list', 'regex'), default='equals')
    condition_field = db.Column(db.String(50), nullable=False)
    condition_value = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.Enum('low', 'medium', 'high', 'critical'), default='medium')
    action_on_match = db.Column(db.Enum('log', 'alert', 'challenge', 'block'), default='log')
    priority = db.Column(db.Integer, default=5)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ActionLog(db.Model):
    __tablename__ = 'action_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50))
    reason = db.Column(db.Text)
    risk_score = db.Column(db.Float)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================
# HELPER FUNCTIONS (Same as before)
# ============================================

def generate_device_fingerprint():
    components = [
        request.user_agent.string if request.user_agent else '',
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.remote_addr
    ]
    return hashlib.sha256('|'.join(components).encode()).hexdigest()

def get_browser():
    ua = request.user_agent.string if request.user_agent else ''
    if 'Chrome' in ua and 'Edg' not in ua:
        return 'Chrome'
    elif 'Firefox' in ua:
        return 'Firefox'
    elif 'Safari' in ua and 'Chrome' not in ua:
        return 'Safari'
    elif 'Edg' in ua:
        return 'Edge'
    return 'Unknown'

def get_operating_system():
    ua = request.user_agent.string if request.user_agent else ''
    if 'Windows' in ua:
        return 'Windows'
    elif 'Mac' in ua:
        return 'macOS'
    elif 'Linux' in ua:
        return 'Linux'
    elif 'Android' in ua:
        return 'Android'
    elif 'iOS' in ua or 'iPhone' in ua or 'iPad' in ua:
        return 'iOS'
    return 'Unknown'

def get_device_type():
    ua = request.user_agent.string.lower() if request.user_agent else ''
    if 'mobile' in ua or 'iphone' in ua:
        return 'mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        return 'tablet'
    return 'desktop'

def get_country_from_ip():
    ip = request.remote_addr
    if ip in ['127.0.0.1', '::1', 'localhost']:
        return 'Local'
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,countryCode', timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('countryCode', 'Unknown')
    except Exception as e:
        logger.error(f"IP Geolocation error: {e}")
    return 'Unknown'

def call_render_api(user_data):
    if not app.config['USE_RENDER_API']:
        return None
    
    api_url = f"{app.config['RENDER_API_URL']}/predict"
    
    try:
        response = requests.post(api_url, json=user_data, timeout=app.config['RENDER_API_TIMEOUT'])
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return {
                    'risk_score': result.get('risk_score', 50),
                    'action': result.get('action', 'challenge'),
                    'method': result.get('method', 'ml'),
                    'request_id': result.get('request_id')
                }
    except Exception as e:
        logger.error(f"Render API error: {e}")
    return None

def calculate_risk_score_rule_based(user, context, failed_attempts):
    risk_score = 0
    matched_rules = []
    rules = RiskRule.query.filter_by(is_active=True).order_by(RiskRule.priority.desc()).all()
    
    for rule in rules:
        matched = False
        if rule.condition_field == 'hour':
            current_value = datetime.now().hour
            if rule.condition_type == 'range':
                values = rule.condition_value.split('-')
                if len(values) == 2:
                    min_val, max_val = int(values[0]), int(values[1])
                    if min_val <= max_val:
                        matched = min_val <= current_value <= max_val
                    else:
                        matched = current_value >= min_val or current_value <= max_val
        elif rule.condition_field == 'failed_attempts':
            current_value = failed_attempts
            if rule.condition_type == 'greater_than':
                matched = current_value > int(rule.condition_value)
        elif rule.condition_field == 'device_known':
            current_value = 1 if context.get('is_known_device') else 0
            if rule.condition_type == 'equals':
                matched = current_value == int(rule.condition_value)
        elif rule.condition_field == 'location_mismatch':
            current_value = 1 if context.get('location_mismatch') else 0
            if rule.condition_type == 'equals':
                matched = current_value == int(rule.condition_value)
        
        if matched:
            risk_score += rule.risk_weight
    
    if risk_score >= 70:
        action = 'block'
    elif risk_score >= 30:
        action = 'challenge'
    else:
        action = 'allow'
    
    return {'risk_score': min(100, max(0, risk_score)), 'action': action, 'method': 'rule_based'}

def calculate_risk_score(user, context, failed_attempts):
    api_result = call_render_api({
        'user_id': user.id if user else 0,
        'username': user.username if user else 'unknown',
        'email': user.email if user else '',
        'role': user.role if user else 'student',
        'hour': datetime.now().hour,
        'minute': datetime.now().minute,
        'day_of_week': datetime.now().weekday(),
        'is_weekend': datetime.now().weekday() >= 5,
        'is_business_hours': 9 <= datetime.now().hour <= 17,
        'device_fingerprint': context.get('device_fingerprint'),
        'browser': context.get('browser'),
        'os': context.get('os'),
        'device_type': context.get('device_type'),
        'country': context.get('country'),
        'failed_attempts': failed_attempts,
        'is_known_device': 1 if context.get('is_known_device') else 0,
        'is_known_location': 1 if context.get('is_known_location') else 0,
        'location_mismatch': 1 if context.get('location_mismatch') else 0,
        'time_anomaly': 1 if context.get('time_anomaly') else 0,
        'velocity_check': context.get('velocity_check', 0),
    })
    if api_result:
        return api_result
    return calculate_risk_score_rule_based(user, context, failed_attempts)

def log_auth_attempt(user_id, username, email, role, status, action, risk_score, context):
    now = datetime.now()
    log = AuthLog(
        user_id=user_id, username=username, email=email, role=role,
        status=status, action_taken=action, risk_score=risk_score,
        created_at=now, hour=now.hour, minute=now.minute,
        day_of_week=now.weekday(), is_weekend=now.weekday() >= 5,
        is_business_hours=9 <= now.hour <= 17, ip_address=request.remote_addr,
        device_fingerprint=context.get('device_fingerprint'),
        browser=context.get('browser'), os=context.get('os'),
        device_type=context.get('device_type'), country=context.get('country'),
        failed_attempts=context.get('failed_attempts', 0),
        is_known_device=1 if context.get('is_known_device') else 0,
        location_mismatch=1 if context.get('location_mismatch') else 0
    )
    db.session.add(log)
    db.session.commit()
    return log.id

def generate_otp():
    return f"{random.randint(100000, 999999)}"

def send_otp_email(email, name, otp, role):
    logger.info(f"OTP for {email} ({role}): {otp}")
    return True

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.is_admin() else 'dashboard'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid request'}), 400
    
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'student')
    
    user = User.query.filter((User.username == username) | (User.email == username)).first()
    
    device_fingerprint = generate_device_fingerprint()
    browser = get_browser()
    os = get_operating_system()
    device_type = get_device_type()
    country = get_country_from_ip()
    
    context = {
        'device_fingerprint': device_fingerprint, 'browser': browser, 'os': os,
        'device_type': device_type, 'country': country, 'failed_attempts': 0,
        'is_known_device': False, 'is_known_location': False,
        'location_mismatch': False, 'time_anomaly': False, 'velocity_check': 0
    }
    
    if not user:
        risk_result = calculate_risk_score(None, context, 1)
        log_auth_attempt(None, username, None, role, 'failed', 'none', risk_result['risk_score'], context)
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    if not user.check_password(password):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        db.session.commit()
        risk_result = calculate_risk_score(user, context, user.failed_attempts)
        log_auth_attempt(user.id, user.username, user.email, user.role, 'failed', 'none', risk_result['risk_score'], context)
        return jsonify({'success': False, 'message': 'Invalid credentials', 'failed_attempts': user.failed_attempts})
    
    if user.role != role:
        risk_result = calculate_risk_score(user, context, user.failed_attempts or 0)
        log_auth_attempt(user.id, user.username, user.email, user.role, 'failed', 'none', risk_result['risk_score'], context)
        return jsonify({'success': False, 'message': f'Invalid credentials for this role'})
    
    # Reset failed attempts on successful login
    user.failed_attempts = 0
    db.session.commit()
    
    # Get risk assessment
    risk_result = calculate_risk_score(user, context, context['failed_attempts'])
    risk_score = risk_result['risk_score']
    action = risk_result['action']
    method = risk_result.get('method', 'rule_based')
    
    logger.info(f"Login - User: {user.username}, Score: {risk_score}, Action: {action}")
    
    # Handle different risk actions
    if action == 'allow' and risk_score < 30:
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        log_auth_attempt(user.id, user.username, user.email, user.role, 'success', action, risk_score, context)
        
        # Redirect to appropriate dashboard
        if user.is_admin():
            redirect_url = url_for('admin_dashboard')
        else:
            redirect_url = url_for('student_dashboard')
            
        return jsonify({
            'success': True, 'requires_otp': False, 'message': 'Login successful',
            'redirect': redirect_url, 'risk_score': risk_score,
            'risk_action': action, 'risk_method': method
        })
    elif action == 'block':
        log_auth_attempt(user.id, user.username, user.email, user.role, 'blocked', action, risk_score, context)
        return jsonify({
            'success': False, 'message': 'Access denied due to suspicious activity. Please contact support.',
            'risk_score': risk_score, 'risk_action': action, 'blocked': True
        })
    else:  # challenge
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        otp = OTPCode(user_id=user.id, otp_code=otp_code, expires_at=expires_at, is_used=False)
        db.session.add(otp)
        db.session.commit()
        
        send_otp_email(user.email, user.full_name or user.username, otp_code, user.role)
        
        session['pending_auth'] = True
        session['otp_id'] = otp.id
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['risk_score'] = risk_score
        
        log_auth_attempt(user.id, user.username, user.email, user.role, 'challenge', action, risk_score, context)
        
        return jsonify({
            'success': True, 'requires_otp': True, 'message': 'Verification code sent to your email',
            'risk_score': risk_score, 'risk_action': action, 'risk_method': method,
            'device_known': context['is_known_device'], 'location_known': context['is_known_location'],
            'time_normal': not context['time_anomaly'], 'velocity_normal': context['velocity_check'] == 0,
            'otp_expiry': 300
        })

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.get_json()
    otp_input = data.get('otp')
    
    if not session.get('pending_auth'):
        return jsonify({'success': False, 'message': 'No pending authentication'})
    
    otp = OTPCode.query.get(session.get('otp_id'))
    
    if not otp or otp.is_used or datetime.utcnow() > otp.expires_at:
        return jsonify({'success': False, 'message': 'Invalid or expired OTP'})
    
    if otp.otp_code != otp_input:
        return jsonify({'success': False, 'message': 'Invalid verification code'})
    
    otp.is_used = True
    user = User.query.get(otp.user_id)
    login_user(user)
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    session.pop('pending_auth', None)
    session.pop('otp_id', None)
    
    if user.is_admin():
        redirect_url = url_for('admin_dashboard')
    else:
        redirect_url = url_for('student_dashboard')
    
    return jsonify({'success': True, 'message': 'Verification successful', 'redirect': redirect_url})

@app.route('/api/resend-otp', methods=['POST'])
def api_resend_otp():
    if not session.get('pending_auth'):
        return jsonify({'success': False, 'message': 'No pending authentication'})
    
    old_otp = OTPCode.query.get(session.get('otp_id'))
    if old_otp:
        old_otp.is_used = True
    
    user = User.query.get(session.get('user_id'))
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    new_otp = OTPCode(user_id=user.id, otp_code=otp_code, expires_at=expires_at, is_used=False)
    db.session.add(new_otp)
    db.session.commit()
    
    session['otp_id'] = new_otp.id
    send_otp_email(user.email, user.full_name or user.username, otp_code, user.role)
    
    return jsonify({'success': True, 'message': 'New verification code sent', 'otp_expiry': 300})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

# ============================================
# ADMIN DASHBOARD ROUTES
# ============================================

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    current_date = datetime.utcnow().date()
    now = datetime.now()
    
    # Statistics
    stats = {
        'total_users': User.query.count(),
        'total_students': User.query.filter_by(role='student').count(),
        'total_supervisors': User.query.filter_by(role='supervisor').count(),
        'total_admins': User.query.filter_by(role='admin').count(),
        'active_users': User.query.filter(User.last_login >= datetime.utcnow() - timedelta(days=30)).count(),
    }
    
    # Auth Log Statistics - Fix DISTINCT queries for MySQL
    stats['total_auth_attempts'] = AuthLog.query.count()
    stats['successful_logins'] = AuthLog.query.filter_by(status='success').count()
    stats['failed_logins'] = AuthLog.query.filter_by(status='failed').count()
    stats['blocked_attempts'] = AuthLog.query.filter_by(action_taken='block').count()
    stats['challenged_attempts'] = AuthLog.query.filter_by(action_taken='challenge').count()
    
    # Today's statistics
    today_start = datetime.combine(current_date, datetime.min.time())
    stats['today_logins'] = AuthLog.query.filter(
        AuthLog.created_at >= today_start,
        AuthLog.status == 'success'
    ).count()
    stats['today_failed'] = AuthLog.query.filter(
        AuthLog.created_at >= today_start,
        AuthLog.status == 'failed'
    ).count()
    stats['today_blocked'] = AuthLog.query.filter(
        AuthLog.created_at >= today_start,
        AuthLog.action_taken == 'block'
    ).count()
    
    # Risk statistics
    stats['avg_risk_score'] = db.session.query(func.avg(AuthLog.risk_score)).scalar() or 0
    stats['high_risk_logins'] = AuthLog.query.filter(AuthLog.risk_score >= 70).count()
    stats['medium_risk_logins'] = AuthLog.query.filter(AuthLog.risk_score.between(30, 69)).count()
    stats['low_risk_logins'] = AuthLog.query.filter(AuthLog.risk_score < 30).count()
    
    # Device statistics - Fix for MySQL (use count with group_by instead of distinct)
    stats['unique_devices'] = db.session.query(AuthLog.device_fingerprint).filter(AuthLog.device_fingerprint.isnot(None)).distinct().count()
    stats['unique_browsers'] = db.session.query(AuthLog.browser).filter(AuthLog.browser.isnot(None)).distinct().count()
    stats['unique_os'] = db.session.query(AuthLog.os).filter(AuthLog.os.isnot(None)).distinct().count()
    
    # Location statistics - Fix for MySQL
    stats['unique_countries'] = db.session.query(AuthLog.country).filter(AuthLog.country.isnot(None), AuthLog.country != 'Local').distinct().count()
    location_mismatches = AuthLog.query.filter(AuthLog.location_mismatch == 1).count()
    stats['location_mismatch_rate'] = round((location_mismatches / stats['total_auth_attempts'] * 100), 1) if stats['total_auth_attempts'] > 0 else 0
    
    # OTP Statistics
    stats['total_otp_sent'] = OTPCode.query.count()
    stats['otp_verified'] = OTPCode.query.filter_by(is_used=True).count()
    stats['otp_expired'] = OTPCode.query.filter(OTPCode.expires_at < datetime.utcnow(), OTPCode.is_used == False).count()
    
    # Risk Rules
    stats['total_rules'] = RiskRule.query.count()
    stats['active_rules'] = RiskRule.query.filter_by(is_active=True).count()
    stats['inactive_rules'] = RiskRule.query.filter_by(is_active=False).count()
    
    # Recent Activities
    recent_activities = []
    
    # Recent logins
    recent_logins = AuthLog.query.order_by(AuthLog.created_at.desc()).limit(10).all()
    for log in recent_logins:
        recent_activities.append({
            'type': 'login',
            'description': f"User {log.username or 'Unknown'} {log.status} from {log.country or 'Unknown'} using {log.browser or 'Unknown'}",
            'time': log.created_at,
            'icon': 'fa-sign-in-alt',
            'color': 'success' if log.status == 'success' else 'danger'
        })
    
    # Recent OTPs
    recent_otps = OTPCode.query.order_by(OTPCode.created_at.desc()).limit(5).all()
    for otp in recent_otps:
        user = db.session.get(User, otp.user_id)
        recent_activities.append({
            'type': 'otp',
            'description': f"OTP {'verified' if otp.is_used else 'sent'} to {user.email if user else 'Unknown'}",
            'time': otp.created_at,
            'icon': 'fa-key',
            'color': 'info'
        })
    
    # Sort activities by time
    recent_activities.sort(key=lambda x: x['time'], reverse=True)
    recent_activities = recent_activities[:15]
    
    # Chart data for login trends (last 7 days)
    login_trends = []
    for i in range(6, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_start = datetime.combine(date, datetime.min.time())
        date_end = datetime.combine(date, datetime.max.time())
        
        success_count = AuthLog.query.filter(
            AuthLog.created_at.between(date_start, date_end),
            AuthLog.status == 'success'
        ).count()
        
        failed_count = AuthLog.query.filter(
            AuthLog.created_at.between(date_start, date_end),
            AuthLog.status == 'failed'
        ).count()
        
        login_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'success': success_count,
            'failed': failed_count
        })
    
    # Browser distribution
    browser_stats = db.session.query(
        AuthLog.browser, func.count(AuthLog.id)
    ).filter(AuthLog.browser.isnot(None)).group_by(AuthLog.browser).all()
    browser_data = [{'browser': b[0] if b[0] else 'Unknown', 'count': b[1]} for b in browser_stats]
    
    # OS distribution
    os_stats = db.session.query(
        AuthLog.os, func.count(AuthLog.id)
    ).filter(AuthLog.os.isnot(None)).group_by(AuthLog.os).all()
    os_data = [{'os': o[0] if o[0] else 'Unknown', 'count': o[1]} for o in os_stats]
    
    # Risk score distribution by hour
    hour_risk = db.session.query(
        AuthLog.hour, func.avg(AuthLog.risk_score)
    ).filter(AuthLog.hour.isnot(None)).group_by(AuthLog.hour).order_by(AuthLog.hour).all()
    hour_risk_data = [{'hour': h[0], 'avg_risk': float(h[1]) if h[1] else 0} for h in hour_risk]
    
    # Top countries by login attempts
    country_stats = db.session.query(
        AuthLog.country, func.count(AuthLog.id)
    ).filter(AuthLog.country.isnot(None), AuthLog.country != 'Local').group_by(AuthLog.country).order_by(func.count(AuthLog.id).desc()).limit(10).all()
    country_data = [{'country': c[0] if c[0] else 'Unknown', 'count': c[1]} for c in country_stats]
    
    # Recent successful logins
    recent_placements = AuthLog.query.filter_by(status='success').order_by(AuthLog.created_at.desc()).limit(5).all()
    
    # Upcoming deadlines (if you have sessions table)
    upcoming_deadlines = []
    
    return render_template('admin_dashboard.html', 
                         user=current_user,
                         stats=stats,
                         recent_activities=recent_activities,
                         login_trends=login_trends,
                         browser_data=browser_data,
                         os_data=os_data,
                         hour_risk_data=hour_risk_data,
                         country_data=country_data,
                         recent_placements=recent_placements,
                         upcoming_deadlines=upcoming_deadlines,
                         datetime=now)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard' if current_user.is_admin() else 'login'))
    
    recent_logins = AuthLog.query.filter_by(user_id=current_user.id).order_by(AuthLog.created_at.desc()).limit(10).all()
    return render_template('student_dashboard.html', user=current_user, recent_logins=recent_logins)

# ============================================
# ADDITIONAL ADMIN ROUTES
# ============================================

@app.route('/admin/logs')
@login_required
def admin_logs():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    logs = AuthLog.query.order_by(AuthLog.created_at.desc()).paginate(page=page, per_page=per_page)
    
    # Pass user to template
    return render_template('admin_logs.html', logs=logs, user=current_user)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users, user=current_user)

@app.route('/admin/rules')
@login_required
def admin_rules():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    rules = RiskRule.query.order_by(RiskRule.priority.desc()).all()
    return render_template('admin_rules.html', rules=rules, user=current_user)



@app.route('/admin/risk-rules/add', methods=['GET', 'POST'])
@login_required
def add_risk_rule():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        rule = RiskRule(
            rule_name=request.form.get('rule_name'),
            rule_description=request.form.get('rule_description'),
            rule_category=request.form.get('rule_category'),
            risk_weight=int(request.form.get('risk_weight', 10)),
            condition_type=request.form.get('condition_type'),
            condition_field=request.form.get('condition_field'),
            condition_value=request.form.get('condition_value'),
            risk_level=request.form.get('risk_level'),
            action_on_match=request.form.get('action_on_match'),
            priority=int(request.form.get('priority', 5)),
            is_active=request.form.get('is_active') == 'on'
        )
        db.session.add(rule)
        db.session.commit()
        
        # Log action
        action_log = ActionLog(
            user_id=current_user.id,
            action='add_rule',
            reason=f"Added new rule: {rule.rule_name}",
            ip_address=request.remote_addr
        )
        db.session.add(action_log)
        db.session.commit()
        
        return redirect(url_for('admin_rules'))
    
    return render_template('add_rule.html')

@app.route('/admin/risk-rules/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_risk_rule(rule_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    rule = RiskRule.query.get_or_404(rule_id)
    
    if request.method == 'POST':
        rule.rule_name = request.form.get('rule_name')
        rule.rule_description = request.form.get('rule_description')
        rule.rule_category = request.form.get('rule_category')
        rule.risk_weight = int(request.form.get('risk_weight', 10))
        rule.condition_type = request.form.get('condition_type')
        rule.condition_field = request.form.get('condition_field')
        rule.condition_value = request.form.get('condition_value')
        rule.risk_level = request.form.get('risk_level')
        rule.action_on_match = request.form.get('action_on_match')
        rule.priority = int(request.form.get('priority', 5))
        rule.is_active = request.form.get('is_active') == 'on'
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log action
        action_log = ActionLog(
            user_id=current_user.id,
            action='edit_rule',
            reason=f"Edited rule: {rule.rule_name}",
            ip_address=request.remote_addr
        )
        db.session.add(action_log)
        db.session.commit()
        
        return redirect(url_for('admin_rules'))
    
    return render_template('edit_rule.html', rule=rule)

@app.route('/admin/risk-rules/toggle/<int:rule_id>')
@login_required
def toggle_risk_rule(rule_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    rule = RiskRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()
    
    return redirect(url_for('admin_rules'))

@app.route('/admin/risk-rules/delete/<int:rule_id>')
@login_required
def delete_risk_rule(rule_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    rule = RiskRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    
    return redirect(url_for('admin_rules'))

@app.route('/admin/reports/daily')
@login_required
def daily_report():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    logs = AuthLog.query.filter(
        AuthLog.created_at.between(today_start, today_end)
    ).order_by(AuthLog.created_at.desc()).all()
    
    return render_template('daily_report.html', logs=logs, date=today)

@app.route('/admin/reports/weekly')
@login_required
def weekly_report():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    week_start = datetime.utcnow() - timedelta(days=7)
    logs = AuthLog.query.filter(AuthLog.created_at >= week_start).order_by(AuthLog.created_at.desc()).all()
    
    return render_template('weekly_report.html', logs=logs, week_start=week_start)

@app.route('/admin/reports/monthly')
@login_required
def monthly_report():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    month_start = datetime.utcnow() - timedelta(days=30)
    logs = AuthLog.query.filter(AuthLog.created_at >= month_start).order_by(AuthLog.created_at.desc()).all()
    
    return render_template('monthly_report.html', logs=logs, month_start=month_start)

@app.route('/admin/model-status')
@login_required
def model_status():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    api_status = 'Unknown'
    api_response_time = None
    
    if app.config['USE_RENDER_API']:
        try:
            start_time = datetime.utcnow()
            response = requests.get(f"{app.config['RENDER_API_URL']}/health", timeout=5)
            api_response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            api_status = 'Online' if response.status_code == 200 else 'Error'
        except:
            api_status = 'Offline'
    
    recent_predictions = AuthLog.query.filter(AuthLog.risk_score.isnot(None)).order_by(AuthLog.created_at.desc()).limit(20).all()
    
    return render_template('model_status.html', 
                         api_status=api_status, 
                         api_response_time=api_response_time,
                         recent_predictions=recent_predictions,
                         user=current_user,
                         app=app)

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'timestamp': datetime.utcnow().isoformat()
    })

# ============================================
# CREATE DEFAULT ADMIN
# ============================================

def create_default_admin():
    admin = User.query.filter_by(email='admin@test.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@test.com',
            full_name='System Administrator',
            role='admin'
        )
        admin.set_password('Admin123!')
        db.session.add(admin)
        db.session.commit()
        logger.info("Created default admin user: admin@test.com / Admin123!")




@app.template_filter('datetime')
def format_datetime(value):
    """Format datetime for display"""
    if value:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except:
                return value
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return 'Never'
# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    print("\n" + "="*60)
    print("🔐 MFA System with AI Risk Assessment")
    print("="*60)
    print("\n📊 Database: mfa_system (MySQL)")
    print(f"🌐 Server: http://localhost:5000")
    print(f"🤖 Render API: {app.config['RENDER_API_URL']}")
    print("\n🔐 Admin Login:")
    print("   Email: admin@test.com")
    print("   Password: Admin123!")
    print("\n📝 Admin Dashboard: http://localhost:5000/admin/dashboard")
    print("="*60 + "\n")
    
    app.run(host='127.0.0.1', port=5000, debug=True)