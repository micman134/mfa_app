from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100))
    role = db.Column(db.String(20), default='student')  # student, admin, supervisor
    is_active = db.Column(db.Boolean, default=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))
    
    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def get_id(self):
        return str(self.id)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_student(self):
        return self.role == 'student'

class AuthLog(db.Model):
    __tablename__ = 'auth_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    role = db.Column(db.String(20))
    status = db.Column(db.String(20))  # success, failed, challenge, blocked
    action_taken = db.Column(db.String(20))
    risk_score = db.Column(db.Float)
    risk_method = db.Column(db.String(20))
    request_id = db.Column(db.String(50))
    
    # Time features
    hour = db.Column(db.Integer)
    minute = db.Column(db.Integer)
    day_of_week = db.Column(db.Integer)
    is_weekend = db.Column(db.Boolean)
    is_business_hours = db.Column(db.Boolean)
    
    # Device features
    device_fingerprint = db.Column(db.String(256))
    browser = db.Column(db.String(50))
    os = db.Column(db.String(50))
    device_type = db.Column(db.String(20))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    # Security features
    failed_attempts = db.Column(db.Integer, default=0)
    is_known_device = db.Column(db.Boolean, default=False)
    is_known_location = db.Column(db.Boolean, default=False)
    location_mismatch = db.Column(db.Boolean, default=False)
    time_anomaly = db.Column(db.Boolean, default=False)
    velocity_check = db.Column(db.Integer, default=0)
    
    # Location
    country = db.Column(db.String(2))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OTPCode(db.Model):
    __tablename__ = 'otp_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    attempt_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_valid(self):
        return not self.is_used and datetime.utcnow() < self.expires_at and self.attempt_count < 3

class UserDevice(db.Model):
    __tablename__ = 'user_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_fingerprint = db.Column(db.String(256), nullable=False)
    browser = db.Column(db.String(50))
    os = db.Column(db.String(50))
    device_type = db.Column(db.String(20))
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_trusted = db.Column(db.Boolean, default=False)

class UserLocation(db.Model):
    __tablename__ = 'user_locations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    country = db.Column(db.String(2))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    ip_address = db.Column(db.String(45))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)