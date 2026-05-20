import numpy as np
import joblib
import os
import json
import requests
import logging
from datetime import datetime
from flask import current_app
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self, app=None):
        self.random_forest = None
        self.gradient_boosting = None
        self.isolation_forest = None
        self.scaler = None
        self.model_path = 'models/'
        self.use_external_api = False
        self.api_url = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        self.use_external_api = app.config.get('USE_EXTERNAL_RISK_API', False)
        self.api_url = app.config.get('RISK_API_URL', 'http://localhost:5000/predict')
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models if they exist"""
        os.makedirs(self.model_path, exist_ok=True)
        
        rf_path = os.path.join(self.model_path, 'risk_model_rf.pkl')
        gb_path = os.path.join(self.model_path, 'risk_model_gb.pkl')
        scaler_path = os.path.join(self.model_path, 'scaler.pkl')
        if_path = os.path.join(self.model_path, 'isolation_forest.pkl')
        
        if os.path.exists(rf_path):
            try:
                self.random_forest = joblib.load(rf_path)
                self.gradient_boosting = joblib.load(gb_path)
                self.scaler = joblib.load(scaler_path)
                if os.path.exists(if_path):
                    self.isolation_forest = joblib.load(if_path)
                logger.info("✅ Loaded ML models successfully")
                return True
            except Exception as e:
                logger.error(f"Error loading models: {e}")
        
        logger.warning("⚠️ No pre-trained models found. Using rule-based engine.")
        return False
    
    def extract_features(self, request_data):
        """Extract features from request data for ML prediction"""
        now = datetime.now()
        
        features = [
            request_data.get('hour', now.hour) / 24.0,  # Hour normalized
            request_data.get('minute', now.minute) / 60.0,  # Minute normalized
            request_data.get('day_of_week', now.weekday()) / 6.0,  # Day of week
            1 if request_data.get('is_weekend', now.weekday() >= 5) else 0,  # Is weekend
            1 if request_data.get('is_business_hours', 9 <= now.hour <= 17) else 0,  # Business hours
            min(1.0, request_data.get('failed_attempts', 0) / 10.0),  # Failed attempts
            1 if request_data.get('device_fingerprint') else 0,  # Has device fingerprint
            1.0 if request_data.get('browser', '') in ['Chrome', 'Firefox', 'Safari', 'Edge'] else 0.5,  # Browser
            1.0 if request_data.get('os', '') in ['Windows', 'macOS', 'iOS', 'Android', 'Linux'] else 0.5,  # OS
            {'mobile': 1.0, 'tablet': 0.7, 'desktop': 0.3}.get(request_data.get('device_type'), 0.5),  # Device
            1 if request_data.get('country') else 0,  # Has country
            1 if request_data.get('location_mismatch') else 0,  # Location mismatch
            1 if request_data.get('is_known_device') else 0,  # Known device
            1 if request_data.get('is_known_location') else 0,  # Known location
            1 if request_data.get('time_anomaly') else 0,  # Time anomaly
            min(1.0, request_data.get('velocity_check', 0) / 1000.0),  # Velocity
            1 if request_data.get('cookies_enabled') else 0,  # Cookies
            1 if request_data.get('javascript_enabled') else 0,  # JavaScript
        ]
        
        return np.array(features, dtype=np.float32).reshape(1, -1)
    
    def predict_ml(self, features):
        """Predict risk score using ML models"""
        if not all([self.random_forest, self.gradient_boosting, self.scaler]):
            return None
        
        try:
            features_scaled = self.scaler.transform(features)
            
            rf_risk = self.random_forest.predict(features_scaled)[0]
            gb_risk = self.gradient_boosting.predict(features_scaled)[0]
            risk_normalized = (rf_risk + gb_risk) / 2
            
            if self.isolation_forest:
                is_anomaly = self.isolation_forest.predict(features_scaled)[0]
                if is_anomaly == -1:
                    risk_normalized = min(1.0, risk_normalized * 1.2)
            
            risk_score = risk_normalized * 100
            return max(0, min(100, risk_score))
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return None
    
    def predict_rule_based(self, request_data):
        """Rule-based risk calculation"""
        score = 50
        
        hour = request_data.get('hour', datetime.now().hour)
        if hour < 6 or hour > 22:
            score += 20
        elif 9 <= hour <= 17:
            score -= 10
        
        if request_data.get('is_weekend'):
            score += 10
        
        failed = request_data.get('failed_attempts', 0)
        score += min(30, failed * 10)
        
        if not request_data.get('device_fingerprint'):
            score += 25
        
        if request_data.get('location_mismatch'):
            score += 30
        
        if not request_data.get('is_known_device'):
            score += 15
        
        return max(0, min(100, score))
    
    def predict(self, request_data):
        """Main prediction method"""
        # Try external API first
        if self.use_external_api and self.api_url:
            try:
                import requests
                response = requests.post(
                    self.api_url,
                    json=request_data,
                    timeout=current_app.config.get('RISK_API_TIMEOUT', 2)
                )
                if response.status_code == 200:
                    result = response.json()
                    return result.get('risk_score', 50), result.get('action', 'challenge'), 'external_api'
            except Exception as e:
                logger.warning(f"External API failed: {e}")
        
        # Try ML models
        features = self.extract_features(request_data)
        ml_score = self.predict_ml(features)
        
        if ml_score is not None:
            action = self._get_action_from_score(ml_score)
            return ml_score, action, 'ml_ensemble'
        
        # Fallback to rule-based
        rule_score = self.predict_rule_based(request_data)
        action = self._get_action_from_score(rule_score)
        return rule_score, action, 'rule_based'
    
    def _get_action_from_score(self, score):
        if score < 30:
            return 'allow'
        elif score < 70:
            return 'challenge'
        else:
            return 'block'
    
    def get_model_info(self):
        return {
            'model_loaded': self.random_forest is not None,
            'models': {
                'random_forest': self.random_forest is not None,
                'gradient_boosting': self.gradient_boosting is not None,
                'isolation_forest': self.isolation_forest is not None
            }
        }

# Singleton instance
risk_engine = RiskEngine()