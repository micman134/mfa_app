# email_utils.py
from flask_mail import Message
from flask import render_template_string
import logging
from threading import Thread
from datetime import datetime

logger = logging.getLogger(__name__)

def send_async_email(app, mail, msg):
    """Send email asynchronously"""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info("Email sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

def send_email(app, mail, subject, recipients, html_body, text_body=None):
    """Send email synchronously or asynchronously"""
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    if text_body:
        msg.body = text_body
    
    # Send asynchronously to avoid blocking
    thr = Thread(target=send_async_email, args=[app, mail, msg])
    thr.start()
    return True

def send_otp_email(app, mail, to_email, to_name, otp_code, role='user', risk_score=None):
    """Send OTP verification email"""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # HTML Email Template
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MFA Verification Code</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                background: #ffffff;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            .header h2 {
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }
            .header p {
                margin: 10px 0 0;
                opacity: 0.9;
            }
            .content {
                padding: 40px 30px;
                background: #fff;
            }
            .greeting {
                font-size: 18px;
                margin-bottom: 20px;
            }
            .otp-box {
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border: 3px dashed #667eea;
                padding: 25px;
                text-align: center;
                margin: 25px 0;
                font-size: 48px;
                font-weight: bold;
                letter-spacing: 10px;
                color: #667eea;
                border-radius: 15px;
                font-family: monospace;
            }
            .info-box {
                background: #e3f2fd;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 4px solid #2196f3;
            }
            .warning-box {
                background: #fff3cd;
                border: 1px solid #ffeeba;
                color: #856404;
                padding: 15px;
                border-radius: 10px;
                margin: 20px 0;
                font-size: 14px;
                border-left: 4px solid #ffc107;
            }
            .role-badge {
                display: inline-block;
                background: rgba(255,255,255,0.2);
                padding: 5px 15px;
                border-radius: 50px;
                font-size: 14px;
                margin-top: 10px;
            }
            .footer {
                background: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #666;
                font-size: 12px;
                border-top: 1px solid #dee2e6;
            }
            .button {
                display: inline-block;
                padding: 10px 20px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🔐 Multi-Factor Authentication</h2>
                <div class="role-badge">{{ role|upper }} Access</div>
                <p>Secure Login with AI Risk Assessment</p>
            </div>
            
            <div class="content">
                <div class="greeting">
                    Hello <strong>{{ name }}</strong>,
                </div>
                
                <p>You are trying to log in to the MFA System as <strong>{{ role|upper }}</strong>. 
                   Use the following verification code to complete your login:</p>
                
                <div class="otp-box">
                    {{ otp }}
                </div>
                
                <div class="info-box">
                    <strong>⏰ This code will expire in 5 minutes</strong><br>
                    <small>Code requested at: {{ timestamp }}</small>
                </div>
                
                {% if risk_score and risk_score > 50 %}
                <div class="warning-box">
                    <strong>⚠️ Security Alert:</strong><br>
                    This login attempt was flagged as <strong>medium/high risk</strong> (Score: {{ risk_score }}/100).<br>
                    If this wasn't you, please contact support immediately.
                </div>
                {% endif %}
                
                <div class="info-box" style="background: #f8f9fa;">
                    <strong>🔒 Security Tips:</strong><br>
                    • Never share this code with anyone<br>
                    • Our staff will never ask for this code<br>
                    • If you didn't request this, please ignore this email<br>
                    • Enable 2FA on your email account for added security
                </div>
                
                <hr style="margin: 20px 0;">
                <p style="font-size: 13px; color: #999;">
                    Having trouble? Contact your system administrator at 
                    <a href="mailto:support@mfasystem.com">support@mfasystem.com</a>
                </p>
            </div>
            
            <div class="footer">
                <p>&copy; 2024 MFA System. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
                <p><small>Secure Login with AI-Powered Risk Assessment</small></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version (for email clients that don't support HTML)
    text_template = """
    MFA Verification Code - {{ role|upper }} Login
    =============================================
    
    Hello {{ name }},
    
    Use the following code to complete your login: {{ otp }}
    
    This code expires in 5 minutes.
    Requested at: {{ timestamp }}
    
    {% if risk_score and risk_score > 50 %}
    ⚠️ SECURITY ALERT: This login attempt was flagged as medium/high risk (Score: {{ risk_score }}/100).
    If this wasn't you, please contact support immediately.
    {% endif %}
    
    Security Tips:
    ---------------
    • Never share this code with anyone
    • Our staff will never ask for this code
    • If you didn't request this, please ignore this email
    
    ---
    MFA System - Secure Login with AI-Powered Risk Assessment
    """
    
    html_body = render_template_string(html_template, 
                                      name=to_name, 
                                      otp=otp_code, 
                                      role=role,
                                      risk_score=risk_score,
                                      timestamp=timestamp)
    
    text_body = render_template_string(text_template,
                                      name=to_name,
                                      otp=otp_code,
                                      role=role,
                                      risk_score=risk_score,
                                      timestamp=timestamp)
    
    subject = f"MFA Verification Code - {role.upper()} Login"
    
    return send_email(app, mail, subject, [to_email], html_body, text_body)

def send_test_email(app, mail, to_email):
    """Send a test email to verify configuration"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>MFA System - Test Email</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
            .success { color: #28a745; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🔐 MFA System</h2>
            </div>
            <div class="content">
                <h3 class="success">✓ Email Configuration Successful!</h3>
                <p>Your email settings are working correctly.</p>
                <p>You will now receive OTP codes for MFA verification.</p>
                <hr>
                <p><small>Sent at: {{ timestamp }}</small></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    html_body = render_template_string(html_template, timestamp=timestamp)
    
    subject = "MFA System - Test Email"
    return send_email(app, mail, subject, [to_email], html_body)