"""
Production Configuration for qPKI Application
"""
import os
import secrets
from datetime import timedelta

class ProductionConfig:
    """Production configuration with security hardening"""
    
    # Flask Core Settings
    DEBUG = False
    TESTING = False
    ENV = 'production'
    
    # Security Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
    
    # Session Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.environ.get('PERMANENT_SESSION_LIFETIME', 7200)))
    
    # Security Headers
    PREFERRED_URL_SCHEME = 'https'
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'True').lower() == 'true'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://qpki:password@localhost/qpki_prod')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DATABASE_POOL_SIZE', 20)),
        'max_overflow': int(os.environ.get('DATABASE_MAX_OVERFLOW', 30)),
        'pool_timeout': int(os.environ.get('DATABASE_POOL_TIMEOUT', 60)),
        'pool_recycle': int(os.environ.get('DATABASE_POOL_RECYCLE', 3600)),
        'pool_pre_ping': True,
        'echo': False
    }
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE_PATH = os.environ.get('LOG_FILE_PATH', '/opt/qpki/logs/qpki.log')
    AUDIT_LOG_PATH = os.environ.get('AUDIT_LOG_PATH', '/opt/qpki/logs/audit.log')
    LOG_MAX_SIZE = int(os.environ.get('LOG_MAX_SIZE', 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', 10))
    LOG_TO_SYSLOG = os.environ.get('LOG_TO_SYSLOG', 'True').lower() == 'true'
    SYSLOG_ADDRESS = os.environ.get('SYSLOG_ADDRESS', '/dev/log')
    
    # File Storage Paths
    CERTIFICATE_STORAGE_DIR = os.environ.get('CERTIFICATE_STORAGE_DIR', '/opt/qpki/data/certificates')
    CA_STORAGE_DIR = os.environ.get('CA_STORAGE_DIR', '/opt/qpki/data/ca')
    CRL_STORAGE_DIR = os.environ.get('CRL_STORAGE_DIR', '/opt/qpki/data/crl')
    KEY_STORAGE_DIR = os.environ.get('KEY_STORAGE_DIR', '/opt/qpki/data/keys')
    BACKUP_STORAGE_DIR = os.environ.get('BACKUP_STORAGE_DIR', '/opt/qpki/backups')
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True').lower() == 'true'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    RATELIMIT_LOGIN_ATTEMPTS = os.environ.get('RATELIMIT_LOGIN_ATTEMPTS', '5 per 15 minutes')
    RATELIMIT_API_CALLS = os.environ.get('RATELIMIT_API_CALLS', '1000 per hour')
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('SMTP_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('SMTP_PORT', 587))
    MAIL_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('SMTP_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('SMTP_USERNAME')
    MAIL_PASSWORD = os.environ.get('SMTP_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('FROM_EMAIL', 'qpki@localhost')
    
    # Security & Authentication
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or secrets.token_urlsafe(16)
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS', 12))
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    ACCOUNT_LOCKOUT_DURATION = int(os.environ.get('ACCOUNT_LOCKOUT_DURATION', 1800))
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 3600))
    FORCE_PASSWORD_CHANGE_DAYS = int(os.environ.get('FORCE_PASSWORD_CHANGE_DAYS', 90))
    
    # MFA Configuration
    MFA_ISSUER_NAME = os.environ.get('MFA_ISSUER_NAME', 'qPKI Production')
    
    # Monitoring & Health Checks
    HEALTH_CHECK_PATH = os.environ.get('HEALTH_CHECK_PATH', '/health')
    METRICS_ENABLED = os.environ.get('METRICS_ENABLED', 'True').lower() == 'true'
    PROMETHEUS_METRICS_PATH = os.environ.get('PROMETHEUS_METRICS_PATH', '/metrics')
    
    # Backup Configuration
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', 'True').lower() == 'true'
    BACKUP_SCHEDULE = os.environ.get('BACKUP_SCHEDULE', 'daily')
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', 30))
    BACKUP_ENCRYPTION_KEY = os.environ.get('BACKUP_ENCRYPTION_KEY') or secrets.token_urlsafe(32)
    
    # Maintenance Mode
    MAINTENANCE_MODE = os.environ.get('MAINTENANCE_MODE', 'False').lower() == 'true'
    MAINTENANCE_MESSAGE = os.environ.get('MAINTENANCE_MESSAGE', 'System is under maintenance.')
    
    # Security Headers Configuration
    SECURITY_HEADERS = {
        'Strict-Transport-Security': f"max-age={os.environ.get('HSTS_MAX_AGE', 31536000)}; includeSubDomains; preload",
        'Content-Security-Policy': os.environ.get('CONTENT_SECURITY_POLICY', 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com"),
        'X-Frame-Options': os.environ.get('X_FRAME_OPTIONS', 'DENY'),
        'X-Content-Type-Options': os.environ.get('X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        'X-XSS-Protection': os.environ.get('X_XSS_PROTECTION', '1; mode=block'),
        'Referrer-Policy': os.environ.get('REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cache-Control': 'no-cache, no-store, must-revalidate, private',
        'Pragma': 'no-cache',
        'Expires': '0'
    }
    
    @staticmethod
    def init_app(app):
        """Initialize production-specific settings"""
        # Set up production logging
        import logging
        from logging.handlers import RotatingFileHandler, SysLogHandler
        
        # File handler
        if not app.debug:
            if not os.path.exists('/opt/qpki/logs'):
                os.makedirs('/opt/qpki/logs', mode=0o750)
                
            file_handler = RotatingFileHandler(
                ProductionConfig.LOG_FILE_PATH,
                maxBytes=ProductionConfig.LOG_MAX_SIZE,
                backupCount=ProductionConfig.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(getattr(logging, ProductionConfig.LOG_LEVEL))
            app.logger.addHandler(file_handler)
            
            # Syslog handler
            if ProductionConfig.LOG_TO_SYSLOG:
                try:
                    syslog_handler = SysLogHandler(address=ProductionConfig.SYSLOG_ADDRESS)
                    syslog_handler.setFormatter(logging.Formatter(
                        'qpki[%(process)d]: %(levelname)s %(message)s'
                    ))
                    syslog_handler.setLevel(getattr(logging, ProductionConfig.LOG_LEVEL))
                    app.logger.addHandler(syslog_handler)
                except Exception as e:
                    app.logger.warning(f"Could not set up syslog handler: {e}")
            
            app.logger.setLevel(getattr(logging, ProductionConfig.LOG_LEVEL))
            app.logger.info('qPKI production startup')
        
        # Set up security headers
        @app.after_request
        def set_security_headers(response):
            for header, value in ProductionConfig.SECURITY_HEADERS.items():
                response.headers[header] = value
            return response
        
        # Force HTTPS redirect
        if ProductionConfig.FORCE_HTTPS:
            @app.before_request
            def force_https():
                from flask import request, redirect, url_for
                if not request.is_secure and not app.debug:
                    return redirect(request.url.replace('http://', 'https://'))
        
        # Maintenance mode check
        if ProductionConfig.MAINTENANCE_MODE:
            @app.before_request
            def check_maintenance_mode():
                from flask import request, jsonify, render_template_string
                if request.endpoint not in ['static', 'health_check']:
                    maintenance_template = '''
                    <!DOCTYPE html>
                    <html>
                    <head><title>Maintenance Mode</title></head>
                    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                        <h1>🔧 Maintenance Mode</h1>
                        <p>{{ message }}</p>
                        <p>Please try again later.</p>
                    </body>
                    </html>
                    '''
                    return render_template_string(maintenance_template, 
                                                message=ProductionConfig.MAINTENANCE_MESSAGE), 503
