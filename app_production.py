#!/usr/bin/env python3
"""
qPKI Production Application
Enhanced security and production-ready configuration
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import secrets

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

def create_app():
    """Application factory for production environment"""
    app = Flask(__name__)
    
    # Load production configuration
    if os.environ.get('FLASK_ENV') == 'production':
        from config.production import ProductionConfig
        app.config.from_object(ProductionConfig)
        ProductionConfig.init_app(app)
    else:
        # Fallback to secure defaults
        app.config.update(
            SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32),
            DEBUG=False,
            TESTING=False,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WTF_CSRF_ENABLED=True,
            PREFERRED_URL_SCHEME='https'
        )
    
    # Initialize security extensions
    init_security_extensions(app)
    
    # Initialize core application components
    init_app_components(app)
    
    # Register blueprints and routes
    register_blueprints(app)
    
    # Set up health check and monitoring
    setup_monitoring(app)
    
    return app

def init_security_extensions(app):
    """Initialize security extensions"""
    
    # Rate Limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://'),
        default_limits=[app.config.get('RATELIMIT_DEFAULT', '100 per hour')]
    )
    
    # Content Security Policy and security headers
    csp = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",  # Required for Bootstrap
            'cdnjs.cloudflare.com'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Required for Bootstrap
            'cdnjs.cloudflare.com'
        ],
        'font-src': [
            "'self'",
            'cdnjs.cloudflare.com'
        ],
        'img-src': [
            "'self'",
            'data:'
        ],
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'"
    }
    
    # Initialize Talisman for security headers
    Talisman(app, 
        force_https=app.config.get('FORCE_HTTPS', True),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src', 'style-src'],
        feature_policy={
            'geolocation': "'none'",
            'camera': "'none'",
            'microphone': "'none'"
        }
    )
    
    return limiter

def init_app_components(app):
    """Initialize core application components"""
    try:
        # Database initialization
        from qpki.database import DatabaseManager, DatabaseConfig
        
        # Initialize database manager
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        app.db_manager = db_manager
        
        # Initialize authentication system
        from qpki.auth import AuthenticationManager
        auth_manager = AuthenticationManager(db_manager)
        app.auth_manager = auth_manager
        
        # Initialize email notifications
        from qpki.email_notifier import EmailNotificationService
        email_service = EmailNotificationService()
        app.email_service = email_service
        
        app.logger.info("Core application components initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to initialize application components: {e}")
        raise

def register_blueprints(app):
    """Register all application blueprints"""
    try:
        # Authentication routes
        from qpki.auth.routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
        
        # API routes (if available)
        try:
            from qpki.api.routes import api_bp
            app.register_blueprint(api_bp, url_prefix='/api')
        except ImportError:
            app.logger.info("API blueprint not available")
        
        # Main application routes
        register_main_routes(app)
        
        app.logger.info("Blueprints registered successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to register blueprints: {e}")
        raise

def register_main_routes(app):
    """Register main application routes"""
    
    @app.before_request
    def security_checks():
        """Perform security checks on each request"""
        # Skip security checks for health endpoints
        if request.endpoint in ['health_check', 'metrics']:
            return
        
        # Check for maintenance mode
        if app.config.get('MAINTENANCE_MODE', False):
            if request.endpoint not in ['static', 'maintenance']:
                return jsonify({'error': 'System maintenance in progress'}), 503
        
        # Log security-relevant requests
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            app.logger.info(f"Security: {request.method} {request.path} from {request.remote_addr}")
    
    @app.after_request
    def after_request(response):
        """Set additional security headers"""
        # Remove server information
        response.headers.pop('Server', None)
        
        # Set cache control for sensitive pages
        if request.endpoint and 'auth' in request.endpoint:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
    
    @app.errorhandler(404)
    def not_found(error):
        """Custom 404 handler"""
        app.logger.warning(f"404 error: {request.path} from {request.remote_addr}")
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Custom 500 handler"""
        app.logger.error(f"500 error: {request.path} from {request.remote_addr}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        """Custom 403 handler"""
        app.logger.warning(f"403 error: {request.path} from {request.remote_addr}")
        return jsonify({'error': 'Forbidden'}), 403

def setup_monitoring(app):
    """Set up health check and monitoring endpoints"""
    
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            # Check database connectivity
            if hasattr(app, 'db_manager'):
                db_healthy = app.db_manager.check_connection()
            else:
                db_healthy = False
            
            # Basic health status
            health_status = {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'database': 'connected' if db_healthy else 'disconnected',
                'timestamp': os.times()._asdict()['elapsed']
            }
            
            status_code = 200 if db_healthy else 503
            return jsonify(health_status), status_code
            
        except Exception as e:
            app.logger.error(f"Health check failed: {e}")
            return jsonify({'status': 'error', 'error': str(e)}), 503
    
    @app.route('/metrics')
    def metrics():
        """Basic metrics endpoint (can be extended with Prometheus)"""
        if not app.config.get('METRICS_ENABLED', False):
            return jsonify({'error': 'Metrics disabled'}), 404
        
        try:
            metrics_data = {
                'uptime': os.times()._asdict()['elapsed'],
                'requests_total': getattr(g, 'request_count', 0),
                'memory_usage': get_memory_usage(),
                'active_sessions': get_active_sessions_count(app)
            }
            return jsonify(metrics_data)
        except Exception as e:
            app.logger.error(f"Metrics collection failed: {e}")
            return jsonify({'error': 'Metrics unavailable'}), 500

def get_memory_usage():
    """Get current memory usage"""
    try:
        import psutil
        process = psutil.Process()
        return {
            'rss': process.memory_info().rss,
            'vms': process.memory_info().vms,
            'percent': process.memory_percent()
        }
    except ImportError:
        return {'error': 'psutil not available'}

def get_active_sessions_count(app):
    """Get count of active user sessions"""
    try:
        if hasattr(app, 'auth_manager'):
            # This would need to be implemented in the auth manager
            return app.auth_manager.get_active_sessions_count()
        return 0
    except:
        return 0

def setup_production_directories():
    """Create required production directories with proper permissions"""
    directories = [
        '/opt/qpki/data/certificates',
        '/opt/qpki/data/ca',
        '/opt/qpki/data/crl',
        '/opt/qpki/data/keys',
        '/opt/qpki/logs',
        '/opt/qpki/backups'
    ]
    
    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True, mode=0o750)
        except PermissionError:
            print(f"Warning: Could not create directory {directory} - check permissions")

if __name__ == '__main__':
    # Load environment from production config
    if os.path.exists('.env.production'):
        from dotenv import load_dotenv
        load_dotenv('.env.production')
    
    # Set production environment
    os.environ['FLASK_ENV'] = 'production'
    
    # Setup directories
    setup_production_directories()
    
    # Create application
    app = create_app()
    
    # Get configuration
    port = int(os.environ.get('WEB_PORT', 9090))
    host = os.environ.get('HOST', '0.0.0.0')
    
    # Production server settings
    app.logger.info(f"Starting qPKI in production mode on {host}:{port}")
    
    # Use Gunicorn in production (this is for fallback only)
    if os.environ.get('USE_GUNICORN', 'True').lower() == 'true':
        print("For production, please use Gunicorn:")
        print(f"gunicorn -w 4 -b {host}:{port} --timeout 120 app_production:app")
        sys.exit(1)
    else:
        app.run(host=host, port=port, debug=False, threaded=True)
