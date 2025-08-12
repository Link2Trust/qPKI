"""
qPKI REST API Application

Flask application factory for the comprehensive qPKI REST API with
full PKI operations, authentication, rate limiting, and documentation.
"""

import os
import logging
from flask import Flask, request, jsonify
from flask_restful import Api
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from marshmallow import ValidationError

from ..database import DatabaseManager, DatabaseConfig
from .resources.ca_resources import CAResource, CAListResource
from .resources.certificate_resources import CertificateResource, CertificateListResource
from .resources.crl_resources import CRLResource, CRLListResource
from .resources.ocsp_resources import OCSPResource
from .resources.audit_resources import AuditLogResource, AuditLogListResource
from .resources.system_resources import SystemStatusResource, SystemInfoResource
from .auth import APIAuthManager
from .middleware import APIMiddleware, error_handler


def create_api_app(config=None):
    """
    Create and configure Flask API application.
    
    Args:
        config: Configuration dictionary or path to config file
    
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Configure application
    _configure_app(app, config)
    
    # Initialize database
    db_config = DatabaseConfig.from_env()
    db_manager = DatabaseManager(db_config)
    app.db_manager = db_manager
    
    # Initialize rate limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"]
    )
    app.limiter = limiter
    
    # Initialize API authentication
    auth_manager = APIAuthManager(app)
    app.auth_manager = auth_manager
    
    # Initialize middleware
    middleware = APIMiddleware(app)
    app.middleware = middleware
    
    # Create RESTful API instance
    api = Api(app, catch_all_404s=True)
    
    # Register API resources
    _register_resources(api)
    
    # Configure Swagger documentation
    _configure_swagger(app)
    
    # Register error handlers
    _register_error_handlers(app)
    
    # Register middleware
    _register_middleware(app)
    
    return app


def _configure_app(app, config=None):
    """Configure Flask application settings."""
    
    # Default configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('QPKI_API_SECRET_KEY', 'dev-key-change-in-production'),
        'JSONIFY_PRETTYPRINT_REGULAR': True,
        'API_TITLE': 'qPKI REST API',
        'API_VERSION': 'v1',
        'OPENAPI_VERSION': '3.0.2',
        'API_DESCRIPTION': 'Comprehensive REST API for qPKI quantum-safe PKI operations',
        
        # Rate limiting
        'RATELIMIT_STORAGE_URL': os.environ.get('REDIS_URL', 'memory://'),
        'RATELIMIT_STRATEGY': 'fixed-window',
        
        # Authentication
        'JWT_SECRET_KEY': os.environ.get('QPKI_JWT_SECRET', 'jwt-secret-change-in-production'),
        'JWT_ACCESS_TOKEN_EXPIRES': 3600,  # 1 hour
        'JWT_REFRESH_TOKEN_EXPIRES': 86400 * 7,  # 1 week
        
        # API settings
        'MAX_CONTENT_LENGTH': 10 * 1024 * 1024,  # 10MB
        'JSON_SORT_KEYS': True,
        'RESTFUL_JSON': {
            'ensure_ascii': False,
            'sort_keys': True,
            'indent': 2
        }
    })
    
    # Override with provided configuration
    if config:
        if isinstance(config, dict):
            app.config.update(config)
        elif isinstance(config, str) and os.path.exists(config):
            app.config.from_pyfile(config)


def _register_resources(api):
    """Register all API resources with their endpoints."""
    
    # Certificate Authority endpoints
    api.add_resource(CAListResource, '/api/v1/cas')
    api.add_resource(CAResource, '/api/v1/cas/<string:ca_id>')
    
    # Certificate endpoints  
    api.add_resource(CertificateListResource, '/api/v1/certificates')
    api.add_resource(CertificateResource, '/api/v1/certificates/<string:cert_id>')
    
    # Certificate Revocation List endpoints
    api.add_resource(CRLListResource, '/api/v1/crls')
    api.add_resource(CRLResource, '/api/v1/crls/<string:crl_id>')
    
    # OCSP endpoints
    api.add_resource(OCSPResource, '/api/v1/ocsp')
    
    # Audit log endpoints
    api.add_resource(AuditLogListResource, '/api/v1/audit/logs')
    api.add_resource(AuditLogResource, '/api/v1/audit/logs/<string:event_id>')
    
    # System endpoints
    api.add_resource(SystemStatusResource, '/api/v1/system/status')
    api.add_resource(SystemInfoResource, '/api/v1/system/info')


def _configure_swagger(app):
    """Configure Swagger/OpenAPI documentation."""
    
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/api/v1/apispec.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/v1/docs/"
    }
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": app.config['API_TITLE'],
            "description": app.config['API_DESCRIPTION'], 
            "version": app.config['API_VERSION'],
            "contact": {
                "name": "qPKI API Support",
                "email": "support@link2trust.com"
            },
            "license": {
                "name": "MIT License",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "host": "localhost:5000",
        "basePath": "/",
        "schemes": ["http", "https"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT token for API authentication. Format: Bearer <token>"
            },
            "ApiKey": {
                "type": "apiKey", 
                "name": "X-API-Key",
                "in": "header",
                "description": "API key for service authentication"
            }
        },
        "security": [
            {"Bearer": []},
            {"ApiKey": []}
        ],
        "tags": [
            {
                "name": "Certificate Authorities",
                "description": "Certificate Authority management operations"
            },
            {
                "name": "Certificates", 
                "description": "Certificate lifecycle management"
            },
            {
                "name": "CRLs",
                "description": "Certificate Revocation List operations"
            },
            {
                "name": "OCSP",
                "description": "Online Certificate Status Protocol"
            },
            {
                "name": "Audit",
                "description": "Audit logging and compliance"
            },
            {
                "name": "System",
                "description": "System status and information"
            }
        ]
    }
    
    Swagger(app, config=swagger_config, template=swagger_template)


def _register_error_handlers(app):
    """Register global error handlers."""
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle marshmallow validation errors."""
        return jsonify({
            'error': 'Validation failed',
            'message': 'Request data validation failed',
            'details': error.messages
        }), 400
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle bad request errors."""
        return jsonify({
            'error': 'Bad Request',
            'message': 'The request could not be processed due to invalid syntax or missing parameters',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle unauthorized errors."""
        return jsonify({
            'error': 'Unauthorized', 
            'message': 'Authentication is required to access this resource',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle forbidden errors."""
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle not found errors."""
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource could not be found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(429) 
    def handle_rate_limit_exceeded(error):
        """Handle rate limit exceeded errors."""
        return jsonify({
            'error': 'Rate Limit Exceeded',
            'message': 'Too many requests. Please try again later.',
            'status_code': 429,
            'retry_after': getattr(error, 'retry_after', None)
        }), 429
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle internal server errors."""
        app.logger.error(f"Internal server error: {error}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred while processing the request',
            'status_code': 500
        }), 500


def _register_middleware(app):
    """Register request/response middleware."""
    
    @app.before_request
    def before_request():
        """Execute before each request."""
        # Log API requests (excluding health checks)
        if not request.path.endswith('/health'):
            app.logger.info(f"{request.method} {request.path} from {request.remote_addr}")
    
    @app.after_request  
    def after_request(response):
        """Execute after each request."""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY' 
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Add API version header
        response.headers['X-API-Version'] = app.config['API_VERSION']
        
        return response


# Health check endpoint (not requiring authentication)
def register_health_check(app):
    """Register health check endpoint."""
    
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        try:
            # Check database connection
            db_healthy = app.db_manager.check_connection()
            
            status = {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'timestamp': '2025-01-08T12:00:00Z',
                'version': app.config['API_VERSION'],
                'checks': {
                    'database': 'up' if db_healthy else 'down'
                }
            }
            
            return jsonify(status), 200 if db_healthy else 503
            
        except Exception as e:
            app.logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 503


if __name__ == '__main__':
    # Create and run the API application
    api_app = create_api_app()
    register_health_check(api_app)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run application
    api_app.run(
        host='0.0.0.0',
        port=int(os.environ.get('API_PORT', 5000)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )
