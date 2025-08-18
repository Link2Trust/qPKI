"""
qPKI REST API Application - Basic Version

Simplified Flask application for qPKI REST API with basic endpoints.
"""

import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify, current_app
from flask_restful import Api, Resource
from flasgger import Swagger

from ..database import DatabaseManager, DatabaseConfig


# Basic Resource Classes
class HealthResource(Resource):
    """Health check endpoint."""
    
    def get(self):
        """
        Health Check
        ---
        tags:
          - System
        responses:
          200:
            description: System is healthy
        """
        try:
            # Check database connection
            db_manager = current_app.db_manager
            db_healthy = db_manager.check_connection()
            
            return {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'version': 'v1',
                'checks': {
                    'database': 'up' if db_healthy else 'down'
                }
            }, 200 if db_healthy else 503
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }, 503


class StatusResource(Resource):
    """System status endpoint."""
    
    def get(self):
        """
        System Status
        ---
        tags:
          - System
        responses:
          200:
            description: System status information
        """
        return {
            'service': 'qPKI REST API',
            'version': 'v1.0.0',
            'status': 'running',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'uptime': 'Service started'
        }


class OCSPResource(Resource):
    """OCSP responder endpoint."""
    
    def get(self):
        """
        OCSP Responder Status
        ---
        tags:
          - OCSP
        responses:
          200:
            description: OCSP responder status and information
        """
        try:
            db_manager = current_app.db_manager
            
            # Get certificate count from database for status
            cert_count = 0
            revoked_count = 0
            db_connected = False
            
            if db_manager:
                try:
                    # Test database connection first
                    db_connected = db_manager.check_connection()
                    
                    if db_connected:
                        # Basic database query to show OCSP is connected
                        with db_manager.get_session() as session:
                            from ..database.models import Certificate, CertificateStatus
                            cert_count = session.query(Certificate).count()
                            revoked_count = session.query(Certificate).filter(
                                Certificate.status == CertificateStatus.REVOKED
                            ).count()
                except Exception as e:
                    current_app.logger.error(f"Database query error: {e}")
                    db_connected = False
            
            return {
                'responder_status': 'active' if db_connected else 'limited',
                'service': 'qPKI OCSP Responder',
                'version': '1.0.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'supported_algorithms': ['sha1', 'sha256'],
                'certificate_count': cert_count,
                'revoked_count': revoked_count,
                'database_connected': db_connected,
                'response_types': ['good', 'revoked', 'unknown'],
                'features': {
                    'real_time_status': True,
                    'database_integration': db_connected,
                    'response_caching': True,
                    'hybrid_certificates': True
                },
                'endpoints': {
                    'status_check': '/api/v1/ocsp',
                    'certificate_status': '/api/v1/ocsp/status/{serial_number}'
                }
            }
        except Exception as e:
            current_app.logger.error(f"OCSP status error: {e}")
            return {
                'responder_status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }, 500
    
    def post(self):
        """
        OCSP Request Handler
        ---
        tags:
          - OCSP
        parameters:
          - name: serial_number
            in: formData
            type: string
            required: true
            description: Certificate serial number to check
          - name: issuer_hash
            in: formData
            type: string
            required: false
            description: Issuer name hash (optional for demo)
        responses:
          200:
            description: OCSP response with certificate status
          400:
            description: Bad request
        """
        try:
            # Get request data
            data = request.get_json() or {}
            serial_number = data.get('serial_number') or request.form.get('serial_number')
            
            if not serial_number:
                return {
                    'error': 'Missing serial_number parameter',
                    'message': 'Please provide a certificate serial number to check'
                }, 400
            
            # Simulate OCSP response (in real implementation, this would query the database)
            db_manager = current_app.db_manager
            cert_status = 'unknown'
            cert_info = None
            
            if db_manager:
                try:
                    # Check database connection first
                    if db_manager.check_connection():
                        with db_manager.get_session() as session:
                            from ..database.models import Certificate, CertificateStatus
                            cert = session.query(Certificate).filter(
                                Certificate.serial_number == serial_number
                            ).first()
                            
                            if cert:
                                # Check certificate status properly
                                if cert.status == CertificateStatus.REVOKED:
                                    cert_status = 'revoked'
                                elif cert.not_after < datetime.utcnow():
                                    cert_status = 'expired' 
                                else:
                                    cert_status = 'good'
                                
                                cert_info = {
                                    'common_name': cert.common_name,
                                    'issuer_ca_id': cert.issuer_ca_id,
                                    'not_before': cert.not_before.isoformat() if cert.not_before else None,
                                    'not_after': cert.not_after.isoformat() if cert.not_after else None,
                                    'status': cert.status.value if cert.status else 'unknown'
                                }
                            else:
                                cert_status = 'unknown'
                    else:
                        current_app.logger.warning("Database connection failed for OCSP query")
                        cert_status = 'unknown'
                            
                except Exception as e:
                    current_app.logger.error(f"Database query error: {e}")
                    cert_status = 'unknown'
            
            # Return OCSP-like response
            response = {
                'response_status': 'successful',
                'response_type': 'basic_ocsp_response',
                'produced_at': datetime.utcnow().isoformat() + 'Z',
                'responses': [{
                    'cert_id': {
                        'serial_number': serial_number,
                        'hash_algorithm': 'sha256'
                    },
                    'cert_status': cert_status,
                    'this_update': datetime.utcnow().isoformat() + 'Z',
                    'next_update': (datetime.utcnow().replace(hour=23, minute=59, second=59)).isoformat() + 'Z'
                }]
            }
            
            if cert_info:
                response['certificate_info'] = cert_info
            
            return response
            
        except Exception as e:
            return {
                'response_status': 'internal_error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }, 500


def create_app(config=None):
    """Create and configure Flask application."""
    
    app = Flask(__name__)
    
    # Configure application
    app.config.update({
        'SECRET_KEY': os.environ.get('QPKI_API_SECRET_KEY', 'dev-key-change-in-production'),
        'JSONIFY_PRETTYPRINT_REGULAR': True,
        'API_TITLE': 'qPKI REST API',
        'API_VERSION': 'v1',
        'API_DESCRIPTION': 'Comprehensive REST API for qPKI quantum-safe PKI operations'
    })
    
    # Initialize database
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        app.db_manager = db_manager
    except Exception as e:
        app.logger.error(f"Failed to initialize database: {e}")
        app.db_manager = None
    
    # Create API instance
    api = Api(app, catch_all_404s=True)
    
    # Register resources
    api.add_resource(HealthResource, '/health')
    api.add_resource(StatusResource, '/api/v1/system/status')
    api.add_resource(OCSPResource, '/api/v1/ocsp')
    
    # Configure Swagger
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
            "title": "qPKI REST API",
            "description": "Comprehensive REST API for qPKI quantum-safe PKI operations",
            "version": "v1"
        },
        "host": "localhost:9091",
        "basePath": "/",
        "schemes": ["http", "https"]
    }
    
    Swagger(app, config=swagger_config, template=swagger_template)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource could not be found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'error': 'Internal Server Error', 
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    return app


if __name__ == '__main__':
    # Create and run the application
    app = create_app()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run application
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('API_PORT', 9091)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )
