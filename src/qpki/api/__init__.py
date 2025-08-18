"""
qPKI REST API Module

Comprehensive REST API for all PKI operations including certificate management,
CA operations, CRL handling, OCSP, and audit logging.
"""

from .simple_app import create_app

__all__ = [
    'create_app'
]
