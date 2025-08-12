"""
Database Manager for qPKI

Handles database connections, migrations, and CRUD operations for the PKI system.
"""

import os
import uuid
import json
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

from sqlalchemy import create_engine, text, and_, or_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.inspection import inspect

from .config import DatabaseConfig
from .models import (
    Base, CertificateAuthority, Certificate, CertificateRevocationList, 
    AuditLog, NotificationHistory, OCSPResponse,
    CertificateStatus, CAType, CertificateType, RevocationReason, AuditEventType
)


class DatabaseManager:
    """
    Database manager for qPKI system.
    
    Provides high-level database operations for managing certificates,
    certificate authorities, CRLs, audit logs, and notifications.
    """
    
    def __init__(self, config: DatabaseConfig):
        """Initialize database manager with configuration."""
        self.config = config
        self.engine = None
        self.session_factory = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize database connection
        self._initialize_engine()
        self._initialize_session_factory()
        
        # Create tables if auto_migrate is enabled
        if self.config.auto_migrate:
            self.migrate_database()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine."""
        try:
            connection_url = self.config.get_connection_url()
            engine_kwargs = self.config.get_engine_kwargs()
            
            self.engine = create_engine(connection_url, **engine_kwargs)
            
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            self.logger.info(f"Database connection established: {self.config.db_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def _initialize_session_factory(self):
        """Initialize session factory."""
        self.session_factory = sessionmaker(bind=self.engine)
    
    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def migrate_database(self) -> bool:
        """Create or migrate database schema."""
        try:
            # Create all tables
            Base.metadata.create_all(self.engine)
            
            # Log migration
            self._log_audit_event(
                event_type=AuditEventType.CONFIGURATION_CHANGED,
                action="database_migration",
                description="Database schema created/updated",
                success=True
            )
            
            self.logger.info("Database migration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Database migration failed: {e}")
            self._log_audit_event(
                event_type=AuditEventType.SYSTEM_ERROR,
                action="database_migration",
                description=f"Database migration failed: {str(e)}",
                success=False,
                error_message=str(e)
            )
            return False
    
    def check_connection(self) -> bool:
        """Check if database connection is healthy."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics."""
        try:
            with self.get_session() as session:
                # Get table statistics
                ca_count = session.query(CertificateAuthority).count()
                cert_count = session.query(Certificate).count()
                crl_count = session.query(CertificateRevocationList).count()
                audit_count = session.query(AuditLog).count()
                notification_count = session.query(NotificationHistory).count()
                
                # Get expiring certificates (next 30 days)
                expiring_soon = session.query(Certificate).filter(
                    and_(
                        Certificate.not_after <= datetime.now(timezone.utc) + timedelta(days=30),
                        Certificate.not_after > datetime.now(timezone.utc),
                        Certificate.status == CertificateStatus.VALID
                    )
                ).count()
                
                return {
                    'database_type': self.config.db_type,
                    'connection_healthy': True,
                    'statistics': {
                        'certificate_authorities': ca_count,
                        'certificates': cert_count,
                        'certificate_revocation_lists': crl_count,
                        'audit_logs': audit_count,
                        'notifications': notification_count,
                        'certificates_expiring_soon': expiring_soon
                    },
                    'last_checked': datetime.now(timezone.utc).isoformat()
                }
                
        except Exception as e:
            return {
                'database_type': self.config.db_type,
                'connection_healthy': False,
                'error': str(e),
                'last_checked': datetime.now(timezone.utc).isoformat()
            }
    
    # Certificate Authority Operations
    
    def create_ca(self, ca_data: Dict[str, Any]) -> Optional[CertificateAuthority]:
        """Create a new Certificate Authority."""
        try:
            with self.get_session() as session:
                # Generate unique CA ID
                ca_id = str(uuid.uuid4())
                
                # Create CA object
                ca = CertificateAuthority(
                    ca_id=ca_id,
                    common_name=ca_data['common_name'],
                    organization=ca_data.get('organization'),
                    organizational_unit=ca_data.get('organizational_unit'),
                    country=ca_data.get('country'),
                    state=ca_data.get('state'),
                    locality=ca_data.get('locality'),
                    email=ca_data.get('email'),
                    ca_type=CAType(ca_data.get('ca_type', 'root')),
                    parent_ca_id=ca_data.get('parent_ca_id'),
                    serial_number=ca_data['serial_number'],
                    not_before=datetime.fromisoformat(ca_data['not_before'].replace('Z', '+00:00')),
                    not_after=datetime.fromisoformat(ca_data['not_after'].replace('Z', '+00:00')),
                    algorithm_type=ca_data['algorithm_type'],
                    key_size=ca_data.get('key_size'),
                    curve_name=ca_data.get('curve_name'),
                    dilithium_variant=ca_data.get('dilithium_variant'),
                    certificate_data=ca_data['certificate_data'],
                    public_keys=ca_data['public_keys'],
                    cryptographic_info=ca_data['cryptographic_info'],
                    private_keys=ca_data['private_keys'],  # Should be encrypted
                    path_length_constraint=ca_data.get('path_length_constraint'),
                    fingerprint=ca_data['fingerprint'],
                    created_by=ca_data.get('created_by', 'system')
                )
                
                session.add(ca)
                session.flush()  # Get the ID
                
                # Log audit event
                self._log_audit_event(
                    event_type=AuditEventType.CA_CREATED,
                    action="create_ca",
                    resource_type="ca",
                    resource_id=ca.ca_id,
                    resource_name=ca.common_name,
                    description=f"Certificate Authority '{ca.common_name}' created",
                    success=True,
                    user_id=ca_data.get('created_by', 'system')
                )
                
                return ca
                
        except IntegrityError as e:
            self.logger.error(f"CA creation failed - integrity error: {e}")
            self._log_audit_event(
                event_type=AuditEventType.SYSTEM_ERROR,
                action="create_ca",
                description=f"CA creation failed: {str(e)}",
                success=False,
                error_message=str(e)
            )
            return None
        except Exception as e:
            self.logger.error(f"CA creation failed: {e}")
            return None
    
    def get_ca_by_id(self, ca_id: str) -> Optional[CertificateAuthority]:
        """Get Certificate Authority by ID."""
        try:
            with self.get_session() as session:
                return session.query(CertificateAuthority).filter_by(ca_id=ca_id).first()
        except Exception as e:
            self.logger.error(f"Failed to get CA by ID {ca_id}: {e}")
            return None
    
    def get_ca_by_common_name(self, common_name: str) -> Optional[CertificateAuthority]:
        """Get Certificate Authority by common name."""
        try:
            with self.get_session() as session:
                return session.query(CertificateAuthority).filter_by(common_name=common_name).first()
        except Exception as e:
            self.logger.error(f"Failed to get CA by common name {common_name}: {e}")
            return None
    
    def list_cas(self, ca_type: Optional[str] = None, status: Optional[str] = None) -> List[CertificateAuthority]:
        """List Certificate Authorities with optional filters."""
        try:
            with self.get_session() as session:
                query = session.query(CertificateAuthority)
                
                if ca_type:
                    query = query.filter(CertificateAuthority.ca_type == CAType(ca_type))
                
                if status:
                    query = query.filter(CertificateAuthority.status == CertificateStatus(status))
                
                return query.order_by(CertificateAuthority.created_at.desc()).all()
                
        except Exception as e:
            self.logger.error(f"Failed to list CAs: {e}")
            return []
    
    # Certificate Operations
    
    def create_certificate(self, cert_data: Dict[str, Any]) -> Optional[Certificate]:
        """Create a new certificate."""
        try:
            with self.get_session() as session:
                # Generate unique certificate ID
                cert_id = str(uuid.uuid4())
                
                # Create certificate object
                cert = Certificate(
                    cert_id=cert_id,
                    serial_number=cert_data['serial_number'],
                    common_name=cert_data['common_name'],
                    organization=cert_data.get('organization'),
                    organizational_unit=cert_data.get('organizational_unit'),
                    country=cert_data.get('country'),
                    state=cert_data.get('state'),
                    locality=cert_data.get('locality'),
                    email=cert_data.get('email'),
                    issuer_ca_id=cert_data['issuer_ca_id'],
                    certificate_type=CertificateType(cert_data.get('certificate_type', 'hybrid')),
                    not_before=datetime.fromisoformat(cert_data['not_before'].replace('Z', '+00:00')),
                    not_after=datetime.fromisoformat(cert_data['not_after'].replace('Z', '+00:00')),
                    algorithm_type=cert_data['algorithm_type'],
                    key_size=cert_data.get('key_size'),
                    curve_name=cert_data.get('curve_name'),
                    dilithium_variant=cert_data.get('dilithium_variant'),
                    key_usage=cert_data.get('key_usage', []),
                    extended_key_usage=cert_data.get('extended_key_usage', []),
                    subject_alt_names=cert_data.get('subject_alt_names', []),
                    certificate_data=cert_data['certificate_data'],
                    public_keys=cert_data['public_keys'],
                    cryptographic_info=cert_data['cryptographic_info'],
                    signature_data=cert_data['signature_data'],
                    private_keys=cert_data['private_keys'],  # Should be encrypted
                    fingerprint=cert_data['fingerprint'],
                    created_by=cert_data.get('created_by', 'system')
                )
                
                session.add(cert)
                session.flush()  # Get the ID
                
                # Log audit event
                self._log_audit_event(
                    event_type=AuditEventType.CERTIFICATE_ISSUED,
                    action="create_certificate",
                    resource_type="certificate",
                    resource_id=cert.cert_id,
                    resource_name=cert.common_name,
                    description=f"Certificate '{cert.common_name}' issued",
                    success=True,
                    user_id=cert_data.get('created_by', 'system')
                )
                
                return cert
                
        except IntegrityError as e:
            self.logger.error(f"Certificate creation failed - integrity error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Certificate creation failed: {e}")
            return None
    
    def get_certificate_by_id(self, cert_id: str) -> Optional[Certificate]:
        """Get certificate by ID."""
        try:
            with self.get_session() as session:
                return session.query(Certificate).filter_by(cert_id=cert_id).first()
        except Exception as e:
            self.logger.error(f"Failed to get certificate by ID {cert_id}: {e}")
            return None
    
    def get_certificate_by_serial(self, serial_number: str) -> Optional[Certificate]:
        """Get certificate by serial number."""
        try:
            with self.get_session() as session:
                return session.query(Certificate).filter_by(serial_number=serial_number).first()
        except Exception as e:
            self.logger.error(f"Failed to get certificate by serial {serial_number}: {e}")
            return None
    
    def list_certificates(self, 
                         issuer_ca_id: Optional[str] = None,
                         status: Optional[str] = None,
                         cert_type: Optional[str] = None,
                         limit: int = 100,
                         offset: int = 0) -> List[Certificate]:
        """List certificates with optional filters."""
        try:
            with self.get_session() as session:
                query = session.query(Certificate)
                
                if issuer_ca_id:
                    query = query.filter(Certificate.issuer_ca_id == issuer_ca_id)
                
                if status:
                    query = query.filter(Certificate.status == CertificateStatus(status))
                
                if cert_type:
                    query = query.filter(Certificate.certificate_type == CertificateType(cert_type))
                
                return query.order_by(Certificate.created_at.desc()).limit(limit).offset(offset).all()
                
        except Exception as e:
            self.logger.error(f"Failed to list certificates: {e}")
            return []
    
    def revoke_certificate(self, cert_id: str, reason: str, revoked_by: Optional[str] = None) -> bool:
        """Revoke a certificate."""
        try:
            with self.get_session() as session:
                cert = session.query(Certificate).filter_by(cert_id=cert_id).first()
                
                if not cert:
                    return False
                
                # Update certificate status
                cert.status = CertificateStatus.REVOKED
                cert.revocation_date = datetime.now(timezone.utc)
                cert.revocation_reason = RevocationReason(reason)
                cert.updated_at = datetime.now(timezone.utc)
                
                session.flush()
                
                # Log audit event
                self._log_audit_event(
                    event_type=AuditEventType.CERTIFICATE_REVOKED,
                    action="revoke_certificate",
                    resource_type="certificate",
                    resource_id=cert.cert_id,
                    resource_name=cert.common_name,
                    description=f"Certificate '{cert.common_name}' revoked: {reason}",
                    success=True,
                    user_id=revoked_by or 'system'
                )
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to revoke certificate {cert_id}: {e}")
            return False
    
    def get_expiring_certificates(self, days_ahead: int = 30) -> List[Certificate]:
        """Get certificates expiring within specified days."""
        try:
            with self.get_session() as session:
                expiry_threshold = datetime.now(timezone.utc) + timedelta(days=days_ahead)
                
                return session.query(Certificate).filter(
                    and_(
                        Certificate.not_after <= expiry_threshold,
                        Certificate.not_after > datetime.now(timezone.utc),
                        Certificate.status == CertificateStatus.VALID
                    )
                ).order_by(Certificate.not_after).all()
                
        except Exception as e:
            self.logger.error(f"Failed to get expiring certificates: {e}")
            return []
    
    # CRL Operations
    
    def create_crl(self, crl_data: Dict[str, Any]) -> Optional[CertificateRevocationList]:
        """Create a new Certificate Revocation List."""
        try:
            with self.get_session() as session:
                crl_id = str(uuid.uuid4())
                
                crl = CertificateRevocationList(
                    crl_id=crl_id,
                    crl_number=crl_data['crl_number'],
                    issuer_ca_id=crl_data['issuer_ca_id'],
                    this_update=datetime.fromisoformat(crl_data['this_update'].replace('Z', '+00:00')),
                    next_update=datetime.fromisoformat(crl_data['next_update'].replace('Z', '+00:00')),
                    version=crl_data.get('version', 'v2'),
                    revoked_certificates=crl_data.get('revoked_certificates', []),
                    signature_data=crl_data['signature_data'],
                    created_by=crl_data.get('created_by', 'system')
                )
                
                session.add(crl)
                session.flush()
                
                # Log audit event
                self._log_audit_event(
                    event_type=AuditEventType.CRL_GENERATED,
                    action="create_crl",
                    resource_type="crl",
                    resource_id=crl.crl_id,
                    description=f"CRL generated for CA {crl_data['issuer_ca_id']}",
                    success=True,
                    user_id=crl_data.get('created_by', 'system')
                )
                
                return crl
                
        except Exception as e:
            self.logger.error(f"CRL creation failed: {e}")
            return None
    
    def get_latest_crl(self, issuer_ca_id: str) -> Optional[CertificateRevocationList]:
        """Get the latest CRL for a CA."""
        try:
            with self.get_session() as session:
                return session.query(CertificateRevocationList).filter(
                    CertificateRevocationList.issuer_ca_id == issuer_ca_id
                ).order_by(CertificateRevocationList.this_update.desc()).first()
                
        except Exception as e:
            self.logger.error(f"Failed to get latest CRL: {e}")
            return None
    
    # Audit Operations
    
    def _log_audit_event(self, 
                        event_type: AuditEventType,
                        action: str,
                        success: bool,
                        description: Optional[str] = None,
                        resource_type: Optional[str] = None,
                        resource_id: Optional[str] = None,
                        resource_name: Optional[str] = None,
                        user_id: Optional[str] = None,
                        user_ip: Optional[str] = None,
                        user_agent: Optional[str] = None,
                        session_id: Optional[str] = None,
                        event_data: Optional[Dict[str, Any]] = None,
                        error_code: Optional[str] = None,
                        error_message: Optional[str] = None):
        """Log an audit event."""
        try:
            with self.get_session() as session:
                event_id = str(uuid.uuid4())
                
                audit_log = AuditLog(
                    event_id=event_id,
                    event_type=event_type,
                    user_id=user_id,
                    user_ip=user_ip,
                    user_agent=user_agent,
                    session_id=session_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    resource_name=resource_name,
                    action=action,
                    description=description,
                    event_data=event_data,
                    success=success,
                    error_code=error_code,
                    error_message=error_message
                )
                
                session.add(audit_log)
                
        except Exception as e:
            # Don't let audit failures break the main operation
            self.logger.error(f"Failed to log audit event: {e}")
    
    def get_audit_logs(self, 
                      event_type: Optional[str] = None,
                      user_id: Optional[str] = None,
                      resource_type: Optional[str] = None,
                      resource_id: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      limit: int = 100,
                      offset: int = 0) -> List[AuditLog]:
        """Get audit logs with optional filters."""
        try:
            with self.get_session() as session:
                query = session.query(AuditLog)
                
                if event_type:
                    query = query.filter(AuditLog.event_type == AuditEventType(event_type))
                
                if user_id:
                    query = query.filter(AuditLog.user_id == user_id)
                
                if resource_type:
                    query = query.filter(AuditLog.resource_type == resource_type)
                
                if resource_id:
                    query = query.filter(AuditLog.resource_id == resource_id)
                
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)
                
                return query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
                
        except Exception as e:
            self.logger.error(f"Failed to get audit logs: {e}")
            return []
    
    # Notification Operations
    
    def create_notification_history(self, notification_data: Dict[str, Any]) -> Optional[NotificationHistory]:
        """Create notification history entry."""
        try:
            with self.get_session() as session:
                notification = NotificationHistory(
                    notification_id=str(uuid.uuid4()),
                    certificate_id=notification_data['certificate_id'],
                    certificate_common_name=notification_data['certificate_common_name'],
                    certificate_email=notification_data['certificate_email'],
                    notification_type=notification_data['notification_type'],
                    days_until_expiry=notification_data.get('days_until_expiry'),
                    expiry_date=datetime.fromisoformat(notification_data['expiry_date'].replace('Z', '+00:00')),
                    recipient_email=notification_data['recipient_email'],
                    subject=notification_data['subject'],
                    email_template=notification_data.get('email_template'),
                    status=notification_data.get('status', 'sent'),
                    error_message=notification_data.get('error_message')
                )
                
                session.add(notification)
                return notification
                
        except Exception as e:
            self.logger.error(f"Failed to create notification history: {e}")
            return None
    
    def get_notification_history(self, 
                               certificate_id: Optional[str] = None,
                               notification_type: Optional[str] = None,
                               limit: int = 100) -> List[NotificationHistory]:
        """Get notification history with optional filters."""
        try:
            with self.get_session() as session:
                query = session.query(NotificationHistory)
                
                if certificate_id:
                    query = query.filter(NotificationHistory.certificate_id == certificate_id)
                
                if notification_type:
                    query = query.filter(NotificationHistory.notification_type == notification_type)
                
                return query.order_by(NotificationHistory.sent_at.desc()).limit(limit).all()
                
        except Exception as e:
            self.logger.error(f"Failed to get notification history: {e}")
            return []
