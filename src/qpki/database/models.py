"""
Database Models for qPKI

SQLAlchemy ORM models for storing certificates, certificate authorities,
certificate revocation lists, audit logs, and notification history.
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON,
    ForeignKey, Index, UniqueConstraint, LargeBinary, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from datetime import datetime
import enum
from typing import Dict, Any, Optional, List


Base = declarative_base()


class CertificateStatus(enum.Enum):
    """Certificate status enumeration."""
    VALID = "valid"
    EXPIRED = "expired" 
    REVOKED = "revoked"
    PENDING = "pending"
    SUSPENDED = "suspended"


class CAType(enum.Enum):
    """Certificate Authority type enumeration."""
    ROOT = "root"
    SUBORDINATE = "subordinate"
    INTERMEDIATE = "intermediate"


class CertificateType(enum.Enum):
    """Certificate type enumeration."""
    HYBRID = "hybrid"
    CLASSIC = "classic" 
    RSA = "rsa"
    ECC = "ecc"
    ML_DSA = "ml_dsa"


class RevocationReason(enum.Enum):
    """Certificate revocation reason enumeration."""
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"


class AuditEventType(enum.Enum):
    """Audit event type enumeration."""
    CA_CREATED = "ca_created"
    CA_DELETED = "ca_deleted"
    CERTIFICATE_ISSUED = "certificate_issued"
    CERTIFICATE_REVOKED = "certificate_revoked"
    CERTIFICATE_RENEWED = "certificate_renewed"
    CRL_GENERATED = "crl_generated"
    KEY_GENERATED = "key_generated"
    KEY_DELETED = "key_deleted"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    CONFIGURATION_CHANGED = "configuration_changed"
    BACKUP_CREATED = "backup_created"
    SYSTEM_ERROR = "system_error"


class CertificateAuthority(Base):
    """Certificate Authority model."""
    
    __tablename__ = 'certificate_authorities'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # CA identification
    ca_id = Column(String(64), unique=True, nullable=False, index=True)
    common_name = Column(String(255), nullable=False)
    organization = Column(String(255))
    organizational_unit = Column(String(255))
    country = Column(String(2))
    state = Column(String(255))
    locality = Column(String(255))
    email = Column(String(255))
    
    # CA properties
    ca_type = Column(SQLEnum(CAType), nullable=False, default=CAType.ROOT)
    parent_ca_id = Column(String(64), ForeignKey('certificate_authorities.ca_id'), nullable=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    
    # Validity period
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    
    # Cryptographic information
    algorithm_type = Column(String(50), nullable=False)  # hybrid, rsa, ecc
    key_size = Column(Integer)  # for RSA
    curve_name = Column(String(50))  # for ECC
    dilithium_variant = Column(Integer)  # for hybrid/post-quantum
    
    # Certificate data (JSON format for flexibility)
    certificate_data = Column(JSON, nullable=False)
    public_keys = Column(JSON, nullable=False)
    cryptographic_info = Column(JSON, nullable=False)
    
    # Private keys (encrypted JSON - consider HSM integration for production)
    private_keys = Column(Text, nullable=False)  # Encrypted private key data
    
    # Status and metadata
    status = Column(SQLEnum(CertificateStatus), nullable=False, default=CertificateStatus.VALID)
    path_length_constraint = Column(Integer, nullable=True)
    fingerprint = Column(String(128), unique=True, nullable=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(String(255))
    
    # Relationships
    parent_ca = relationship("CertificateAuthority", remote_side=[ca_id], backref="subordinate_cas")
    certificates = relationship("Certificate", back_populates="issuer_ca", cascade="all, delete-orphan")
    crls = relationship("CertificateRevocationList", back_populates="issuer_ca", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_ca_common_name', common_name),
        Index('idx_ca_organization', organization),
        Index('idx_ca_type', ca_type),
        Index('idx_ca_status', status),
        Index('idx_ca_not_after', not_after),
        Index('idx_ca_ca_id', ca_id),  # Add unique index for ca_id
        UniqueConstraint('ca_id', name='uq_ca_ca_id'),  # Explicit unique constraint
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CA to dictionary representation."""
        return {
            'id': self.id,
            'ca_id': self.ca_id,
            'common_name': self.common_name,
            'organization': self.organization,
            'organizational_unit': self.organizational_unit,
            'country': self.country,
            'state': self.state,
            'locality': self.locality,
            'email': self.email,
            'ca_type': self.ca_type.value if self.ca_type else None,
            'parent_ca_id': self.parent_ca_id,
            'serial_number': self.serial_number,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'algorithm_type': self.algorithm_type,
            'key_size': self.key_size,
            'curve_name': self.curve_name,
            'dilithium_variant': self.dilithium_variant,
            'certificate_data': self.certificate_data,
            'public_keys': self.public_keys,
            'cryptographic_info': self.cryptographic_info,
            'status': self.status.value if self.status else None,
            'path_length_constraint': self.path_length_constraint,
            'fingerprint': self.fingerprint,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }


class Certificate(Base):
    """Certificate model."""
    
    __tablename__ = 'certificates'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Certificate identification
    cert_id = Column(String(64), unique=True, nullable=False, index=True)
    serial_number = Column(String(64), unique=True, nullable=False, index=True)
    
    # Subject information
    common_name = Column(String(255), nullable=False)
    organization = Column(String(255))
    organizational_unit = Column(String(255))
    country = Column(String(2))
    state = Column(String(255))
    locality = Column(String(255))
    email = Column(String(255))
    
    # Issuer CA
    issuer_ca_id = Column(String(64), ForeignKey('certificate_authorities.ca_id'), nullable=False)
    
    # Certificate properties
    certificate_type = Column(SQLEnum(CertificateType), nullable=False, default=CertificateType.HYBRID)
    
    # Validity period
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    
    # Cryptographic information
    algorithm_type = Column(String(50), nullable=False)
    key_size = Column(Integer)  # for RSA
    curve_name = Column(String(50))  # for ECC
    dilithium_variant = Column(Integer)  # for hybrid/post-quantum
    
    # Key usage and extensions
    key_usage = Column(JSON)  # List of key usage values
    extended_key_usage = Column(JSON)  # List of extended key usage values
    subject_alt_names = Column(JSON)  # Subject alternative names
    
    # Certificate data (JSON format for flexibility)
    certificate_data = Column(JSON, nullable=False)
    public_keys = Column(JSON, nullable=False)
    cryptographic_info = Column(JSON, nullable=False)
    signature_data = Column(JSON, nullable=False)
    
    # Private keys (encrypted JSON)
    private_keys = Column(Text, nullable=False)
    
    # Status and revocation
    status = Column(SQLEnum(CertificateStatus), nullable=False, default=CertificateStatus.VALID)
    revocation_date = Column(DateTime, nullable=True)
    revocation_reason = Column(SQLEnum(RevocationReason), nullable=True)
    
    # Metadata
    fingerprint = Column(String(128), unique=True, nullable=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(String(255))
    
    # Relationships
    issuer_ca = relationship("CertificateAuthority", back_populates="certificates")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_cert_common_name', common_name),
        Index('idx_cert_organization', organization),
        Index('idx_cert_email', email),
        Index('idx_cert_type', certificate_type),
        Index('idx_cert_status', status),
        Index('idx_cert_not_after', not_after),
        Index('idx_cert_issuer', issuer_ca_id),
        Index('idx_cert_revocation', revocation_date),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert certificate to dictionary representation."""
        return {
            'id': self.id,
            'cert_id': self.cert_id,
            'serial_number': self.serial_number,
            'common_name': self.common_name,
            'organization': self.organization,
            'organizational_unit': self.organizational_unit,
            'country': self.country,
            'state': self.state,
            'locality': self.locality,
            'email': self.email,
            'issuer_ca_id': self.issuer_ca_id,
            'certificate_type': self.certificate_type.value if self.certificate_type else None,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'algorithm_type': self.algorithm_type,
            'key_size': self.key_size,
            'curve_name': self.curve_name,
            'dilithium_variant': self.dilithium_variant,
            'key_usage': self.key_usage,
            'extended_key_usage': self.extended_key_usage,
            'subject_alt_names': self.subject_alt_names,
            'certificate_data': self.certificate_data,
            'public_keys': self.public_keys,
            'cryptographic_info': self.cryptographic_info,
            'signature_data': self.signature_data,
            'status': self.status.value if self.status else None,
            'revocation_date': self.revocation_date.isoformat() if self.revocation_date else None,
            'revocation_reason': self.revocation_reason.value if self.revocation_reason else None,
            'fingerprint': self.fingerprint,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }
    
    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.utcnow() > self.not_after
    
    @property
    def days_until_expiry(self) -> int:
        """Get days until certificate expires."""
        delta = self.not_after - datetime.utcnow()
        return delta.days


class CertificateRevocationList(Base):
    """Certificate Revocation List model."""
    
    __tablename__ = 'certificate_revocation_lists'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # CRL identification
    crl_id = Column(String(64), unique=True, nullable=False, index=True)
    crl_number = Column(String(32), nullable=False)
    
    # Issuer CA
    issuer_ca_id = Column(String(64), ForeignKey('certificate_authorities.ca_id'), nullable=False)
    
    # CRL validity period
    this_update = Column(DateTime, nullable=False)
    next_update = Column(DateTime, nullable=False)
    
    # CRL data
    version = Column(String(10), default="v2", nullable=False)
    revoked_certificates = Column(JSON, nullable=False)  # List of revoked certificate entries
    signature_data = Column(JSON, nullable=False)
    
    # Status
    status = Column(String(20), default="active", nullable=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    created_by = Column(String(255))
    
    # Relationships
    issuer_ca = relationship("CertificateAuthority", back_populates="crls")
    
    # Indexes
    __table_args__ = (
        Index('idx_crl_issuer', issuer_ca_id),
        Index('idx_crl_next_update', next_update),
        Index('idx_crl_status', status),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CRL to dictionary representation."""
        return {
            'id': self.id,
            'crl_id': self.crl_id,
            'crl_number': self.crl_number,
            'issuer_ca_id': self.issuer_ca_id,
            'this_update': self.this_update.isoformat() if self.this_update else None,
            'next_update': self.next_update.isoformat() if self.next_update else None,
            'version': self.version,
            'revoked_certificates': self.revoked_certificates,
            'signature_data': self.signature_data,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }


class AuditLog(Base):
    """Audit log model for tracking all PKI operations."""
    
    __tablename__ = 'audit_logs'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Event identification
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    event_type = Column(SQLEnum(AuditEventType), nullable=False)
    
    # Event context
    user_id = Column(String(255))
    user_ip = Column(String(45))  # Support IPv6
    user_agent = Column(String(512))
    session_id = Column(String(128))
    
    # Resource information
    resource_type = Column(String(50))  # ca, certificate, crl, key
    resource_id = Column(String(64))
    resource_name = Column(String(255))
    
    # Event details
    action = Column(String(100), nullable=False)
    description = Column(Text)
    event_data = Column(JSON)  # Additional structured event data
    
    # Result information
    success = Column(Boolean, nullable=False)
    error_code = Column(String(50))
    error_message = Column(Text)
    
    # Timestamp
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_audit_event_type', event_type),
        Index('idx_audit_timestamp', timestamp),
        Index('idx_audit_user_id', user_id),
        Index('idx_audit_resource_type', resource_type),
        Index('idx_audit_resource_id', resource_id),
        Index('idx_audit_success', success),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log entry to dictionary representation."""
        return {
            'id': self.id,
            'event_id': self.event_id,
            'event_type': self.event_type.value if self.event_type else None,
            'user_id': self.user_id,
            'user_ip': self.user_ip,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'resource_name': self.resource_name,
            'action': self.action,
            'description': self.description,
            'event_data': self.event_data,
            'success': self.success,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class NotificationHistory(Base):
    """Notification history model for tracking email notifications."""
    
    __tablename__ = 'notification_history'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Notification identification
    notification_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # Certificate information
    certificate_id = Column(String(64), ForeignKey('certificates.cert_id'), nullable=False)
    certificate_common_name = Column(String(255), nullable=False)
    certificate_email = Column(String(255), nullable=False)
    
    # Notification details
    notification_type = Column(String(50), nullable=False)  # expiry_warning, expiry_critical, expired
    days_until_expiry = Column(Integer)
    expiry_date = Column(DateTime, nullable=False)
    
    # Email details
    recipient_email = Column(String(255), nullable=False)
    subject = Column(String(512), nullable=False)
    email_template = Column(String(100))
    
    # Status
    sent_at = Column(DateTime, default=func.now(), nullable=False)
    status = Column(String(20), default="sent", nullable=False)  # sent, failed, pending
    error_message = Column(Text)
    
    # Retry information
    retry_count = Column(Integer, default=0, nullable=False)
    next_retry_at = Column(DateTime, nullable=True)
    
    # Relationships
    certificate = relationship("Certificate", foreign_keys=[certificate_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_notification_certificate', certificate_id),
        Index('idx_notification_type', notification_type),
        Index('idx_notification_sent_at', sent_at),
        Index('idx_notification_status', status),
        Index('idx_notification_retry', next_retry_at),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification history entry to dictionary representation."""
        return {
            'id': self.id,
            'notification_id': self.notification_id,
            'certificate_id': self.certificate_id,
            'certificate_common_name': self.certificate_common_name,
            'certificate_email': self.certificate_email,
            'notification_type': self.notification_type,
            'days_until_expiry': self.days_until_expiry,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'recipient_email': self.recipient_email,
            'subject': self.subject,
            'email_template': self.email_template,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'status': self.status,
            'error_message': self.error_message,
            'retry_count': self.retry_count,
            'next_retry_at': self.next_retry_at.isoformat() if self.next_retry_at else None
        }


class OCSPResponse(Base):
    """OCSP response cache model."""
    
    __tablename__ = 'ocsp_responses'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Certificate identification
    certificate_id = Column(String(64), ForeignKey('certificates.cert_id'), nullable=False)
    serial_number = Column(String(64), nullable=False, index=True)
    
    # OCSP response data
    response_status = Column(String(20), nullable=False)  # good, revoked, unknown
    response_data = Column(LargeBinary, nullable=False)  # DER-encoded OCSP response
    
    # Validity period
    produced_at = Column(DateTime, nullable=False)
    this_update = Column(DateTime, nullable=False)
    next_update = Column(DateTime, nullable=False)
    
    # Cache control
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Relationships
    certificate = relationship("Certificate", foreign_keys=[certificate_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_ocsp_serial_number', serial_number),
        Index('idx_ocsp_next_update', next_update),
        UniqueConstraint('certificate_id', 'produced_at', name='uq_ocsp_cert_produced'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert OCSP response to dictionary representation."""
        return {
            'id': self.id,
            'certificate_id': self.certificate_id,
            'serial_number': self.serial_number,
            'response_status': self.response_status,
            'produced_at': self.produced_at.isoformat() if self.produced_at else None,
            'this_update': self.this_update.isoformat() if self.this_update else None,
            'next_update': self.next_update.isoformat() if self.next_update else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
