"""
User Authentication Models for qPKI

SQLAlchemy ORM models for user management, authentication, and session tracking.
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, JSON, 
    ForeignKey, Index, UniqueConstraint, Text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import enum
from typing import Dict, Any, Optional

# Use the same base as the main models
from ..database.models import Base


class UserRole(enum.Enum):
    """User role enumeration."""
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class UserStatus(enum.Enum):
    """User status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING = "pending"


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = 'users'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User identification
    user_id = Column(String(64), unique=True, nullable=False, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    
    # Personal information
    full_name = Column(String(255), nullable=False)
    department = Column(String(255))
    phone = Column(String(50))
    
    # Authentication
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(64), nullable=False)
    
    # Authorization
    role = Column(String(50), nullable=False, default=UserRole.VIEWER.value)
    permissions = Column(JSON)  # Additional granular permissions
    
    # Account status
    status = Column(String(20), nullable=False, default=UserStatus.ACTIVE.value)
    is_active = Column(Boolean, nullable=False, default=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    
    # Password policy
    password_last_changed = Column(DateTime, nullable=False, default=func.now())
    password_expires_at = Column(DateTime, nullable=True)
    force_password_change = Column(Boolean, nullable=False, default=False)
    
    # Login tracking
    last_login = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # Support IPv6
    login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # Two-factor authentication
    totp_secret = Column(String(255), nullable=True)
    backup_codes = Column(JSON, nullable=True)  # Encrypted backup codes
    two_factor_enabled = Column(Boolean, nullable=False, default=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(String(255))
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_user_username', username),
        Index('idx_user_email', email),
        Index('idx_user_role', role),
        Index('idx_user_status', status),
        Index('idx_user_last_login', last_login),
    )
    
    def set_password(self, password: str) -> None:
        """Set user password with salt and hash."""
        self.salt = secrets.token_hex(32)
        self.password_hash = self._hash_password(password, self.salt)
        self.password_last_changed = datetime.now(timezone.utc)
        self.password_expires_at = datetime.now(timezone.utc) + timedelta(days=90)  # 90-day expiry
    
    def check_password(self, password: str) -> bool:
        """Check if provided password matches the stored hash."""
        return self.password_hash == self._hash_password(password, self.salt)
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using PBKDF2."""
        import hashlib
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    
    def is_password_expired(self) -> bool:
        """Check if user's password has expired."""
        if not self.password_expires_at:
            return False
        
        # Handle timezone-naive comparison
        expires_at = self.password_expires_at
        if expires_at.tzinfo is None:
            # If stored datetime is naive, treat it as UTC
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        return datetime.now(timezone.utc) > expires_at
    
    def is_account_locked(self) -> bool:
        """Check if user account is locked."""
        if self.status == UserStatus.LOCKED.value:
            return True
        if self.locked_until:
            # Handle timezone-naive comparison
            locked_until = self.locked_until
            if locked_until.tzinfo is None:
                # If stored datetime is naive, treat it as UTC
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < locked_until:
                return True
        return False
    
    def reset_login_attempts(self) -> None:
        """Reset failed login attempts counter."""
        self.login_attempts = 0
        self.locked_until = None
    
    def increment_login_attempts(self) -> None:
        """Increment failed login attempts and lock account if needed."""
        self.login_attempts += 1
        # Lock account after 5 failed attempts for 30 minutes
        if self.login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def record_successful_login(self, ip_address: str) -> None:
        """Record successful login."""
        self.last_login = datetime.now(timezone.utc)
        self.last_login_ip = ip_address
        self.reset_login_attempts()
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        # Admin has all permissions
        if self.role == UserRole.ADMIN.value:
            return True
        
        # Check role-based permissions
        role_permissions = {
            UserRole.OPERATOR.value: [
                'ca.create', 'ca.view', 'cert.create', 'cert.view', 
                'cert.revoke', 'crl.generate', 'crl.view'
            ],
            UserRole.AUDITOR.value: [
                'ca.view', 'cert.view', 'crl.view', 'audit.view', 
                'system.view', 'notifications.view'
            ],
            UserRole.VIEWER.value: [
                'ca.view', 'cert.view', 'crl.view'
            ]
        }
        
        if permission in role_permissions.get(self.role, []):
            return True
        
        # Check granular permissions
        if self.permissions and permission in self.permissions:
            return self.permissions[permission]
        
        return False
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary representation."""
        user_dict = {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'department': self.department,
            'phone': self.phone,
            'role': self.role,
            'status': self.status,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'two_factor_enabled': self.two_factor_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'last_login_ip': self.last_login_ip,
            'login_attempts': self.login_attempts,
            'password_last_changed': self.password_last_changed.isoformat() if self.password_last_changed else None,
            'password_expires_at': self.password_expires_at.isoformat() if self.password_expires_at else None,
            'force_password_change': self.force_password_change,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }
        
        if include_sensitive:
            user_dict.update({
                'permissions': self.permissions,
                'totp_secret': self.totp_secret,
                'backup_codes': self.backup_codes
            })
        
        return user_dict


class UserSession(Base):
    """User session model for tracking active sessions."""
    
    __tablename__ = 'user_sessions'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Session identification
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False)
    
    # User reference
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Session metadata
    ip_address = Column(String(45), nullable=False)  # Support IPv6
    user_agent = Column(String(512))
    
    # Session lifetime
    created_at = Column(DateTime, default=func.now(), nullable=False)
    last_accessed = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Session status
    is_active = Column(Boolean, nullable=False, default=True)
    logout_reason = Column(String(50))  # expired, manual, forced
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    # Indexes
    __table_args__ = (
        Index('idx_session_token', session_token),
        Index('idx_session_user_id', user_id),
        Index('idx_session_expires_at', expires_at),
        Index('idx_session_active', is_active),
    )
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            # If stored datetime is naive, treat it as UTC
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at
    
    def extend_session(self, duration_hours: int = 8) -> None:
        """Extend session expiry time."""
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        self.last_accessed = datetime.now(timezone.utc)
    
    def invalidate(self, reason: str = "manual") -> None:
        """Invalidate the session."""
        self.is_active = False
        self.logout_reason = reason
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary representation."""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active,
            'logout_reason': self.logout_reason
        }


class APIKey(Base):
    """API key model for programmatic access."""
    
    __tablename__ = 'api_keys'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Key identification
    key_id = Column(String(64), unique=True, nullable=False, index=True)
    key_name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(16), nullable=False)  # First few chars for identification
    
    # User reference
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Key properties
    is_active = Column(Boolean, nullable=False, default=True)
    permissions = Column(JSON)  # Specific permissions for this key
    allowed_ips = Column(JSON)  # IP restrictions
    
    # Usage tracking
    last_used = Column(DateTime, nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    usage_count = Column(Integer, nullable=False, default=0)
    
    # Key lifetime
    created_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    # Indexes
    __table_args__ = (
        Index('idx_api_key_hash', key_hash),
        Index('idx_api_key_user_id', user_id),
        Index('idx_api_key_active', is_active),
        Index('idx_api_key_expires_at', expires_at),
    )
    
    @staticmethod
    def generate_api_key() -> tuple[str, str, str]:
        """Generate new API key and return (key, hash, prefix)."""
        key = f"qpki_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:12] + "..."
        return key, key_hash, key_prefix
    
    def is_expired(self) -> bool:
        """Check if API key has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def record_usage(self, ip_address: str) -> None:
        """Record API key usage."""
        self.last_used = datetime.now(timezone.utc)
        self.last_used_ip = ip_address
        self.usage_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert API key to dictionary representation."""
        return {
            'id': self.id,
            'key_id': self.key_id,
            'key_name': self.key_name,
            'key_prefix': self.key_prefix,
            'user_id': self.user_id,
            'is_active': self.is_active,
            'permissions': self.permissions,
            'allowed_ips': self.allowed_ips,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'last_used_ip': self.last_used_ip,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
