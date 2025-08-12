"""
Audit Event Types and Data Structures

Defines comprehensive audit event types and data structures for
RFC 3647 compliant PKI audit logging.
"""

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import json


class AuditEventType(enum.Enum):
    """Comprehensive audit event types based on RFC 3647."""
    
    # Certificate Authority Events
    CA_CREATED = "ca_created"
    CA_DELETED = "ca_deleted"
    CA_KEY_GENERATED = "ca_key_generated"
    CA_KEY_COMPROMISED = "ca_key_compromised"
    CA_CERTIFICATE_RENEWED = "ca_certificate_renewed"
    CA_STATUS_CHANGED = "ca_status_changed"
    
    # Certificate Lifecycle Events
    CERTIFICATE_REQUESTED = "certificate_requested"
    CERTIFICATE_ISSUED = "certificate_issued"
    CERTIFICATE_REVOKED = "certificate_revoked"
    CERTIFICATE_RENEWED = "certificate_renewed"
    CERTIFICATE_SUSPENDED = "certificate_suspended"
    CERTIFICATE_UNSUSPENDED = "certificate_unsuspended"
    CERTIFICATE_VALIDATED = "certificate_validated"
    CERTIFICATE_EXPORTED = "certificate_exported"
    
    # Key Management Events
    KEY_GENERATED = "key_generated"
    KEY_DELETED = "key_deleted"
    KEY_COMPROMISED = "key_compromised"
    KEY_RECOVERED = "key_recovered"
    KEY_ARCHIVED = "key_archived"
    KEY_ESCROW = "key_escrow"
    
    # CRL Events
    CRL_GENERATED = "crl_generated"
    CRL_PUBLISHED = "crl_published"
    CRL_UPDATED = "crl_updated"
    
    # OCSP Events
    OCSP_REQUEST_RECEIVED = "ocsp_request_received"
    OCSP_RESPONSE_SENT = "ocsp_response_sent"
    OCSP_ERROR = "ocsp_error"
    
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session_expired"
    PASSWORD_CHANGED = "password_changed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    
    # Authorization Events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    
    # Configuration Events
    CONFIGURATION_CHANGED = "configuration_changed"
    POLICY_UPDATED = "policy_updated"
    TEMPLATE_MODIFIED = "template_modified"
    
    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    DATABASE_MIGRATED = "database_migrated"
    
    # Security Events
    INTRUSION_DETECTED = "intrusion_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    SECURITY_VIOLATION = "security_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # Error Events
    SYSTEM_ERROR = "system_error"
    APPLICATION_ERROR = "application_error"
    VALIDATION_ERROR = "validation_error"
    NETWORK_ERROR = "network_error"
    
    # Compliance Events
    AUDIT_LOG_ARCHIVED = "audit_log_archived"
    COMPLIANCE_CHECK = "compliance_check"
    POLICY_VIOLATION = "policy_violation"
    
    # API Events
    API_CALL = "api_call"
    API_ERROR = "api_error"
    API_RATE_LIMITED = "api_rate_limited"


class AuditSeverity(enum.Enum):
    """Audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditOutcome(enum.Enum):
    """Audit event outcome status."""
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class AuditContext:
    """Context information for audit events."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    api_key_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # Additional context
    organization: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary."""
        return {
            k: v for k, v in self.__dict__.items() 
            if v is not None
        }


@dataclass
class AuditResource:
    """Resource information for audit events."""
    resource_type: str  # ca, certificate, crl, key, user, etc.
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    parent_resource_type: Optional[str] = None
    parent_resource_id: Optional[str] = None
    
    # Additional resource metadata
    resource_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary."""
        result = {
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'resource_name': self.resource_name,
            'parent_resource_type': self.parent_resource_type,
            'parent_resource_id': self.parent_resource_id
        }
        
        if self.resource_attributes:
            result['resource_attributes'] = self.resource_attributes
            
        return {k: v for k, v in result.items() if v is not None}


@dataclass
class AuditEvent:
    """Comprehensive audit event structure."""
    
    # Event identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType = AuditEventType.SYSTEM_ERROR
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Event classification
    severity: AuditSeverity = AuditSeverity.MEDIUM
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    category: str = "general"
    
    # Event description
    action: str = ""
    description: str = ""
    message: Optional[str] = None
    
    # Context information
    context: Optional[AuditContext] = None
    resource: Optional[AuditResource] = None
    
    # Event data
    event_data: Dict[str, Any] = field(default_factory=dict)
    
    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    
    # Compliance and correlation
    compliance_tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    related_events: List[str] = field(default_factory=list)
    
    # Metadata
    source_system: str = "qpki"
    source_component: Optional[str] = None
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary for storage."""
        result = {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'outcome': self.outcome.value,
            'category': self.category,
            'action': self.action,
            'description': self.description,
            'message': self.message,
            'event_data': self.event_data,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'stack_trace': self.stack_trace,
            'compliance_tags': self.compliance_tags,
            'correlation_id': self.correlation_id,
            'related_events': self.related_events,
            'source_system': self.source_system,
            'source_component': self.source_component,
            'version': self.version
        }
        
        # Add context if present
        if self.context:
            result['context'] = self.context.to_dict()
        
        # Add resource if present
        if self.resource:
            result['resource'] = self.resource.to_dict()
        
        # Remove None values
        return {k: v for k, v in result.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary."""
        # Extract context
        context_data = data.get('context')
        context = AuditContext(**context_data) if context_data else None
        
        # Extract resource
        resource_data = data.get('resource')
        resource = AuditResource(**resource_data) if resource_data else None
        
        # Create event
        return cls(
            event_id=data.get('event_id', str(uuid.uuid4())),
            event_type=AuditEventType(data.get('event_type', 'system_error')),
            timestamp=datetime.fromisoformat(data['timestamp']) if 'timestamp' in data else datetime.now(timezone.utc),
            severity=AuditSeverity(data.get('severity', 'medium')),
            outcome=AuditOutcome(data.get('outcome', 'success')),
            category=data.get('category', 'general'),
            action=data.get('action', ''),
            description=data.get('description', ''),
            message=data.get('message'),
            context=context,
            resource=resource,
            event_data=data.get('event_data', {}),
            error_code=data.get('error_code'),
            error_message=data.get('error_message'),
            stack_trace=data.get('stack_trace'),
            compliance_tags=data.get('compliance_tags', []),
            correlation_id=data.get('correlation_id'),
            related_events=data.get('related_events', []),
            source_system=data.get('source_system', 'qpki'),
            source_component=data.get('source_component'),
            version=data.get('version', '1.0')
        )
    
    def to_json(self) -> str:
        """Convert audit event to JSON string."""
        return json.dumps(self.to_dict(), default=str, indent=2)
    
    def get_hash(self) -> str:
        """Generate hash for tamper detection."""
        import hashlib
        
        # Create a deterministic string representation
        data_str = json.dumps(self.to_dict(), sort_keys=True, default=str)
        
        # Generate SHA-256 hash
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def add_compliance_tag(self, tag: str):
        """Add compliance tag to event."""
        if tag not in self.compliance_tags:
            self.compliance_tags.append(tag)
    
    def add_related_event(self, event_id: str):
        """Add related event ID."""
        if event_id not in self.related_events:
            self.related_events.append(event_id)
    
    def set_error(self, error_code: str, error_message: str, stack_trace: Optional[str] = None):
        """Set error information."""
        self.outcome = AuditOutcome.ERROR
        self.error_code = error_code
        self.error_message = error_message
        self.stack_trace = stack_trace
        
        if self.severity == AuditSeverity.LOW:
            self.severity = AuditSeverity.MEDIUM


def create_ca_event(action: str, ca_id: str, ca_name: str, context: Optional[AuditContext] = None) -> AuditEvent:
    """Create CA-related audit event."""
    return AuditEvent(
        event_type=AuditEventType.CA_CREATED if 'create' in action.lower() else AuditEventType.CA_STATUS_CHANGED,
        action=action,
        description=f"Certificate Authority operation: {action}",
        category="certificate_authority",
        context=context,
        resource=AuditResource(
            resource_type="ca",
            resource_id=ca_id,
            resource_name=ca_name
        ),
        compliance_tags=["rfc3647", "ca_lifecycle"]
    )


def create_certificate_event(action: str, cert_id: str, common_name: str, 
                           issuer_ca_id: str, context: Optional[AuditContext] = None) -> AuditEvent:
    """Create certificate-related audit event."""
    event_type_map = {
        'issued': AuditEventType.CERTIFICATE_ISSUED,
        'revoked': AuditEventType.CERTIFICATE_REVOKED,
        'renewed': AuditEventType.CERTIFICATE_RENEWED,
        'validated': AuditEventType.CERTIFICATE_VALIDATED,
        'exported': AuditEventType.CERTIFICATE_EXPORTED
    }
    
    event_type = AuditEventType.CERTIFICATE_ISSUED
    for key, value in event_type_map.items():
        if key in action.lower():
            event_type = value
            break
    
    return AuditEvent(
        event_type=event_type,
        action=action,
        description=f"Certificate operation: {action} for {common_name}",
        category="certificate",
        context=context,
        resource=AuditResource(
            resource_type="certificate",
            resource_id=cert_id,
            resource_name=common_name,
            parent_resource_type="ca",
            parent_resource_id=issuer_ca_id
        ),
        compliance_tags=["rfc3647", "certificate_lifecycle"]
    )


def create_authentication_event(action: str, user_id: str, success: bool,
                              context: Optional[AuditContext] = None) -> AuditEvent:
    """Create authentication-related audit event."""
    event_type = AuditEventType.LOGIN_SUCCESS if success else AuditEventType.LOGIN_FAILED
    outcome = AuditOutcome.SUCCESS if success else AuditOutcome.FAILURE
    severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
    
    return AuditEvent(
        event_type=event_type,
        action=action,
        description=f"Authentication attempt for user {user_id}",
        category="authentication",
        severity=severity,
        outcome=outcome,
        context=context,
        resource=AuditResource(
            resource_type="user",
            resource_id=user_id
        ),
        compliance_tags=["authentication", "security"]
    )


def create_system_event(action: str, description: str, severity: AuditSeverity = AuditSeverity.LOW) -> AuditEvent:
    """Create system-related audit event."""
    return AuditEvent(
        event_type=AuditEventType.SYSTEM_STARTUP if 'startup' in action.lower() else AuditEventType.CONFIGURATION_CHANGED,
        action=action,
        description=description,
        category="system",
        severity=severity,
        compliance_tags=["system_operations"]
    )
