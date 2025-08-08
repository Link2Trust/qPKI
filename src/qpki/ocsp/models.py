"""
OCSP Models and Data Structures

Defines data structures for OCSP requests, responses, and certificate status.
"""

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes


class CertificateStatus(enum.Enum):
    """OCSP certificate status values."""
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class RevocationReason(enum.Enum):
    """Certificate revocation reasons (RFC 5280)."""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


@dataclass
class CertID:
    """Certificate identifier for OCSP requests."""
    hash_algorithm: str
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    serial_number: int
    
    def __str__(self) -> str:
        return f"CertID(serial={self.serial_number}, hash_alg={self.hash_algorithm})"


@dataclass
class SingleRequest:
    """Single certificate request within an OCSP request."""
    cert_id: CertID
    single_request_extensions: Optional[List[x509.Extension]] = None


@dataclass
class OCSPRequest:
    """OCSP request structure."""
    tbs_request: 'TBSRequest'
    optional_signature: Optional[bytes] = None
    
    def __str__(self) -> str:
        return f"OCSPRequest(requests={len(self.tbs_request.request_list)})"


@dataclass 
class TBSRequest:
    """TBS (To Be Signed) request structure."""
    version: int
    requestor_name: Optional[str]
    request_list: List[SingleRequest]
    request_extensions: Optional[List[x509.Extension]] = None


@dataclass
class RevokedInfo:
    """Information about a revoked certificate."""
    revocation_time: datetime
    revocation_reason: Optional[RevocationReason] = None


@dataclass
class CertStatus:
    """Certificate status information."""
    status: CertificateStatus
    revoked_info: Optional[RevokedInfo] = None
    
    def __str__(self) -> str:
        if self.status == CertificateStatus.REVOKED and self.revoked_info:
            return f"{self.status.value} (reason: {self.revoked_info.revocation_reason})"
        return self.status.value


@dataclass
class SingleResponse:
    """Single certificate response within an OCSP response."""
    cert_id: CertID
    cert_status: CertStatus
    this_update: datetime
    next_update: Optional[datetime] = None
    single_extensions: Optional[List[x509.Extension]] = None


@dataclass
class ResponseData:
    """OCSP response data structure."""
    version: int
    responder_id: str
    produced_at: datetime
    responses: List[SingleResponse]
    response_extensions: Optional[List[x509.Extension]] = None


@dataclass
class BasicOCSPResponse:
    """Basic OCSP response structure."""
    tbs_response_data: ResponseData
    signature_algorithm: str
    signature: bytes
    certificates: Optional[List[x509.Certificate]] = None


@dataclass
class OCSPResponse:
    """OCSP response structure."""
    response_status: str  # successful, malformed_request, internal_error, etc.
    response_bytes: Optional[BasicOCSPResponse] = None
    
    def __str__(self) -> str:
        if self.response_bytes:
            response_count = len(self.response_bytes.tbs_response_data.responses)
            return f"OCSPResponse(status={self.response_status}, responses={response_count})"
        return f"OCSPResponse(status={self.response_status})"


class OCSPResponseStatus(enum.Enum):
    """OCSP response status values."""
    SUCCESSFUL = "successful"
    MALFORMED_REQUEST = "malformed_request"
    INTERNAL_ERROR = "internal_error"
    TRY_LATER = "try_later"
    SIG_REQUIRED = "sig_required"
    UNAUTHORIZED = "unauthorized"


@dataclass
class OCSPConfiguration:
    """OCSP responder configuration."""
    # Responder identity
    responder_name: str
    responder_key_file: str
    responder_cert_file: str
    
    # Response settings
    response_validity_hours: int = 24
    signature_algorithm: str = "sha256"
    include_certs: bool = True
    
    # Cache settings
    enable_response_caching: bool = True
    cache_duration_minutes: int = 60
    
    # Security settings
    require_request_signature: bool = False
    allowed_hash_algorithms: List[str] = None
    max_request_size: int = 1024 * 1024  # 1MB
    
    # Database settings
    use_database: bool = True
    database_config: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.allowed_hash_algorithms is None:
            self.allowed_hash_algorithms = ["sha1", "sha256", "sha384", "sha512"]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'responder_name': self.responder_name,
            'responder_key_file': self.responder_key_file,
            'responder_cert_file': self.responder_cert_file,
            'response_validity_hours': self.response_validity_hours,
            'signature_algorithm': self.signature_algorithm,
            'include_certs': self.include_certs,
            'enable_response_caching': self.enable_response_caching,
            'cache_duration_minutes': self.cache_duration_minutes,
            'require_request_signature': self.require_request_signature,
            'allowed_hash_algorithms': self.allowed_hash_algorithms,
            'max_request_size': self.max_request_size,
            'use_database': self.use_database,
            'database_config': self.database_config
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'OCSPConfiguration':
        """Create configuration from dictionary."""
        return cls(**config_dict)


@dataclass
class CertificateInfo:
    """Certificate information for OCSP processing."""
    serial_number: int
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    status: CertificateStatus
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[RevocationReason] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        if self.not_after:
            return datetime.utcnow() > self.not_after
        return False
    
    def get_cert_status(self) -> CertStatus:
        """Get certificate status for OCSP response."""
        if self.status == CertificateStatus.REVOKED:
            revoked_info = RevokedInfo(
                revocation_time=self.revocation_time,
                revocation_reason=self.revocation_reason
            )
            return CertStatus(CertificateStatus.REVOKED, revoked_info)
        elif self.is_expired():
            return CertStatus(CertificateStatus.UNKNOWN)
        else:
            return CertStatus(self.status)


def create_cert_id(issuer_cert: x509.Certificate, 
                   serial_number: int,
                   hash_algorithm: str = "sha1") -> CertID:
    """
    Create certificate identifier for OCSP operations.
    
    Args:
        issuer_cert: Issuer certificate
        serial_number: Certificate serial number
        hash_algorithm: Hash algorithm to use (default: sha1)
    
    Returns:
        CertID object
    """
    # Select hash algorithm
    if hash_algorithm.lower() == "sha1":
        hasher = hashes.SHA1()
    elif hash_algorithm.lower() == "sha256":
        hasher = hashes.SHA256()
    elif hash_algorithm.lower() == "sha384":
        hasher = hashes.SHA384()
    elif hash_algorithm.lower() == "sha512":
        hasher = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    
    # Hash issuer name (DER-encoded)
    issuer_name_der = issuer_cert.subject.public_bytes()
    digest = hashes.Hash(hasher)
    digest.update(issuer_name_der)
    issuer_name_hash = digest.finalize()
    
    # Hash issuer public key
    issuer_public_key = issuer_cert.public_key()
    issuer_key_bytes = issuer_public_key.public_key()
    digest = hashes.Hash(hasher)
    digest.update(issuer_key_bytes)
    issuer_key_hash = digest.finalize()
    
    return CertID(
        hash_algorithm=hash_algorithm,
        issuer_name_hash=issuer_name_hash,
        issuer_key_hash=issuer_key_hash,
        serial_number=serial_number
    )


def parse_hash_algorithm_oid(oid: str) -> str:
    """Parse hash algorithm from OID."""
    oid_to_name = {
        "1.3.14.3.2.26": "sha1",
        "2.16.840.1.101.3.4.2.1": "sha256", 
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512"
    }
    return oid_to_name.get(oid, "unknown")
