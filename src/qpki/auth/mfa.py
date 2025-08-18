"""
Multi-Factor Authentication (MFA) Module for qPKI

Implements TOTP (Time-based One-Time Password) authentication using authenticator apps.
"""

import secrets
import base64
import qrcode
from io import BytesIO
from typing import List, Tuple, Optional
import pyotp
from cryptography.fernet import Fernet
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta


class MFAManager:
    """Manages Multi-Factor Authentication operations."""
    
    def __init__(self, app_name: str = "qPKI", issuer_name: str = "qPKI Certificate Authority"):
        self.app_name = app_name
        self.issuer_name = issuer_name
        self._encryption_key = self._get_or_create_encryption_key()
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for backup codes."""
        key_file = os.path.join(os.path.dirname(__file__), '../../../.mfa_key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            return key
    
    def generate_secret_key(self) -> str:
        """Generate a new TOTP secret key."""
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, user_email: str, secret_key: str) -> str:
        """Get provisioning URI for QR code generation."""
        totp = pyotp.TOTP(secret_key)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, provisioning_uri: str) -> BytesIO:
        """Generate QR code for TOTP setup."""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to BytesIO for web display
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer
    
    def verify_totp_code(self, secret_key: str, user_code: str, window: int = 1) -> bool:
        """
        Verify TOTP code.
        
        Args:
            secret_key: User's TOTP secret key
            user_code: Code provided by user
            window: Time window tolerance (default 1 = ±30 seconds)
        
        Returns:
            True if code is valid
        """
        try:
            totp = pyotp.TOTP(secret_key)
            return totp.verify(user_code, valid_window=window)
        except Exception:
            return False
    
    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate backup codes for MFA recovery."""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric backup code
            code = secrets.token_hex(4).upper()
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    def encrypt_backup_codes(self, codes: List[str]) -> str:
        """Encrypt backup codes for secure storage."""
        fernet = Fernet(self._encryption_key)
        codes_json = json.dumps(codes)
        encrypted_codes = fernet.encrypt(codes_json.encode())
        return base64.b64encode(encrypted_codes).decode()
    
    def decrypt_backup_codes(self, encrypted_codes: str) -> List[str]:
        """Decrypt backup codes from storage."""
        try:
            fernet = Fernet(self._encryption_key)
            encrypted_data = base64.b64decode(encrypted_codes.encode())
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception:
            return []
    
    def verify_backup_code(self, encrypted_codes: str, user_code: str) -> Tuple[bool, str]:
        """
        Verify backup code and return updated encrypted codes list.
        
        Args:
            encrypted_codes: Encrypted backup codes from database
            user_code: Backup code provided by user
        
        Returns:
            (is_valid, updated_encrypted_codes)
        """
        try:
            codes = self.decrypt_backup_codes(encrypted_codes)
            user_code_formatted = user_code.upper().replace('-', '').replace(' ', '')
            
            for i, code in enumerate(codes):
                code_formatted = code.replace('-', '')
                if code_formatted == user_code_formatted:
                    # Remove used backup code
                    codes.pop(i)
                    updated_encrypted = self.encrypt_backup_codes(codes)
                    return True, updated_encrypted
            
            return False, encrypted_codes
        except Exception:
            return False, encrypted_codes
    
    def get_backup_codes_count(self, encrypted_codes: str) -> int:
        """Get number of remaining backup codes."""
        try:
            codes = self.decrypt_backup_codes(encrypted_codes)
            return len(codes)
        except Exception:
            return 0
    
    def is_valid_totp_format(self, code: str) -> bool:
        """Check if code format is valid for TOTP (6 digits)."""
        return code.isdigit() and len(code) == 6
    
    def is_valid_backup_code_format(self, code: str) -> bool:
        """Check if code format is valid for backup code."""
        cleaned_code = code.upper().replace('-', '').replace(' ', '')
        return len(cleaned_code) == 8 and all(c.isalnum() for c in cleaned_code)


class MFASetupSession:
    """Manages MFA setup session state."""
    
    def __init__(self):
        self._sessions = {}
    
    def create_setup_session(self, user_id: int, secret_key: str) -> str:
        """Create MFA setup session."""
        session_token = secrets.token_urlsafe(32)
        self._sessions[session_token] = {
            'user_id': user_id,
            'secret_key': secret_key,
            'created_at': datetime.now(timezone.utc),
            'verified': False
        }
        return session_token
    
    def get_setup_session(self, session_token: str) -> Optional[dict]:
        """Get MFA setup session."""
        from datetime import datetime, timezone, timedelta
        
        session = self._sessions.get(session_token)
        if not session:
            return None
        
        # Check if session has expired (15 minutes)
        if datetime.now(timezone.utc) - session['created_at'] > timedelta(minutes=15):
            self.cleanup_session(session_token)
            return None
        
        return session
    
    def mark_session_verified(self, session_token: str) -> bool:
        """Mark setup session as verified."""
        session = self.get_setup_session(session_token)
        if session:
            session['verified'] = True
            return True
        return False
    
    def cleanup_session(self, session_token: str) -> None:
        """Remove setup session."""
        self._sessions.pop(session_token, None)
    
    def cleanup_expired_sessions(self) -> None:
        """Clean up expired setup sessions."""
        from datetime import datetime, timezone, timedelta
        
        expired_tokens = []
        for token, session in self._sessions.items():
            if datetime.now(timezone.utc) - session['created_at'] > timedelta(minutes=15):
                expired_tokens.append(token)
        
        for token in expired_tokens:
            self.cleanup_session(token)


# Global MFA setup session manager
mfa_setup_sessions = MFASetupSession()
