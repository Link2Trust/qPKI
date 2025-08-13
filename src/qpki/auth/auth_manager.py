"""
Authentication Manager for qPKI

Handles user authentication, session management, and authorization.
"""

import os
import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from flask import session, request, current_app
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from ..database.manager import DatabaseManager
from .models import User, UserSession, APIKey, UserRole, UserStatus


class AuthenticationManager:
    """Authentication and session management."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.Session = sessionmaker(bind=db_manager.engine)
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, Optional[dict], str]:
        """
        Authenticate user with username and password.
        
        Returns:
            (success, user_data_dict, message)
        """
        db_session = self.Session()
        try:
            # Find user by username or email
            user = db_session.query(User).filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if not user:
                return False, None, "Invalid username or password"
            
            # Check if account is locked
            if user.is_account_locked():
                return False, None, f"Account is locked. Try again later."
            
            # Check if account is active
            if not user.is_active or user.status != UserStatus.ACTIVE.value:
                return False, None, "Account is inactive"
            
            # Verify password
            if not user.check_password(password):
                user.increment_login_attempts()
                db_session.commit()
                return False, None, "Invalid username or password"
            
            # Check if password has expired
            if user.is_password_expired():
                return False, None, "Password has expired. Please contact administrator."
            
            # Successful authentication
            if ip_address:
                user.record_successful_login(ip_address)
            db_session.commit()
            
            # Return user data instead of object to avoid session issues
            user_data = {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'full_name': user.full_name,
                'email': user.email,
                'force_password_change': user.force_password_change,
                'is_password_expired': user.is_password_expired()
            }
            
            return True, user_data, "Authentication successful"
            
        except Exception as e:
            db_session.rollback()
            return False, None, f"Authentication error: {str(e)}"
        finally:
            db_session.close()
    
    def create_session(self, user_data: dict, ip_address: str = None, user_agent: str = None) -> Optional[str]:
        """
        Create a new session for authenticated user.
        
        Args:
            user_data: Dictionary with user info (id, username, role, etc.)
            ip_address: Client IP address
            user_agent: Client user agent string
        
        Returns:
            session_token or None
        """
        db_session = self.Session()
        try:
            # Generate secure session token
            session_id = str(uuid.uuid4())
            session_token = secrets.token_urlsafe(32)
            
            # Create session
            user_session = UserSession(
                session_id=session_id,
                session_token=session_token,
                user_id=user_data['id'],
                ip_address=ip_address or request.remote_addr or "unknown",
                user_agent=user_agent or request.user_agent.string if request else None,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=8)  # 8-hour session
            )
            
            db_session.add(user_session)
            db_session.commit()
            
            # Store session info in Flask session
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            session['role'] = user_data['role']
            session['session_token'] = session_token
            session['session_id'] = session_id
            
            return session_token
            
        except Exception as e:
            db_session.rollback()
            current_app.logger.error(f"Error creating session: {e}")
            return None
        finally:
            db_session.close()
    
    def validate_session(self, session_token: str = None) -> Tuple[bool, Optional[dict]]:
        """
        Validate session token and return user data if valid.
        
        Returns:
            (valid, user_data_dict)
        """
        if not session_token:
            session_token = session.get('session_token')
        
        if not session_token:
            return False, None
        
        db_session = self.Session()
        try:
            # Find active session
            user_session = db_session.query(UserSession).filter_by(
                session_token=session_token,
                is_active=True
            ).first()
            
            if not user_session:
                return False, None
            
            # Check if session has expired
            if user_session.is_expired():
                user_session.invalidate("expired")
                db_session.commit()
                return False, None
            
            # Get associated user
            user = db_session.query(User).filter_by(id=user_session.user_id).first()
            
            if not user or not user.is_active:
                user_session.invalidate("user_inactive")
                db_session.commit()
                return False, None
            
            # Update last accessed time
            user_session.last_accessed = datetime.now(timezone.utc)
            db_session.commit()
            
            # Return user data dictionary to avoid session binding issues
            user_data = {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'full_name': user.full_name,
                'email': user.email,
                'status': user.status,
                'is_active': user.is_active,
                'force_password_change': user.force_password_change,
                'is_password_expired': user.is_password_expired(),
                'permissions': user.permissions
            }
            
            return True, user_data
            
        except Exception as e:
            current_app.logger.error(f"Error validating session: {e}")
            return False, None
        finally:
            db_session.close()
    
    def logout_user(self, session_token: str = None) -> bool:
        """
        Logout user and invalidate session.
        
        Returns:
            success
        """
        if not session_token:
            session_token = session.get('session_token')
        
        if not session_token:
            return False
        
        db_session = self.Session()
        try:
            # Find and invalidate session
            user_session = db_session.query(UserSession).filter_by(
                session_token=session_token
            ).first()
            
            if user_session:
                user_session.invalidate("manual")
                db_session.commit()
            
            # Clear Flask session
            session.clear()
            
            return True
            
        except Exception as e:
            current_app.logger.error(f"Error during logout: {e}")
            return False
        finally:
            db_session.close()
    
    def create_user(self, user_data: Dict[str, Any], created_by: str = None) -> Tuple[bool, Optional[User], str]:
        """
        Create a new user account.
        
        Returns:
            (success, user_object, message)
        """
        db_session = self.Session()
        try:
            # Check if username or email already exists
            existing_user = db_session.query(User).filter(
                (User.username == user_data['username']) | 
                (User.email == user_data['email'])
            ).first()
            
            if existing_user:
                return False, None, "Username or email already exists"
            
            # Create new user
            user = User(
                user_id=str(uuid.uuid4()),
                username=user_data['username'],
                email=user_data['email'],
                full_name=user_data['full_name'],
                department=user_data.get('department'),
                phone=user_data.get('phone'),
                role=user_data.get('role', UserRole.VIEWER.value),
                status=user_data.get('status', UserStatus.ACTIVE.value),
                created_by=created_by
            )
            
            # Set password
            user.set_password(user_data['password'])
            
            # Force password change if specified
            if user_data.get('force_password_change'):
                user.force_password_change = True
            
            db_session.add(user)
            db_session.commit()
            
            return True, user, "User created successfully"
            
        except IntegrityError:
            db_session.rollback()
            return False, None, "User already exists"
        except Exception as e:
            db_session.rollback()
            return False, None, f"Error creating user: {str(e)}"
        finally:
            db_session.close()
    
    def update_user(self, user_id: int, updates: Dict[str, Any], updated_by: str = None) -> Tuple[bool, Optional[User], str]:
        """
        Update user information.
        
        Returns:
            (success, user_object, message)
        """
        db_session = self.Session()
        try:
            user = db_session.query(User).filter_by(id=user_id).first()
            
            if not user:
                return False, None, "User not found"
            
            # Update allowed fields
            allowed_fields = [
                'full_name', 'email', 'department', 'phone', 'role', 
                'status', 'is_active', 'permissions'
            ]
            
            for field in allowed_fields:
                if field in updates:
                    setattr(user, field, updates[field])
            
            # Handle password update
            if 'password' in updates:
                user.set_password(updates['password'])
                user.force_password_change = False
                # Clear login attempts on successful password change
                user.reset_login_attempts()
            
            user.updated_at = datetime.now(timezone.utc)
            db_session.commit()
            
            return True, user, "User updated successfully"
            
        except Exception as e:
            db_session.rollback()
            return False, None, f"Error updating user: {str(e)}"
        finally:
            db_session.close()
    
    def get_user(self, user_id: int = None, username: str = None, email: str = None) -> Optional[User]:
        """Get user by ID, username, or email."""
        db_session = self.Session()
        try:
            query = db_session.query(User)
            
            if user_id:
                return query.filter_by(id=user_id).first()
            elif username:
                return query.filter_by(username=username).first()
            elif email:
                return query.filter_by(email=email).first()
            
            return None
            
        finally:
            db_session.close()
    
    def list_users(self, limit: int = 100, offset: int = 0) -> list[User]:
        """List all users with pagination."""
        db_session = self.Session()
        try:
            return db_session.query(User).offset(offset).limit(limit).all()
        finally:
            db_session.close()
    
    def delete_user(self, user_id: int) -> Tuple[bool, str]:
        """Delete user account."""
        db_session = self.Session()
        try:
            user = db_session.query(User).filter_by(id=user_id).first()
            
            if not user:
                return False, "User not found"
            
            # Invalidate all user sessions
            sessions = db_session.query(UserSession).filter_by(user_id=user_id).all()
            for session_obj in sessions:
                session_obj.invalidate("user_deleted")
            
            # Delete user (cascade will handle sessions and API keys)
            db_session.delete(user)
            db_session.commit()
            
            return True, "User deleted successfully"
            
        except Exception as e:
            db_session.rollback()
            return False, f"Error deleting user: {str(e)}"
        finally:
            db_session.close()
    
    def create_default_admin(self) -> Tuple[bool, str]:
        """Create default admin user if no users exist."""
        db_session = self.Session()
        try:
            # Check if any users exist
            user_count = db_session.query(User).count()
            
            if user_count > 0:
                return False, "Users already exist"
            
            # Create default admin
            admin_password = secrets.token_urlsafe(12)  # Generate random password
            
            admin = User(
                user_id=str(uuid.uuid4()),
                username="admin",
                email="admin@qpki.local",
                full_name="System Administrator",
                role=UserRole.ADMIN.value,
                status=UserStatus.ACTIVE.value,
                force_password_change=True,
                created_by="system"
            )
            
            admin.set_password(admin_password)
            
            db_session.add(admin)
            db_session.commit()
            
            return True, f"Default admin created. Username: admin, Password: {admin_password}"
            
        except Exception as e:
            db_session.rollback()
            return False, f"Error creating default admin: {str(e)}"
        finally:
            db_session.close()
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        db_session = self.Session()
        try:
            expired_sessions = db_session.query(UserSession).filter(
                UserSession.expires_at < datetime.now(timezone.utc),
                UserSession.is_active == True
            ).all()
            
            count = len(expired_sessions)
            
            for session_obj in expired_sessions:
                session_obj.invalidate("expired")
            
            db_session.commit()
            
            return count
            
        except Exception as e:
            current_app.logger.error(f"Error cleaning up sessions: {e}")
            return 0
        finally:
            db_session.close()


def has_permission(user_data: dict, permission: str) -> bool:
    """Check if user has specific permission based on user data dictionary."""
    # Admin has all permissions
    if user_data.get('role') == UserRole.ADMIN.value:
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
    
    if permission in role_permissions.get(user_data.get('role'), []):
        return True
    
    # Check granular permissions
    user_permissions = user_data.get('permissions')
    if user_permissions and permission in user_permissions:
        return user_permissions[permission]
    
    return False


def login_required(permission: str = None):
    """
    Decorator to require authentication and optionally check permissions.
    
    Args:
        permission: Optional permission string to check
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import redirect, url_for, flash, g
            
            # Check if user is authenticated
            auth_manager = current_app.auth_manager
            valid, user = auth_manager.validate_session()
            
            if not valid or not user:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            # Store user in g for use in templates and views
            g.current_user = user
            
            # Check permission if specified
            if permission and not has_permission(user, permission):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin role."""
    return login_required()(f)  # Admin has all permissions by default
