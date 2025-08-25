"""
Demo-aware Authentication Wrapper

This module wraps the standard authentication to route demo users
to a separate database.
"""

from typing import Optional, Tuple, Dict, Any
from flask import session, current_app
from .auth_manager import AuthenticationManager
from ..database.demo_router import get_database_for_user, is_demo_user


class DemoAwareAuthManager:
    """Authentication manager that routes demo users to separate database."""
    
    def __init__(self, production_db_manager, demo_db_manager=None):
        self.production_auth = AuthenticationManager(production_db_manager)
        self.demo_auth = None
        self.demo_db_manager = demo_db_manager
    
    def _get_demo_auth(self):
        """Lazy initialization of demo auth manager."""
        if self.demo_auth is None and self.demo_db_manager:
            self.demo_auth = AuthenticationManager(self.demo_db_manager)
        return self.demo_auth
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, Optional[dict], str]:
        """
        Authenticate user with automatic routing to appropriate database.
        
        Args:
            username: Username or email
            password: User password
            ip_address: Client IP address
            
        Returns:
            (success, user_data_dict, message)
        """
        # Check if this is a demo user
        if is_demo_user(username):
            print(f"[DEBUG] Routing demo user '{username}' to demo database")
            demo_auth = self._get_demo_auth()
            if demo_auth:
                success, user_data, message = demo_auth.authenticate_user(username, password, ip_address)
                if success:
                    # Mark session as demo
                    session['is_demo_user'] = True
                    session['demo_username'] = username
                return success, user_data, message
            else:
                return False, None, "Demo authentication not available"
        else:
            print(f"[DEBUG] Routing production user '{username}' to production database")
            # Production user authentication
            session['is_demo_user'] = False
            return self.production_auth.authenticate_user(username, password, ip_address)
    
    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Get user by ID, routing to appropriate database."""
        # Check if current session is demo
        if session.get('is_demo_user', False):
            demo_auth = self._get_demo_auth()
            if demo_auth:
                return demo_auth.get_user_by_id(user_id)
        else:
            return self.production_auth.get_user_by_id(user_id)
        return None
    
    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username, routing to appropriate database."""
        if is_demo_user(username):
            demo_auth = self._get_demo_auth()
            if demo_auth:
                return demo_auth.get_user_by_username(username)
        else:
            return self.production_auth.get_user_by_username(username)
        return None
    
    def create_user(self, user_data: dict, created_by: str = None) -> Tuple[bool, Optional[dict], str]:
        """Create user in appropriate database."""
        username = user_data.get('username', '')
        
        if is_demo_user(username):
            demo_auth = self._get_demo_auth()
            if demo_auth:
                return demo_auth.create_user(user_data, created_by)
            else:
                return False, None, "Demo database not available"
        else:
            return self.production_auth.create_user(user_data, created_by)
    
    def update_user(self, user_id: int, updates: dict, updated_by: str = None) -> Tuple[bool, str]:
        """Update user in appropriate database."""
        # Check if current session is demo
        if session.get('is_demo_user', False):
            demo_auth = self._get_demo_auth()
            if demo_auth:
                return demo_auth.update_user(user_id, updates, updated_by)
        else:
            return self.production_auth.update_user(user_id, updates, updated_by)
        return False, "Authentication manager not available"
    
    def get_current_auth_manager(self):
        """Get the appropriate auth manager for current session."""
        if session.get('is_demo_user', False):
            return self._get_demo_auth()
        else:
            return self.production_auth
    
    def is_current_user_demo(self) -> bool:
        """Check if current user is a demo user."""
        return session.get('is_demo_user', False)
    
    def get_database_info(self) -> dict:
        """Get information about which database is being used."""
        is_demo = session.get('is_demo_user', False)
        return {
            'is_demo': is_demo,
            'database_type': 'demo' if is_demo else 'production',
            'demo_username': session.get('demo_username', '') if is_demo else None
        }
    
    # Delegate other methods to production auth manager by default
    def __getattr__(self, name):
        """Delegate unknown methods to appropriate auth manager."""
        if session.get('is_demo_user', False):
            demo_auth = self._get_demo_auth()
            if demo_auth and hasattr(demo_auth, name):
                return getattr(demo_auth, name)
        
        if hasattr(self.production_auth, name):
            return getattr(self.production_auth, name)
        
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
