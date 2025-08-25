"""
Demo Database Router

This module provides functionality to route demo users to a separate database
to prevent them from accessing production data.
"""

import os
from typing import Optional, Dict, Any
from .config import DatabaseConfig
from .manager import DatabaseManager


class DemoRouter:
    """Routes database operations for demo users to separate database."""
    
    def __init__(self):
        self.production_db = None
        self.demo_db = None
        self.demo_users = {'demo', 'admin'}  # Users that should use demo DB
        
    def get_database_manager(self, username: Optional[str] = None) -> DatabaseManager:
        """
        Get appropriate database manager based on username.
        
        Args:
            username: The username to check for demo routing
            
        Returns:
            DatabaseManager: Appropriate database manager
        """
        if username and username.lower() in self.demo_users:
            return self.get_demo_database()
        else:
            return self.get_production_database()
    
    def get_production_database(self) -> DatabaseManager:
        """Get production database manager."""
        if self.production_db is None:
            config = self._get_production_config()
            self.production_db = DatabaseManager(config)
        return self.production_db
    
    def get_demo_database(self) -> DatabaseManager:
        """Get demo database manager."""
        if self.demo_db is None:
            config = self._get_demo_config()
            self.demo_db = DatabaseManager(config)
        return self.demo_db
    
    def _get_production_config(self) -> DatabaseConfig:
        """Get production database configuration."""
        config = DatabaseConfig()
        
        # Check if we're in production environment
        if os.getenv('FLASK_ENV') == 'production':
            # Use PostgreSQL for production
            config.db_type = 'postgresql'
            config.host = 'localhost'
            config.port = 5432
            config.database = 'qpki_production'
            config.username = 'qpki_user'
            config.password = os.getenv('POSTGRES_PASSWORD', '')
        else:
            # Use SQLite for development
            config.db_type = 'sqlite'
            config.database = 'qpki'  # This will be the main SQLite file
            
        return config
    
    def _get_demo_config(self) -> DatabaseConfig:
        """Get demo database configuration."""
        config = DatabaseConfig()
        config.db_type = 'sqlite'
        config.database = 'qpki_demo'  # Always use SQLite for demo
        return config
    
    def is_demo_user(self, username: str) -> bool:
        """Check if a username is a demo user."""
        return username.lower() in self.demo_users
    
    def add_demo_user(self, username: str):
        """Add a username to the demo users list."""
        self.demo_users.add(username.lower())
    
    def remove_demo_user(self, username: str):
        """Remove a username from the demo users list."""
        self.demo_users.discard(username.lower())
    
    def get_demo_users(self) -> set:
        """Get the set of demo users."""
        return self.demo_users.copy()


# Global instance
demo_router = DemoRouter()


def get_database_for_user(username: Optional[str] = None) -> DatabaseManager:
    """
    Convenience function to get database manager for a user.
    
    Args:
        username: The username to route
        
    Returns:
        DatabaseManager: Appropriate database manager
    """
    return demo_router.get_database_manager(username)


def is_demo_user(username: str) -> bool:
    """
    Check if a user is a demo user.
    
    Args:
        username: Username to check
        
    Returns:
        bool: True if demo user, False otherwise
    """
    return demo_router.is_demo_user(username)
