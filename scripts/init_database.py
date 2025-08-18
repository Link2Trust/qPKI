#!/usr/bin/env python3
"""
Database Initialization Script for qPKI

This script initializes the database, creates tables, and sets up the default admin user.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from qpki.database import DatabaseManager, DatabaseConfig
from qpki.auth import AuthenticationManager, UserRole
from qpki.auth.models import Base


def initialize_database():
    """Initialize the database and create all tables."""
    try:
        # Get database configuration from environment or use defaults
        db_config = DatabaseConfig.from_env()
        
        print(f"Initializing database: {db_config.database_url}")
        
        # Create database manager
        db_manager = DatabaseManager(db_config)
        
        # Create all tables
        print("Creating database tables...")
        db_manager.create_tables()
        print("✓ Database tables created successfully")
        
        # Initialize authentication manager
        auth_manager = AuthenticationManager(db_manager)
        
        # Create default admin user if no users exist
        print("Checking for existing users...")
        success, message = auth_manager.create_default_admin()
        
        if success:
            print(f"✓ {message}")
        else:
            print(f"ℹ {message}")
        
        # Test database connection
        if db_manager.check_connection():
            print("✓ Database connection test successful")
        else:
            print("✗ Database connection test failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False


def create_sample_users():
    """Create sample users for testing (optional)."""
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        auth_manager = AuthenticationManager(db_manager)
        
        sample_users = [
            {
                'username': 'operator',
                'email': 'operator@qpki.local',
                'full_name': 'PKI Operator',
                'role': UserRole.OPERATOR.value,
                'password': 'SecureOperator123!'
            },
            {
                'username': 'auditor',
                'email': 'auditor@qpki.local', 
                'full_name': 'Security Auditor',
                'role': UserRole.AUDITOR.value,
                'password': 'SecureAuditor123!'
            },
            {
                'username': 'viewer',
                'email': 'viewer@qpki.local',
                'full_name': 'Certificate Viewer',
                'role': UserRole.VIEWER.value,
                'password': 'SecureViewer123!'
            }
        ]
        
        print("\nCreating sample users...")
        for user_data in sample_users:
            success, user, message = auth_manager.create_user(user_data, 'system')
            if success:
                print(f"✓ Created user: {user.username} ({user.role})")
            else:
                print(f"ℹ User {user_data['username']} already exists")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to create sample users: {e}")
        return False


if __name__ == '__main__':
    print("qPKI Database Initialization")
    print("=" * 40)
    
    # Initialize database and create tables
    if not initialize_database():
        sys.exit(1)
    
    # Ask if user wants to create sample users
    if len(sys.argv) > 1 and sys.argv[1] == '--sample-users':
        create_sample_users()
    else:
        print("\nTo create sample users, run:")
        print("python scripts/init_database.py --sample-users")
    
    print("\n✓ Database initialization complete!")
    print("\nNext steps:")
    print("1. Set environment variables for database connection if needed")
    print("2. Start the application: python app.py")
    print("3. Access the login page: http://localhost:9090/auth/login")
