#!/usr/bin/env python3
"""
Password reset utility for qPKI application.
Allows resetting passwords for any user.
"""

import os
import sys
import secrets
import argparse

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.qpki.database import DatabaseManager, DatabaseConfig
from src.qpki.auth import AuthenticationManager

def reset_user_password(username, new_password=None, force_change=False):
    """Reset password for a specific user"""
    try:
        # Initialize database
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        
        if not db_manager.check_connection():
            print("❌ Could not connect to database")
            return False
        
        # Initialize authentication manager
        auth_manager = AuthenticationManager(db_manager)
        
        # Get the user
        user = auth_manager.get_user(username=username)
        
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        # Generate new password if not provided
        if not new_password:
            new_password = secrets.token_urlsafe(16)
        
        # Update the user's password
        success, updated_user, message = auth_manager.update_user(
            user.id,
            {
                'password': new_password,
                'force_password_change': force_change
            },
            'password_reset_utility'
        )
        
        if success:
            print(f"✅ Password reset successfully for user '{username}'!")
            print(f"New Password: {new_password}")
            if force_change:
                print("⚠️  User will be required to change password on next login.")
            else:
                print("✓ User can use this password immediately.")
            return True
        else:
            print(f"❌ Failed to reset password: {message}")
            return False
            
    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        return False

def list_users():
    """List all users in the system"""
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        auth_manager = AuthenticationManager(db_manager)
        
        from src.qpki.auth.models import User
        from sqlalchemy.orm import sessionmaker
        
        Session = sessionmaker(bind=db_manager.engine)
        db_session = Session()
        
        try:
            users = db_session.query(User).all()
            
            if not users:
                print("No users found in database")
                return
            
            print(f"Found {len(users)} users:")
            print("-" * 60)
            for user in users:
                status = "Active" if user.is_active else "Inactive"
                force_change = "Yes" if user.force_password_change else "No"
                print(f"Username: {user.username:15} Role: {user.role:10} Status: {status:8} Force Change: {force_change}")
                
        finally:
            db_session.close()
            
    except Exception as e:
        print(f"❌ Error listing users: {e}")

def main():
    parser = argparse.ArgumentParser(description='qPKI Password Reset Utility')
    parser.add_argument('--list', action='store_true', help='List all users')
    parser.add_argument('--username', '-u', help='Username to reset password for')
    parser.add_argument('--password', '-p', help='New password (auto-generated if not provided)')
    parser.add_argument('--force-change', '-f', action='store_true', 
                       help='Force user to change password on next login')
    
    args = parser.parse_args()
    
    if args.list:
        list_users()
        return
    
    if not args.username:
        print("❌ Username is required. Use --username or -u")
        print("Use --list to see all users")
        sys.exit(1)
    
    reset_user_password(args.username, args.password, args.force_change)

if __name__ == "__main__":
    main()
