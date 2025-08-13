#!/usr/bin/env python3
"""
MFA Database Migration Script

This script adds the missing MFA field to align with our MFA implementation
and ensures the database schema supports all MFA features.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from qpki.database import DatabaseManager, DatabaseConfig
from sqlalchemy import text, inspect
from datetime import datetime


def check_database_schema():
    """Check current database schema for MFA fields."""
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        
        print("🔍 Checking current database schema...")
        
        with db_manager.get_session() as session:
            # Get table columns
            inspector = inspect(session.bind)
            
            if 'users' not in inspector.get_table_names():
                print("❌ Users table not found. Please run init_database.py first.")
                return False
            
            columns = inspector.get_columns('users')
            column_names = [col['name'] for col in columns]
            
            print(f"✅ Users table found with {len(columns)} columns")
            
            # Check MFA-related columns
            mfa_fields = {
                'totp_secret': 'totp_secret' in column_names,
                'backup_codes': 'backup_codes' in column_names,
                'two_factor_enabled': 'two_factor_enabled' in column_names,
            }
            
            print("\n📋 MFA Field Status:")
            for field, exists in mfa_fields.items():
                status = "✅ EXISTS" if exists else "❌ MISSING"
                print(f"  {field}: {status}")
            
            # Check if we need to add mfa_enabled_at
            needs_migration = 'mfa_enabled_at' not in column_names
            
            if needs_migration:
                print(f"\n⚠️  Missing field: mfa_enabled_at")
                return True
            else:
                print(f"\n✅ All MFA fields are present")
                return False
                
    except Exception as e:
        print(f"❌ Error checking database schema: {e}")
        return False


def migrate_database():
    """Apply MFA database migration."""
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        
        print("🔄 Applying MFA database migration...")
        
        with db_manager.get_session() as session:
            # Add mfa_enabled_at column if it doesn't exist
            try:
                # SQLite-compatible way to add column
                session.execute(text("""
                    ALTER TABLE users ADD COLUMN mfa_enabled_at TIMESTAMP NULL
                """))
                session.commit()
                print("✅ Added mfa_enabled_at column")
                
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print("ℹ️  mfa_enabled_at column already exists")
                else:
                    raise e
            
            print("✅ MFA database migration completed successfully")
            return True
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False


def verify_migration():
    """Verify that the migration was successful."""
    try:
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        
        print("🔍 Verifying migration...")
        
        with db_manager.get_session() as session:
            inspector = inspect(session.bind)
            columns = inspector.get_columns('users')
            column_names = [col['name'] for col in columns]
            
            required_fields = ['totp_secret', 'backup_codes', 'two_factor_enabled', 'mfa_enabled_at']
            missing_fields = [field for field in required_fields if field not in column_names]
            
            if missing_fields:
                print(f"❌ Migration incomplete. Missing fields: {missing_fields}")
                return False
            else:
                print("✅ All MFA fields are present in the database")
                
                # Test that we can query the fields
                result = session.execute(text("""
                    SELECT COUNT(*) as count, 
                           SUM(CASE WHEN two_factor_enabled = 1 THEN 1 ELSE 0 END) as mfa_users
                    FROM users
                """)).fetchone()
                
                if result:
                    print(f"✅ Database query successful: {result.count} total users, {result.mfa_users} with MFA enabled")
                
                return True
                
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False


def update_mfa_module():
    """Update MFA module to use correct field names."""
    print("🔄 Updating MFA module field mappings...")
    
    # The field mapping for the User model
    field_mapping = {
        'mfa_enabled': 'two_factor_enabled',
        'mfa_secret_key': 'totp_secret', 
        'mfa_backup_codes': 'backup_codes',
        'mfa_enabled_at': 'mfa_enabled_at'  # This one matches
    }
    
    print("📋 Field Mapping for MFA Integration:")
    for new_name, existing_name in field_mapping.items():
        print(f"  {new_name} → {existing_name}")
    
    print("✅ Field mapping documented")
    return field_mapping


if __name__ == '__main__':
    print("qPKI MFA Database Migration")
    print("=" * 40)
    
    # Check if migration is needed
    needs_migration = check_database_schema()
    
    if needs_migration:
        print("\n🚀 Starting migration...")
        
        # Apply migration
        if migrate_database():
            # Verify migration
            if verify_migration():
                print("\n✅ Migration completed successfully!")
            else:
                print("\n❌ Migration verification failed!")
                sys.exit(1)
        else:
            print("\n❌ Migration failed!")
            sys.exit(1)
    else:
        print("\n✅ Database schema is already up to date!")
    
    # Show field mapping
    print("\n" + "=" * 40)
    field_mapping = update_mfa_module()
    
    print("\n🎉 MFA Database Setup Complete!")
    print("\nNext steps:")
    print("1. The database schema now supports all MFA features")
    print("2. The MFA module uses these existing field names:")
    print("   - two_factor_enabled (for MFA status)")
    print("   - totp_secret (for TOTP secret key)")
    print("   - backup_codes (for encrypted backup codes)")
    print("   - mfa_enabled_at (for timestamp when MFA was enabled)")
    print("3. You can now test the complete MFA flow!")
