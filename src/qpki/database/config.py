"""
Database Configuration Management

Handles database connection settings and environment-based configuration.
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import quote_plus


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    
    # Database type (postgresql, mysql, sqlite)
    db_type: str = "postgresql"
    
    # Connection settings
    host: str = "localhost"
    port: int = 5432
    database: str = "qpki"
    username: str = "qpki"
    password: str = ""
    
    # Connection pool settings
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    # SSL settings
    ssl_mode: str = "prefer"  # disable, allow, prefer, require, verify-ca, verify-full
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_ca: Optional[str] = None
    
    # Application settings
    echo_queries: bool = False
    auto_migrate: bool = True
    backup_enabled: bool = True
    backup_interval_hours: int = 24
    
    @classmethod
    def from_env(cls) -> 'DatabaseConfig':
        """Create configuration from environment variables."""
        
        # Determine database type
        db_type = os.getenv('QPKI_DB_TYPE', 'postgresql').lower()
        
        # Set default ports based on database type
        default_ports = {
            'postgresql': 5432,
            'mysql': 3306,
            'sqlite': 0
        }
        
        return cls(
            db_type=db_type,
            host=os.getenv('QPKI_DB_HOST', 'localhost'),
            port=int(os.getenv('QPKI_DB_PORT', default_ports.get(db_type, 5432))),
            database=os.getenv('QPKI_DB_NAME', 'qpki'),
            username=os.getenv('QPKI_DB_USER', 'qpki'),
            password=os.getenv('QPKI_DB_PASSWORD', ''),
            pool_size=int(os.getenv('QPKI_DB_POOL_SIZE', 10)),
            max_overflow=int(os.getenv('QPKI_DB_MAX_OVERFLOW', 20)),
            pool_timeout=int(os.getenv('QPKI_DB_POOL_TIMEOUT', 30)),
            pool_recycle=int(os.getenv('QPKI_DB_POOL_RECYCLE', 3600)),
            ssl_mode=os.getenv('QPKI_DB_SSL_MODE', 'prefer'),
            ssl_cert=os.getenv('QPKI_DB_SSL_CERT'),
            ssl_key=os.getenv('QPKI_DB_SSL_KEY'),
            ssl_ca=os.getenv('QPKI_DB_SSL_CA'),
            echo_queries=os.getenv('QPKI_DB_ECHO', 'false').lower() == 'true',
            auto_migrate=os.getenv('QPKI_DB_AUTO_MIGRATE', 'true').lower() == 'true',
            backup_enabled=os.getenv('QPKI_DB_BACKUP_ENABLED', 'true').lower() == 'true',
            backup_interval_hours=int(os.getenv('QPKI_DB_BACKUP_INTERVAL', 24))
        )
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'DatabaseConfig':
        """Create configuration from dictionary."""
        return cls(**config_dict)
    
    def get_connection_url(self) -> str:
        """Generate database connection URL."""
        
        if self.db_type == 'sqlite':
            return f"sqlite:///{self.database}"
        
        # URL encode password to handle special characters
        encoded_password = quote_plus(self.password) if self.password else ""
        
        # Build connection URL
        if self.db_type == 'postgresql':
            driver = "postgresql+psycopg2"
        elif self.db_type == 'mysql':
            driver = "mysql+pymysql"
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
        
        # Base URL
        if encoded_password:
            url = f"{driver}://{self.username}:{encoded_password}@{self.host}:{self.port}/{self.database}"
        else:
            url = f"{driver}://{self.username}@{self.host}:{self.port}/{self.database}"
        
        # Add SSL parameters for PostgreSQL
        if self.db_type == 'postgresql' and self.ssl_mode != 'disable':
            ssl_params = [f"sslmode={self.ssl_mode}"]
            
            if self.ssl_cert:
                ssl_params.append(f"sslcert={self.ssl_cert}")
            if self.ssl_key:
                ssl_params.append(f"sslkey={self.ssl_key}")
            if self.ssl_ca:
                ssl_params.append(f"sslrootcert={self.ssl_ca}")
            
            url += "?" + "&".join(ssl_params)
        
        # Add SSL parameters for MySQL
        elif self.db_type == 'mysql' and self.ssl_mode != 'disable':
            ssl_params = []
            
            if self.ssl_ca:
                ssl_params.append(f"ssl_ca={self.ssl_ca}")
            if self.ssl_cert:
                ssl_params.append(f"ssl_cert={self.ssl_cert}")
            if self.ssl_key:
                ssl_params.append(f"ssl_key={self.ssl_key}")
            
            if ssl_params:
                url += "?" + "&".join(ssl_params)
        
        return url
    
    def get_engine_kwargs(self) -> Dict[str, Any]:
        """Get SQLAlchemy engine configuration."""
        kwargs = {
            'echo': self.echo_queries,
            'pool_size': self.pool_size,
            'max_overflow': self.max_overflow,
            'pool_timeout': self.pool_timeout,
            'pool_recycle': self.pool_recycle,
        }
        
        # SQLite doesn't support connection pooling
        if self.db_type == 'sqlite':
            kwargs = {'echo': self.echo_queries}
        
        return kwargs
    
    def validate(self) -> bool:
        """Validate configuration settings."""
        
        # Check required fields
        if not self.database:
            raise ValueError("Database name is required")
        
        if self.db_type not in ['postgresql', 'mysql', 'sqlite']:
            raise ValueError(f"Unsupported database type: {self.db_type}")
        
        if self.db_type != 'sqlite':
            if not self.host:
                raise ValueError("Database host is required")
            if not self.username:
                raise ValueError("Database username is required")
            if self.port <= 0 or self.port > 65535:
                raise ValueError("Invalid database port")
        
        # Validate SSL settings
        if self.ssl_mode not in ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']:
            raise ValueError(f"Invalid SSL mode: {self.ssl_mode}")
        
        # Validate pool settings
        if self.pool_size <= 0:
            raise ValueError("Pool size must be positive")
        if self.max_overflow < 0:
            raise ValueError("Max overflow cannot be negative")
        if self.pool_timeout <= 0:
            raise ValueError("Pool timeout must be positive")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'db_type': self.db_type,
            'host': self.host,
            'port': self.port,
            'database': self.database,
            'username': self.username,
            'password': self.password,
            'pool_size': self.pool_size,
            'max_overflow': self.max_overflow,
            'pool_timeout': self.pool_timeout,
            'pool_recycle': self.pool_recycle,
            'ssl_mode': self.ssl_mode,
            'ssl_cert': self.ssl_cert,
            'ssl_key': self.ssl_key,
            'ssl_ca': self.ssl_ca,
            'echo_queries': self.echo_queries,
            'auto_migrate': self.auto_migrate,
            'backup_enabled': self.backup_enabled,
            'backup_interval_hours': self.backup_interval_hours
        }


def load_config(config_file: Optional[str] = None) -> DatabaseConfig:
    """Load database configuration from file or environment."""
    
    if config_file and os.path.exists(config_file):
        import json
        with open(config_file, 'r') as f:
            config_dict = json.load(f)
        return DatabaseConfig.from_dict(config_dict)
    else:
        return DatabaseConfig.from_env()


def save_config(config: DatabaseConfig, config_file: str) -> bool:
    """Save database configuration to file."""
    
    try:
        import json
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
        
        return True
    except Exception:
        return False
