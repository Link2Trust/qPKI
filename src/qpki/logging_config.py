#!/usr/bin/env python3
"""
qPKI Logging Configuration

Centralized logging configuration for the qPKI system.
Provides structured logging to file and console with different levels.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import json


class JSONFormatter(logging.Formatter):
    """Custom formatter to output logs in JSON format for structured logging."""
    
    def format(self, record):
        # Create base log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add thread and process info if available
        if hasattr(record, 'thread'):
            log_entry['thread_id'] = record.thread
        if hasattr(record, 'process'):
            log_entry['process_id'] = record.process
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'message']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


def setup_logging(
    log_level: str = "INFO",
    log_file: str = None,
    log_dir: str = "logs",
    max_file_size: int = 50 * 1024 * 1024,  # 50MB
    backup_count: int = 10,
    json_format: bool = False,
    console_output: bool = True
):
    """
    Setup centralized logging for qPKI.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Name of the log file (default: qpki_YYYYMMDD.log)
        log_dir: Directory to store log files
        max_file_size: Maximum size of each log file before rotation
        backup_count: Number of backup files to keep
        json_format: Whether to use JSON formatting
        console_output: Whether to output to console as well
    
    Returns:
        Logger instance
    """
    
    # Create logs directory if it doesn't exist
    log_dir = Path(log_dir)
    log_dir.mkdir(exist_ok=True)
    
    # Generate default log file name if not provided
    if not log_file:
        date_str = datetime.now().strftime("%Y%m%d")
        log_file = f"qpki_{date_str}.log"
    
    log_file_path = log_dir / log_file
    
    # Configure root logger
    logger = logging.getLogger('qpki')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=max_file_size,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    # Choose formatter
    if json_format:
        file_formatter = JSONFormatter()
    else:
        file_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-20s:%(lineno)-4d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(getattr(logging, log_level.upper()))
    logger.addHandler(file_handler)
    
    # Console handler (optional)
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)  # Console shows INFO and above
        logger.addHandler(console_handler)
    
    # Log the logging setup
    logger.info("qPKI Logging System Initialized", extra={
        'log_level': log_level,
        'log_file': str(log_file_path),
        'max_file_size': max_file_size,
        'backup_count': backup_count,
        'json_format': json_format,
        'console_output': console_output
    })
    
    return logger


def get_logger(name: str = None):
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f'qpki.{name}')
    return logging.getLogger('qpki')


def log_function_call(func):
    """
    Decorator to log function calls with parameters and return values.
    
    Usage:
        @log_function_call
        def my_function(param1, param2):
            return result
    """
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        
        # Log function entry
        logger.debug(f"Entering {func.__name__}", extra={
            'function': func.__name__,
            'args': str(args) if args else None,
            'kwargs': str(kwargs) if kwargs else None,
            'action': 'function_entry'
        })
        
        try:
            # Execute function
            result = func(*args, **kwargs)
            
            # Log successful completion
            logger.debug(f"Completed {func.__name__}", extra={
                'function': func.__name__,
                'result_type': type(result).__name__,
                'action': 'function_exit'
            })
            
            return result
            
        except Exception as e:
            # Log exception
            logger.error(f"Exception in {func.__name__}: {e}", extra={
                'function': func.__name__,
                'exception_type': type(e).__name__,
                'action': 'function_error'
            }, exc_info=True)
            raise
    
    return wrapper


def log_activity(logger, activity_type: str, details: dict = None, level: str = "INFO"):
    """
    Log a structured activity with consistent format.
    
    Args:
        logger: Logger instance
        activity_type: Type of activity (e.g., 'certificate_created', 'email_sent', etc.)
        details: Dictionary of additional details
        level: Log level
    """
    extra_data = {
        'activity_type': activity_type,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if details:
        extra_data.update(details)
    
    message = f"Activity: {activity_type}"
    if details and 'description' in details:
        message += f" - {details['description']}"
    
    log_level = getattr(logging, level.upper())
    logger.log(log_level, message, extra=extra_data)


# Pre-configured loggers for different components
def get_web_logger():
    """Get logger for web application."""
    return get_logger('web')


def get_crypto_logger():
    """Get logger for cryptographic operations."""
    return get_logger('crypto')


def get_email_logger():
    """Get logger for email operations."""
    return get_logger('email')


def get_database_logger():
    """Get logger for database operations."""
    return get_logger('database')


def get_cli_logger():
    """Get logger for CLI operations."""
    return get_logger('cli')


if __name__ == '__main__':
    # Test the logging system
    logger = setup_logging(log_level="DEBUG", json_format=True)
    
    logger.info("Testing qPKI logging system")
    logger.debug("This is a debug message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test activity logging
    log_activity(logger, "system_test", {
        'description': 'Testing logging configuration',
        'component': 'logging_config',
        'test_result': 'success'
    })
    
    print("Logging test completed. Check logs directory for output.")
