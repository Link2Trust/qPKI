"""
Gunicorn configuration for qPKI production deployment
"""
import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('WEB_PORT', 9090)}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = os.environ.get('GUNICORN_WORKER_CLASS', 'sync')
worker_connections = 1000
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 120))
keepalive = int(os.environ.get('GUNICORN_KEEPALIVE', 5))
max_requests = 1000
max_requests_jitter = 50

# Application
wsgi_module = 'app_production:create_app()'
pythonpath = '/opt/qpki'
chdir = '/opt/qpki'

# Security
user = 'qpki'
group = 'qpki'
umask = 0o027
tmp_upload_dir = '/opt/qpki/tmp'

# Logging
accesslog = '/opt/qpki/logs/access.log'
errorlog = '/opt/qpki/logs/error.log'
loglevel = os.environ.get('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Logging configuration
logconfig_dict = {
    'version': 1,
    'disable_existing_loggers': False,
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file']
    },
    'loggers': {
        'gunicorn.error': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
            'qualname': 'gunicorn.error'
        },
        'gunicorn.access': {
            'level': 'INFO',
            'handlers': ['console', 'access_file'],
            'propagate': False,
            'qualname': 'gunicorn.access'
        },
        'qpki': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
            'qualname': 'qpki'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'generic',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'generic',
            'filename': '/opt/qpki/logs/qpki.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10
        },
        'access_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'access',
            'filename': '/opt/qpki/logs/access.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10
        }
    },
    'formatters': {
        'generic': {
            'format': '%(asctime)s [%(process)d] [%(levelname)s] %(name)s: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
            'class': 'logging.Formatter'
        },
        'access': {
            'format': '%(message)s',
            'class': 'logging.Formatter'
        }
    }
}

# Process naming
proc_name = 'qpki-gunicorn'

# SSL/TLS (if terminating SSL at Gunicorn level)
# keyfile = '/path/to/private.key'
# certfile = '/path/to/certificate.crt'
# ssl_version = 2  # TLS 1.2
# ciphers = 'HIGH:!aNULL:!MD5:!DSS:!RC4'

# Preload application for better performance
preload_app = True

# Restart workers after this many requests (helps prevent memory leaks)
max_requests = 1000
max_requests_jitter = 100

# Graceful timeout
graceful_timeout = 30

# Environment variables
raw_env = [
    'FLASK_ENV=production',
    'PYTHONPATH=/opt/qpki/src',
]

# Server mechanics
daemon = False  # Set to True to run as daemon
pidfile = '/opt/qpki/run/gunicorn.pid'

# Worker process initialization
def when_ready(server):
    """Called when the server is ready to serve requests"""
    server.log.info("qPKI server is ready. Listening on %s", server.address)

def worker_int(worker):
    """Called when a worker receives the SIGINT or SIGQUIT signal"""
    worker.log.info("worker received INT or QUIT signal")

def on_starting(server):
    """Called when the master process is initialized"""
    server.log.info("Starting qPKI server...")

def on_reload(server):
    """Called during reload"""
    server.log.info("Reloading qPKI server...")

def on_exit(server):
    """Called when gunicorn is shutting down"""
    server.log.info("Shutting down qPKI server...")

# Security checks
def post_fork(server, worker):
    """Called after a worker has been forked"""
    server.log.info("Worker spawned (pid: %s)", worker.pid)
    
    # Set up signal handlers, initialize connections, etc.
    import signal
    
    def worker_abort(signum, frame):
        server.log.info("Worker received abort signal")
        
    signal.signal(signal.SIGABRT, worker_abort)
