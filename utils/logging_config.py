import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler

def setup_logging(log_level=logging.INFO):
    """Setup application-wide logging configuration"""
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Console handler with color formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S%f'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler with rotation
    log_file = os.path.join(log_dir, f"scanner_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S%f'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

def get_logger(name):
    """Get a logger with the specified name"""
    return logging.getLogger(name)

def get_component_logger(component_name, include_id=False):
    """Get a logger for a specific component with optional ID inclusion"""
    logger_name = f"subdomain_scanner.{component_name}"
    if include_id:
        logger_name = f"{logger_name}.{id}"
    return logging.getLogger(logger_name)

# Configure logging levels for different components
logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

# Custom log levels for different types of discoveries
DISCOVERY = 25  # Between INFO and WARNING
logging.addLevelName(DISCOVERY, 'DISCOVERY')

def discovery(self, message, *args, **kwargs):
    """Custom log level for subdomain discoveries"""
    if self.isEnabledFor(DISCOVERY):
        self._log(DISCOVERY, message, args, **kwargs)

# Add custom log level method to Logger class
logging.Logger.discovery = discovery
