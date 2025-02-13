import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging(log_level=logging.INFO):
    """
    Sets up logging configuration for the application.
    Creates rotating file handlers for different log files.
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Common log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Setup rotating file handler for subdomain finder
    subdomain_handler = logging.handlers.RotatingFileHandler(
        'logs/subdomain_finder.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3
    )
    subdomain_handler.setFormatter(formatter)
    subdomain_handler.setLevel(log_level)
    root_logger.addHandler(subdomain_handler)

    # Setup daily rotating handler for scanner
    scanner_handler = logging.handlers.TimedRotatingFileHandler(
        f'logs/scanner_{datetime.now().strftime("%Y%m%d")}.log',
        when='midnight',
        interval=1,
        backupCount=7
    )
    scanner_handler.setFormatter(formatter)
    scanner_handler.setLevel(log_level)
    root_logger.addHandler(scanner_handler)

    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)

    return root_logger

def get_logger(name: str) -> logging.Logger:
    """
    Gets a logger instance with the specified name.
    Ensures it inherits the root logger's configuration.
    """
    return logging.getLogger(name)

def get_component_logger(name: str, include_id: bool = False) -> logging.Logger:
    """
    Gets a logger instance for a component, optionally including an ID in the name.
    
    Args:
        name: Base name for the logger
        include_id: Whether to include a unique ID in the logger name
        
    Returns:
        Logger instance with the specified configuration
    """
    if include_id:
        import uuid
        component_id = str(uuid.uuid4())[:8]
        name = f"{name}[{component_id}]"
    return get_logger(name)
