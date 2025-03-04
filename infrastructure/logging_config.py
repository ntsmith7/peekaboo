# infrastructure/logging_config.py
import logging
import os

def setup_logging(log_level=logging.INFO, handler=None):
    """
    Sets up logging configuration with an optional handler.
    If a handler is provided, it will be used instead of the default handlers.
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    for hdlr in root_logger.handlers[:]:
        root_logger.removeHandler(hdlr)

    if handler:
        # Use the provided handler (e.g., RichHandler)
        root_logger.addHandler(handler)
    else:
        # Simple log format
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Single file handler
        file_handler = logging.FileHandler('logs/scanner.log')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)

        # Console handler for immediate feedback
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level)
        root_logger.addHandler(console_handler)

    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)

    return root_logger

def get_logger(name: str) -> logging.Logger:
    """Gets a logger instance with the specified name."""
    return logging.getLogger(name)