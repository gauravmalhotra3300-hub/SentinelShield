import logging
import logging.handlers
import os
from datetime import datetime

class WAFLogger:
    """Custom logger for WAF system."""
    
    def __init__(self, log_dir='logs', log_file='waf.log'):
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, log_file)
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configure logger
        self.logger = logging.getLogger('SentinelShield')
        self.logger.setLevel(logging.DEBUG)
        
        # Create file handler with rotation
        handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        handler.setLevel(logging.DEBUG)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        if not self.logger.handlers:
            self.logger.addHandler(handler)
            self.logger.addHandler(console_handler)
    
    def log_request(self, request_data):
        """Log incoming request."""
        self.logger.info(f"Request: {request_data}")
    
    def log_threat_detection(self, threat_type, source_ip, details):
        """Log detected threat."""
        self.logger.warning(f"Threat Detected - Type: {threat_type}, Source: {source_ip}, Details: {details}")
    
    def log_blocked_request(self, source_ip, reason):
        """Log blocked request."""
        self.logger.warning(f"Request Blocked - Source: {source_ip}, Reason: {reason}")
    
    def log_error(self, error_msg, exception=None):
        """Log error message."""
        if exception:
            self.logger.error(f"{error_msg}: {str(exception)}")
        else:
            self.logger.error(error_msg)
    
    def log_system_event(self, event):
        """Log system event."""
        self.logger.info(f"System Event: {event}")
    
    def log_stats(self, stats):
        """Log statistics."""
        self.logger.info(f"Statistics: {stats}")
    
    def get_recent_logs(self, lines=50):
        """Get recent log entries."""
        try:
            with open(self.log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except FileNotFoundError:
            return []
    
    def clear_logs(self):
        """Clear log file."""
        try:
            open(self.log_file, 'w').close()
            self.logger.info("Log file cleared")
        except Exception as e:
            self.logger.error(f"Error clearing logs: {str(e)}")
