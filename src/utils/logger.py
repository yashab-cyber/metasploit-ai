"""
Logging Utilities Module
Advanced logging configuration for Metasploit-AI Framework
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json

from rich.logging import RichHandler
from rich.console import Console

# Global logger registry
_loggers = {}

def setup_logger(name: str, level: str = "INFO", 
                log_file: Optional[str] = None,
                max_size: str = "10MB",
                backup_count: int = 5) -> logging.Logger:
    """Setup and configure logger with rich formatting"""
    
    # Convert level string to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler with rich formatting
    console = Console()
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_level=True,
        show_path=True,
        markup=True,
        rich_tracebacks=True
    )
    rich_handler.setLevel(numeric_level)
    
    # Rich formatter
    rich_formatter = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]"
    )
    rich_handler.setFormatter(rich_formatter)
    logger.addHandler(rich_handler)
    
    # File handler if log file specified
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert size string to bytes
        max_bytes = _parse_size(max_size)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        
        # File formatter
        file_formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Store in registry
    _loggers[name] = logger
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """Get existing logger or create default one"""
    if name in _loggers:
        return _loggers[name]
    
    # Create default logger
    return setup_logger(name)

def _parse_size(size_str: str) -> int:
    """Parse size string like '10MB' to bytes"""
    size_str = size_str.upper().strip()
    
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        # Assume bytes
        return int(size_str)

class SecurityLogger:
    """Security-focused logger for sensitive operations"""
    
    def __init__(self, name: str = "security"):
        self.logger = setup_logger(
            f"security.{name}",
            level="INFO",
            log_file="logs/security.log"
        )
    
    def log_scan_start(self, target: str, scan_type: str, user: str = "system"):
        """Log scan initiation"""
        self.logger.info(
            f"SCAN_START - Target: {target}, Type: {scan_type}, User: {user}",
            extra={
                'event_type': 'scan_start',
                'target': target,
                'scan_type': scan_type,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_scan_complete(self, target: str, vulnerabilities_count: int, user: str = "system"):
        """Log scan completion"""
        self.logger.info(
            f"SCAN_COMPLETE - Target: {target}, Vulnerabilities: {vulnerabilities_count}, User: {user}",
            extra={
                'event_type': 'scan_complete',
                'target': target,
                'vulnerabilities_count': vulnerabilities_count,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_exploit_attempt(self, target: str, exploit_name: str, user: str = "system"):
        """Log exploit attempt"""
        self.logger.warning(
            f"EXPLOIT_ATTEMPT - Target: {target}, Exploit: {exploit_name}, User: {user}",
            extra={
                'event_type': 'exploit_attempt',
                'target': target,
                'exploit_name': exploit_name,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_exploit_success(self, target: str, exploit_name: str, session_id: str = None, user: str = "system"):
        """Log successful exploit"""
        self.logger.critical(
            f"EXPLOIT_SUCCESS - Target: {target}, Exploit: {exploit_name}, Session: {session_id}, User: {user}",
            extra={
                'event_type': 'exploit_success',
                'target': target,
                'exploit_name': exploit_name,
                'session_id': session_id,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_session_created(self, target: str, session_id: str, user: str = "system"):
        """Log session creation"""
        self.logger.critical(
            f"SESSION_CREATED - Target: {target}, Session: {session_id}, User: {user}",
            extra={
                'event_type': 'session_created',
                'target': target,
                'session_id': session_id,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_session_command(self, session_id: str, command: str, user: str = "system"):
        """Log session command execution"""
        self.logger.warning(
            f"SESSION_COMMAND - Session: {session_id}, Command: {command[:100]}, User: {user}",
            extra={
                'event_type': 'session_command',
                'session_id': session_id,
                'command': command,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_unauthorized_access(self, source_ip: str, attempted_action: str):
        """Log unauthorized access attempt"""
        self.logger.error(
            f"UNAUTHORIZED_ACCESS - Source: {source_ip}, Action: {attempted_action}",
            extra={
                'event_type': 'unauthorized_access',
                'source_ip': source_ip,
                'attempted_action': attempted_action,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_api_access(self, endpoint: str, source_ip: str, user: str = "anonymous"):
        """Log API access"""
        self.logger.info(
            f"API_ACCESS - Endpoint: {endpoint}, Source: {source_ip}, User: {user}",
            extra={
                'event_type': 'api_access',
                'endpoint': endpoint,
                'source_ip': source_ip,
                'user': user,
                'timestamp': datetime.now().isoformat()
            }
        )

class AuditLogger:
    """Audit logger for compliance and tracking"""
    
    def __init__(self):
        self.logger = setup_logger(
            "audit",
            level="INFO",
            log_file="logs/audit.log"
        )
    
    def log_action(self, action: str, user: str, target: str = None, 
                   result: str = "success", details: dict = None):
        """Log auditable action"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'user': user,
            'target': target,
            'result': result,
            'details': details or {}
        }
        
        self.logger.info(
            f"AUDIT - {action} by {user} on {target or 'N/A'} - {result}",
            extra=audit_entry
        )

class PerformanceLogger:
    """Performance monitoring logger"""
    
    def __init__(self):
        self.logger = setup_logger(
            "performance",
            level="INFO",
            log_file="logs/performance.log"
        )
    
    def log_operation_time(self, operation: str, duration: float, target: str = None):
        """Log operation execution time"""
        self.logger.info(
            f"PERFORMANCE - {operation} took {duration:.2f}s on {target or 'N/A'}",
            extra={
                'operation': operation,
                'duration': duration,
                'target': target,
                'timestamp': datetime.now().isoformat()
            }
        )
    
    def log_resource_usage(self, cpu_percent: float, memory_mb: float, operation: str = None):
        """Log resource usage"""
        self.logger.info(
            f"RESOURCE_USAGE - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB, Operation: {operation or 'N/A'}",
            extra={
                'cpu_percent': cpu_percent,
                'memory_mb': memory_mb,
                'operation': operation,
                'timestamp': datetime.now().isoformat()
            }
        )

class JSONFileHandler(logging.Handler):
    """Custom handler that writes JSON logs to file"""
    
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
    
    def emit(self, record):
        """Emit log record as JSON"""
        try:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            # Add extra fields if available
            if hasattr(record, '__dict__'):
                for key, value in record.__dict__.items():
                    if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                                 'pathname', 'filename', 'module', 'exc_info', 
                                 'exc_text', 'stack_info', 'lineno', 'funcName', 
                                 'created', 'msecs', 'relativeCreated', 'thread',
                                 'threadName', 'processName', 'process', 'getMessage']:
                        log_entry[key] = value
            
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception:
            self.handleError(record)

def setup_json_logger(name: str, filename: str, level: str = "INFO") -> logging.Logger:
    """Setup logger with JSON file output"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        json_handler = JSONFileHandler(filename)
        json_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(json_handler)
    
    return logger

def configure_framework_logging(config):
    """Configure logging for the entire framework"""
    try:
        # Main framework logger
        main_logger = setup_logger(
            "metasploit-ai",
            level=config.logging.level,
            log_file=config.logging.file,
            max_size=config.logging.max_size,
            backup_count=config.logging.backup_count
        )
        
        # Security logger
        security_logger = SecurityLogger()
        
        # Audit logger
        audit_logger = AuditLogger()
        
        # Performance logger
        performance_logger = PerformanceLogger()
        
        # JSON structured logs
        json_logger = setup_json_logger(
            "metasploit-ai.structured",
            "logs/structured.jsonl"
        )
        
        main_logger.info("🔧 Logging system configured successfully")
        
        return {
            'main': main_logger,
            'security': security_logger,
            'audit': audit_logger,
            'performance': performance_logger,
            'json': json_logger
        }
        
    except Exception as e:
        # Fallback to basic logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger("metasploit-ai")
        logger.error(f"Failed to configure advanced logging: {e}")
        return {'main': logger}

class LogRotationManager:
    """Manage log rotation and cleanup"""
    
    def __init__(self, log_directory: str = "logs"):
        self.log_directory = Path(log_directory)
        self.logger = get_logger(__name__)
    
    def rotate_logs(self, max_age_days: int = 30, max_size_mb: int = 100):
        """Rotate old log files"""
        try:
            current_time = datetime.now()
            
            for log_file in self.log_directory.glob("*.log*"):
                # Check file age
                file_age = current_time.timestamp() - log_file.stat().st_mtime
                age_days = file_age / (24 * 3600)
                
                # Check file size
                file_size_mb = log_file.stat().st_size / (1024 * 1024)
                
                if age_days > max_age_days or file_size_mb > max_size_mb:
                    # Archive old file
                    archive_name = f"{log_file.name}.{current_time.strftime('%Y%m%d_%H%M%S')}"
                    archive_path = self.log_directory / "archive" / archive_name
                    
                    archive_path.parent.mkdir(parents=True, exist_ok=True)
                    log_file.rename(archive_path)
                    
                    self.logger.info(f"Archived log file: {log_file.name}")
        
        except Exception as e:
            self.logger.error(f"Log rotation error: {e}")
    
    def cleanup_old_archives(self, max_archive_days: int = 90):
        """Clean up old archived logs"""
        try:
            current_time = datetime.now()
            archive_dir = self.log_directory / "archive"
            
            if not archive_dir.exists():
                return
            
            for archive_file in archive_dir.glob("*"):
                file_age = current_time.timestamp() - archive_file.stat().st_mtime
                age_days = file_age / (24 * 3600)
                
                if age_days > max_archive_days:
                    archive_file.unlink()
                    self.logger.info(f"Deleted old archive: {archive_file.name}")
        
        except Exception as e:
            self.logger.error(f"Archive cleanup error: {e}")

# Decorator for automatic logging
def log_function_call(logger_name: str = None):
    """Decorator to automatically log function calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger(logger_name or func.__module__)
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} completed successfully")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} failed: {e}")
                raise
        
        return wrapper
    return decorator

# Context manager for operation logging
class LogOperation:
    """Context manager for logging operation duration"""
    
    def __init__(self, operation_name: str, logger_name: str = None):
        self.operation_name = operation_name
        self.logger = get_logger(logger_name or __name__)
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"Starting operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.info(f"Operation completed: {self.operation_name} ({duration:.2f}s)")
        else:
            self.logger.error(f"Operation failed: {self.operation_name} ({duration:.2f}s) - {exc_val}")
        
        return False  # Don't suppress exceptions
