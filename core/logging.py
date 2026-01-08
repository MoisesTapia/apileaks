"""
APILeak Structured Logging System
Provides structured logging with DEBUG, INFO, WARNING, ERROR levels
"""

import logging
import sys
from typing import Any, Dict, Optional
import structlog
from structlog.stdlib import LoggerFactory


def setup_logging(
    level: str = "INFO",
    json_logs: bool = False,
    log_file: Optional[str] = None
) -> structlog.stdlib.BoundLogger:
    """
    Configure structured logging for APILeak
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        json_logs: Whether to output JSON formatted logs
        log_file: Optional log file path
        
    Returns:
        Configured structlog logger
    """
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper())
    )
    
    # Configure processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        logging.getLogger().addHandler(file_handler)
    
    return structlog.get_logger("apileak")


class APILeakLogger:
    """
    APILeak logging wrapper with context management
    """
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self.logger = logger
        self._context: Dict[str, Any] = {}
    
    def bind(self, **kwargs) -> "APILeakLogger":
        """Bind context to logger"""
        new_logger = APILeakLogger(self.logger.bind(**kwargs))
        new_logger._context = {**self._context, **kwargs}
        return new_logger
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        self.logger.error(message, **kwargs)
    
    def exception(self, message: str, **kwargs) -> None:
        """Log exception with traceback"""
        self.logger.exception(message, **kwargs)


def get_logger(name: str = "apileak") -> APILeakLogger:
    """Get a configured APILeak logger"""
    return APILeakLogger(structlog.get_logger(name))