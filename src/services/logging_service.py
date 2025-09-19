"""Structured JSON logging service using loguru.

This module provides structured JSON logging with proper formatting,
error handling, and virtual environment awareness.
"""
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional, Union
from datetime import datetime

from loguru import logger

from ..lib.config import DNSProxyConfig, ensure_log_directory, get_virtual_env_info
from ..lib.exceptions import DNSProxyError, ConfigurationError


class LoggingService:
    """Structured JSON logging service with loguru backend."""

    def __init__(self, config: DNSProxyConfig):
        """Initialize logging service with configuration.

        Args:
            config: DNS proxy configuration

        Raises:
            ConfigurationError: If logging configuration is invalid
        """
        self.config = config
        self._initialized = False
        self._log_format = None
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Setup loguru logger with configuration."""
        try:
            # Remove default logger
            logger.remove()

            # Ensure log directory exists
            ensure_log_directory(self.config.log_file)

            # Configure JSON format
            self._log_format = self._get_log_format()

            # Add console handler
            logger.add(
                sys.stderr,
                format=self._log_format,
                level=self.config.log_level,
                serialize=True,
                backtrace=True,
                diagnose=True
            )

            # Add file handler with rotation
            logger.add(
                self.config.log_file,
                format=self._log_format,
                level=self.config.log_level,
                serialize=True,
                rotation=self.config.log_max_size,
                retention=self.config.log_retention,
                compression=self.config.log_compression,
                backtrace=True,
                diagnose=True,
                enqueue=True  # Thread-safe logging
            )

            self._initialized = True

            # Log initialization with virtual environment info
            if self.config.venv_aware:
                venv_info = get_virtual_env_info()
                self.info(
                    "Logging service initialized",
                    extra={
                        "component": "logging_service",
                        "log_level": self.config.log_level,
                        "log_file": self.config.log_file,
                        "virtual_env": venv_info
                    }
                )

        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize logging service: {e}",
                "logging_service"
            )

    def _get_log_format(self) -> str:
        """Get log format string for structured JSON logging."""
        return (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "{name}:{function}:{line} - "
            "{message}"
        )

    def _add_context(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Add common context to log entries.

        Args:
            extra: Additional context to include

        Returns:
            Context dictionary with standard fields
        """
        context = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": "dns-proxy",
            "version": "1.0.0"
        }

        if self.config.venv_aware:
            venv_info = get_virtual_env_info()
            if venv_info.get("in_venv"):
                context["virtual_env"] = venv_info["virtual_env"]

        if extra:
            context.update(extra)

        return context

    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message with structured context.

        Args:
            message: Log message
            extra: Additional context
        """
        if not self._initialized:
            return

        context = self._add_context(extra)
        logger.bind(**context).debug(message)

    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log info message with structured context.

        Args:
            message: Log message
            extra: Additional context
        """
        if not self._initialized:
            return

        context = self._add_context(extra)
        logger.bind(**context).info(message)

    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message with structured context.

        Args:
            message: Log message
            extra: Additional context
        """
        if not self._initialized:
            return

        context = self._add_context(extra)
        logger.bind(**context).warning(message)

    def error(self, message: str, error: Optional[Exception] = None,
              extra: Optional[Dict[str, Any]] = None) -> None:
        """Log error message with structured context and exception details.

        Args:
            message: Log message
            error: Exception to include in log
            extra: Additional context
        """
        if not self._initialized:
            return

        context = self._add_context(extra)

        if error:
            context["error"] = {
                "type": type(error).__name__,
                "message": str(error)
            }

            # Add DNS proxy specific error context
            if isinstance(error, DNSProxyError):
                context["error"].update({
                    "error_code": error.error_code,
                    "context": error.context
                })

        logger.bind(**context).error(message)

    def critical(self, message: str, error: Optional[Exception] = None,
                 extra: Optional[Dict[str, Any]] = None) -> None:
        """Log critical message with structured context and exception details.

        Args:
            message: Log message
            error: Exception to include in log
            extra: Additional context
        """
        if not self._initialized:
            return

        context = self._add_context(extra)

        if error:
            context["error"] = {
                "type": type(error).__name__,
                "message": str(error)
            }

            if isinstance(error, DNSProxyError):
                context["error"].update({
                    "error_code": error.error_code,
                    "context": error.context
                })

        logger.bind(**context).critical(message)

    def log_request(self, client_ip: str, query_name: str, query_type: str,
                    request_id: Optional[str] = None) -> None:
        """Log DNS request with structured context.

        Args:
            client_ip: Client IP address
            query_name: DNS query name
            query_type: DNS query type
            request_id: Optional request ID for tracing
        """
        extra = {
            "component": "dns_request",
            "client_ip": client_ip,
            "query_name": query_name,
            "query_type": query_type
        }

        if request_id:
            extra["request_id"] = request_id

        self.info(f"DNS request: {query_name} {query_type} from {client_ip}", extra)

    def log_response(self, query_name: str, query_type: str, upstream_source: str,
                     response_time: float, answer_count: int, ttl: int,
                     request_id: Optional[str] = None) -> None:
        """Log DNS response with structured context.

        Args:
            query_name: DNS query name
            query_type: DNS query type
            upstream_source: Source of response (cache/upstream)
            response_time: Response time in milliseconds
            answer_count: Number of answers in response
            ttl: Response TTL
            request_id: Optional request ID for tracing
        """
        extra = {
            "component": "dns_response",
            "query_name": query_name,
            "query_type": query_type,
            "upstream_source": upstream_source,
            "response_time_ms": response_time,
            "answer_count": answer_count,
            "ttl": ttl
        }

        if request_id:
            extra["request_id"] = request_id

        self.info(
            f"DNS response: {query_name} {query_type} "
            f"({answer_count} answers, {response_time:.1f}ms, from {upstream_source})",
            extra
        )

    def log_cache_operation(self, operation: str, cache_key: tuple,
                           hit: Optional[bool] = None, size: Optional[int] = None) -> None:
        """Log cache operation with structured context.

        Args:
            operation: Cache operation (get, set, delete, etc.)
            cache_key: Cache key
            hit: Whether operation was a cache hit
            size: Current cache size
        """
        query_name, query_type = cache_key
        extra = {
            "component": "dns_cache",
            "operation": operation,
            "query_name": query_name,
            "query_type": query_type
        }

        if hit is not None:
            extra["cache_hit"] = hit

        if size is not None:
            extra["cache_size"] = size

        if operation == "get":
            status = "hit" if hit else "miss"
            self.debug(f"Cache {operation}: {query_name} {query_type} ({status})", extra)
        else:
            self.debug(f"Cache {operation}: {query_name} {query_type}", extra)

    def log_upstream_request(self, upstream_url: str, query_name: str, query_type: str,
                            timeout_connect: int, timeout_read: int) -> None:
        """Log upstream request with structured context.

        Args:
            upstream_url: Upstream service URL
            query_name: DNS query name
            query_type: DNS query type
            timeout_connect: Connect timeout
            timeout_read: Read timeout
        """
        extra = {
            "component": "upstream_service",
            "operation": "request",
            "upstream_url": upstream_url,
            "query_name": query_name,
            "query_type": query_type,
            "timeout_connect": timeout_connect,
            "timeout_read": timeout_read
        }

        self.debug(f"Upstream request: {query_name} {query_type} to {upstream_url}", extra)

    def log_upstream_response(self, upstream_url: str, query_name: str, query_type: str,
                             status_code: int, response_time: float,
                             answer_count: int) -> None:
        """Log upstream response with structured context.

        Args:
            upstream_url: Upstream service URL
            query_name: DNS query name
            query_type: DNS query type
            status_code: HTTP status code
            response_time: Response time in milliseconds
            answer_count: Number of answers received
        """
        extra = {
            "component": "upstream_service",
            "operation": "response",
            "upstream_url": upstream_url,
            "query_name": query_name,
            "query_type": query_type,
            "status_code": status_code,
            "response_time_ms": response_time,
            "answer_count": answer_count
        }

        self.info(
            f"Upstream response: {query_name} {query_type} "
            f"({status_code}, {answer_count} answers, {response_time:.1f}ms)",
            extra
        )

    def log_circuit_breaker(self, upstream_url: str, state: str, failure_count: int,
                           next_retry_time: Optional[str] = None) -> None:
        """Log circuit breaker state change with structured context.

        Args:
            upstream_url: Upstream service URL
            state: Circuit breaker state
            failure_count: Current failure count
            next_retry_time: When circuit will allow next retry
        """
        extra = {
            "component": "circuit_breaker",
            "upstream_url": upstream_url,
            "state": state,
            "failure_count": failure_count
        }

        if next_retry_time:
            extra["next_retry_time"] = next_retry_time

        self.warning(
            f"Circuit breaker {state}: {upstream_url} "
            f"({failure_count} failures)",
            extra
        )

    def log_performance_metrics(self, metrics: Dict[str, Union[int, float]]) -> None:
        """Log performance metrics with structured context.

        Args:
            metrics: Performance metrics dictionary
        """
        extra = {
            "component": "performance_metrics",
            **metrics
        }

        self.info("Performance metrics", extra)

    def flush(self) -> None:
        """Flush all log handlers."""
        if self._initialized:
            # Loguru handles flushing automatically, but we can force it
            logger.complete()

    def shutdown(self) -> None:
        """Shutdown logging service gracefully."""
        if self._initialized:
            self.info("Shutting down logging service", {"component": "logging_service"})
            logger.stop()
            self._initialized = False

    def is_level_enabled(self, level: str) -> bool:
        """Check if log level is enabled.

        Args:
            level: Log level to check

        Returns:
            True if level is enabled
        """
        if not self._initialized:
            return False

        level_map = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50
        }

        current_level = level_map.get(self.config.log_level, 20)
        check_level = level_map.get(level.upper(), 0)

        return check_level >= current_level

    @classmethod
    def create_default(cls) -> 'LoggingService':
        """Create logging service with default configuration.

        Returns:
            LoggingService with default settings
        """
        from ..lib.config import DNSProxyConfig
        config = DNSProxyConfig()
        return cls(config)

    def __enter__(self) -> 'LoggingService':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with graceful shutdown."""
        if exc_type:
            self.error(
                f"Exception in logging context: {exc_val}",
                error=exc_val,
                extra={"exception_type": exc_type.__name__ if exc_type else None}
            )
        self.shutdown()