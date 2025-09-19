"""Upstream Service model with circuit breaker state.

This module provides the UpstreamService data model that represents
the Google DoH service configuration and health status with circuit breaker pattern.
"""
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class CircuitBreakerState(Enum):
    """Circuit breaker states for upstream service."""
    CLOSED = "CLOSED"      # Normal operation
    OPEN = "OPEN"          # Circuit breaker open, blocking requests
    HALF_OPEN = "HALF_OPEN"  # Testing if service has recovered


@dataclass
class UpstreamService:
    """Upstream Service model representing DoH service configuration and health."""

    service_url: str
    timeout_connect: int
    timeout_read: int
    retry_attempts: int
    last_successful_request: Optional[datetime] = None
    consecutive_failures: int = 0
    circuit_breaker_state: CircuitBreakerState = CircuitBreakerState.CLOSED
    circuit_breaker_open_time: Optional[datetime] = None
    circuit_breaker_timeout: int = 60  # seconds
    failure_threshold: int = 5

    def validate(self) -> None:
        """Validate upstream service configuration.

        Raises:
            ValueError: If any validation rule fails.
        """
        self._validate_service_url()
        self._validate_timeouts()
        self._validate_retry_attempts()
        self._validate_consecutive_failures()
        self._validate_failure_threshold()

    def _validate_service_url(self) -> None:
        """Validate service URL format."""
        if not self.service_url:
            raise ValueError("Service URL cannot be empty")

        if not isinstance(self.service_url, str):
            raise ValueError("Service URL must be a string")

        if not self.service_url.startswith("https://"):
            raise ValueError("Service URL must use HTTPS protocol")

        # Basic URL format validation
        if not ("." in self.service_url and len(self.service_url) > 8):
            raise ValueError(f"Invalid service URL format: {self.service_url}")

    def _validate_timeouts(self) -> None:
        """Validate timeout values."""
        if not isinstance(self.timeout_connect, int) or self.timeout_connect <= 0:
            raise ValueError("Connect timeout must be a positive integer")

        if not isinstance(self.timeout_read, int) or self.timeout_read <= 0:
            raise ValueError("Read timeout must be a positive integer")

        # Reasonable upper limits
        if self.timeout_connect > 300:  # 5 minutes
            raise ValueError("Connect timeout exceeds reasonable limit of 300 seconds")

        if self.timeout_read > 300:  # 5 minutes
            raise ValueError("Read timeout exceeds reasonable limit of 300 seconds")

    def _validate_retry_attempts(self) -> None:
        """Validate retry attempts configuration."""
        if not isinstance(self.retry_attempts, int):
            raise ValueError("Retry attempts must be an integer")

        if not (0 <= self.retry_attempts <= 10):
            raise ValueError("Retry attempts must be between 0 and 10")

    def _validate_consecutive_failures(self) -> None:
        """Validate consecutive failures count."""
        if not isinstance(self.consecutive_failures, int):
            raise ValueError("Consecutive failures must be an integer")

        if self.consecutive_failures < 0:
            raise ValueError("Consecutive failures must be non-negative")

    def _validate_failure_threshold(self) -> None:
        """Validate failure threshold."""
        if not isinstance(self.failure_threshold, int):
            raise ValueError("Failure threshold must be an integer")

        if self.failure_threshold <= 0:
            raise ValueError("Failure threshold must be positive")

    def record_success(self, current_time: Optional[datetime] = None) -> None:
        """Record successful request and update circuit breaker state.

        Args:
            current_time: Current time. Uses utcnow() if None.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        self.last_successful_request = current_time
        self.consecutive_failures = 0

        # Close circuit breaker on success
        if self.circuit_breaker_state != CircuitBreakerState.CLOSED:
            self.circuit_breaker_state = CircuitBreakerState.CLOSED
            self.circuit_breaker_open_time = None

    def record_failure(self, current_time: Optional[datetime] = None) -> None:
        """Record failed request and update circuit breaker state.

        Args:
            current_time: Current time. Uses utcnow() if None.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        self.consecutive_failures += 1

        # Open circuit breaker if failure threshold exceeded
        if (self.consecutive_failures >= self.failure_threshold and
            self.circuit_breaker_state == CircuitBreakerState.CLOSED):
            self.circuit_breaker_state = CircuitBreakerState.OPEN
            self.circuit_breaker_open_time = current_time

    def should_allow_request(self, current_time: Optional[datetime] = None) -> bool:
        """Check if requests should be allowed based on circuit breaker state.

        Args:
            current_time: Current time. Uses utcnow() if None.

        Returns:
            True if request should be allowed, False if blocked by circuit breaker.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        if self.circuit_breaker_state == CircuitBreakerState.CLOSED:
            return True

        if self.circuit_breaker_state == CircuitBreakerState.OPEN:
            # Check if timeout has passed
            if (self.circuit_breaker_open_time and
                current_time >= self.circuit_breaker_open_time + timedelta(seconds=self.circuit_breaker_timeout)):
                # Transition to half-open state
                self.circuit_breaker_state = CircuitBreakerState.HALF_OPEN
                return True
            return False

        if self.circuit_breaker_state == CircuitBreakerState.HALF_OPEN:
            # Allow limited requests to test if service has recovered
            return True

        return False

    def is_healthy(self, current_time: Optional[datetime] = None) -> bool:
        """Check if upstream service is considered healthy.

        Args:
            current_time: Current time. Uses utcnow() if None.

        Returns:
            True if service is healthy, False otherwise.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        # Service is unhealthy if circuit breaker is open
        if self.circuit_breaker_state == CircuitBreakerState.OPEN:
            return False

        # Service is degraded if there are recent failures but not enough to open circuit
        if self.consecutive_failures > 0:
            return False

        # Service is healthy if we've had recent successful requests
        if self.last_successful_request:
            time_since_success = current_time - self.last_successful_request
            # Consider healthy if successful request within last 5 minutes
            return time_since_success <= timedelta(minutes=5)

        # No recent requests - considered healthy by default
        return True

    def get_health_status(self, current_time: Optional[datetime] = None) -> str:
        """Get detailed health status description.

        Args:
            current_time: Current time. Uses utcnow() if None.

        Returns:
            Health status description.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        if self.circuit_breaker_state == CircuitBreakerState.OPEN:
            time_remaining = None
            if self.circuit_breaker_open_time:
                recovery_time = self.circuit_breaker_open_time + timedelta(seconds=self.circuit_breaker_timeout)
                time_remaining = recovery_time - current_time
                if time_remaining.total_seconds() > 0:
                    return f"CIRCUIT_OPEN (recovery in {int(time_remaining.total_seconds())}s)"
            return "CIRCUIT_OPEN"

        if self.circuit_breaker_state == CircuitBreakerState.HALF_OPEN:
            return "TESTING_RECOVERY"

        if self.consecutive_failures > 0:
            return f"DEGRADED ({self.consecutive_failures} failures)"

        if self.last_successful_request:
            time_since_success = current_time - self.last_successful_request
            return f"HEALTHY (last success {int(time_since_success.total_seconds())}s ago)"

        return "HEALTHY"

    def get_failure_rate(self, window_minutes: int = 5) -> float:
        """Get failure rate over a time window.

        Note: This is a simplified implementation. In production,
        you would maintain a sliding window of request outcomes.

        Args:
            window_minutes: Time window in minutes.

        Returns:
            Failure rate as a percentage (0.0 to 100.0).
        """
        # Simplified: just return based on consecutive failures
        if self.consecutive_failures == 0:
            return 0.0

        # Estimate based on consecutive failures
        # This is a placeholder implementation
        failure_percentage = min(100.0, (self.consecutive_failures / self.failure_threshold) * 100)
        return failure_percentage

    def reset_circuit_breaker(self) -> None:
        """Manually reset circuit breaker to closed state."""
        self.circuit_breaker_state = CircuitBreakerState.CLOSED
        self.circuit_breaker_open_time = None
        self.consecutive_failures = 0

    def to_dict(self) -> dict:
        """Convert upstream service to dictionary for serialization."""
        return {
            "service_url": self.service_url,
            "timeout_connect": self.timeout_connect,
            "timeout_read": self.timeout_read,
            "retry_attempts": self.retry_attempts,
            "last_successful_request": (self.last_successful_request.isoformat()
                                      if self.last_successful_request else None),
            "consecutive_failures": self.consecutive_failures,
            "circuit_breaker_state": self.circuit_breaker_state.value,
            "circuit_breaker_open_time": (self.circuit_breaker_open_time.isoformat()
                                        if self.circuit_breaker_open_time else None),
            "circuit_breaker_timeout": self.circuit_breaker_timeout,
            "failure_threshold": self.failure_threshold,
            "health_status": self.get_health_status(),
            "is_healthy": self.is_healthy(),
            "failure_rate": self.get_failure_rate()
        }

    def __str__(self) -> str:
        """String representation of upstream service."""
        return (f"UpstreamService({self.service_url}: {self.get_health_status()}, "
                f"{self.consecutive_failures} failures)")

    @classmethod
    def create_default(cls, service_url: str = "https://8.8.8.8/resolve") -> 'UpstreamService':
        """Create upstream service with default configuration.

        Args:
            service_url: DoH service URL.

        Returns:
            UpstreamService with default settings.
        """
        return cls(
            service_url=service_url,
            timeout_connect=5,
            timeout_read=10,
            retry_attempts=3,
            circuit_breaker_timeout=60,
            failure_threshold=5
        )

    @classmethod
    def from_dict(cls, data: dict) -> 'UpstreamService':
        """Create upstream service from dictionary.

        Args:
            data: Dictionary representation.

        Returns:
            UpstreamService instance.
        """
        last_successful_request = None
        if data.get('last_successful_request'):
            last_successful_request = datetime.fromisoformat(data['last_successful_request'])

        circuit_breaker_open_time = None
        if data.get('circuit_breaker_open_time'):
            circuit_breaker_open_time = datetime.fromisoformat(data['circuit_breaker_open_time'])

        circuit_breaker_state = CircuitBreakerState(data.get('circuit_breaker_state', 'CLOSED'))

        return cls(
            service_url=data['service_url'],
            timeout_connect=data['timeout_connect'],
            timeout_read=data['timeout_read'],
            retry_attempts=data['retry_attempts'],
            last_successful_request=last_successful_request,
            consecutive_failures=data['consecutive_failures'],
            circuit_breaker_state=circuit_breaker_state,
            circuit_breaker_open_time=circuit_breaker_open_time,
            circuit_breaker_timeout=data.get('circuit_breaker_timeout', 60),
            failure_threshold=data.get('failure_threshold', 5)
        )