"""Upstream DoH service with retry logic and circuit breaker.

This module provides upstream DNS-over-HTTPS service client with
comprehensive error handling, retry logic, and circuit breaker pattern.
"""
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode
import urllib.request
import urllib.error
from threading import RLock

from ..models.upstream_service import UpstreamService, CircuitBreakerState
from ..models.dns_query import DNSQuery
from ..models.dns_response import DNSResponse
from ..lib.exceptions import (
    UpstreamTimeoutError, UpstreamConnectionError, UpstreamServiceError,
    CircuitBreakerOpenError, ValidationError, is_retriable_error
)
from ..services.logging_service import LoggingService


class UpstreamDoHService:
    """Upstream DNS-over-HTTPS service with retry logic and circuit breaker."""

    def __init__(self, upstream_service: UpstreamService,
                 logging_service: Optional[LoggingService] = None):
        """Initialize upstream DoH service.

        Args:
            upstream_service: Upstream service configuration
            logging_service: Optional logging service for structured logging

        Raises:
            ValueError: If upstream service configuration is invalid
        """
        upstream_service.validate()
        self.upstream_service = upstream_service
        self.logging_service = logging_service
        self._lock = RLock()

        # Request statistics
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "timeout_errors": 0,
            "connection_errors": 0,
            "service_errors": 0,
            "circuit_breaker_blocks": 0,
            "total_response_time": 0.0
        }

        self._log_debug("Upstream DoH service initialized", {
            "service_url": upstream_service.service_url,
            "timeout_connect": upstream_service.timeout_connect,
            "timeout_read": upstream_service.timeout_read,
            "retry_attempts": upstream_service.retry_attempts
        })

    def query(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> DNSResponse:
        """Execute DNS query against upstream DoH service.

        Args:
            dns_query: DNS query to execute
            request_id: Optional request ID for tracing

        Returns:
            DNS response from upstream service

        Raises:
            ValidationError: If query is invalid
            CircuitBreakerOpenError: If circuit breaker is open
            UpstreamTimeoutError: If request times out
            UpstreamConnectionError: If connection fails
            UpstreamServiceError: If service returns error
        """
        dns_query.validate()

        with self._lock:
            # Check circuit breaker
            if not self.upstream_service.should_allow_request():
                self._stats["circuit_breaker_blocks"] += 1
                raise CircuitBreakerOpenError(
                    f"Circuit breaker open for {self.upstream_service.service_url}",
                    service_url=self.upstream_service.service_url,
                    failure_count=self.upstream_service.consecutive_failures,
                    next_retry_time=self._get_next_retry_time()
                )

            self._stats["total_requests"] += 1

        # Execute query with retries
        return self._execute_with_retries(dns_query, request_id)

    def _execute_with_retries(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> DNSResponse:
        """Execute query with retry logic.

        Args:
            dns_query: DNS query to execute
            request_id: Optional request ID for tracing

        Returns:
            DNS response from upstream service

        Raises:
            UpstreamTimeoutError: If all retries timeout
            UpstreamConnectionError: If all retries fail connection
            UpstreamServiceError: If service returns non-retriable error
        """
        last_error = None
        max_attempts = self.upstream_service.retry_attempts + 1  # Initial attempt + retries

        for attempt in range(max_attempts):
            try:
                if attempt > 0:
                    # Log retry attempt
                    self._log_debug(f"Retrying upstream request (attempt {attempt + 1}/{max_attempts})", {
                        "query_name": dns_query.query_name,
                        "query_type": dns_query.query_type,
                        "attempt": attempt + 1,
                        "max_attempts": max_attempts
                    })

                response = self._execute_single_request(dns_query, request_id)

                # Record success
                with self._lock:
                    self.upstream_service.record_success()
                    self._stats["successful_requests"] += 1

                return response

            except Exception as e:
                last_error = e

                # Record failure
                with self._lock:
                    self.upstream_service.record_failure()
                    self._stats["failed_requests"] += 1

                    # Update specific error statistics
                    if isinstance(e, UpstreamTimeoutError):
                        self._stats["timeout_errors"] += 1
                    elif isinstance(e, UpstreamConnectionError):
                        self._stats["connection_errors"] += 1
                    elif isinstance(e, UpstreamServiceError):
                        self._stats["service_errors"] += 1

                # Log circuit breaker state changes
                self._log_circuit_breaker_if_changed()

                # Check if error should trigger retry
                if not is_retriable_error(e) or attempt == max_attempts - 1:
                    break

                # Exponential backoff for retries
                if attempt < max_attempts - 1:
                    backoff_time = min(2 ** attempt, 10)  # Cap at 10 seconds
                    time.sleep(backoff_time)

        # All retries failed, raise the last error
        raise last_error

    def _execute_single_request(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> DNSResponse:
        """Execute single HTTP request to upstream DoH service.

        Args:
            dns_query: DNS query to execute
            request_id: Optional request ID for tracing

        Returns:
            DNS response from upstream service

        Raises:
            UpstreamTimeoutError: If request times out
            UpstreamConnectionError: If connection fails
            UpstreamServiceError: If service returns error
        """
        start_time = time.time()

        try:
            # Build request URL
            url = self._build_request_url(dns_query)

            # Log upstream request
            self._log_upstream_request(dns_query, request_id)

            # Create request with headers
            request = urllib.request.Request(url)
            request.add_header('Accept', 'application/dns-json')
            request.add_header('User-Agent', 'DNS-Proxy/1.0.0')

            # Execute request with timeout
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.upstream_service.timeout_read
                ) as response:
                    response_data = response.read().decode('utf-8')
                    status_code = response.getcode()
                    response_time = (time.time() - start_time) * 1000  # Convert to ms

                    # Update response time statistics
                    with self._lock:
                        self._stats["total_response_time"] += response_time

                    # Parse and validate response
                    dns_response = self._parse_response(
                        dns_query, response_data, status_code, response_time
                    )

                    # Log upstream response
                    self._log_upstream_response(dns_query, status_code, response_time, dns_response, request_id)

                    return dns_response

            except urllib.error.HTTPError as e:
                response_time = (time.time() - start_time) * 1000
                error_content = e.read().decode('utf-8') if e.fp else None

                raise UpstreamServiceError(
                    f"HTTP {e.code} error from upstream: {e.reason}",
                    status_code=e.code,
                    upstream_url=self.upstream_service.service_url,
                    response_content=error_content
                )

            except urllib.error.URLError as e:
                response_time = (time.time() - start_time) * 1000

                if "timeout" in str(e.reason).lower():
                    raise UpstreamTimeoutError(
                        f"Timeout connecting to upstream: {e.reason}",
                        timeout_seconds=self.upstream_service.timeout_read,
                        upstream_url=self.upstream_service.service_url
                    )
                else:
                    raise UpstreamConnectionError(
                        f"Connection error to upstream: {e.reason}",
                        upstream_url=self.upstream_service.service_url,
                        original_error=e
                    )

        except (UpstreamTimeoutError, UpstreamConnectionError, UpstreamServiceError):
            raise
        except Exception as e:
            raise UpstreamServiceError(
                f"Unexpected error in upstream request: {e}",
                upstream_url=self.upstream_service.service_url,
                response_content=str(e)
            )

    def _build_request_url(self, dns_query: DNSQuery) -> str:
        """Build DoH request URL with query parameters.

        Args:
            dns_query: DNS query

        Returns:
            Complete request URL
        """
        params = {
            'name': dns_query.query_name,
            'type': dns_query.query_type,
            'cd': 'false',  # Disable DNSSEC validation
            'do': 'false',  # Don't set DO bit
            'edns_client_subnet': '0.0.0.0/0'  # Don't send client subnet
        }

        query_string = urlencode(params)
        return f"{self.upstream_service.service_url}?{query_string}"

    def _parse_response(self, dns_query: DNSQuery, response_data: str,
                       status_code: int, response_time: float) -> DNSResponse:
        """Parse DoH JSON response into DNS response.

        Args:
            dns_query: Original DNS query
            response_data: Raw response data
            status_code: HTTP status code
            response_time: Response time in milliseconds

        Returns:
            Parsed DNS response

        Raises:
            UpstreamServiceError: If response parsing fails
        """
        try:
            data = json.loads(response_data)

            # Validate response structure
            if not isinstance(data, dict):
                raise UpstreamServiceError(
                    "Invalid response format: expected JSON object",
                    status_code=status_code,
                    upstream_url=self.upstream_service.service_url,
                    response_content=response_data[:500]
                )

            # Debug log the actual response structure
            self._log_debug(f"DoH response structure: {json.dumps(data, indent=2)[:500]}", {
                "query_name": dns_query.query_name,
                "query_type": dns_query.query_type
            })

            # Extract answers
            answers = data.get('Answer', [])
            if not isinstance(answers, list):
                answers = []

            # Extract TTL from answers or use default
            ttl = self._extract_ttl(answers)

            # Create DNS response
            dns_response = DNSResponse(
                query_name=dns_query.query_name,
                query_type=dns_query.query_type,
                answers=answers,
                response_size=len(response_data),
                ttl=ttl,
                upstream_source="upstream",
                response_time=response_time
            )

            dns_response.validate()
            return dns_response

        except json.JSONDecodeError as e:
            raise UpstreamServiceError(
                f"Invalid JSON response: {e}",
                status_code=status_code,
                upstream_url=self.upstream_service.service_url,
                response_content=response_data[:500]
            )
        except ValidationError as e:
            raise UpstreamServiceError(
                f"Response validation failed: {e}",
                status_code=status_code,
                upstream_url=self.upstream_service.service_url,
                response_content=response_data[:500]
            )

    def _extract_ttl(self, answers: List[Dict[str, Any]]) -> int:
        """Extract minimum TTL from answer records.

        Args:
            answers: List of answer records

        Returns:
            Minimum TTL value
        """
        if not answers:
            return 300  # Default TTL for empty responses

        min_ttl = float('inf')
        for answer in answers:
            if isinstance(answer, dict) and 'TTL' in answer:
                ttl = answer['TTL']
                if isinstance(ttl, int) and ttl >= 0:
                    min_ttl = min(min_ttl, ttl)

        return int(min_ttl) if min_ttl != float('inf') else 300

    def _get_next_retry_time(self) -> Optional[str]:
        """Get next retry time for circuit breaker.

        Returns:
            ISO format timestamp of next retry or None
        """
        if (self.upstream_service.circuit_breaker_state == CircuitBreakerState.OPEN and
            self.upstream_service.circuit_breaker_open_time):
            retry_time = (self.upstream_service.circuit_breaker_open_time +
                         timedelta(seconds=self.upstream_service.circuit_breaker_timeout))
            return retry_time.isoformat()
        return None

    def _log_circuit_breaker_if_changed(self) -> None:
        """Log circuit breaker state if it has changed."""
        if (self.logging_service and
            self.upstream_service.circuit_breaker_state != CircuitBreakerState.CLOSED):
            self.logging_service.log_circuit_breaker(
                upstream_url=self.upstream_service.service_url,
                state=self.upstream_service.circuit_breaker_state.value,
                failure_count=self.upstream_service.consecutive_failures,
                next_retry_time=self._get_next_retry_time()
            )

    def _log_upstream_request(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> None:
        """Log upstream request.

        Args:
            dns_query: DNS query being sent
            request_id: Optional request ID for tracing
        """
        if self.logging_service:
            extra_context = {
                "component": "upstream_service",
                "operation": "request",
                "upstream_url": self.upstream_service.service_url,
                "query_name": dns_query.query_name,
                "query_type": dns_query.query_type,
                "timeout_connect": self.upstream_service.timeout_connect,
                "timeout_read": self.upstream_service.timeout_read
            }

            if request_id:
                extra_context["request_id"] = request_id

            self.logging_service.debug(
                f"Upstream request: {dns_query.query_name} {dns_query.query_type} to {self.upstream_service.service_url}",
                extra=extra_context
            )

    def _log_upstream_response(self, dns_query: DNSQuery, status_code: int,
                              response_time: float, dns_response: DNSResponse,
                              request_id: Optional[str] = None) -> None:
        """Log upstream response.

        Args:
            dns_query: Original DNS query
            status_code: HTTP status code
            response_time: Response time in milliseconds
            dns_response: Parsed DNS response
            request_id: Optional request ID for tracing
        """
        if self.logging_service:
            extra_context = {
                "component": "upstream_service",
                "operation": "response",
                "upstream_url": self.upstream_service.service_url,
                "query_name": dns_query.query_name,
                "query_type": dns_query.query_type,
                "status_code": status_code,
                "response_time_ms": response_time,
                "answer_count": dns_response.get_answer_count()
            }

            if request_id:
                extra_context["request_id"] = request_id

            self.logging_service.info(
                f"Upstream response: {dns_query.query_name} {dns_query.query_type} "
                f"({status_code}, {dns_response.get_answer_count()} answers, {response_time:.1f}ms)",
                extra=extra_context
            )

    def shutdown(self) -> None:
        """Shutdown upstream service gracefully."""
        if self.logging_service:
            self.logging_service.info("Shutting down upstream service", extra={
                "component": "upstream_service",
                "service_url": self.upstream_service.service_url,
                "final_stats": self._stats
            })

        # Reset circuit breaker to clean state
        try:
            with self._lock:
                self.upstream_service.reset_circuit_breaker()
                # Clear statistics
                self._stats.clear()

            if self.logging_service:
                self.logging_service.info("Upstream service shutdown complete", extra={
                    "component": "upstream_service"
                })
        except Exception as e:
            if self.logging_service:
                self.logging_service.warning(f"Error during upstream service shutdown: {e}")

    def _log_debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message using logging service.

        Args:
            message: Log message
            extra: Additional context
        """
        if self.logging_service:
            context = {"component": "upstream_service"}
            if extra:
                context.update(extra)
            self.logging_service.debug(message, context)

    def get_health_status(self) -> Dict[str, Any]:
        """Get upstream service health status.

        Returns:
            Dictionary with health status information
        """
        with self._lock:
            total_requests = self._stats["total_requests"]
            success_rate = (
                (self._stats["successful_requests"] / total_requests * 100)
                if total_requests > 0 else 100.0
            )
            avg_response_time = (
                (self._stats["total_response_time"] / self._stats["successful_requests"])
                if self._stats["successful_requests"] > 0 else 0.0
            )

            return {
                "service_url": self.upstream_service.service_url,
                "circuit_breaker_state": self.upstream_service.circuit_breaker_state.value,
                "consecutive_failures": self.upstream_service.consecutive_failures,
                "is_healthy": self.upstream_service.is_healthy(),
                "health_status": self.upstream_service.get_health_status(),
                "last_successful_request": (
                    self.upstream_service.last_successful_request.isoformat()
                    if self.upstream_service.last_successful_request else None
                ),
                "total_requests": total_requests,
                "successful_requests": self._stats["successful_requests"],
                "failed_requests": self._stats["failed_requests"],
                "success_rate": round(success_rate, 2),
                "average_response_time": round(avg_response_time, 2),
                "timeout_errors": self._stats["timeout_errors"],
                "connection_errors": self._stats["connection_errors"],
                "service_errors": self._stats["service_errors"],
                "circuit_breaker_blocks": self._stats["circuit_breaker_blocks"]
            }

    def reset_circuit_breaker(self) -> None:
        """Manually reset circuit breaker to closed state."""
        with self._lock:
            self.upstream_service.reset_circuit_breaker()
            self._log_debug("Circuit breaker manually reset", {
                "service_url": self.upstream_service.service_url
            })

    def reset_stats(self) -> None:
        """Reset service statistics."""
        with self._lock:
            self._stats = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "timeout_errors": 0,
                "connection_errors": 0,
                "service_errors": 0,
                "circuit_breaker_blocks": 0,
                "total_response_time": 0.0
            }
            self._log_debug("Service statistics reset")

    @classmethod
    def create_default(cls, service_url: str = "https://8.8.8.8/resolve",
                      logging_service: Optional[LoggingService] = None) -> 'UpstreamDoHService':
        """Create upstream DoH service with default configuration.

        Args:
            service_url: DoH service URL
            logging_service: Optional logging service

        Returns:
            UpstreamDoHService with default settings
        """
        upstream_service = UpstreamService.create_default(service_url)
        return cls(upstream_service, logging_service)

    def __enter__(self) -> 'UpstreamDoHService':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        if exc_type:
            self._log_debug(f"Exception in upstream service context: {exc_val}")