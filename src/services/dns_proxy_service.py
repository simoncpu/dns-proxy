"""DNS proxy service with comprehensive error handling.

This module provides the main DNS proxy service that coordinates
cache, upstream services, and provides the primary DNS resolution interface.
"""
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from threading import RLock

from ..models.dns_query import DNSQuery
from ..models.dns_response import DNSResponse
from ..models.upstream_service import UpstreamService
from ..services.dns_cache_service import DNSCacheService
from ..services.upstream_service import UpstreamDoHService
from ..services.logging_service import LoggingService
from ..lib.config import DNSProxyConfig
from ..lib.exceptions import (
    DNSProxyError, ValidationError, ServiceUnavailableError,
    CircuitBreakerOpenError, RateLimitExceededError, is_client_error
)


class DNSProxyService:
    """Main DNS proxy service coordinating cache, upstream, and logging."""

    def __init__(self, config: DNSProxyConfig,
                 cache_service: Optional[DNSCacheService] = None,
                 upstream_service: Optional[UpstreamDoHService] = None,
                 logging_service: Optional[LoggingService] = None):
        """Initialize DNS proxy service.

        Args:
            config: DNS proxy configuration
            cache_service: Optional DNS cache service
            upstream_service: Optional upstream DoH service
            logging_service: Optional logging service

        Raises:
            ValidationError: If configuration is invalid
        """
        config.validate()
        self.config = config
        self._lock = RLock()

        # Initialize logging service first
        self.logging_service = logging_service or LoggingService(config)

        # Initialize cache service
        self.cache_service = cache_service or DNSCacheService(
            max_size=config.cache_size,
            logging_service=self.logging_service
        )

        # Initialize upstream service
        upstream_model = UpstreamService(
            service_url=config.upstream_dns_url,
            timeout_connect=config.upstream_timeout_connect,
            timeout_read=config.upstream_timeout_read,
            retry_attempts=config.upstream_retry_attempts,
            circuit_breaker_timeout=config.circuit_breaker_timeout,
            failure_threshold=config.circuit_breaker_failure_threshold
        )

        self.upstream_service = upstream_service or UpstreamDoHService(
            upstream_model,
            logging_service=self.logging_service
        )

        # Rate limiting state (if enabled)
        self._rate_limiter = None
        if config.rate_limit_enabled:
            self._rate_limiter = self._initialize_rate_limiter()

        # Service statistics
        self._stats = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "upstream_queries": 0,
            "upstream_errors": 0,
            "validation_errors": 0,
            "rate_limit_errors": 0,
            "circuit_breaker_errors": 0,
            "total_response_time": 0.0
        }

        self._service_start_time = datetime.utcnow()

        self.logging_service.info(
            "DNS proxy service initialized",
            extra={
                "component": "dns_proxy_service",
                "cache_size": config.cache_size,
                "upstream_url": config.upstream_dns_url,
                "rate_limit_enabled": config.rate_limit_enabled
            }
        )

    def resolve(self, query_name: str, query_type: str,
                client_ip: Optional[str] = None,
                client_port: Optional[int] = None,
                request_id: Optional[str] = None,
                packet_size: Optional[int] = None) -> DNSResponse:
        """Resolve DNS query with caching and upstream fallback.

        Args:
            query_name: DNS query name
            query_type: DNS query type
            client_ip: Optional client IP for logging and rate limiting
            request_id: Optional request ID for tracing (auto-generated if None)

        Returns:
            DNS response from cache or upstream

        Raises:
            ValidationError: If query is invalid
            RateLimitExceededError: If rate limit is exceeded
            ServiceUnavailableError: If service is unavailable
            DNSProxyError: For other DNS proxy errors
        """
        start_time = time.time()
        if request_id is None:
            request_id = str(uuid.uuid4())[:8]

        try:
            # Check service health before processing
            self._check_service_health()

            # Validate and create DNS query
            dns_query = DNSQuery(
                query_name=query_name,
                query_type=query_type,
                client_ip=client_ip or "unknown",
                client_port=client_port or 0,
                request_id=request_id or "unknown",
                packet_size=packet_size or 0
            )
            dns_query.validate()

            # Log incoming request with full service coordination
            self.logging_service.log_request(
                client_ip=client_ip or "unknown",
                query_name=query_name,
                query_type=query_type,
                request_id=request_id
            )

            # Check rate limiting
            if self._rate_limiter and client_ip:
                self._check_rate_limit(client_ip)

            # Update statistics
            with self._lock:
                self._stats["total_queries"] += 1

            # Try cache first
            cached_response = self._try_cache(dns_query, request_id)
            if cached_response:
                response_time = (time.time() - start_time) * 1000
                with self._lock:
                    self._stats["cache_hits"] += 1
                    self._stats["total_response_time"] += response_time

                # Update cached response time
                cached_response.response_time = response_time

                # Log response
                self.logging_service.log_response(
                    query_name=query_name,
                    query_type=query_type,
                    upstream_source="cache",
                    response_time=response_time,
                    answer_count=cached_response.get_answer_count(),
                    ttl=cached_response.ttl,
                    request_id=request_id
                )

                return cached_response

            # Cache miss - query upstream
            with self._lock:
                self._stats["cache_misses"] += 1

            upstream_response = self._query_upstream(dns_query, request_id)
            response_time = (time.time() - start_time) * 1000

            # Update response time
            upstream_response.response_time = response_time

            # Cache the response if TTL > 0
            if upstream_response.ttl > 0:
                self._try_cache_response(upstream_response, request_id)

            # Update statistics
            with self._lock:
                self._stats["upstream_queries"] += 1
                self._stats["total_response_time"] += response_time

            # Log response
            self.logging_service.log_response(
                query_name=query_name,
                query_type=query_type,
                upstream_source="upstream",
                response_time=response_time,
                answer_count=upstream_response.get_answer_count(),
                ttl=upstream_response.ttl,
                request_id=request_id
            )

            return upstream_response

        except ValidationError as e:
            with self._lock:
                self._stats["validation_errors"] += 1
            self.logging_service.error(f"Query validation failed: {e}", error=e, extra={
                "component": "dns_proxy_service",
                "request_id": request_id,
                "query_name": query_name,
                "query_type": query_type
            })
            raise

        except RateLimitExceededError as e:
            with self._lock:
                self._stats["rate_limit_errors"] += 1
            self.logging_service.warning(f"Rate limit exceeded: {e}", extra={
                "component": "dns_proxy_service",
                "request_id": request_id,
                "client_ip": client_ip
            })
            raise

        except CircuitBreakerOpenError as e:
            with self._lock:
                self._stats["circuit_breaker_errors"] += 1
            self.logging_service.warning(f"Circuit breaker open: {e}", extra={
                "component": "dns_proxy_service",
                "request_id": request_id,
                "upstream_url": self.config.upstream_dns_url
            })
            raise

        except Exception as e:
            with self._lock:
                self._stats["upstream_errors"] += 1

            # Log the error
            self.logging_service.error(f"DNS resolution failed: {e}", error=e, extra={
                "component": "dns_proxy_service",
                "request_id": request_id,
                "query_name": query_name,
                "query_type": query_type
            })

            # Re-raise known DNS proxy errors
            if isinstance(e, DNSProxyError):
                raise

            # Wrap unknown errors
            raise ServiceUnavailableError(
                f"DNS resolution failed: {e}",
                reason="internal_error"
            )

    def _check_service_health(self) -> None:
        """Check all service components health before processing requests.

        Raises:
            ServiceUnavailableError: If critical services are unhealthy
        """
        # Check upstream service health
        if not self.upstream_service.upstream_service.is_healthy():
            # Log degraded service but continue (we might have cache hits)
            self.logging_service.warning(
                "Upstream service is unhealthy, operating in degraded mode",
                extra={
                    "component": "dns_proxy_service",
                    "upstream_status": self.upstream_service.upstream_service.get_health_status()
                }
            )

        # Check cache service status (basic validation)
        try:
            cache_size = len(self.cache_service)
            if cache_size >= self.config.cache_size:
                self.logging_service.warning(
                    "Cache is at maximum capacity, cleanup may be needed",
                    extra={
                        "component": "dns_proxy_service",
                        "cache_size": cache_size,
                        "cache_max": self.config.cache_size
                    }
                )
        except Exception as e:
            self.logging_service.error(
                f"Cache service health check failed: {e}",
                error=e,
                extra={"component": "dns_proxy_service"}
            )

    def _try_cache(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> Optional[DNSResponse]:
        """Try to get response from cache.

        Args:
            dns_query: DNS query
            request_id: Optional request ID for tracing

        Returns:
            Cached response or None if not found
        """
        try:
            return self.cache_service.get(dns_query.query_name, dns_query.query_type, request_id)
        except Exception as e:
            # Log cache error but don't fail the request
            self.logging_service.warning(f"Cache lookup failed: {e}", extra={
                "component": "dns_proxy_service",
                "query_name": dns_query.query_name,
                "query_type": dns_query.query_type
            })
            return None

    def _query_upstream(self, dns_query: DNSQuery, request_id: Optional[str] = None) -> DNSResponse:
        """Query upstream service.

        Args:
            dns_query: DNS query
            request_id: Optional request ID for tracing

        Returns:
            Response from upstream service

        Raises:
            DNSProxyError: If upstream query fails
        """
        try:
            return self.upstream_service.query(dns_query, request_id)
        except Exception as e:
            # Log upstream error
            self.logging_service.error(f"Upstream query failed: {e}", error=e, extra={
                "component": "dns_proxy_service",
                "query_name": dns_query.query_name,
                "query_type": dns_query.query_type,
                "upstream_url": self.config.upstream_dns_url
            })
            raise

    def _try_cache_response(self, response: DNSResponse, request_id: Optional[str] = None) -> None:
        """Try to cache response.

        Args:
            response: DNS response to cache
            request_id: Optional request ID for tracing
        """
        try:
            self.cache_service.set(response, request_id)
        except Exception as e:
            # Log cache error but don't fail the request
            self.logging_service.warning(f"Cache storage failed: {e}", extra={
                "component": "dns_proxy_service",
                "query_name": response.query_name,
                "query_type": response.query_type
            })

    def _check_rate_limit(self, client_ip: str) -> None:
        """Check rate limiting for client IP.

        Args:
            client_ip: Client IP address

        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        if not self._rate_limiter:
            return

        # Simple rate limiting implementation
        # In production, you'd use a more sophisticated rate limiter
        current_time = datetime.utcnow()
        window_start = current_time.replace(second=0, microsecond=0)

        if client_ip not in self._rate_limiter:
            self._rate_limiter[client_ip] = {"window": window_start, "count": 0}

        client_data = self._rate_limiter[client_ip]

        # Reset counter if new window
        if client_data["window"] < window_start:
            client_data["window"] = window_start
            client_data["count"] = 0

        # Check limit
        if client_data["count"] >= self.config.rate_limit_requests_per_minute:
            raise RateLimitExceededError(
                f"Rate limit exceeded for {client_ip}",
                client_ip=client_ip,
                limit=self.config.rate_limit_requests_per_minute,
                window_seconds=60,
                retry_after=60
            )

        # Increment counter
        client_data["count"] += 1

    def _initialize_rate_limiter(self) -> Dict[str, Dict[str, Any]]:
        """Initialize rate limiter state.

        Returns:
            Rate limiter state dictionary
        """
        return {}

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive service statistics.

        Returns:
            Dictionary with service statistics
        """
        with self._lock:
            # Calculate derived statistics
            total_queries = self._stats["total_queries"]
            cache_hit_rate = (
                (self._stats["cache_hits"] / total_queries * 100)
                if total_queries > 0 else 0.0
            )
            avg_response_time = (
                (self._stats["total_response_time"] / total_queries)
                if total_queries > 0 else 0.0
            )
            uptime_seconds = (datetime.utcnow() - self._service_start_time).total_seconds()

            # Get component statistics
            cache_stats = self.cache_service.get_stats()
            upstream_stats = self.upstream_service.get_health_status()

            return {
                "service": {
                    "uptime_seconds": round(uptime_seconds, 2),
                    "start_time": self._service_start_time.isoformat(),
                    "total_queries": total_queries,
                    "cache_hit_rate": round(cache_hit_rate, 2),
                    "average_response_time": round(avg_response_time, 2),
                    "rate_limit_enabled": self.config.rate_limit_enabled
                },
                "queries": {
                    "total": total_queries,
                    "cache_hits": self._stats["cache_hits"],
                    "cache_misses": self._stats["cache_misses"],
                    "upstream_queries": self._stats["upstream_queries"]
                },
                "errors": {
                    "upstream_errors": self._stats["upstream_errors"],
                    "validation_errors": self._stats["validation_errors"],
                    "rate_limit_errors": self._stats["rate_limit_errors"],
                    "circuit_breaker_errors": self._stats["circuit_breaker_errors"]
                },
                "cache": cache_stats,
                "upstream": upstream_stats,
                "config": {
                    "cache_size": self.config.cache_size,
                    "upstream_url": self.config.upstream_dns_url,
                    "upstream_timeout_read": self.config.upstream_timeout_read,
                    "circuit_breaker_threshold": self.config.circuit_breaker_failure_threshold
                }
            }

    def get_health_status(self) -> Dict[str, Any]:
        """Get service health status.

        Returns:
            Dictionary with health status
        """
        upstream_healthy = self.upstream_service.upstream_service.is_healthy()
        cache_size = len(self.cache_service)

        # Determine overall health
        is_healthy = upstream_healthy and cache_size < self.config.cache_size * 0.95

        health_status = "healthy"
        if not upstream_healthy:
            health_status = "degraded"
        elif cache_size >= self.config.cache_size * 0.95:
            health_status = "warning"

        return {
            "status": health_status,
            "healthy": is_healthy,
            "components": {
                "upstream": {
                    "healthy": upstream_healthy,
                    "status": self.upstream_service.upstream_service.get_health_status()
                },
                "cache": {
                    "healthy": cache_size < self.config.cache_size * 0.95,
                    "utilization": cache_size / self.config.cache_size * 100,
                    "size": cache_size,
                    "max_size": self.config.cache_size
                }
            },
            "uptime": (datetime.utcnow() - self._service_start_time).total_seconds()
        }

    def cleanup_cache(self) -> Dict[str, int]:
        """Cleanup expired cache entries.

        Returns:
            Dictionary with cleanup statistics
        """
        try:
            expired_count = self.cache_service.cleanup_expired()
            self.logging_service.info(f"Cache cleanup completed", extra={
                "component": "dns_proxy_service",
                "expired_entries": expired_count,
                "remaining_entries": len(self.cache_service)
            })
            return {"expired_entries": expired_count, "remaining_entries": len(self.cache_service)}
        except Exception as e:
            self.logging_service.error(f"Cache cleanup failed: {e}", error=e)
            return {"expired_entries": 0, "remaining_entries": len(self.cache_service)}

    def reset_circuit_breaker(self) -> None:
        """Manually reset upstream circuit breaker."""
        self.upstream_service.reset_circuit_breaker()
        self.logging_service.info("Circuit breaker manually reset", extra={
            "component": "dns_proxy_service",
            "upstream_url": self.config.upstream_dns_url
        })

    def reset_stats(self) -> None:
        """Reset all service statistics."""
        with self._lock:
            self._stats = {
                "total_queries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "upstream_queries": 0,
                "upstream_errors": 0,
                "validation_errors": 0,
                "rate_limit_errors": 0,
                "circuit_breaker_errors": 0,
                "total_response_time": 0.0
            }
            self._service_start_time = datetime.utcnow()

        # Reset component statistics
        self.cache_service.reset_stats()
        self.upstream_service.reset_stats()

        self.logging_service.info("Service statistics reset", extra={
            "component": "dns_proxy_service"
        })

    def shutdown(self) -> None:
        """Shutdown service gracefully with comprehensive cleanup."""
        self.logging_service.info("Shutting down DNS proxy service", extra={
            "component": "dns_proxy_service"
        })

        # Step 1: Stop accepting new requests (handled by server)
        # Step 2: Cleanup cache with final statistics
        try:
            cache_stats = self.cache_service.get_stats()
            self.logging_service.info("Final cache statistics", extra={
                "component": "dns_proxy_service",
                "cache_size": len(self.cache_service),
                "cache_stats": cache_stats
            })

            cleanup_result = self.cleanup_cache()
            self.logging_service.info("Cache cleanup completed", extra={
                "component": "dns_proxy_service",
                "cleanup_result": cleanup_result
            })

            # Shutdown cache service
            self.cache_service.shutdown()

        except Exception as e:
            self.logging_service.warning(f"Cache cleanup during shutdown failed: {e}")

        # Step 3: Shutdown upstream service (reset circuit breaker state)
        try:
            upstream_stats = self.upstream_service.get_health_status()
            self.logging_service.info("Final upstream statistics", extra={
                "component": "dns_proxy_service",
                "upstream_stats": upstream_stats
            })

            # Reset circuit breaker to clean state for next startup
            if hasattr(self.upstream_service, 'shutdown'):
                self.upstream_service.shutdown()
        except Exception as e:
            self.logging_service.warning(f"Upstream service shutdown failed: {e}")

        # Step 4: Clear service statistics and state
        try:
            final_stats = dict(self._stats)
            self.logging_service.info("Final service statistics", extra={
                "component": "dns_proxy_service",
                "final_stats": final_stats
            })

            # Clear internal state
            with self._lock:
                self._stats.clear()
                if self._rate_limiter:
                    self._rate_limiter.clear()

        except Exception as e:
            self.logging_service.warning(f"State cleanup failed: {e}")

        # Step 5: Shutdown logging service last
        try:
            self.logging_service.info("DNS proxy service shutdown complete", extra={
                "component": "dns_proxy_service"
            })
            # Flush any remaining logs before shutdown
            self.logging_service.flush()
            self.logging_service.shutdown()
        except Exception as e:
            print(f"Logging shutdown failed: {e}")

    @classmethod
    def create_default(cls, config: Optional[DNSProxyConfig] = None) -> 'DNSProxyService':
        """Create DNS proxy service with default configuration.

        Args:
            config: Optional configuration. Uses default if None.

        Returns:
            DNSProxyService with default settings
        """
        if config is None:
            from ..lib.config import load_config
            config = load_config()

        return cls(config)

    def __enter__(self) -> 'DNSProxyService':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with graceful shutdown."""
        if exc_type:
            self.logging_service.error(
                f"Exception in DNS proxy service context: {exc_val}",
                error=exc_val
            )
        self.shutdown()


def parse_dns_query(packet_data: bytes) -> DNSQuery:
    """Parse DNS query packet and extract query information.

    Args:
        packet_data: Raw DNS packet bytes

    Returns:
        DNSQuery object with extracted information

    Raises:
        ValidationError: If packet is malformed or invalid
    """
    try:
        from dnslib import DNSRecord

        # Parse DNS packet
        record = DNSRecord.parse(packet_data)

        # Extract query information
        if not record.questions:
            raise ValidationError("DNS packet contains no questions")

        question = record.questions[0]
        query_name = str(question.qname)

        # Map QTYPE to string representation
        from dnslib import QTYPE
        qtype_map = {
            QTYPE.A: "A",
            QTYPE.AAAA: "AAAA",
            QTYPE.CNAME: "CNAME",
            QTYPE.MX: "MX",
            QTYPE.TXT: "TXT",
            QTYPE.PTR: "PTR",
            QTYPE.NS: "NS",
            QTYPE.SOA: "SOA"
        }
        query_type = qtype_map.get(question.qtype, str(question.qtype))
        request_id = str(record.header.id)

        # Create DNSQuery object
        dns_query = DNSQuery(
            query_name=query_name,
            query_type=query_type,
            client_ip="0.0.0.0",  # Will be set by caller
            client_port=0,        # Will be set by caller
            request_id=request_id,
            packet_size=len(packet_data)
        )

        return dns_query

    except Exception as e:
        raise ValidationError(f"Failed to parse DNS packet: {e}") from e