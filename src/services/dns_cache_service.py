"""TTL-aware DNS cache service using cachetools.

This module provides a TTL-aware DNS cache with LRU eviction policy,
proper expiration handling, and comprehensive logging.
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from threading import RLock

from cachetools import TTLCache

from ..models.cache_entry import CacheEntry
from ..models.dns_response import DNSResponse
from ..lib.exceptions import CacheError, ValidationError
from ..services.logging_service import LoggingService


class DNSCacheService:
    """TTL-aware DNS cache service with LRU eviction."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300,
                 logging_service: Optional[LoggingService] = None):
        """Initialize DNS cache service.

        Args:
            max_size: Maximum number of cache entries
            default_ttl: Default TTL for entries without explicit TTL
            logging_service: Optional logging service for structured logging

        Raises:
            ValueError: If max_size is invalid
        """
        if max_size <= 0:
            raise ValueError("Cache max_size must be positive")

        if default_ttl < 0:
            raise ValueError("Default TTL must be non-negative")

        self.max_size = max_size
        self.default_ttl = default_ttl
        self.logging_service = logging_service

        # Thread-safe TTL cache with LRU eviction
        self._cache: TTLCache = TTLCache(maxsize=max_size, ttl=default_ttl)
        self._lock = RLock()

        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "expired": 0,
            "evicted": 0
        }

        self._log_debug("DNS cache service initialized", {
            "max_size": max_size,
            "default_ttl": default_ttl
        })

    def get(self, query_name: str, query_type: str, request_id: Optional[str] = None) -> Optional[DNSResponse]:
        """Get cached DNS response.

        Args:
            query_name: DNS query name
            query_type: DNS query type
            request_id: Optional request ID for tracing

        Returns:
            Cached DNS response or None if not found/expired

        Raises:
            ValidationError: If query parameters are invalid
            CacheError: If cache operation fails
        """
        self._validate_query_params(query_name, query_type)
        cache_key = self._create_cache_key(query_name, query_type)

        try:
            with self._lock:
                cache_entry = self._cache.get(cache_key)

                if cache_entry is None:
                    self._stats["misses"] += 1
                    self._log_cache_operation("get", cache_key, hit=False, request_id=request_id)
                    return None

                # Check if entry has expired (double-check)
                if cache_entry.is_expired():
                    # Remove expired entry
                    del self._cache[cache_key]
                    self._stats["expired"] += 1
                    self._stats["misses"] += 1
                    self._log_cache_operation("get", cache_key, hit=False, request_id=request_id)
                    return None

                # Record access and return response
                cache_entry.access()
                self._stats["hits"] += 1

                # Convert cache entry back to DNS response
                response = self._cache_entry_to_response(cache_entry)

                self._log_cache_operation("get", cache_key, hit=True, size=len(self._cache), request_id=request_id)
                return response

        except Exception as e:
            raise CacheError(f"Failed to get cache entry: {e}", cache_key, "get")

    def set(self, response: DNSResponse, request_id: Optional[str] = None) -> None:
        """Store DNS response in cache.

        Args:
            response: DNS response to cache
            request_id: Optional request ID for tracing

        Raises:
            ValidationError: If response is invalid
            CacheError: If cache operation fails
        """
        if not isinstance(response, DNSResponse):
            raise ValidationError("Response must be a DNSResponse instance")

        response.validate()

        # Don't cache responses with TTL of 0
        if response.ttl <= 0:
            return

        cache_key = self._create_cache_key(response.query_name, response.query_type)

        try:
            with self._lock:
                # Create cache entry
                cache_entry = CacheEntry.create(
                    query_name=response.query_name,
                    query_type=response.query_type,
                    response_data=self._response_to_cache_data(response),
                    ttl_seconds=response.ttl
                )

                # Store in cache with TTL
                old_size = len(self._cache)
                self._cache[cache_key] = cache_entry
                new_size = len(self._cache)

                # Track evictions
                if new_size <= old_size:
                    self._stats["evicted"] += old_size - new_size + 1

                self._stats["sets"] += 1
                self._log_cache_operation("set", cache_key, size=new_size, request_id=request_id)

        except Exception as e:
            raise CacheError(f"Failed to set cache entry: {e}", cache_key, "set")

    def delete(self, query_name: str, query_type: str) -> bool:
        """Delete cached DNS response.

        Args:
            query_name: DNS query name
            query_type: DNS query type

        Returns:
            True if entry was deleted, False if not found

        Raises:
            ValidationError: If query parameters are invalid
            CacheError: If cache operation fails
        """
        self._validate_query_params(query_name, query_type)
        cache_key = self._create_cache_key(query_name, query_type)

        try:
            with self._lock:
                if cache_key in self._cache:
                    del self._cache[cache_key]
                    self._stats["deletes"] += 1
                    self._log_cache_operation("delete", cache_key, size=len(self._cache))
                    return True
                return False

        except Exception as e:
            raise CacheError(f"Failed to delete cache entry: {e}", cache_key, "delete")

    def clear(self) -> None:
        """Clear all cache entries.

        Raises:
            CacheError: If cache operation fails
        """
        try:
            with self._lock:
                entries_count = len(self._cache)
                self._cache.clear()
                self._log_debug("Cache cleared", {"entries_removed": entries_count})

        except Exception as e:
            raise CacheError(f"Failed to clear cache: {e}", operation="clear")

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of expired entries removed

        Raises:
            CacheError: If cleanup operation fails
        """
        try:
            with self._lock:
                current_time = datetime.utcnow()
                expired_keys = []

                # Find expired entries
                for key, entry in self._cache.items():
                    if entry.is_expired(current_time):
                        expired_keys.append(key)

                # Remove expired entries
                for key in expired_keys:
                    del self._cache[key]

                expired_count = len(expired_keys)
                self._stats["expired"] += expired_count

                if expired_count > 0:
                    self._log_debug("Expired entries cleaned", {
                        "expired_count": expired_count,
                        "remaining_size": len(self._cache)
                    })

                return expired_count

        except Exception as e:
            raise CacheError(f"Failed to cleanup expired entries: {e}", operation="cleanup")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "utilization": len(self._cache) / self.max_size * 100,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "hit_rate": round(hit_rate, 2),
                "sets": self._stats["sets"],
                "deletes": self._stats["deletes"],
                "expired": self._stats["expired"],
                "evicted": self._stats["evicted"],
                "total_requests": total_requests
            }

    def get_entries(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get cache entries for debugging/monitoring.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of cache entry dictionaries
        """
        with self._lock:
            entries = []
            count = 0

            for key, entry in self._cache.items():
                if limit and count >= limit:
                    break

                query_name, query_type = key
                entries.append({
                    "query_name": query_name,
                    "query_type": query_type,
                    "hit_count": entry.hit_count,
                    "stored_at": entry.stored_at.isoformat(),
                    "expires_at": entry.expires_at.isoformat(),
                    "age_seconds": entry.get_age(),
                    "remaining_ttl": entry.get_remaining_ttl(),
                    "is_expired": entry.is_expired()
                })
                count += 1

            return entries

    def contains(self, query_name: str, query_type: str) -> bool:
        """Check if cache contains entry (without accessing it).

        Args:
            query_name: DNS query name
            query_type: DNS query type

        Returns:
            True if cache contains non-expired entry
        """
        try:
            self._validate_query_params(query_name, query_type)
            cache_key = self._create_cache_key(query_name, query_type)

            with self._lock:
                if cache_key not in self._cache:
                    return False

                entry = self._cache[cache_key]
                return not entry.is_expired()

        except Exception:
            return False

    def _create_cache_key(self, query_name: str, query_type: str) -> Tuple[str, str]:
        """Create cache key from query parameters.

        Args:
            query_name: DNS query name
            query_type: DNS query type

        Returns:
            Cache key tuple
        """
        # Normalize query name to lowercase for case-insensitive caching
        return (query_name.lower(), query_type.upper())

    def _validate_query_params(self, query_name: str, query_type: str) -> None:
        """Validate query parameters.

        Args:
            query_name: DNS query name
            query_type: DNS query type

        Raises:
            ValidationError: If parameters are invalid
        """
        if not query_name or not isinstance(query_name, str):
            raise ValidationError("Query name must be a non-empty string", "query_name", query_name)

        if not query_type or not isinstance(query_type, str):
            raise ValidationError("Query type must be a non-empty string", "query_type", query_type)

    def _response_to_cache_data(self, response: DNSResponse) -> Dict[str, Any]:
        """Convert DNS response to cache data format.

        Args:
            response: DNS response

        Returns:
            Cache data dictionary
        """
        return {
            "Answer": response.answers,
            "response_size": response.response_size,
            "upstream_source": response.upstream_source,
            "response_time": response.response_time,
            "timestamp": response.timestamp.isoformat() if response.timestamp else None
        }

    def _cache_entry_to_response(self, cache_entry: CacheEntry) -> DNSResponse:
        """Convert cache entry to DNS response.

        Args:
            cache_entry: Cache entry

        Returns:
            DNS response
        """
        query_name, query_type = cache_entry.cache_key
        data = cache_entry.response_data

        timestamp = None
        if data.get("timestamp"):
            timestamp = datetime.fromisoformat(data["timestamp"])

        return DNSResponse(
            query_name=query_name,
            query_type=query_type,
            answers=data.get("Answer", []),
            response_size=data.get("response_size", 0),
            ttl=cache_entry.get_remaining_ttl(),
            upstream_source="cache",  # Always mark as cache source
            response_time=data.get("response_time", 0.0),
            timestamp=timestamp
        )

    def _log_cache_operation(self, operation: str, cache_key: Tuple[str, str],
                           hit: Optional[bool] = None, size: Optional[int] = None,
                           request_id: Optional[str] = None) -> None:
        """Log cache operation using logging service.

        Args:
            operation: Cache operation
            cache_key: Cache key
            hit: Whether operation was a hit
            size: Current cache size
            request_id: Optional request ID for tracing
        """
        if self.logging_service:
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

            if request_id:
                extra["request_id"] = request_id

            if operation == "get":
                status = "hit" if hit else "miss"
                self.logging_service.debug(f"Cache {operation}: {query_name} {query_type} ({status})", extra)
            else:
                self.logging_service.debug(f"Cache {operation}: {query_name} {query_type}", extra)

    def shutdown(self) -> None:
        """Shutdown cache service gracefully."""
        if self.logging_service:
            self.logging_service.info("Shutting down DNS cache service", extra={
                "component": "dns_cache",
                "final_cache_size": len(self._cache),
                "final_stats": self._stats
            })

        try:
            with self._lock:
                # Clear all cache entries
                cache_size = len(self._cache)
                self._cache.clear()

                # Clear statistics
                self._stats.clear()

                if self.logging_service:
                    self.logging_service.info("DNS cache service shutdown complete", extra={
                        "component": "dns_cache",
                        "cleared_entries": cache_size
                    })

        except Exception as e:
            if self.logging_service:
                self.logging_service.warning(f"Error during cache service shutdown: {e}")

    def _log_debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message using logging service.

        Args:
            message: Log message
            extra: Additional context
        """
        if self.logging_service:
            context = {"component": "dns_cache"}
            if extra:
                context.update(extra)
            self.logging_service.debug(message, context)

    def reset_stats(self) -> None:
        """Reset cache statistics."""
        with self._lock:
            self._stats = {
                "hits": 0,
                "misses": 0,
                "sets": 0,
                "deletes": 0,
                "expired": 0,
                "evicted": 0
            }
            self._log_debug("Cache statistics reset")

    @classmethod
    def create_default(cls, logging_service: Optional[LoggingService] = None) -> 'DNSCacheService':
        """Create DNS cache service with default configuration.

        Args:
            logging_service: Optional logging service

        Returns:
            DNSCacheService with default settings
        """
        return cls(max_size=1000, default_ttl=300, logging_service=logging_service)

    def __len__(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: Tuple[str, str]) -> bool:
        """Check if cache contains key."""
        if isinstance(key, tuple) and len(key) == 2:
            query_name, query_type = key
            return self.contains(query_name, query_type)
        return False

    def __enter__(self) -> 'DNSCacheService':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        if exc_type:
            self._log_debug(f"Exception in cache context: {exc_val}")
        self.cleanup_expired()