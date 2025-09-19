"""Cache Entry model with TTL handling.

This module provides the CacheEntry data model that represents cached DNS responses
with proper TTL management and eviction metadata.
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """Cache Entry model representing cached DNS responses with TTL."""

    cache_key: Tuple[str, str]  # (query_name, query_type)
    response_data: Dict[str, Any]
    stored_at: datetime
    expires_at: datetime
    hit_count: int = 0
    last_accessed: Optional[datetime] = None

    def __post_init__(self):
        """Initialize last_accessed if not provided."""
        if self.last_accessed is None:
            self.last_accessed = self.stored_at

    def validate(self) -> None:
        """Validate cache entry according to contract requirements.

        Raises:
            ValueError: If any validation rule fails.
        """
        self._validate_cache_key()
        self._validate_response_data()
        self._validate_timestamps()
        self._validate_hit_count()

    def _validate_cache_key(self) -> None:
        """Validate cache key format."""
        if not isinstance(self.cache_key, tuple):
            raise ValueError("Cache key must be a tuple")

        if len(self.cache_key) != 2:
            raise ValueError("Cache key must be a tuple of (query_name, query_type)")

        query_name, query_type = self.cache_key

        if not isinstance(query_name, str) or not query_name:
            raise ValueError("Query name in cache key must be a non-empty string")

        if not isinstance(query_type, str) or not query_type:
            raise ValueError("Query type in cache key must be a non-empty string")

    def _validate_response_data(self) -> None:
        """Validate response data is a valid JSON structure."""
        if not isinstance(self.response_data, dict):
            raise ValueError("Response data must be a dictionary")

        # Basic structure validation
        if "Answer" in self.response_data:
            if not isinstance(self.response_data["Answer"], list):
                raise ValueError("Response data Answer field must be a list")

    def _validate_timestamps(self) -> None:
        """Validate timestamp relationships."""
        if not isinstance(self.stored_at, datetime):
            raise ValueError("stored_at must be a datetime object")

        if not isinstance(self.expires_at, datetime):
            raise ValueError("expires_at must be a datetime object")

        if self.expires_at <= self.stored_at:
            raise ValueError("expires_at must be after stored_at")

        if self.last_accessed and not isinstance(self.last_accessed, datetime):
            raise ValueError("last_accessed must be a datetime object or None")

        if self.last_accessed and self.last_accessed < self.stored_at:
            raise ValueError("last_accessed cannot be before stored_at")

    def _validate_hit_count(self) -> None:
        """Validate hit count."""
        if not isinstance(self.hit_count, int):
            raise ValueError("Hit count must be an integer")

        if self.hit_count < 0:
            raise ValueError("Hit count must be non-negative")

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check if cache entry has expired.

        Args:
            current_time: Current time for comparison. Uses utcnow() if None.

        Returns:
            True if entry has expired, False otherwise.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        return current_time >= self.expires_at

    def time_to_expire(self, current_time: Optional[datetime] = None) -> float:
        """Get time remaining until expiration in seconds.

        Args:
            current_time: Current time for comparison. Uses utcnow() if None.

        Returns:
            Seconds until expiration. Negative if already expired.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        delta = self.expires_at - current_time
        return delta.total_seconds()

    def access(self, current_time: Optional[datetime] = None) -> None:
        """Record access to this cache entry.

        Args:
            current_time: Current time for access recording. Uses utcnow() if None.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        self.hit_count += 1
        self.last_accessed = current_time

    def get_age(self, current_time: Optional[datetime] = None) -> float:
        """Get age of cache entry in seconds.

        Args:
            current_time: Current time for comparison. Uses utcnow() if None.

        Returns:
            Age in seconds since storage.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        delta = current_time - self.stored_at
        return delta.total_seconds()

    def get_ttl_seconds(self) -> int:
        """Get original TTL in seconds."""
        delta = self.expires_at - self.stored_at
        return int(delta.total_seconds())

    def get_remaining_ttl(self, current_time: Optional[datetime] = None) -> int:
        """Get remaining TTL in seconds.

        Args:
            current_time: Current time for comparison. Uses utcnow() if None.

        Returns:
            Remaining TTL in seconds. 0 if expired.
        """
        remaining = self.time_to_expire(current_time)
        return max(0, int(remaining))

    def to_dict(self) -> Dict[str, Any]:
        """Convert cache entry to dictionary for serialization."""
        return {
            "cache_key": self.cache_key,
            "response_data": self.response_data,
            "stored_at": self.stored_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "hit_count": self.hit_count,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
            "age_seconds": self.get_age(),
            "remaining_ttl": self.get_remaining_ttl(),
            "is_expired": self.is_expired()
        }

    def __str__(self) -> str:
        """String representation of cache entry."""
        query_name, query_type = self.cache_key
        remaining = self.get_remaining_ttl()
        status = "expired" if self.is_expired() else f"{remaining}s remaining"
        return f"CacheEntry({query_name} {query_type}: {self.hit_count} hits, {status})"

    @classmethod
    def create(cls, query_name: str, query_type: str, response_data: Dict[str, Any],
               ttl_seconds: int, current_time: Optional[datetime] = None) -> 'CacheEntry':
        """Create a new cache entry with TTL.

        Args:
            query_name: DNS query name
            query_type: DNS query type
            response_data: Response data to cache
            ttl_seconds: TTL in seconds
            current_time: Current time. Uses utcnow() if None.

        Returns:
            New CacheEntry instance.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        cache_key = (query_name, query_type)
        expires_at = current_time + timedelta(seconds=ttl_seconds)

        return cls(
            cache_key=cache_key,
            response_data=response_data,
            stored_at=current_time,
            expires_at=expires_at,
            hit_count=0,
            last_accessed=current_time
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        """Create cache entry from dictionary.

        Args:
            data: Dictionary representation of cache entry.

        Returns:
            CacheEntry instance.
        """
        stored_at = datetime.fromisoformat(data['stored_at'])
        expires_at = datetime.fromisoformat(data['expires_at'])
        last_accessed = None
        if data.get('last_accessed'):
            last_accessed = datetime.fromisoformat(data['last_accessed'])

        return cls(
            cache_key=tuple(data['cache_key']),
            response_data=data['response_data'],
            stored_at=stored_at,
            expires_at=expires_at,
            hit_count=data['hit_count'],
            last_accessed=last_accessed
        )

    def update_expiration(self, new_ttl_seconds: int,
                         current_time: Optional[datetime] = None) -> None:
        """Update expiration time with new TTL.

        Args:
            new_ttl_seconds: New TTL in seconds
            current_time: Current time. Uses utcnow() if None.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        self.expires_at = current_time + timedelta(seconds=new_ttl_seconds)

    def refresh(self, new_response_data: Dict[str, Any], new_ttl_seconds: int,
                current_time: Optional[datetime] = None) -> None:
        """Refresh cache entry with new data and TTL.

        Args:
            new_response_data: New response data
            new_ttl_seconds: New TTL in seconds
            current_time: Current time. Uses utcnow() if None.
        """
        if current_time is None:
            current_time = datetime.utcnow()

        self.response_data = new_response_data
        self.stored_at = current_time
        self.expires_at = current_time + timedelta(seconds=new_ttl_seconds)
        self.last_accessed = current_time
        # Note: hit_count is preserved across refreshes