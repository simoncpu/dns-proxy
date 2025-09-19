"""DNS Response model with validation.

This module provides the DNSResponse data model that represents DNS responses
with proper validation and TTL handling according to the service contract.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class DNSResponse:
    """DNS Response model representing responses from upstream or cache."""

    query_name: str
    query_type: str
    answers: List[Dict[str, Any]]
    response_size: int
    ttl: int
    upstream_source: str
    response_time: float
    timestamp: Optional[datetime] = None

    # Valid upstream sources
    VALID_SOURCES = {"upstream", "cache"}

    def __post_init__(self):
        """Initialize timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def validate(self) -> None:
        """Validate DNS response according to contract requirements.

        Raises:
            ValueError: If any validation rule fails.
        """
        self._validate_query_name()
        self._validate_query_type()
        self._validate_answers()
        self._validate_response_size()
        self._validate_ttl()
        self._validate_upstream_source()
        self._validate_response_time()

    def _validate_query_name(self) -> None:
        """Validate query name format."""
        if not self.query_name:
            raise ValueError("Query name cannot be empty")

        if not isinstance(self.query_name, str):
            raise ValueError("Query name must be a string")

    def _validate_query_type(self) -> None:
        """Validate query type."""
        if not self.query_type:
            raise ValueError("Query type cannot be empty")

        if not isinstance(self.query_type, str):
            raise ValueError("Query type must be a string")

        # Reference supported types from DNSQuery
        from .dns_query import DNSQuery
        if self.query_type not in DNSQuery.SUPPORTED_TYPES:
            raise ValueError(f"Unsupported query type: {self.query_type}")

    def _validate_answers(self) -> None:
        """Validate DNS answer records format."""
        if not isinstance(self.answers, list):
            raise ValueError("Answers must be a list")

        # Empty answers are valid (NXDOMAIN case)
        for i, answer in enumerate(self.answers):
            if not isinstance(answer, dict):
                raise ValueError(f"Answer {i} must be a dictionary")

            # Validate required fields in answer
            required_fields = {"name", "data"}
            for field in required_fields:
                if field not in answer:
                    raise ValueError(f"Answer {i} missing required field: {field}")

            # Validate answer data types
            if not isinstance(answer["name"], str):
                raise ValueError(f"Answer {i} name must be a string")

            if not isinstance(answer["data"], str):
                raise ValueError(f"Answer {i} data must be a string")

            # Validate TTL if present
            if "TTL" in answer:
                ttl_value = answer["TTL"]
                if not isinstance(ttl_value, int) or ttl_value < 0:
                    raise ValueError(f"Answer {i} TTL must be a non-negative integer")

    def _validate_response_size(self) -> None:
        """Validate response size according to DNS limits."""
        if not isinstance(self.response_size, int):
            raise ValueError("Response size must be an integer")

        if self.response_size <= 0:
            raise ValueError(f"Response size must be positive, got: {self.response_size}")

        # Reasonable upper bound for DNS responses (4KB)
        if self.response_size > 4096:
            raise ValueError(f"Response size exceeds reasonable limit of 4KB: {self.response_size}")

    def _validate_ttl(self) -> None:
        """Validate TTL value."""
        if not isinstance(self.ttl, int):
            raise ValueError("TTL must be an integer")

        if self.ttl < 0:
            raise ValueError(f"TTL must be non-negative, got: {self.ttl}")

        # Maximum TTL according to RFC (2^31 - 1 seconds)
        max_ttl = 2147483647
        if self.ttl > max_ttl:
            raise ValueError(f"TTL exceeds maximum value: {self.ttl}")

    def _validate_upstream_source(self) -> None:
        """Validate upstream source value."""
        if not self.upstream_source:
            raise ValueError("Upstream source cannot be empty")

        if self.upstream_source not in self.VALID_SOURCES:
            raise ValueError(f"Invalid upstream source: {self.upstream_source}. "
                           f"Valid sources: {', '.join(self.VALID_SOURCES)}")

    def _validate_response_time(self) -> None:
        """Validate response time."""
        if not isinstance(self.response_time, (int, float)):
            raise ValueError("Response time must be a number")

        if self.response_time < 0:
            raise ValueError(f"Response time must be positive, got: {self.response_time}")

        # Reasonable upper bound (30 seconds)
        if self.response_time > 30000:  # milliseconds
            raise ValueError(f"Response time exceeds reasonable limit: {self.response_time}ms")

    def get_minimum_ttl(self) -> int:
        """Get minimum TTL from all answer records."""
        if not self.answers:
            return self.ttl

        min_ttl = self.ttl
        for answer in self.answers:
            if "TTL" in answer:
                min_ttl = min(min_ttl, answer["TTL"])

        return min_ttl

    def is_from_cache(self) -> bool:
        """Check if response is from cache."""
        return self.upstream_source == "cache"

    def is_from_upstream(self) -> bool:
        """Check if response is from upstream."""
        return self.upstream_source == "upstream"

    def has_answers(self) -> bool:
        """Check if response has answer records."""
        return len(self.answers) > 0

    def get_answer_count(self) -> int:
        """Get number of answer records."""
        return len(self.answers)

    def to_dict(self) -> Dict[str, Any]:
        """Convert DNS response to dictionary for logging/serialization."""
        return {
            "query_name": self.query_name,
            "query_type": self.query_type,
            "answers": self.answers,
            "response_size": self.response_size,
            "ttl": self.ttl,
            "upstream_source": self.upstream_source,
            "response_time": self.response_time,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "answer_count": self.get_answer_count(),
            "min_ttl": self.get_minimum_ttl(),
            "from_cache": self.is_from_cache()
        }

    def __str__(self) -> str:
        """String representation of DNS response."""
        source_str = "cache" if self.is_from_cache() else "upstream"
        return (f"DNSResponse({self.query_name} {self.query_type}: "
                f"{self.get_answer_count()} answers from {source_str}, "
                f"TTL={self.ttl}s, {self.response_time:.1f}ms)")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DNSResponse':
        """Create DNS response from dictionary."""
        timestamp = None
        if data.get('timestamp'):
            timestamp = datetime.fromisoformat(data['timestamp'])

        return cls(
            query_name=data['query_name'],
            query_type=data['query_type'],
            answers=data['answers'],
            response_size=data['response_size'],
            ttl=data['ttl'],
            upstream_source=data['upstream_source'],
            response_time=data['response_time'],
            timestamp=timestamp
        )

    @classmethod
    def create_empty_response(cls, query_name: str, query_type: str,
                            response_time: float, upstream_source: str = "upstream") -> 'DNSResponse':
        """Create empty response for NXDOMAIN cases."""
        return cls(
            query_name=query_name,
            query_type=query_type,
            answers=[],
            response_size=0,
            ttl=300,  # Default TTL for negative responses
            upstream_source=upstream_source,
            response_time=response_time
        )

    @classmethod
    def create_error_response(cls, query_name: str, query_type: str,
                            response_time: float, error_message: str) -> 'DNSResponse':
        """Create error response for failures."""
        return cls(
            query_name=query_name,
            query_type=query_type,
            answers=[],
            response_size=0,
            ttl=0,  # Don't cache error responses
            upstream_source="upstream",
            response_time=response_time
        )