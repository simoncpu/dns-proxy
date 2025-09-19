"""DNS Query model with validation.

This module provides the DNSQuery data model that represents incoming DNS requests
with proper validation according to the DNS protocol and service contract.
"""
import ipaddress
import re
from datetime import datetime
from typing import Optional
from dataclasses import dataclass


@dataclass
class DNSQuery:
    """DNS Query model representing incoming DNS requests."""

    query_name: str
    query_type: str
    client_ip: str
    client_port: int
    request_id: str
    packet_size: int
    timestamp: Optional[datetime] = None

    # Supported DNS query types
    SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SOA"}

    def __post_init__(self):
        """Initialize timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def validate(self) -> None:
        """Validate DNS query according to contract requirements.

        Raises:
            ValueError: If any validation rule fails.
        """
        self._validate_query_name()
        self._validate_query_type()
        self._validate_client_ip()
        self._validate_client_port()
        self._validate_packet_size()
        self._validate_request_id()

    def _validate_query_name(self) -> None:
        """Validate domain name format according to RFC 1035."""
        if not self.query_name:
            raise ValueError("Query name cannot be empty")

        # Remove trailing dot if present for validation
        name = self.query_name.rstrip('.')

        if not name:
            raise ValueError("Query name cannot be just a dot")

        # Check overall length (RFC 1035: max 255 octets)
        if len(self.query_name.encode('ascii', errors='ignore')) > 255:
            raise ValueError("Query name exceeds maximum length of 255 octets")

        # Validate domain name format
        domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )

        if not domain_pattern.match(name):
            raise ValueError(f"Invalid domain name format: {self.query_name}")

        # Check label length (max 63 octets per label)
        labels = name.split('.')
        for label in labels:
            if len(label) > 63:
                raise ValueError(f"Domain label exceeds 63 characters: {label}")

    def _validate_query_type(self) -> None:
        """Validate DNS query type is supported."""
        if not self.query_type:
            raise ValueError("Query type cannot be empty")

        if self.query_type not in self.SUPPORTED_TYPES:
            raise ValueError(f"Unsupported query type: {self.query_type}. "
                           f"Supported types: {', '.join(sorted(self.SUPPORTED_TYPES))}")

    def _validate_client_ip(self) -> None:
        """Validate client IP address format (IPv4 or IPv6)."""
        if not self.client_ip:
            raise ValueError("Client IP cannot be empty")

        try:
            ipaddress.ip_address(self.client_ip)
        except ValueError as e:
            raise ValueError(f"Invalid client IP address: {self.client_ip}") from e

    def _validate_client_port(self) -> None:
        """Validate client port number range."""
        if not isinstance(self.client_port, int):
            raise ValueError("Client port must be an integer")

        if not (1 <= self.client_port <= 65535):
            raise ValueError(f"Client port must be between 1 and 65535, got: {self.client_port}")

    def _validate_packet_size(self) -> None:
        """Validate DNS packet size according to UDP limits."""
        if not isinstance(self.packet_size, int):
            raise ValueError("Packet size must be an integer")

        if self.packet_size <= 0:
            raise ValueError(f"Packet size must be positive, got: {self.packet_size}")

        # Standard DNS UDP limit is 512 bytes
        if self.packet_size > 512:
            raise ValueError(f"DNS packet size exceeds UDP limit of 512 bytes: {self.packet_size}")

    def _validate_request_id(self) -> None:
        """Validate request ID format."""
        if not self.request_id:
            raise ValueError("Request ID cannot be empty")

        if not isinstance(self.request_id, str):
            raise ValueError("Request ID must be a string")

        # Basic format validation - alphanumeric with underscores and hyphens
        if not re.match(r'^[a-zA-Z0-9_\-]+$', self.request_id):
            raise ValueError(f"Invalid request ID format: {self.request_id}")

    def normalize_query_name(self) -> str:
        """Normalize query name with trailing dot for consistency."""
        if not self.query_name.endswith('.'):
            return f"{self.query_name}."
        return self.query_name

    def to_dict(self) -> dict:
        """Convert DNS query to dictionary for logging/serialization."""
        return {
            "query_name": self.query_name,
            "query_type": self.query_type,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "request_id": self.request_id,
            "packet_size": self.packet_size,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

    def __str__(self) -> str:
        """String representation of DNS query."""
        return f"DNSQuery({self.request_id}: {self.query_name} {self.query_type} from {self.client_ip}:{self.client_port})"

    @classmethod
    def from_dict(cls, data: dict) -> 'DNSQuery':
        """Create DNS query from dictionary."""
        timestamp = None
        if data.get('timestamp'):
            timestamp = datetime.fromisoformat(data['timestamp'])

        return cls(
            query_name=data['query_name'],
            query_type=data['query_type'],
            client_ip=data['client_ip'],
            client_port=data['client_port'],
            request_id=data['request_id'],
            packet_size=data['packet_size'],
            timestamp=timestamp
        )