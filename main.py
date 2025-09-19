#!/usr/bin/env python3
"""DNS Proxy Service"""

from src.lib.exceptions import DNSProxyError, ConfigurationError, ServiceUnavailableError
from src.services.dns_proxy_service import DNSProxyService
from src.lib.config import load_config, ensure_log_directory
from dnslib import DNSRecord, DNSError, RR, QTYPE, CLASS
import sys
import signal
import socket
import threading
from pathlib import Path
from typing import Optional


class DNSServer:
    """Production DNS server with new service architecture."""

    def __init__(self, config_file: str = None):
        """Initialize DNS server.

        Args:
            config_file: Optional path to configuration file
        """
        self.config = load_config(config_file)
        self.dns_service = None
        self.udp_socket = None
        self.running = False
        self.shutdown_event = threading.Event()

    def start(self):
        """Start the DNS server."""
        try:
            # Initialize DNS proxy service
            self.dns_service = DNSProxyService.create_default(self.config)

            # Log startup information
            self.dns_service.logging_service.info(
                f"Starting DNS proxy on port {self.config.dns_port}"
            )

            # Create UDP socket
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to configured port
            try:
                self.udp_socket.bind(('0.0.0.0', self.config.dns_port))
            except PermissionError:
                if self.config.dns_port < 1024:
                    raise ConfigurationError(
                        f"Port {self.config.dns_port} requires root privileges. "
                        f"Consider using a port >= 1024 or running with sudo.",
                        "dns_port", str(self.config.dns_port)
                    )
                raise

            self.running = True

            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

            print(f"DNS Proxy Server listening on port {self.config.dns_port}")
            print(f"Upstream: {self.config.upstream_dns_url}")
            print("Press Ctrl+C to stop")

            # Start request handler loop
            self._run_server_loop()

        except Exception as e:
            if self.dns_service and self.dns_service.logging_service:
                self.dns_service.logging_service.critical(
                    f"Failed to start DNS server: {e}", error=e)
            else:
                print(f"❌ Failed to start DNS server: {e}")
            raise

    def _run_server_loop(self):
        """Main server request handling loop."""
        while self.running and not self.shutdown_event.is_set():
            try:
                # Set socket timeout to allow checking shutdown event
                self.udp_socket.settimeout(1.0)

                try:
                    data, address = self.udp_socket.recvfrom(512)
                    # Handle request in separate thread to avoid blocking
                    threading.Thread(
                        target=self._handle_dns_request,
                        args=(data, address),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue  # Check shutdown event and continue
                except OSError:
                    if self.running:  # Only continue if not shutting down
                        continue
                    break

            except Exception:
                if self.running:
                    continue

    def _handle_dns_request(self, data: bytes, address: tuple):
        """Handle individual DNS request.

        Args:
            data: Raw DNS request data
            address: Client address tuple (ip, port)
        """
        client_ip = address[0]
        client_port = address[1]

        try:
            # Parse DNS request
            request = DNSRecord.parse(data)

            # Extract query information
            qname = str(request.q.qname).rstrip('.')
            qtype = QTYPE[request.q.qtype]

            # Resolve using DNS proxy service
            dns_response = self.dns_service.resolve(
                query_name=qname,
                query_type=qtype,
                client_ip=client_ip,
                client_port=client_port,
                packet_size=len(data)
            )

            # Build DNS response packet
            response_packet = self._build_dns_response(request, dns_response)

            # Send response
            self.udp_socket.sendto(response_packet.pack(), address)

        except DNSError as e:
            # Invalid DNS packet - log and ignore
            self.dns_service.logging_service.warning(
                f"Invalid DNS packet from {client_ip}: {e}"
            )

        except (DNSProxyError, Exception) as e:
            # Send error response
            try:
                error_response = self._build_error_response(request, e)
                self.udp_socket.sendto(error_response.pack(), address)
            except Exception:
                pass  # If we can't send error response, just log it

            self.dns_service.logging_service.error(
                f"Error handling DNS request from {client_ip}: {e}",
                error=e
            )

    def _build_dns_response(self, request: DNSRecord, dns_response) -> DNSRecord:
        """Build DNS response packet from DNS response model."""
        # Create response with the same ID as request
        response = request.reply()
        response.header.rcode = 0  # NOERROR

        # Debug log the answers structure
        self.dns_service.logging_service.debug(
            f"Building DNS response with {len(dns_response.answers)} answers: {dns_response.answers}"
        )

        # Add answer records from the DNS response
        for answer in dns_response.answers:
            try:
                rtype = answer.get('type')
                rdata = answer.get('data', '')
                ttl = answer.get('TTL', dns_response.ttl)
                name = answer.get('name', dns_response.query_name).rstrip('.')

                if rtype and rdata:
                    # Create appropriate RD instance based on record type
                    from dnslib import A, AAAA, CNAME, MX, TXT, NS, PTR

                    # Map numeric types to their handlers and QTYPE values
                    type_mapping = {
                        1: (lambda d: A(d), QTYPE.A),
                        28: (lambda d: AAAA(d), QTYPE.AAAA),
                        5: (lambda d: CNAME(d), QTYPE.CNAME),
                        16: (lambda d: TXT(d), QTYPE.TXT),
                        2: (lambda d: NS(d), QTYPE.NS),
                        12: (lambda d: PTR(d), QTYPE.PTR),
                    }

                    rd = None

                    # Handle MX records specially due to preference field
                    if isinstance(rtype, int) and rtype == 15:
                        parts = rdata.split(' ', 1)
                        preference = int(parts[0]) if len(parts) > 1 else 10
                        exchange = parts[1] if len(parts) > 1 else parts[0]
                        rd = MX(exchange, preference)
                        rtype = QTYPE.MX
                    elif isinstance(rtype, int) and rtype in type_mapping:
                        handler, qtype = type_mapping[rtype]
                        rd = handler(rdata)
                        rtype = qtype
                    else:
                        # Unsupported record type
                        self.dns_service.logging_service.debug(
                            f"Unsupported record type: {rtype} for {name}"
                        )
                        continue

                    if not rd:
                        self.dns_service.logging_service.warning(
                            f"Failed to create RD instance for type {rtype}"
                        )
                        continue

                    response.add_answer(RR(
                        rname=name,
                        rtype=rtype,
                        rclass=CLASS.IN,
                        ttl=ttl,
                        rdata=rd
                    ))
            except Exception as e:
                # Skip malformed records
                self.dns_service.logging_service.warning(
                    f"Skipping malformed answer: {e}"
                )

        return response

    def _build_error_response(self, request: DNSRecord, error: Optional[Exception] = None) -> DNSRecord:
        """Build DNS error response."""
        response = request.reply()

        # Determine appropriate error code
        if error and ("NXDOMAIN" in str(error) or "not found" in str(error).lower()):
            response.header.rcode = 3  # NXDOMAIN
        else:
            response.header.rcode = 2  # SERVFAIL

        return response

    def _signal_handler(self, signum, _):
        """Handle shutdown signals."""
        self.shutdown()

    def shutdown(self):
        """Shutdown DNS server gracefully."""
        if not self.running:
            return

        print("\nShutting down...")
        self.running = False
        self.shutdown_event.set()

        # Close socket
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except Exception:
                pass

        # Shutdown DNS service
        if self.dns_service:
            try:
                self.dns_service.shutdown()
            except Exception:
                pass

        print("Shutdown complete")

    def __enter__(self) -> 'DNSServer':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, _) -> None:
        """Context manager exit with graceful shutdown."""
        if exc_type:
            print(f"Error: {exc_val}")
        self.shutdown()


def main():
    """Main entry point."""
    try:
        # Create and start DNS server
        server = DNSServer()
        server.start()

    except KeyboardInterrupt:
        sys.exit(0)

    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        if e.config_key == "dns_port" and e.config_value and int(e.config_value) < 1024:
            print("Tip: Use a port >= 1024 or run with sudo for privileged ports")
        sys.exit(1)

    except Exception as e:
        print(f"Failed to start DNS server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
