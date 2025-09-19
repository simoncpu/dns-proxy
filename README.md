# DNS Proxy

A production-ready DNS proxy that forwards queries to DNS-over-HTTPS (DoH) services with intelligent caching, circuit breaker protection, and comprehensive monitoring.

**Key Features:**
- High-performance with TTL-aware caching
- Circuit breaker pattern for resilience
- Structured JSON logging with request tracing
- Comprehensive error handling
- Graceful shutdown with resource cleanup
- Real-time statistics and health monitoring

## Quick Start

**Requirements:** Python 3.11+

```bash
# Setup
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run on unprivileged port
DNS_PORT=1053 python3 main.py

# Test it
dig @localhost -p 1053 google.com
```

For production use on port 53: `sudo python3 main.py`

## Configuration

Key environment variables (see `.env.example` for complete list):

```bash
DNS_PORT=53                                   # DNS server port
UPSTREAM_DNS_URL=https://8.8.8.8/resolve      # Upstream DoH service
CACHE_SIZE=1000                               # Maximum cache entries
LOG_LEVEL=INFO                                # DEBUG, INFO, WARNING, ERROR
LOG_FILE=logs/dns-proxy.log                   # Log file path
```

## Testing

```bash
# Query different record types
dig @localhost google.com A
dig @localhost google.com AAAA
dig @localhost google.com MX

# Test caching performance
for i in {1..5}; do time dig @localhost google.com +short; done
```

## Monitoring

- **Logs:** Structured JSON in `logs/dns-proxy.log`
- **Real-time:** `tail -f logs/dns-proxy.log | jq`
- **Metrics:** Cache statistics, circuit breaker state, response times

## Architecture

- **Main Server** (`main.py`): UDP server and request handling
- **DNS Proxy Service**: Core logic and coordination
- **Cache Service**: TTL-aware caching with LRU eviction
- **Upstream Service**: DoH client with circuit breaker
- **Logging Service**: Structured JSON logging

## Troubleshooting

**Permission denied on port 53:** Use `DNS_PORT=1053` or run with `sudo`

**Dependencies missing:** Activate venv: `source venv/bin/activate`

**Service not responding:** Check logs: `tail -f logs/dns-proxy.log`

## Author

Simon Cornelius P. Umacob <t07dq0dfv@mozmail.com>

## License

This project is licensed under the MIT License - see the LICENSE file for details.
