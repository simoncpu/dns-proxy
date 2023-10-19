import socket
import requests
from dnslib import DNSRecord, DNSError, DNSHeader, RR, QTYPE, CLASS, A, AAAA, CNAME, MX, TXT, PTR, NS, SOA

UPSTREAM_DNS_URL = "https://8.8.8.8/resolve"
DNS_PORT = 53
CACHE_SIZE = 128

dns_cache = {}
cache_order = []

RDATA_CLASSES = {
    QTYPE.A: A,
    QTYPE.AAAA: AAAA,
    QTYPE.CNAME: CNAME,
    QTYPE.MX: MX,
    QTYPE.TXT: TXT,
    QTYPE.PTR: PTR,
    QTYPE.NS: NS,
    QTYPE.SOA: SOA,
}

def fetch_from_upstream(qname, qtype):
    cache_key = (qname, qtype)

    if cache_key in dns_cache:
        return dns_cache[cache_key]

    response = requests.get(UPSTREAM_DNS_URL, params={"name": qname, "type": qtype})
    response_json = response.json()

    dns_cache[cache_key] = response_json
    cache_order.append(cache_key)

    if len(cache_order) > CACHE_SIZE:
        oldest_key = cache_order.pop(0)
        del dns_cache[oldest_key]

    return response_json

def dns_proxy(data, address, socket):
    try:
        request = DNSRecord.parse(data)

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        print(f"Received a request for {qname} with record type: {qtype}")

        response_json = fetch_from_upstream(qname, qtype)

        dns_response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))

        for answer in response_json.get('Answer', []):
            rdata_str = answer['data']
            rtype = answer['type']
            rdata_class = RDATA_CLASSES.get(rtype)
            if rdata_class:
                rdata_obj = rdata_class(rdata_str)
                dns_response.add_answer(RR(rname=qname, rtype=rtype, rclass=CLASS.IN, ttl=60, rdata=rdata_obj))

        udp_socket.sendto(dns_response.pack(), address)
    except DNSError:
        pass

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(('0.0.0.0', DNS_PORT))

print(f"🚀 Listening for DNS requests on port {DNS_PORT}...")

while True:
    data, address = udp_socket.recvfrom(512)
    dns_proxy(data, address, udp_socket)
