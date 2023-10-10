import socket
import requests
from dnslib import DNSRecord, DNSError, DNSHeader, RR, QTYPE, CLASS, A, TXT

UPSTREAM_DNS_URL = "https://8.8.8.8/resolve"
#UPSTREAM_DNS_URL = "https://dns.google/resolve"
DNS_PORT = 53

def dns_proxy(data, address, socket):
    try:
        request = DNSRecord.parse(data)

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        
        print(f"Received a request for {qname} with record type: {qtype}")

        response = requests.get(UPSTREAM_DNS_URL, params={"name": qname, "type": qtype})
        response_json = response.json()

        dns_response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))

        for answer in response_json.get('Answer', []):
            rdata = answer['data']
            if answer['type'] == QTYPE.A:
                dns_response.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=CLASS.IN, ttl=60, rdata=A(rdata)))
            elif answer['type'] == QTYPE.TXT:
                print(f"TXT record value for {qname}: {rdata}")
                dns_response.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=CLASS.IN, ttl=60, rdata=TXT(rdata)))

        udp_socket.sendto(dns_response.pack(), address)
    except DNSError:
        pass

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(('0.0.0.0', DNS_PORT))

print(f"Listening for DNS requests on port {DNS_PORT}...")

while True:
    data, address = udp_socket.recvfrom(512)
    dns_proxy(data, address, udp_socket)
