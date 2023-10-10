# dns-proxy

A DNS Proxy server that forwards queries to Google's DNS-over-HTTPS (DoH) service.

## Overview

I created this because even though Chrome and Firefox support DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT), Safari doesn’t yet. I managed to get around this using the Cloudflare app and also with Quad9's mobile provisioning profile. So technically, I didn't need to make my own DNS proxy, but I decided to do it for teh lulz. This version is just the beginning. I'll be learning more about DoT and how to proxy it. Currently, it only handles A and TXT records, but it will support other record types in the future.

## Usage

### Run the shell script

```
$ sudo ./proxy.sh
```

### Test the DNS proxy

```
$ dig @localhost google.com

; <<>> DiG 9.10.6 <<>> @localhost google.com
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32761
;; flags: qr aa rd ra; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
google.com.		60	IN	A	142.250.206.206

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Oct 10 10:04:17 PST 2023
;; MSG SIZE  rcvd: 38
```
