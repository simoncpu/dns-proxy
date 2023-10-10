# dns-proxy

A DNS Proxy server that forwards queries to Google's DNS-over-HTTPS (DoH) service.

## Overview

I created this because even though Chrome and Firefox support DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT), Safari doesn’t yet. I managed to get around this using the Cloudflare app and also with Quad9's mobile provisioning profile. So technically, I didn't need to make my own DNS proxy, but I decided to do it for teh lulz. This version is just the beginning. I'll be learning more about DoT and how to proxy it. Currently, it only handles A and TXT records, but it will support other record types in the future.

## Usage

### Run the shell script

```
sudo ./proxy.sh
```
