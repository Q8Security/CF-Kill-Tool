
  
  ░██████  ░██████████        ░██     ░██ ░██░██ ░██ 
 ░██   ░██ ░██                ░██    ░██     ░██ ░██ 
░██        ░██                ░██   ░██   ░██░██ ░██ 
░██        ░█████████ ░██████ ░███████    ░██░██ ░██ 
░██        ░██                ░██   ░██   ░██░██ ░██ 
 ░██   ░██ ░██                ░██    ░██  ░██░██ ░██ 
  ░██████  ░██                ░██     ░██ ░██░██ ░██ 
                                                                                                                                                                                             
## By : Q8 - Security 
## Mail : LS@Hotmail.com


# CF-Kill

**Cloudflare Real Origin IP Extractor**  

A powerful, clean, and professional Python tool designed to discover the real origin IP addresses behind Cloudflare-protected websites using multiple reconnaissance techniques.

## Features

- 18 reliable reconnaissance methods
- Classified results: **High / Medium / Low** confidence
- Built-in Cloudflare detection
- Strong verification system to confirm real IPs
- Fast asynchronous execution
- Clean professional output
- Filters out fake IPs (including 1.x.x.x ranges)

## Methods Used

### High Confidence
- SPF (ip4 records)
- MX records
- Direct A record

### Medium Confidence
- crt.sh Certificate Transparency
- RapidDNS
- HackerTarget
- ViewDNS
- SecurityTrails
- AlienVault OTX
- ThreatCrowd
- DNSDumpster
- URLScan

### Low Confidence
- Subdomain Brute-force
- Wayback Machine
- DNS History
- NS Records
- Robtex

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/CF-Kill.git
cd CF-Kill
pip3 install -r requirements.txt

python3 cfkill.py example.com



