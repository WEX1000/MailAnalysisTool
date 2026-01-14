# MailScope

MailScope is a **command-line SOC-oriented email analysis tool** for inspecting `.eml` files and extracting security-relevant indicators.

The tool parses email headers and body, identifies sender infrastructure and URLs, and optionally enriches them using external threat intelligence services.

## Features
- RFC-compliant `.eml` parsing
- Extraction of:
  - sender address and domain
  - sender IP (from SMTP `Received` headers)
  - recipients
  - message metadata (Date, Message-ID, User-Agent)
  - URLs from email body (deduplicated)
- Optional enrichment:
  - **VirusTotal** – sender IP and domain reputation
  - **AbuseIPDB** – sender IP abuse confidence
  - **urlscan.io** – sandbox scans for sender domain and URLs

## Usage
python3 MailScope.py -f mail.eml [options]
- -h            show help
- -f <file>     path to .eml file
- -vt           enable VirusTotal (sender IP and domain scan)
- -abuse        enable AbuseIPDB (sender IP scan)
- -url          enable urlscan.io (domain and URL scans)
