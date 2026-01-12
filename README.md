# MailScope

MailScope is a **basic SOC-oriented email analysis tool** for inspecting `.eml` files.

It parses email headers and body, extracts key indicators of compromise (IOCs), and enriches them with reputation data from external threat-intelligence services.

## Features
- Parses `.eml` files (RFC-compliant)
- Extracts sender email, sender domain and SMTP hop IPs
- Collects URLs from email content (deduplicated)
