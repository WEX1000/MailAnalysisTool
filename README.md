
# MailScope - Python-based email analysis tool
It extracts email metadata, body content, URLs, and attachment hashes, then enriches them using OSINT services.
## Features

- Parses `.eml` email files
- Extracts headers, sender details, and message body
- Detects and normalizes URLs
- Extracts attachments and computes SHA-256 hashes
- Enriches hashes, domains, and IPs via OSINT APIs (VirusTotal, URLScan, AbuseIPDB)
- Outputs structured results (JSON)

## Instalation

```Python
git clone https://github.com/WEX1000/MailScope
cd MailScope
python3 -m pip install -r requirements.txt
python3 MailScope.py
```
## Usage
```Python
python3 MailScope.py -f mail.eml
```
## Help
```Python
python3 MailScope.py -h
 __   __  _______  ___   ___      _______  _______  _______  _______  _______
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|
------------------------------------------------------------------------------
  -h            show help
  -f <file>     path to .eml file
  -vt           enable VirusTotal
  -url          enable urlscan.io
  -abuse        enable AbuseIPDB
  -json         saves results to JSON file
------------------------------------------------------------------------------
```