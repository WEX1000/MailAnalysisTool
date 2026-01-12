
# MailAnalysisTool

Basic Python tool for .eml email analysis focused on SOC triage.
It parses email headers and body, extracts sender IP, sender domain and URLs, and enriches them with reputation data from VirusTotal, urlscan.io, and AbuseIPDB. API keys are loaded from an external file. Designed for quick phishing analysis and IOC enrichment.