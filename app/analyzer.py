from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse
import re
import ipaddress
import time
import hashlib

from .utils import URL_REGEX, dedupe
from .vt import vt_ip, vt_domain, vt_hash
from .abuseipdb import abuseipdb_ip
from .urlscan import urlscan_domain

def mail_analysis(path: str, vt_on=False, abuse_on=False, urlscan_on=False):
    with open(path, "rb") as f:
        msg = BytesParser(policy=default).parse(f)

    sender_addr = parseaddr(msg.get("From", ""))[1]
    sender_domain = sender_addr.split("@", 1)[1] if "@" in sender_addr else None
    return_path = parseaddr(msg.get("Return-Path", ""))[1]
    date = msg.get("Date")
    message_id = msg.get("Message-ID")
    user_agent = msg.get("User-Agent") or msg.get("X-Mailer")
    subject = msg.get("Subject", "")

    recipients = []
    for hdr in ("To", "Cc", "Bcc"):
        recipients += [addr for _, addr in getaddresses(msg.get_all(hdr, [])) if addr]

    sender_ip = None
    for h in reversed(msg.get_all("Received", [])):
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", h):
            try:
                if ipaddress.ip_address(ip).is_global:
                    sender_ip = ip
                    break
            except ValueError:
                pass
        if sender_ip:
            break

    body_html = msg.get_body(preferencelist=("html", "plain"))
    urls = dedupe(URL_REGEX.findall(body_html.get_content())) if body_html else []

    body_plain = msg.get_body(preferencelist=("plain", "html"))
    content = body_plain.get_content() if body_plain else ""

    attachments_hashes = {}
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        data = part.get_payload(decode=True)
        if not data:
            continue
    
        name = part.get_filename() or "brak_nazwy"
        sha256 = hashlib.sha256(data).hexdigest()
        attachments_hashes[name] = sha256

    
    print(f"Subject: {subject}")
    print("-" * 78)
    print("Mail content:")
    print(content)
    print("-" * 78)
    print("Basic info:")
    print(f"Date: {date}")
    print(f"Sender domain: {sender_domain}")
    print(f"Sender IP: {sender_ip}")
    print(f"From: {sender_addr}")
    print(f"Return-Path: {return_path}")
    print(f"Recipients: {recipients}")
    print(f"Message-ID: {message_id}")
    print(f"User-Agent/X-Mailer: {user_agent}")
    print("URLs:")
    for u in urls:
        print(f"  - {u}")
    print("Attachements:")
    for name, hash in attachments_hashes.items():
        print(f"  - File name: {name}")
        print(f"    - SHA256 hash: {hash}")
    if not (vt_on or abuse_on or urlscan_on):
        print("-" * 78)

    if vt_on:
        print("-" * 34 + "VirusTotal" + "-" * 34)
        ip_res = vt_ip(sender_ip) if sender_ip else None
        dom_res = vt_domain(sender_domain) if sender_domain else None
        print(f"Sender IP reputation: {ip_res.get('score') if isinstance(ip_res, dict) else None} (No. of security vendors flagging IP as malicious)")
        print(f"Sender domain reputation: {dom_res.get('score') if isinstance(dom_res, dict) else None} (No. of security vendors flagging domain as malicious)")
        for name, hash in attachments_hashes.items():
            print(f"  - File name: {name}")
            print(f"    - Hash reputation: {(vt_hash(hash))['score']} (No. of security vendors flagging domain as malicious)")

        if not (abuse_on or urlscan_on):
            print("-" * 78)

    if abuse_on:
        print("-" * 34 + "AbuseIPDB" + "-" * 35)
        a = abuseipdb_ip(sender_ip) if sender_ip else None
        a = a if isinstance(a, dict) else {}
        print(f"Confidence of abuse: {a.get('confidence')}")
        print(f"Reports: {a.get('reports')}")
        print(f"ISP: {a.get('isp')}")
        print(f"Country: {a.get('country')}")
        if not urlscan_on:
            print("-" * 78)

    if urlscan_on:
        print("-" * 34 + "URLScan" + "-" * 37)
        sd = urlscan_domain(sender_domain) if sender_domain else None
        if isinstance(sd, dict):
            print(f"Sender domain scan: {sd.get('result')}")
        time.sleep(5)
        domains = [urlparse(u).netloc for u in urls]
        for i, d in enumerate(domains, 1):
            res = urlscan_domain(d) if d else None
            if isinstance(res, dict):
                print(f"{i} link scan: {res.get('result')}")
            time.sleep(5)
        print("-" * 78)
