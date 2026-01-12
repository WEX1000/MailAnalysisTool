from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse
import re
import ipaddress
import requests
import sys
import time

LOGO = """ __   __  _______  ___   ___      _______  _______  _______  _______  _______ 
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___ 
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___ 
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|
------------------------------------------------------------------------------"""


# ---------- LOAD KEYS ----------
def load_keys(path="API.key"):
    keys = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip().strip('"').strip("'")
    return keys

KEYS = load_keys("API.key")
VT_API_KEY = KEYS.get("VT_API_KEY", "")
URLSCAN_API_KEY = KEYS.get("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY = KEYS.get("ABUSEIPDB_API_KEY", "")


# ---------- REGEX ----------
URL_REGEX = re.compile(r'https?://[^\s<>"\']+')

def dedupe(items):
    seen = set()
    out = []
    for x in items:
        x = x.strip().rstrip(").,;!\"'<>")
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ---------- VIRUSTOTAL ----------
def vt_get(url: str):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY_not_set"}

    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=15)

    if r.status_code == 401:
        return {"error": "VT_401_unauthorized"}
    if r.status_code == 429:
        return {"error": "VT_429_rate_limited"}
    if r.status_code == 404:
        return {"error": "VT_404_not_found"}

    r.raise_for_status()
    return r.json()

def vt_ip(ip: str):
    if not ip:
        return None
    data = vt_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}")
    if "error" in data:
        return data
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    return {
        "score": stats.get("malicious", 0) + stats.get("suspicious", 0),
        "stats": stats,
        "reputation": a.get("reputation"),
        "country": a.get("country"),
        "asn": a.get("asn"),
        "as_owner": a.get("as_owner"),
    }

def vt_domain(domain: str):
    if not domain:
        return None
    data = vt_get(f"https://www.virustotal.com/api/v3/domains/{domain}")
    if "error" in data:
        return data
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    return {
        "score": stats.get("malicious", 0) + stats.get("suspicious", 0),
        "stats": stats,
        "reputation": a.get("reputation"),
    }


# ---------- AbuseIPDB ----------
def abuseipdb_ip(ip: str):
    if not ip:
        return None
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY_not_set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(url, headers=headers, params=params, timeout=15)

    if r.status_code == 401:
        return {"error": "ABUSEIPDB_401_unauthorized"}
    if r.status_code == 429:
        return {"error": "ABUSEIPDB_429_rate_limited"}
    if r.status_code != 200:
        return {"error": f"ABUSEIPDB_{r.status_code}", "body": r.text[:200]}

    d = r.json().get("data", {})
    return {
        "confidence": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage": d.get("usageType"),
    }


# ---------- URLSCAN ----------
def urlscan_domain(domain: str):
    if not domain:
        return None
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY_not_set"}

    url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    payload = {"url": f"http://{domain}", "visibility": "private"}

    r = requests.post(url, headers=headers, json=payload, timeout=20)

    if r.status_code == 401:
        return {"error": "URLSCAN_401_unauthorized"}
    if r.status_code == 429:
        return {"error": "URLSCAN_429_rate_limited"}
    if r.status_code not in (200, 201):
        return {"error": f"URLSCAN_{r.status_code}", "body": r.text[:200]}

    data = r.json()
    uuid = data.get("uuid")
    return {
        "uuid": uuid,
        "result": data.get("result"),
        "api": data.get("api"),
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None,
    }


# ---------- MAIN ANALYSIS FUNCTION ----------
def mail_analysis(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=default).parse(f)
    
    # ---------- BASIC INFO ----------
    sender_addr = parseaddr(msg.get("From", ""))[1]
    sender_domain = sender_addr.split("@", 1)[1] if "@" in sender_addr else None
    return_path = parseaddr(msg.get("Return-Path", ""))[1]
    date = msg.get("Date")
    message_id = msg.get("Message-ID")
    user_agent = msg.get("User-Agent") or msg.get("X-Mailer")

    # ---------- RECIPIENTS ----------
    recipients = []
    for hdr in ("To", "Cc", "Bcc"):
        recipients += [addr for _, addr in getaddresses(msg.get_all(hdr, [])) if addr]

    # ---------- SENDER IP ----------
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
    
    # ---------- URLS ----------
    body = msg.get_body(preferencelist=("html", "plain"))
    urls = dedupe(URL_REGEX.findall(body.get_content())) if body else []

    # ---------- BASIC RESULTS ----------
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
    if VT_ON == 0 and ABUSEIPDB_ON == 0 and URLSCAN_ON == 0:
        print("-" * 78)

    # ---------- VT RESULTS ----------
    if VT_ON == 1:
        print("-" * 34 + "VirusTotal" + "-" * 34)
        print(f"Sender IP reputation: {(vt_ip(sender_ip) if sender_ip else None)['score']} (no. of vendors flagging IP as malicious)")
        print(f"Sender domain reputation: {(vt_domain(sender_domain) if sender_domain else None)['score']} (no. of vendors flagging IP as malicious)")
        if ABUSEIPDB_ON == 0 and URLSCAN_ON == 0:
            print("-" * 78)
    
    # ---------- ABUSEIPDB RESULTS ----------
    if ABUSEIPDB_ON == 1:
        print("-" * 34 + "AbuseIPDB" + "-" * 35)
        print(f"Confidence of abuse: {(abuseipdb_ip(sender_ip) if sender_ip else None).get('confidence')}")
        print(f"Reports: {(abuseipdb_ip(sender_ip) if sender_ip else None).get('reports')}")
        print(f"ISP: {(abuseipdb_ip(sender_ip) if sender_ip else None).get('isp')}")
        print(f"Country: {(abuseipdb_ip(sender_ip) if sender_ip else None).get('country')}")
        if URLSCAN_ON == 0:
            print("-" * 78)

    # ---------- URLSCAN RESULTS ----------
    if URLSCAN_ON == 1:
        print("-" * 34 + "URLScan" + "-" * 37)
        print(f"Sender domain scan: {(urlscan_domain(sender_domain) if sender_domain else None)['result']}")
        time.sleep(5)
        domains = [urlparse(u).netloc for u in urls]
        i = 1
        for d in domains:
            print(f"{i} link scan: {(urlscan_domain(d) if d else None)['result']}")
            i += 1
            time.sleep(5)
        print("-" * 78)


# ---------- CLI FUNCTION ----------
def main():
    global VT_ON, ABUSEIPDB_ON, URLSCAN_ON
    VT_ON = 0
    ABUSEIPDB_ON = 0    
    URLSCAN_ON = 0
    args = sys.argv[1:]

    if not args:
        print(LOGO)
        print("Missing argument, use -h")
        return

    file_path = None

    i = 0
    while i < len(args):
        if args[i] == "-h":
            print(LOGO)
            print("  -h            show help")
            print("  -f <file>     path to .eml file")
            print("  -vt           enable VirusTotal (API key required), sender domain and IP scan")
            print("  -url          enable urlscan.io (API key required)")
            print("  -abuse        enable AbuseIPDB (API key required), sender IP scan")
            print("-" * 78)
            return

        elif args[i] == "-f" and i + 1 < len(args):
            file_path = args[i + 1]
            i += 2
            continue

        elif args[i] == "-vt":
            VT_ON = 1
            i += 1
            continue

        elif args[i] == "-url":
            URLSCAN_ON = 1
            i += 1
            continue

        elif args[i] == "-abuse":
            ABUSEIPDB_ON = 1
            i += 1
            continue

        else:
            print(LOGO)
            print("Invalid argument, use -h")
            return

        i += 1

    if not file_path:
        print(LOGO)
        print("Missing file path, use -h")
        return

    if not file_path.lower().endswith(".eml"):
        print(LOGO)
        print("Invalid argument, use -h")
        return

    print(LOGO)
    print("File:", file_path)
    print("-" * 78)
    mail_analysis(file_path)

# ---------- MAIN FUNCTION ----------
if __name__ == "__main__":
    main()