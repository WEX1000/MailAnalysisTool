import requests
from .config import VT_API_KEY

def vt_get(url: str):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY_not_set"}

    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=15)
    if r.status_code == 401: return {"error": "VT_401_unauthorized"}
    if r.status_code == 429: return {"error": "VT_429_rate_limited"}
    if r.status_code == 404: return {"error": "VT_404_not_found"}
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

def vt_hash(sha256: str):
    if not sha256:
        return None

    data = vt_get(f"https://www.virustotal.com/api/v3/files/{sha256}")
    if "error" in data:
        return data

    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})

    return {
        "score": stats.get("malicious", 0) + stats.get("suspicious", 0),
        "stats": stats,
        "type": a.get("type_description"),
        "size": a.get("size"),
        "first_seen": a.get("first_submission_date"),
        "last_seen": a.get("last_analysis_date"),
        "reputation": a.get("reputation"),
    }