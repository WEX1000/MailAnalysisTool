import requests
from .config import ABUSEIPDB_API_KEY

def abuseipdb_ip(ip: str):
    if not ip:
        return None
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY_not_set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(url, headers=headers, params=params, timeout=15)
    if r.status_code == 401: return {"error": "ABUSEIPDB_401_unauthorized"}
    if r.status_code == 429: return {"error": "ABUSEIPDB_429_rate_limited"}
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
