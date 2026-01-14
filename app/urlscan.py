import requests
from .config import URLSCAN_API_KEY

def urlscan_domain(domain: str):
    if not domain:
        return None
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY_not_set"}

    url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    payload = {"url": f"http://{domain}", "visibility": "private"}

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code == 401: return {"error": "URLSCAN_401_unauthorized"}
    if r.status_code == 429: return {"error": "URLSCAN_429_rate_limited"}
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
