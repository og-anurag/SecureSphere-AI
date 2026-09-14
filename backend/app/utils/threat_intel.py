"""
Thin wrappers around external threat-intel APIs.
Each function fails soft (returns a dict with "error") instead of raising,
so one dead API never crashes the whole agent graph.
"""
import os
import base64
import requests

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

TIMEOUT = 10


def check_google_safe_browsing(url: str) -> dict:
    """Returns whether Google has flagged this URL as malware/phishing/etc."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"error": "no_api_key", "checked": False}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    body = {
        "client": {"clientId": "securesphere-ai", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=body, timeout=TIMEOUT)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        return {"checked": True, "flagged": bool(matches), "matches": matches}
    except requests.RequestException as e:
        return {"error": str(e), "checked": False}


def check_virustotal_url(url: str) -> dict:
    """Submits/looks up a URL on VirusTotal and returns the vendor verdict counts."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "no_api_key", "checked": False}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=TIMEOUT
        )
        if resp.status_code == 404:
            # Not seen before -> submit it for analysis
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=TIMEOUT
            )
            submit.raise_for_status()
            return {"checked": True, "flagged": False, "note": "submitted_for_first_scan"}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        flagged = stats.get("malicious", 0) + stats.get("suspicious", 0) > 0
        return {"checked": True, "flagged": flagged, "stats": stats}
    except requests.RequestException as e:
        return {"error": str(e), "checked": False}


def check_virustotal_file_hash(file_hash: str) -> dict:
    """Looks up an APK (or any file) by SHA256/MD5 hash on VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "no_api_key", "checked": False}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=TIMEOUT
        )
        if resp.status_code == 404:
            return {"checked": True, "flagged": False, "note": "not_seen_before_treat_as_unknown"}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        flagged = stats.get("malicious", 0) + stats.get("suspicious", 0) > 0
        return {"checked": True, "flagged": flagged, "stats": stats}
    except requests.RequestException as e:
        return {"error": str(e), "checked": False}


def check_abuseipdb(ip: str) -> dict:
    """Checks an IP's abuse confidence score."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "no_api_key", "checked": False}

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        return {
            "checked": True,
            "flagged": data["abuseConfidenceScore"] > 50,
            "score": data["abuseConfidenceScore"],
        }
    except requests.RequestException as e:
        return {"error": str(e), "checked": False}
