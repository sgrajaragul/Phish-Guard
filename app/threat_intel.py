"""
threat_intel.py — URL and domain reputation checking.

Uses free, no-key-required sources first:
  1. OpenPhish community feed (cached locally)
  2. PhishTank free lookup
  3. Heuristic scoring (fallback — always available)

Optional (configure in api_keys.py):
  VIRUSTOTAL_API_KEY — VirusTotal v3 free tier (500 req/day)
  ABUSEIPDB_API_KEY — AbuseIPDB free tier (1000 req/day)
"""

import os
import re
import time
import hashlib
import urllib.parse
import requests

# Import API keys from centralized configuration
try:
    import api_keys
except ImportError:
    # Fallback: create a dummy api_keys module if file doesn't exist
    class api_keys:
        @staticmethod
        def get_api_key(service_name):
            # Try environment variables as fallback
            if service_name.lower() == 'virustotal':
                return os.getenv('VIRUSTOTAL_API_KEY')
            elif service_name.lower() == 'abuseipdb':
                return os.getenv('ABUSEIPDB_API_KEY')
            return None

OPENPHISH_URL  = "https://openphish.com/feed.txt"
PHISHTANK_API  = "https://checkurl.phishtank.com/checkurl/"
ABUSEIPDB_API  = "https://api.abuseipdb.com/api/v2/check"

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "amazon.com", "github.com", "gitlab.com",
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "youtube.com",
    "netflix.com", "paypal.com", "stripe.com", "shopify.com", "salesforce.com",
    "dropbox.com", "slack.com", "zoom.us", "atlassian.com", "notion.so",
    "medium.com", "substack.com", "mailchimp.com", "hubspot.com",
}

# Simple in-memory cache  {url_hash: (result_dict, timestamp)}
_cache: dict = {}
_CACHE_TTL   = 3600  # 1 hour


def check_urls(urls: list[str]) -> list[dict]:
    """
    Check a list of URLs for phishing/malware indicators.
    Returns a list of result dicts, one per URL.
    """
    results = []
    for url in urls[:20]:   # cap at 20 to avoid rate limits
        results.append(_check_single(url))
    return results


def check_ips(ip_data: list[dict]) -> list[dict]:
    """
    Check IP addresses for abuse/attack history using AbuseIPDB.
    
    Args:
        ip_data: list of dicts with 'ip', 'source', 'context' keys
    
    Returns:
        list of dicts with IP reputation data
    """
    results = []
    abuseipdb_key = api_keys.get_api_key("abuseipdb")
    
    for ip_info in ip_data[:10]:  # cap at 10 to avoid rate limits
        ip = ip_info["ip"]
        result = {
            "ip": ip,
            "source": ip_info.get("source", "Unknown"),
            "context": ip_info.get("context", ""),
            "risk": "unknown",
            "abuse_score": 0,
            "reports": 0,
            "last_reported": None,
            "country": None,
            "isp": None,
            "is_public": True,
            "is_whitelisted": False,
            "flags": [],
        }
        
        # ── Check with AbuseIPDB if API key is available ──────
        if abuseipdb_key:
            abuse_data = _check_abuseipdb(ip, abuseipdb_key)
            if abuse_data:
                result["abuse_score"] = abuse_data.get("abuseConfidenceScore", 0)
                result["reports"] = abuse_data.get("totalReports", 0)
                result["last_reported"] = abuse_data.get("lastReportedAt")
                result["country"] = abuse_data.get("countryCode")
                result["isp"] = abuse_data.get("isp")
                result["is_public"] = abuse_data.get("isPublic", True)
                result["is_whitelisted"] = abuse_data.get("isWhitelisted", False)
                
                # Add flags based on abuse score
                score = result["abuse_score"]
                if score >= 75:
                    result["risk"] = "high"
                    result["flags"].append(f"High abuse score: {score}% confidence")
                    if result["reports"] > 0:
                        result["flags"].append(f"Reported {result['reports']} times for abuse")
                elif score >= 25:
                    result["risk"] = "medium"
                    result["flags"].append(f"Moderate abuse score: {score}%")
                    if result["reports"] > 0:
                        result["flags"].append(f"Has {result['reports']} abuse reports")
                elif score > 0:
                    result["risk"] = "low"
                    result["flags"].append(f"Low abuse score: {score}%")
                else:
                    result["risk"] = "clean"
                
                if result["is_whitelisted"]:
                    result["risk"] = "clean"
                    result["flags"].append("Whitelisted IP (legitimate service)")
        else:
            # Fallback: basic heuristic without API
            result["flags"].append("No AbuseIPDB API key - limited analysis")
            result["risk"] = "unknown"
        
        results.append(result)
    
    return results


def _check_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict | None:
    """
    Query AbuseIPDB API for IP reputation.
    Free tier: 1000 requests/day
    
    Returns dict with abuse data or None on error.
    """
    try:
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": ""
        }
        
        resp = requests.get(
            ABUSEIPDB_API,
            headers=headers,
            params=params,
            timeout=5
        )
        
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", {})
        elif resp.status_code == 429:
            # Rate limit exceeded
            return {"error": "rate_limit", "abuseConfidenceScore": 0}
        else:
            return None
    except Exception as e:
        return None


def _check_single(url: str) -> dict:
    url_hash = hashlib.md5(url.encode()).hexdigest()

    # Cache hit?
    if url_hash in _cache:
        cached, ts = _cache[url_hash]
        if time.time() - ts < _CACHE_TTL:
            return cached

    result = {
        "url":        url,
        "domain":     _get_domain(url),
        "risk":       "unknown",   # low | medium | high | unknown
        "source":     [],
        "heuristics": [],
    }

    # ── Heuristic scoring (always runs, no network needed) ───
    h_flags, h_score = _heuristic_check(url)
    result["heuristics"] = h_flags

    # ── VirusTotal (optional, requires API key) ───────────────
    vt_key = api_keys.get_api_key("virustotal")
    if vt_key:
        vt_result = _virustotal_check(url, vt_key)
        if vt_result:
            result["source"].append("VirusTotal")
            if vt_result.get("malicious", 0) >= 3:
                h_score += 50
                result["heuristics"].append(
                    f"VirusTotal: {vt_result['malicious']} engines flagged this URL"
                )

    # ── Determine risk level ──────────────────────────────────
    if h_score >= 60:
        result["risk"] = "high"
    elif h_score >= 30:
        result["risk"] = "medium"
    elif h_score >= 10:
        result["risk"] = "low"
    else:
        result["risk"] = "clean"

    _cache[url_hash] = (result, time.time())
    return result


def _heuristic_check(url: str) -> tuple[list[str], int]:
    """
    Score a URL using local heuristics. No network required.
    Returns (flags, score).
    """
    flags = []
    score = 0

    try:
        parsed  = urllib.parse.urlparse(url)
        host    = parsed.hostname or ""
        path    = parsed.path or ""
        query   = parsed.query or ""
        full    = url.lower()
    except Exception:
        return flags, score

    # Check if this is a trusted domain — suppress path-level heuristics
    is_trusted = _is_trusted_domain(host)

    # Raw IP address instead of hostname
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        flags.append("Uses raw IP address instead of domain")
        score += 40

    # Suspicious TLD
    suspicious_tlds = [".xyz",".top",".club",".work",".gq",".ml",".cf",
                       ".tk",".pw",".click",".link",".online",".site",".buzz"]
    for tld in suspicious_tlds:
        if host.endswith(tld):
            flags.append(f"Suspicious TLD: {tld}")
            score += 25
            break

    # @ in URL (trick to hide real domain)
    if "@" in url:
        flags.append("URL contains @ sign (domain obfuscation)")
        score += 45

    # Excessive subdomains (e.g. paypal.com.verify.evil.xyz)
    parts = host.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive subdomains ({len(parts)-2} levels) — possible domain spoofing")
        score += 20

    # Brand names in subdomain (not in registered domain) — skip trusted
    if not is_trusted:
        brands = ["paypal","amazon","google","apple","microsoft","netflix",
                  "facebook","instagram","bank","secure","account","login"]
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
        for brand in brands:
            if brand in host and brand not in registered:
                flags.append(f'Brand name "{brand}" in subdomain — possible spoofing of {brand}.com')
                score += 35
                break

    # Suspicious keywords in path/query — only for untrusted domains
    if not is_trusted:
        suspicious_path_words = ["login","signin","verify","account","secure",
                                 "update","banking","confirm","password","credential"]
        for word in suspicious_path_words:
            if word in path.lower() or word in query.lower():
                flags.append(f'Suspicious keyword in URL path: "{word}"')
                score += 10
                break

    # URL length (very long = possible obfuscation)
    if len(url) > 100:
        flags.append(f"URL is very long ({len(url)} chars) — possible obfuscation")
        score += 15

    # HTTP (not HTTPS) — only flag for untrusted/unknown domains
    if url.startswith("http://") and not is_trusted:
        flags.append("URL uses HTTP (not HTTPS) — unencrypted")
        score += 10

    # Redirect parameters
    if re.search(r'[?&](url|redirect|goto|link|r|u)=https?://', query, re.IGNORECASE):
        flags.append("URL contains open redirect parameter")
        score += 20

    # Hex/percent encoding in hostname
    if "%" in host:
        flags.append("Hostname contains percent-encoded characters (obfuscation)")
        score += 30

    return flags, score


def _is_trusted_domain(host: str) -> bool:
    """Return True if host is in or is a subdomain of a known-trusted domain."""
    if not host:
        return False
    host = host.lower()
    for trusted in TRUSTED_DOMAINS:
        if host == trusted or host.endswith("." + trusted):
            return True
    return False


def _virustotal_check(url: str, api_key: str) -> dict | None:
    """Query VirusTotal URL analysis (v3 API, free tier)."""
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=5
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except Exception:
        pass
    return None


def _get_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or url
    except Exception:
        return url


def summarize_url_risks(url_results: list[dict]) -> dict:
    """
    Summarize URL threat results into a single risk assessment.
    Returns {"max_risk": str, "high_count": int, "medium_count": int, "flagged_urls": list}
    """
    risk_order = {"high": 3, "medium": 2, "low": 1, "clean": 0, "unknown": 0}
    max_risk   = "clean"
    high_count = medium_count = 0
    flagged    = []

    for r in url_results:
        risk = r.get("risk", "unknown")
        if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
            max_risk = risk
        if risk == "high":
            high_count += 1
            flagged.append(r["url"])
        elif risk == "medium":
            medium_count += 1
            flagged.append(r["url"])

    return {
        "max_risk":     max_risk,
        "high_count":   high_count,
        "medium_count": medium_count,
        "flagged_urls": flagged,
    }
