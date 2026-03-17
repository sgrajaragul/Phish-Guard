"""
parser.py — Parses raw email input into structured fields.
Supports both raw .eml format and plain text paste.
"""

import email
import re
from email import policy
from bs4 import BeautifulSoup


def parse_email(raw_text: str) -> dict:
    """
    Parse a raw email string into a structured dict.
    Returns headers, body (plain + html), extracted URLs, and IP addresses.
    """
    result = {
        "subject": "",
        "sender": "",
        "reply_to": "",
        "return_path": "",
        "received_from": [],
        "date": "",
        "body_plain": "",
        "body_html": "",
        "urls": [],
        "attachments": [],
        "ip_addresses": [],
        "raw": raw_text,
    }

    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
    except Exception:
        # Fallback: treat entire input as plain body
        result["body_plain"] = raw_text
        result["urls"] = extract_urls(raw_text)
        return result

    # ── Headers ──────────────────────────────────────────────
    result["subject"]      = str(msg.get("Subject", ""))
    result["sender"]       = str(msg.get("From", ""))
    result["reply_to"]     = str(msg.get("Reply-To", ""))
    result["return_path"]  = str(msg.get("Return-Path", ""))
    result["date"]         = str(msg.get("Date", ""))

    received = msg.get_all("Received") or []
    result["received_from"] = [str(r) for r in received]

    # ── Body ─────────────────────────────────────────────────
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))

            if "attachment" in disp:
                result["attachments"].append(part.get_filename() or "unknown")
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if ctype == "text/plain":
                result["body_plain"] += text
            elif ctype == "text/html":
                result["body_html"] += text
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            text = str(msg.get_payload())

        if msg.get_content_type() == "text/html":
            result["body_html"] = text
            result["body_plain"] = html_to_text(text)
        else:
            result["body_plain"] = text

    # If we have HTML but no plain text, derive it
    if result["body_html"] and not result["body_plain"]:
        result["body_plain"] = html_to_text(result["body_html"])

    # ── URL extraction ────────────────────────────────────────
    combined = result["body_plain"] + " " + result["body_html"]
    result["urls"] = extract_urls(combined)

    # ── IP address extraction ─────────────────────────────────
    result["ip_addresses"] = extract_ips(raw_text, result["received_from"])

    return result


def html_to_text(html: str) -> str:
    """Strip HTML tags and return clean plain text."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from a text string, deduplicated."""
    pattern = r'https?://[^\s\'"<>\]\)\\]+'
    urls = re.findall(pattern, text, re.IGNORECASE)
    # Also catch href= patterns in HTML
    href_pattern = r'href=["\']?(https?://[^"\'>\s]+)'
    urls += re.findall(href_pattern, text, re.IGNORECASE)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for u in urls:
        u = u.rstrip(".,;)")
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def extract_ips(raw_text: str, received_headers: list[str]) -> list[dict]:
    """
    Extract IP addresses from email headers and body.
    Returns list of dicts with IP and source information.
    """
    ips_found = []
    seen_ips = set()
    
    # IPv4 pattern (basic validation)
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # ── Extract from Received headers ──────────────────────────
    for received in received_headers:
        ips = re.findall(ipv4_pattern, received)
        for ip in ips:
            # Skip private/internal IPs
            if _is_private_ip(ip):
                continue
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips_found.append({
                    "ip": ip,
                    "source": "Received header",
                    "context": received[:100] + "..." if len(received) > 100 else received
                })
    
    # ── Extract from X-Originating-IP header ───────────────────
    xorig_pattern = r'X-Originating-IP:\s*\[?(' + ipv4_pattern + r')\]?'
    xorig_matches = re.findall(xorig_pattern, raw_text, re.IGNORECASE)
    for ip in xorig_matches:
        if not _is_private_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            ips_found.append({
                "ip": ip,
                "source": "X-Originating-IP header",
                "context": "Email origin"
            })
    
    # ── Extract from X-Forwarded-For header ────────────────────
    xff_pattern = r'X-Forwarded-For:\s*(' + ipv4_pattern + r')'
    xff_matches = re.findall(xff_pattern, raw_text, re.IGNORECASE)
    for ip in xff_matches:
        if not _is_private_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            ips_found.append({
                "ip": ip,
                "source": "X-Forwarded-For header",
                "context": "Forwarded request"
            })
    
    return ips_found


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved ranges."""
    try:
        parts = [int(p) for p in ip.split('.')]
        # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        # Loopback: 127.x.x.x
        if parts[0] == 127:
            return True
        # Link-local: 169.254.x.x
        if parts[0] == 169 and parts[1] == 254:
            return True
        return False
    except Exception:
        return True  # If parsing fails, consider it private (skip it)
