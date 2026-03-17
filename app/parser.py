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
    Returns headers, body (plain + html), and extracted URLs.
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
