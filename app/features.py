"""
features.py — Extracts ML-ready and human-readable features from a parsed email.

Categories:
  - Header anomalies   (sender mismatch, reply-to divergence)
  - Urgency language   (NLP keyword scoring)
  - URL signals        (IP-based, excessive redirects, mismatched text)
  - Structural signals (HTML-only, hidden text, unusual attachment types)
  - Credential lures   (login, password, verify language)
"""

import re
import urllib.parse
from collections import Counter


# ── Keyword lists ─────────────────────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "verify now", "act now",
    "account suspended", "account will be suspended", "account will be closed",
    "account will be terminated", "will be terminated", "failure to respond",
    "will be deactivated", "limited time offer", "expires in 24",
    "expires in 48", "unauthorized access detected", "confirm identity",
    "click here to verify", "click below to verify", "click the link below",
    "unusual sign-in", "suspicious sign-in",
]

# Only flag multi-word combos that are unambiguous phishing phrases
CREDENTIAL_WORDS = [
    "social security number", "ssn", "credit card number",
    "enter your credit card", "enter your bank", "enter your password",
    "provide your password", "confirm your password", "verify your password",
    "enter your social", "provide your credit card",
    "update your payment method", "billing details required",
]

THREAT_WORDS = [
    "malware detected", "virus detected", "account hacked",
    "account compromised", "data breach", "suspicious login detected",
    "account frozen", "account restricted", "account blocked",
]

SUSPICIOUS_TLD = [
    ".xyz", ".top", ".club", ".work", ".gq", ".ml", ".cf", ".tk",
    ".pw", ".click", ".link", ".online", ".site", ".buzz",
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".ps1", ".vbs", ".js", ".jar", ".scr",
    ".cmd", ".hta", ".msi", ".dll",
]

# Trusted domains — suppress URL path heuristic flags for these
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "amazon.com", "aws.amazon.com",
    "github.com", "gitlab.com", "linkedin.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "youtube.com", "netflix.com",
    "paypal.com", "stripe.com", "shopify.com", "salesforce.com",
    "dropbox.com", "slack.com", "zoom.us", "atlassian.com", "notion.so",
    "medium.com", "substack.com", "mailchimp.com", "hubspot.com",
}


# ── Main feature extraction ───────────────────────────────────────────────────

def extract_features(parsed: dict) -> dict:
    """
    Return a flat dict of numeric/boolean features for the ML model,
    plus a human-readable 'flags' list for the report.
    """
    features = {}
    flags = []

    subject   = parsed.get("subject", "")
    sender    = parsed.get("sender", "")
    reply_to  = parsed.get("reply_to", "")
    ret_path  = parsed.get("return_path", "")
    body      = parsed.get("body_plain", "")
    body_html = parsed.get("body_html", "")
    urls      = parsed.get("urls", [])
    attachments = parsed.get("attachments", [])

    body_lower = body.lower()

    # ── 1. Header anomalies ───────────────────────────────────
    sender_domain   = _extract_domain(sender)
    replyto_domain  = _extract_domain(reply_to)
    retpath_domain  = _extract_domain(ret_path)

    features["sender_replyto_mismatch"] = int(
        bool(reply_to) and sender_domain != replyto_domain
    )
    features["sender_retpath_mismatch"] = int(
        bool(ret_path) and sender_domain != retpath_domain
    )
    features["no_reply_to"] = int(not bool(reply_to))
    features["has_return_path"] = int(bool(ret_path))

    if features["sender_replyto_mismatch"]:
        flags.append(f"Reply-To domain ({replyto_domain}) differs from sender ({sender_domain})")
    if features["sender_retpath_mismatch"]:
        flags.append(f"Return-Path domain ({retpath_domain}) differs from sender ({sender_domain})")

    # ── 2. Subject signals ────────────────────────────────────
    features["subject_has_urgency"]   = _keyword_score(subject.lower(), URGENCY_WORDS)
    features["subject_all_caps"]      = int(bool(re.search(r'\b[A-Z]{5,}\b', subject)))
    features["subject_has_re_fw"]     = int(bool(re.match(r'^(re:|fw:|fwd:)', subject.lower())))
    features["subject_exclamation"]   = subject.count("!")
    features["subject_question_mark"] = subject.count("?")

    if features["subject_has_urgency"]:
        flags.append(f'Subject uses urgency language: "{subject}"')
    if features["subject_all_caps"]:
        flags.append("Subject contains ALL-CAPS words (5+ letters)")

    # ── 3. Body urgency + credential lures ───────────────────
    features["body_urgency_score"]    = _keyword_score(body_lower, URGENCY_WORDS)
    features["body_credential_score"] = _keyword_score(body_lower, CREDENTIAL_WORDS)
    features["body_threat_score"]     = _keyword_score(body_lower, THREAT_WORDS)
    features["body_word_count"]       = len(body.split())
    features["body_char_count"]       = len(body)

    if features["body_urgency_score"] >= 2:
        flags.append(f"Body contains {features['body_urgency_score']} urgency phrases")
    if features["body_credential_score"] >= 1:
        flags.append("Body explicitly requests sensitive credentials or payment details")

    # ── 4. URL signals ────────────────────────────────────────
    features["url_count"] = len(urls)
    features["urls_with_ip"]         = sum(1 for u in urls if _is_ip_url(u))
    features["urls_with_at_sign"]    = sum(1 for u in urls if "@" in u)
    features["urls_with_redirect"]   = sum(1 for u in urls if _is_redirect(u))
    features["urls_long"]            = sum(1 for u in urls if len(u) > 75)
    features["urls_suspicious_tld"]  = sum(1 for u in urls if _has_suspicious_tld(u))
    features["urls_https_ratio"]     = _https_ratio(urls)
    features["unique_url_domains"]   = len(_unique_domains(urls))

    if features["urls_with_ip"]:
        flags.append(f'{features["urls_with_ip"]} URL(s) use raw IP addresses instead of domain names')
    if features["urls_with_at_sign"]:
        flags.append("URL(s) contain @ sign (common obfuscation trick)")
    if features["urls_suspicious_tld"]:
        flags.append(f'{features["urls_suspicious_tld"]} URL(s) use suspicious TLDs (.xyz, .tk, .ml, etc.)')
    if features["urls_long"]:
        flags.append(f'{features["urls_long"]} URL(s) are unusually long (possible obfuscation)')

    # ── 5. HTML structure signals ─────────────────────────────
    features["is_html_only"]     = int(bool(body_html) and not parsed.get("body_plain", "").strip())
    features["has_html"]         = int(bool(body_html))
    features["hidden_text"]      = _count_hidden_text(body_html)
    features["form_count"]       = body_html.lower().count("<form")
    features["iframe_count"]     = body_html.lower().count("<iframe")
    features["script_count"]     = body_html.lower().count("<script")
    features["image_count"]      = body_html.lower().count("<img")
    features["link_text_mismatch"] = _count_mismatched_links(body_html)

    if features["hidden_text"]:
        flags.append("Hidden text detected (white-on-white or display:none content)")
    if features["form_count"]:
        flags.append(f'Email contains {features["form_count"]} HTML form(s) — unusual for legitimate email')
    if features["script_count"]:
        flags.append("Email contains JavaScript — high-risk indicator")
    if features["link_text_mismatch"]:
        flags.append(f'{features["link_text_mismatch"]} link(s) display different text than actual URL')

    # ── 6. Attachment signals ─────────────────────────────────
    features["attachment_count"]     = len(attachments)
    features["dangerous_attachment"] = sum(
        1 for a in attachments
        if any(a.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    )
    if features["dangerous_attachment"]:
        flags.append(f'Dangerous attachment type detected: {[a for a in attachments]}')

    # ── 7. Sender trust signals ───────────────────────────────
    features["sender_is_freemail"] = int(_is_freemail(sender))
    features["sender_numeric"]     = int(bool(re.search(r'\d{4,}', sender_domain or "")))

    if features["sender_is_freemail"] and features["body_credential_score"] >= 1:
        flags.append("Credential request from a free email provider (Gmail/Yahoo/Hotmail)")

    return {
        "features": features,
        "flags": flags,
        "url_list": urls,
    }


def features_to_vector(features: dict) -> list:
    """
    Flatten feature dict into an ordered numeric list for sklearn.
    Order must match what was used during training.
    """
    keys = sorted(features.keys())
    return [float(features[k]) for k in keys], keys


# ── Helper functions ──────────────────────────────────────────────────────────

def _extract_domain(addr: str) -> str:
    match = re.search(r'@([\w.\-]+)', addr)
    return match.group(1).lower() if match else ""


def _keyword_score(text: str, keywords: list) -> int:
    return sum(1 for kw in keywords if kw in text)


def _is_ip_url(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    except Exception:
        return False


def _is_redirect(url: str) -> bool:
    redirect_params = ["url=", "redirect=", "goto=", "link=", "r=", "u="]
    url_lower = url.lower()
    return any(p in url_lower for p in redirect_params)


def _has_suspicious_tld(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return any(host.endswith(tld) for tld in SUSPICIOUS_TLD)
    except Exception:
        return False


def _https_ratio(urls: list) -> float:
    if not urls:
        return 1.0
    https_count = sum(1 for u in urls if u.startswith("https://"))
    return https_count / len(urls)


def _unique_domains(urls: list) -> set:
    domains = set()
    for u in urls:
        try:
            host = urllib.parse.urlparse(u).hostname or ""
            domains.add(host)
        except Exception:
            pass
    return domains


def _count_hidden_text(html: str) -> int:
    patterns = [
        r'color:\s*white',
        r'color:\s*#fff',
        r'color:\s*#ffffff',
        r'display:\s*none',
        r'visibility:\s*hidden',
        r'font-size:\s*0',
        r'opacity:\s*0',
    ]
    html_lower = html.lower()
    return sum(1 for p in patterns if re.search(p, html_lower))


def _count_mismatched_links(html: str) -> int:
    """Count <a> tags where visible text looks like a URL but differs from href."""
    count = 0
    pattern = re.compile(r'<a\s[^>]*href=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    for match in pattern.finditer(html):
        href = match.group(1)
        text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
        if re.match(r'https?://', text) and text != href:
            count += 1
    return count


def _is_freemail(addr: str) -> bool:
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                      "aol.com", "protonmail.com", "icloud.com", "mail.com"]
    domain = _extract_domain(addr)
    return domain in free_providers
