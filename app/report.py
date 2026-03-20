"""
report.py — Builds the final analysis report combining ML prediction,
            feature flags, and threat intelligence.

UPDATED: Better risk scoring to reduce false positives
"""

from app.threat_intel import summarize_url_risks


RISK_WEIGHTS = {
    # ══════════════════════════════════════════════════════════════════════════
    # PRIMARY SIGNALS (High confidence, independent verification)
    # ══════════════════════════════════════════════════════════════════════════
    
    # Email Authentication FAILURES (⭐ NEW - Most reliable signal)
    "spf_fail":        35,   # SPF fail is very strong signal
    "dkim_fail":       35,   # DKIM fail means forged/tampered
    "dmarc_fail":      30,   # DMARC fail indicates policy violation
    
    # ML model (still primary but now balanced with auth)
    "ml_phishing_confidence": 45,  # Reduced from 55 to balance with auth
    
    # IP threat intelligence (independent verification)
    "ip_high_risk":    25,
    "ip_medium_risk":  12,
    "ip_low_risk":      5,
    
    # URL threat intelligence (independent verification)
    "url_high_risk":   20,
    "url_medium_risk":  8,
    
    # ══════════════════════════════════════════════════════════════════════════
    # SECONDARY SIGNALS (Context-dependent, require ML confidence)
    # ══════════════════════════════════════════════════════════════════════════
    
    # Feature bonuses — only apply when ML is already suspicious
    # These are multiplied by ml_phishing_prob to prevent false positives
    "has_script":           15,  # Reduced from 18
    "has_form":             10,  # Reduced from 12
    "sender_mismatch":       8,  # Reduced from 12
    "dangerous_attachment": 15,  # Reduced from 18
    "credential_lure":       6,  # Reduced from 8
    "ip_url":               10,  # Reduced from 14
    "hidden_text":           6,  # Reduced from 8
    "url_at_sign":           8,  # Reduced from 10
}

# Thresholds for applying feature bonuses
ML_BONUS_THRESHOLD = 0.50  # Increased from 0.45 to be more conservative
BONUS_MULTIPLIER_LOW = 0.2  # When ML < threshold, bonuses are minimal
BONUS_MULTIPLIER_HIGH = 1.0  # When ML >= threshold, full bonuses apply


def build_report(
    parsed:      dict,
    feat_result: dict,
    ml_result:   dict,
    url_results: list[dict],
    ip_results:  list[dict] = None,
) -> dict:
    """
    Build a comprehensive phishing analysis report with reduced false positives.

    Args:
        parsed:      Output from parser.parse_email()
        feat_result: Output from features.extract_features()
        ml_result:   Output from model.predict()
        url_results: Output from threat_intel.check_urls()
        ip_results:  Output from threat_intel.check_ips()

    Returns:
        Full report dict ready for JSON serialization / template rendering.
    """
    if ip_results is None:
        ip_results = []
        
    features   = feat_result["features"]
    flags      = feat_result["flags"]
    url_list   = feat_result.get("url_list", [])
    url_summary = summarize_url_risks(url_results)
    ip_summary  = summarize_ip_risks(ip_results)

    # ── Risk score calculation (0–100) ────────────────────────
    score = 0
    
    # ══════════════════════════════════════════════════════════
    # PRIMARY SIGNALS (Always apply full weight)
    # ══════════════════════════════════════════════════════════
    
    # Email Authentication Failures (⭐ NEW - Highest priority)
    # These are INDEPENDENT signals - don't need ML confirmation
    if not features.get("spf_pass", 0):
        # Check if it's a hard fail or just missing
        if features.get("auth_fail_count", 0) > 0:
            score += RISK_WEIGHTS["spf_fail"]
    
    if not features.get("dkim_pass", 0):
        if features.get("auth_fail_count", 0) > 0:
            score += RISK_WEIGHTS["dkim_fail"]
    
    if not features.get("dmarc_pass", 0):
        if features.get("auth_fail_count", 0) > 0:
            score += RISK_WEIGHTS["dmarc_fail"]
    
    # ML contribution
    phish_prob = ml_result["probability"].get("Phishing", 0.0)
    score += int(phish_prob * RISK_WEIGHTS["ml_phishing_confidence"])
    
    # IP threat intel (independent signal - always full weight)
    score += ip_summary["high_count"]   * RISK_WEIGHTS["ip_high_risk"]
    score += ip_summary["medium_count"] * RISK_WEIGHTS["ip_medium_risk"]
    score += ip_summary["low_count"]    * RISK_WEIGHTS["ip_low_risk"]
    
    # URL threat intel (independent signal - always full weight)
    score += url_summary["high_count"]   * RISK_WEIGHTS["url_high_risk"]
    score += url_summary["medium_count"] * RISK_WEIGHTS["url_medium_risk"]
    
    # ══════════════════════════════════════════════════════════
    # SECONDARY SIGNALS (Context-dependent bonuses)
    # ══════════════════════════════════════════════════════════
    
    # Feature bonuses are scaled by ML confidence to prevent false positives
    # Logic: If ML says probably legit (<50%), these signals carry minimal weight
    #        If ML says probably phishing (>=50%), these signals reinforce verdict
    
    if phish_prob >= ML_BONUS_THRESHOLD:
        bonus_multiplier = BONUS_MULTIPLIER_HIGH
    else:
        bonus_multiplier = BONUS_MULTIPLIER_LOW
    
    # Apply bonuses
    if features.get("script_count", 0) > 0:
        score += int(RISK_WEIGHTS["has_script"] * bonus_multiplier)
    
    if features.get("form_count", 0) > 0:
        score += int(RISK_WEIGHTS["has_form"] * bonus_multiplier)
    
    if features.get("sender_replyto_mismatch") or features.get("sender_retpath_mismatch"):
        score += int(RISK_WEIGHTS["sender_mismatch"] * bonus_multiplier)
    
    if features.get("dangerous_attachment", 0) > 0:
        score += int(RISK_WEIGHTS["dangerous_attachment"] * bonus_multiplier)
    
    if features.get("body_credential_score", 0) >= 1:
        score += int(RISK_WEIGHTS["credential_lure"] * bonus_multiplier)
    
    if features.get("urls_with_ip", 0) > 0:
        score += int(RISK_WEIGHTS["ip_url"] * bonus_multiplier)
    
    if features.get("hidden_text", 0) > 0:
        score += int(RISK_WEIGHTS["hidden_text"] * bonus_multiplier)
    
    if features.get("urls_with_at_sign", 0) > 0:
        score += int(RISK_WEIGHTS["url_at_sign"] * bonus_multiplier)
    
    # ══════════════════════════════════════════════════════════
    # LEGITIMATE EMAIL ADJUSTMENTS (Reduce false positives)
    # ══════════════════════════════════════════════════════════
    
    # If ALL authentication checks pass, significantly reduce score
    if (features.get("spf_pass", 0) and 
        features.get("dkim_pass", 0) and 
        features.get("dmarc_pass", 0)):
        # All auth passed - very strong legitimate signal
        score = int(score * 0.6)  # Reduce by 40%
        flags.append("✓ All email authentication checks passed (SPF, DKIM, DMARC)")
    
    # If at least SPF+DKIM pass (common for legit emails without DMARC)
    elif (features.get("spf_pass", 0) and features.get("dkim_pass", 0)):
        score = int(score * 0.75)  # Reduce by 25%
        flags.append("✓ Email authentication passed (SPF + DKIM)")
    
    score = min(score, 100)   # cap at 100

    # ── Verdict ───────────────────────────────────────────────
    # More conservative thresholds to reduce false positives
    if score >= 75:  # Increased from 70
        verdict = "Phishing"
        verdict_color = "danger"
    elif score >= 50:  # Increased from 40
        verdict = "Suspicious"
        verdict_color = "warning"
    else:
        verdict = "Likely Legitimate"
        verdict_color = "success"

    # ── Build URL detail rows ─────────────────────────────────
    url_details = []
    for r in url_results:
        url_details.append({
            "url":        r["url"],
            "domain":     r["domain"],
            "risk":       r["risk"],
            "heuristics": r["heuristics"],
        })

    # ── Build IP detail rows ──────────────────────────────────
    ip_details = []
    for r in ip_results:
        ip_details.append({
            "ip":            r["ip"],
            "source":        r["source"],
            "context":       r["context"],
            "risk":          r["risk"],
            "abuse_score":   r.get("abuse_score", 0),
            "reports":       r.get("reports", 0),
            "last_reported": r.get("last_reported"),
            "country":       r.get("country"),
            "isp":           r.get("isp"),
            "flags":         r.get("flags", []),
        })

    # ── Collect all red flags ─────────────────────────────────
    all_flags = list(flags)  # from feature extractor
    for r in url_results:
        for h in r.get("heuristics", []):
            entry = f"[{r['domain']}] {h}"
            if entry not in all_flags:
                all_flags.append(entry)
    for r in ip_results:
        for f in r.get("flags", []):
            entry = f"[IP: {r['ip']}] {f}"
            if entry not in all_flags:
                all_flags.append(entry)

    # ── Build recommendation ──────────────────────────────────
    recommendation = _build_recommendation(score, all_flags, features)

    return {
        # Core verdict
        "verdict":       verdict,
        "verdict_color": verdict_color,
        "risk_score":    score,

        # ML details
        "ml_label":       ml_result["label"],
        "ml_confidence":  round(ml_result["confidence"] * 100, 1),
        "ml_probability": {
            k: round(v * 100, 1) for k, v in ml_result["probability"].items()
        },

        # Email metadata
        "sender":     parsed.get("sender", "—"),
        "reply_to":   parsed.get("reply_to", "—"),
        "subject":    parsed.get("subject", "—"),
        "date":       parsed.get("date", "—"),

        # Email Authentication (⭐ NEW)
        "spf_status":   "Pass" if features.get("spf_pass", 0) else "Fail",
        "dkim_status":  "Pass" if features.get("dkim_pass", 0) else "Fail",
        "dmarc_status": "Pass" if features.get("dmarc_pass", 0) else "Fail",

        # Flags and URLs
        "flags":       all_flags,
        "url_count":   len(url_list),
        "url_details": url_details,
        "url_summary": url_summary,

        # IP addresses
        "ip_count":    len(ip_results),
        "ip_details":  ip_details,
        "ip_summary":  ip_summary,

        # Attachment info
        "attachments": parsed.get("attachments", []),

        # Recommendation
        "recommendation": recommendation,

        # Raw features (for debug / advanced view)
        "features": features,
    }


def _build_recommendation(score: int, flags: list, features: dict) -> str:
    if score >= 75:
        lines = [
            "⚠️ This email shows strong indicators of a phishing attack.",
            "Do NOT click any links or download attachments.",
            "Do NOT enter credentials if you followed a link from this email.",
            "Report this email to your IT/security team and delete it.",
        ]
    elif score >= 50:
        lines = [
            "⚠️ This email has several suspicious characteristics.",
            "Treat with caution — verify the sender through a separate channel before acting.",
            "Do not click links unless you are certain of their origin.",
        ]
    else:
        lines = [
            "✅ This email appears to be legitimate based on available signals.",
        ]
        # Add authentication confidence if all checks passed
        if features.get("spf_pass", 0) and features.get("dkim_pass", 0):
            lines.append("Email authentication (SPF/DKIM) passed successfully.")
        lines.append("Always exercise caution — no automated tool is 100% accurate.")

    if features.get("script_count", 0) > 0:
        lines.append("JavaScript was found in this email — this is almost never legitimate.")
    if features.get("dangerous_attachment", 0) > 0:
        lines.append("Dangerous attachment detected — do not open it.")

    return " ".join(lines)


def summarize_ip_risks(ip_results: list[dict]) -> dict:
    """
    Summarize IP threat results into a single risk assessment.
    """
    risk_order = {"high": 4, "medium": 3, "low": 2, "clean": 1, "unknown": 0}
    max_risk   = "clean"
    high_count = medium_count = low_count = 0
    flagged    = []

    for r in ip_results:
        risk = r.get("risk", "unknown")
        if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
            max_risk = risk
        if risk == "high":
            high_count += 1
            flagged.append({
                "ip": r["ip"],
                "abuse_score": r.get("abuse_score", 0),
                "reports": r.get("reports", 0)
            })
        elif risk == "medium":
            medium_count += 1
            flagged.append({
                "ip": r["ip"],
                "abuse_score": r.get("abuse_score", 0),
                "reports": r.get("reports", 0)
            })
        elif risk == "low":
            low_count += 1

    return {
        "max_risk":     max_risk,
        "high_count":   high_count,
        "medium_count": medium_count,
        "low_count":    low_count,
        "flagged_ips":  flagged,
    }
