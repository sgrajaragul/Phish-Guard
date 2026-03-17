"""
report.py — Builds the final analysis report combining ML prediction,
            feature flags, and URL threat intelligence.
"""

from app.threat_intel import summarize_url_risks


RISK_WEIGHTS = {
    # ML model is the primary signal — max 55 pts
    "ml_phishing_confidence": 55,

    # URL threat intelligence — strong independent signal
    "url_high_risk":   20,
    "url_medium_risk":  8,

    # Feature bonuses — only meaningful alongside ML suspicion
    # These are multiplied by ml_phishing_prob so they don't inflate legit scores
    "has_script":           18,
    "has_form":             12,
    "sender_mismatch":      12,
    "dangerous_attachment": 18,
    "credential_lure":       8,
    "ip_url":               14,
    "hidden_text":           8,
    "url_at_sign":          10,
}

# Below this ML threshold, feature bonuses are heavily dampened
ML_BONUS_THRESHOLD = 0.45


def build_report(
    parsed:      dict,
    feat_result: dict,
    ml_result:   dict,
    url_results: list[dict],
) -> dict:
    """
    Build a comprehensive phishing analysis report.

    Args:
        parsed:      Output from parser.parse_email()
        feat_result: Output from features.extract_features()
        ml_result:   Output from model.predict()
        url_results: Output from threat_intel.check_urls()

    Returns:
        Full report dict ready for JSON serialization / template rendering.
    """
    features   = feat_result["features"]
    flags      = feat_result["flags"]
    url_list   = feat_result.get("url_list", [])
    url_summary = summarize_url_risks(url_results)

    # ── Risk score calculation (0–100) ────────────────────────
    score = 0

    # ML contribution — primary signal (up to 55 pts)
    phish_prob = ml_result["probability"].get("Phishing", 0.0)
    score += int(phish_prob * RISK_WEIGHTS["ml_phishing_confidence"])

    # URL threat intel — independent of ML, always full weight
    score += url_summary["high_count"]   * RISK_WEIGHTS["url_high_risk"]
    score += url_summary["medium_count"] * RISK_WEIGHTS["url_medium_risk"]

    # Feature flag bonuses — scaled by ML confidence
    # When ML says <45% phishing, bonuses are heavily dampened (×0.3)
    # When ML says >45% phishing, bonuses apply at full weight
    # This prevents legit emails from scoring high just from keyword matches
    bonus_multiplier = 1.0 if phish_prob >= ML_BONUS_THRESHOLD else 0.3

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

    score = min(score, 100)   # cap at 100

    # ── Verdict ───────────────────────────────────────────────
    if score >= 70:
        verdict = "Phishing"
        verdict_color = "danger"
    elif score >= 40:
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

    # ── Collect all red flags ─────────────────────────────────
    all_flags = list(flags)  # from feature extractor
    for r in url_results:
        for h in r.get("heuristics", []):
            entry = f"[{r['domain']}] {h}"
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

        # Flags and URLs
        "flags":       all_flags,
        "url_count":   len(url_list),
        "url_details": url_details,
        "url_summary": url_summary,

        # Attachment info
        "attachments": parsed.get("attachments", []),

        # Recommendation
        "recommendation": recommendation,

        # Raw features (for debug / advanced view)
        "features": features,
    }


def _build_recommendation(score: int, flags: list, features: dict) -> str:
    if score >= 70:
        lines = [
            "⚠️ This email shows strong indicators of a phishing attack.",
            "Do NOT click any links or download attachments.",
            "Do NOT enter credentials if you followed a link from this email.",
            "Report this email to your IT/security team and delete it.",
        ]
    elif score >= 40:
        lines = [
            "⚠️ This email has several suspicious characteristics.",
            "Treat with caution — verify the sender through a separate channel before acting.",
            "Do not click links unless you are certain of their origin.",
        ]
    else:
        lines = [
            "✅ This email appears to be legitimate based on available signals.",
            "Always exercise caution — no automated tool is 100% accurate.",
        ]

    if features.get("script_count", 0) > 0:
        lines.append("JavaScript was found in this email — this is almost never legitimate.")
    if features.get("dangerous_attachment", 0) > 0:
        lines.append("Dangerous attachment detected — do not open it.")

    return " ".join(lines)
