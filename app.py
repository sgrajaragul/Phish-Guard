"""
app.py — PhishGuard Flask web application.
Run with:  python app.py
"""

import os
from flask import Flask, request, jsonify, render_template

from app.parser import parse_email
from app.features import extract_features
from app.threat_intel import check_urls, check_ips
from app.report import build_report
from app.model import predict, model_exists

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # 2MB max upload


@app.route("/")
def index():
    return render_template("index.html", model_ready=model_exists())


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze
    Accepts JSON: { "email": "<raw email text>" }
    OR multipart form with file upload: field name "email_file"

    Returns full analysis report as JSON.
    """
    raw_email = ""

    # ── Accept file upload ────────────────────────────────────
    if "email_file" in request.files:
        f = request.files["email_file"]
        try:
            raw_email = f.read().decode("utf-8", errors="replace")
        except Exception as e:
            return jsonify({"error": f"Could not read file: {e}"}), 400

    # ── Accept JSON body ──────────────────────────────────────
    elif request.is_json:
        data = request.get_json()
        raw_email = data.get("email", "")

    # ── Accept form field ─────────────────────────────────────
    elif "email_text" in request.form:
        raw_email = request.form["email_text"]

    if not raw_email.strip():
        return jsonify({"error": "No email content provided."}), 400

    try:
        # ── Pipeline ──────────────────────────────────────────
        parsed      = parse_email(raw_email)
        feat_result = extract_features(parsed)
        url_results = check_urls(feat_result.get("url_list", []))
        ip_results  = check_ips(parsed.get("ip_addresses", []))

        if model_exists():
            ml_result = predict(parsed)
        else:
            # Fallback: rule-based only when model not trained yet
            flags     = feat_result["flags"]
            heuristic_score = len(flags) * 8
            phish_prob = min(heuristic_score / 100, 0.99)
            ml_result  = {
                "label":       "Phishing" if phish_prob > 0.5 else "Legitimate",
                "confidence":  phish_prob if phish_prob > 0.5 else 1 - phish_prob,
                "probability": {"Phishing": phish_prob, "Legitimate": 1 - phish_prob},
            }

        report = build_report(parsed, feat_result, ml_result, url_results, ip_results)
        return jsonify(report)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": model_exists()})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    
    print("=" * 60)
    print(f"  PhishGuard — AI-Powered Phishing Email Analyzer")
    print("=" * 60)
    print(f"[*] Server: http://localhost:{port}")
    
    # Check model status
    if not model_exists():
        print("[!] Model not trained yet — run training script first:")
        print("    python train_enhanced.py (recommended)")
        print("    python train_hybrid.py --phishing-dir ./samples")
        print("[*] Heuristic-only mode active until model is trained.")
    else:
        print("[✓] ML model loaded and ready")
    
    # Check API services
    try:
        import api_keys
        configured = api_keys.get_all_configured_services()
        if configured:
            print(f"[✓] API Services: {', '.join(configured)}")
        else:
            print("[!] No API services configured")
            print("    Edit api_keys.py to add VirusTotal/AbuseIPDB keys")
    except ImportError:
        print("[!] api_keys.py not found - using environment variables")
        print("    Create api_keys.py from api_keys.template.py")
    
    print("=" * 60)
    print()
    
    app.run(host="0.0.0.0", port=port, debug=debug)
