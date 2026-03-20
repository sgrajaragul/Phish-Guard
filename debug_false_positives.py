"""
debug_false_positives.py — Tool to test emails and debug false positive detections

Usage:
    python debug_false_positives.py test_email.eml
    python debug_false_positives.py --interactive
"""

import sys
import argparse
from pathlib import Path

# Add app to path
sys.path.insert(0, ".")

from app.parser import parse_email
from app.features import extract_features
from app.threat_intel import check_urls, check_ips
from app.report import build_report
from app.model import predict, model_exists


def analyze_email_debug(raw_email: str) -> dict:
    """
    Analyze an email and return detailed debugging information.
    """
    print("=" * 70)
    print("  PhishGuard — Debug Analysis")
    print("=" * 70)
    print()
    
    # Parse
    print("[1] Parsing email...")
    parsed = parse_email(raw_email)
    print(f"    Subject: {parsed.get('subject', 'N/A')}")
    print(f"    From: {parsed.get('sender', 'N/A')}")
    print(f"    Reply-To: {parsed.get('reply_to', 'N/A')}")
    print()
    
    # Extract features
    print("[2] Extracting features...")
    feat_result = extract_features(parsed)
    features = feat_result["features"]
    
    # Show email authentication
    print("    Email Authentication:")
    print(f"      SPF:   {'✓ PASS' if features.get('spf_pass', 0) else '✗ FAIL/NONE'}")
    print(f"      DKIM:  {'✓ PASS' if features.get('dkim_pass', 0) else '✗ FAIL/NONE'}")
    print(f"      DMARC: {'✓ PASS' if features.get('dmarc_pass', 0) else '✗ FAIL/NONE'}")
    print()
    
    # Show suspicious features
    print("    Suspicious Features Found:")
    if features.get('subject_has_urgency', 0):
        print(f"      - Urgency language in subject")
    if features.get('body_credential_score', 0):
        print(f"      - Credential requests in body ({features['body_credential_score']} phrases)")
    if features.get('urls_with_ip', 0):
        print(f"      - {features['urls_with_ip']} URL(s) with IP addresses")
    if features.get('script_count', 0):
        print(f"      - JavaScript found ({features['script_count']} scripts)")
    if features.get('form_count', 0):
        print(f"      - HTML forms found ({features['form_count']} forms)")
    if not any([
        features.get('subject_has_urgency', 0),
        features.get('body_credential_score', 0),
        features.get('urls_with_ip', 0),
        features.get('script_count', 0),
        features.get('form_count', 0)
    ]):
        print("      (none detected)")
    print()
    
    # Check URLs
    print("[3] Checking URLs...")
    url_results = check_urls(feat_result.get("url_list", []))
    print(f"    Found {len(url_results)} URL(s)")
    for r in url_results:
        print(f"      - {r['url'][:60]}... → Risk: {r['risk'].upper()}")
    print()
    
    # Check IPs
    print("[4] Checking IP addresses...")
    ip_results = check_ips(parsed.get("ip_addresses", []))
    print(f"    Found {len(ip_results)} public IP(s)")
    for r in ip_results:
        print(f"      - {r['ip']} → Risk: {r['risk'].upper()} (Abuse: {r.get('abuse_score', 0)}%)")
    print()
    
    # ML prediction
    print("[5] ML Model Prediction...")
    if model_exists():
        ml_result = predict(parsed)
        print(f"    Label: {ml_result['label']}")
        print(f"    Confidence: {ml_result['confidence']*100:.1f}%")
        print(f"    Phishing Probability: {ml_result['probability']['Phishing']*100:.1f}%")
    else:
        print("    Model not trained - using heuristics only")
        ml_result = {
            "label": "Unknown",
            "confidence": 0.5,
            "probability": {"Phishing": 0.5, "Legitimate": 0.5}
        }
    print()
    
    # Build report
    print("[6] Generating Risk Score...")
    report = build_report(parsed, feat_result, ml_result, url_results, ip_results)
    
    print("=" * 70)
    print("  FINAL ANALYSIS")
    print("=" * 70)
    print(f"  Verdict: {report['verdict']}")
    print(f"  Risk Score: {report['risk_score']}/100")
    print(f"  ML Confidence: {report['ml_confidence']}%")
    print()
    
    print("  Flags:")
    for flag in report['flags'][:10]:  # Show first 10 flags
        print(f"    - {flag}")
    if len(report['flags']) > 10:
        print(f"    ... and {len(report['flags']) - 10} more")
    print()
    
    print("  Recommendation:")
    print(f"    {report['recommendation']}")
    print("=" * 70)
    print()
    
    # Detailed breakdown for debugging
    print("DETAILED SCORE BREAKDOWN (for debugging):")
    print(f"  Base ML Score: {int(ml_result['probability']['Phishing'] * 45)} points")
    
    # Show authentication impact
    auth_reduction = 0
    if features.get('spf_pass', 0) and features.get('dkim_pass', 0) and features.get('dmarc_pass', 0):
        auth_reduction = 40
        print(f"  Authentication Bonus: -40% (all checks passed)")
    elif features.get('spf_pass', 0) and features.get('dkim_pass', 0):
        auth_reduction = 25
        print(f"  Authentication Bonus: -25% (SPF+DKIM passed)")
    
    print(f"  URL Threat Intel: {url_results[0]['risk'] if url_results else 'none'}")
    print(f"  IP Threat Intel: {ip_results[0]['risk'] if ip_results else 'none'}")
    print()
    
    return report


def main():
    parser = argparse.ArgumentParser(description="Debug false positive detections")
    parser.add_argument("email_file", nargs="?", help="Path to .eml file to analyze")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    args = parser.parse_args()
    
    if args.interactive:
        print("Interactive mode - paste email content (Ctrl+D when done):")
        print("-" * 70)
        raw_email = sys.stdin.read()
    elif args.email_file:
        email_path = Path(args.email_file)
        if not email_path.exists():
            print(f"Error: File not found: {args.email_file}")
            sys.exit(1)
        with open(email_path, 'rb') as f:
            raw_email = f.read().decode('utf-8', errors='replace')
    else:
        parser.print_help()
        sys.exit(1)
    
    analyze_email_debug(raw_email)


if __name__ == "__main__":
    main()
