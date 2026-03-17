"""
test_ip_feature.py — Demo script showing the new IP threat intelligence feature

This script demonstrates how PhishGuard now extracts and analyzes IP addresses
from email headers to detect if they've been used in previous phishing attacks.
"""

from app.parser import parse_email
from app.threat_intel import check_ips

# Sample phishing email with suspicious IP in headers
SAMPLE_EMAIL = """Received: from mail.suspicious-domain.xyz (185.220.101.5)
    by mail.google.com with ESMTP id abc123
    for <victim@example.com>; Mon, 15 Jan 2024 10:30:00 -0800 (PST)
Received: from [192.168.1.100] (unknown [45.142.212.61])
    by mail.suspicious-domain.xyz (Postfix) with ESMTP id XYZ789
    Mon, 15 Jan 2024 18:30:00 +0000 (UTC)
X-Originating-IP: [103.253.145.28]
From: security@paypal-verify.xyz
To: victim@example.com
Subject: URGENT: Verify your account immediately
Date: Mon, 15 Jan 2024 10:30:00 -0800

Dear customer,

Your PayPal account has been compromised. Click here immediately to verify:
http://192.168.1.1/login.php

Enter your password and credit card details now.

PayPal Security Team
"""


def main():
    print("=" * 70)
    print("  PhishGuard — IP Threat Intelligence Demo")
    print("=" * 70)
    print()
    
    # Parse the email
    print("[1] Parsing email and extracting IP addresses...")
    parsed = parse_email(SAMPLE_EMAIL)
    
    ip_addresses = parsed.get("ip_addresses", [])
    print(f"    Found {len(ip_addresses)} public IP address(es):")
    for ip_info in ip_addresses:
        print(f"      - {ip_info['ip']} (from: {ip_info['source']})")
    print()
    
    # Check IPs for abuse history
    print("[2] Checking IPs against AbuseIPDB...")
    
    abuseipdb_key = input("    Enter your AbuseIPDB API key (or press Enter to skip): ").strip()
    
    if abuseipdb_key:
        import os
        os.environ["ABUSEIPDB_API_KEY"] = abuseipdb_key
        ip_results = check_ips(ip_addresses)
        
        print()
        print("[3] IP Reputation Results:")
        print("-" * 70)
        
        for result in ip_results:
            print(f"\n  IP: {result['ip']}")
            print(f"  Source: {result['source']}")
            print(f"  Risk Level: {result['risk'].upper()}")
            print(f"  Abuse Score: {result['abuse_score']}%")
            print(f"  Total Reports: {result['reports']}")
            
            if result.get('country'):
                print(f"  Country: {result['country']}")
            if result.get('isp'):
                print(f"  ISP: {result['isp']}")
            
            if result.get('flags'):
                print(f"  Flags:")
                for flag in result['flags']:
                    print(f"    ⚠️  {flag}")
            print("-" * 70)
        
        print("\n✅ IP analysis complete!")
        print("\nInterpretation:")
        print("  - abuse_score 0-24%:   Clean/Low risk")
        print("  - abuse_score 25-74%:  Medium risk - proceed with caution")
        print("  - abuse_score 75-100%: High risk - likely malicious")
        
    else:
        print("    Skipped (no API key provided)")
        print()
        print("    To enable IP threat intelligence:")
        print("    1. Get a free API key at https://www.abuseipdb.com/register")
        print("    2. Set environment variable: export ABUSEIPDB_API_KEY=your_key")
        print("    3. Restart the application")
    
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
