# IP Threat Intelligence Feature - Complete Guide

## Overview

PhishGuard now includes **IP Threat Intelligence** powered by AbuseIPDB, which automatically:
- ✅ Extracts IP addresses from email headers (Received, X-Originating-IP, X-Forwarded-For)
- ✅ Checks if those IPs have been used in previous phishing/spam/malware attacks
- ✅ Displays abuse confidence score (0-100%), number of reports, and attack history
- ✅ Adds IP reputation data to the risk score calculation
- ✅ Shows country, ISP, and detailed flags for each IP

## What's New

### 1. **Automatic IP Extraction** (`parser.py`)
   - Extracts public IPs from email routing headers
   - Filters out private/internal IPs (10.x.x.x, 192.168.x.x, 127.x.x.x)
   - Tracks the source of each IP (which header it came from)
   - Returns context information for each IP

### 2. **AbuseIPDB Integration** (`threat_intel.py`)
   - New function: `check_ips(ip_data)` 
   - Queries AbuseIPDB API for each IP address
   - Returns comprehensive reputation data:
     * Abuse confidence score (0-100%)
     * Total number of abuse reports
     * Last reported date
     * Country code and ISP
     * Whitelist status
     * Risk classification (clean/low/medium/high)

### 3. **Enhanced Risk Scoring** (`report.py`)
   - IPs now contribute to the overall risk score:
     * High-risk IP: +25 points
     * Medium-risk IP: +12 points
     * Low-risk IP: +5 points
   - IP flags are included in the report's flag list
   - New report fields: `ip_count`, `ip_details`, `ip_summary`

### 4. **Updated Report Output**
   ```json
   {
     "ip_count": 2,
     "ip_details": [
       {
         "ip": "185.220.101.5",
         "source": "Received header",
         "context": "from mail.suspicious-domain.xyz...",
         "risk": "high",
         "abuse_score": 85,
         "reports": 47,
         "last_reported": "2024-01-15T10:30:00Z",
         "country": "NL",
         "isp": "Evil Hosting Ltd",
         "flags": [
           "High abuse score: 85% confidence",
           "Reported 47 times for abuse"
         ]
       }
     ],
     "ip_summary": {
       "max_risk": "high",
       "high_count": 1,
       "medium_count": 0,
       "low_count": 0,
       "flagged_ips": [...]
     }
   }
   ```

## Setup Instructions

### Step 1: Get AbuseIPDB API Key (Free)

1. Go to https://www.abuseipdb.com/register
2. Create a free account
3. Navigate to your account settings
4. Copy your API key

**Free Tier Limits:**
- 1,000 requests per day
- 90-day lookback window
- Perfect for PhishGuard's use case

### Step 2: Configure PhishGuard

Add the API key to your environment:

```bash
# Linux/Mac
export ABUSEIPDB_API_KEY=your_api_key_here

# Windows (PowerShell)
$env:ABUSEIPDB_API_KEY="your_api_key_here"

# Or add to .env file
echo "ABUSEIPDB_API_KEY=your_api_key_here" >> .env
```

### Step 3: Start the Application

```bash
python app.py
```

The application will now automatically check IPs against AbuseIPDB when analyzing emails.

## How It Works

### Email Routing Path Analysis

When an email is sent, it passes through multiple mail servers, each adding a "Received" header. PhishGuard analyzes this routing path to identify:

1. **Origin IP** - Where the email originally came from
2. **Relay IPs** - Intermediate mail servers
3. **X-Originating-IP** - Original sender IP (if present)

**Example email path:**
```
Your inbox (gmail.com)
    ↑ Received from: mail.company.com [203.0.113.5]
    ↑ Received from: suspicious-server.xyz [185.220.101.5] ← FLAGGED!
    ↑ X-Originating-IP: [103.253.145.28] ← FLAGGED!
```

### Abuse Score Interpretation

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0% | Clean | No reports or whitelisted |
| 1-24% | Low | Few reports, likely false positives |
| 25-74% | Medium | Multiple reports, investigate further |
| 75-100% | High | Strong evidence of malicious activity |

### Common Attack Patterns Detected

1. **Known Phishing Servers**
   - IPs with history of sending phishing emails
   - Abuse score typically 75%+

2. **Spam Botnets**
   - Compromised servers/devices
   - Multiple reports across different categories

3. **Malware Distribution**
   - IPs associated with malware campaigns
   - High report counts

4. **Brute Force Attacks**
   - IPs attempting password attacks
   - May indicate compromised mail server

## Testing the Feature

### Test with Sample Email

```bash
python test_ip_feature.py
```

This will:
1. Parse a sample phishing email
2. Extract IP addresses from headers
3. Check them against AbuseIPDB (if API key is set)
4. Display detailed reputation information

### Example Output

```
======================================================================
  PhishGuard — IP Threat Intelligence Demo
======================================================================

[1] Parsing email and extracting IP addresses...
    Found 3 public IP address(es):
      - 185.220.101.5 (from: Received header)
      - 45.142.212.61 (from: Received header)
      - 103.253.145.28 (from: X-Originating-IP header)

[2] Checking IPs against AbuseIPDB...

[3] IP Reputation Results:
----------------------------------------------------------------------

  IP: 185.220.101.5
  Source: Received header
  Risk Level: HIGH
  Abuse Score: 85%
  Total Reports: 47
  Country: NL
  ISP: Evil Hosting Ltd
  Flags:
    ⚠️  High abuse score: 85% confidence
    ⚠️  Reported 47 times for abuse
----------------------------------------------------------------------
```

## Without API Key (Fallback Mode)

If no AbuseIPDB API key is provided, PhishGuard will:
- ✅ Still extract and display IP addresses
- ✅ Show which headers they came from
- ⚠️  Mark risk as "unknown" (no reputation data)
- ⚠️  Skip IP-based risk score additions

This allows the tool to remain functional without requiring API keys.

## Privacy & Security Notes

- PhishGuard only checks **public** IP addresses
- Private IPs (10.x, 192.168.x, 127.x) are automatically filtered out
- IP checks are cached for 1 hour to minimize API calls
- Rate limiting is implemented (max 10 IPs per analysis)

## Troubleshooting

### "No IPs found in email"
- Email may only contain private/internal IPs
- Email headers may be stripped or missing
- Try with a different email sample

### "Rate limit exceeded"
- Free tier: 1000 requests/day
- Solution: Wait 24 hours or upgrade AbuseIPDB plan
- Tip: Cached results help reduce API calls

### "API key invalid"
- Double-check your API key
- Ensure no extra spaces in environment variable
- Verify key is active at abuseipdb.com

## Integration with Existing Features

The IP threat intelligence integrates seamlessly with:

✅ **ML Classifier** - IPs add to overall phishing probability
✅ **URL Analysis** - Combined with URL threat intel for complete picture
✅ **Risk Scoring** - Weighted contribution to 0-100 risk score
✅ **Report Flags** - IP warnings appear alongside other red flags

## API Response Fields

Complete list of fields returned for each IP:

```python
{
    "ip": str,                    # IP address
    "source": str,                # Which header it came from
    "context": str,               # Header context/snippet
    "risk": str,                  # clean/low/medium/high/unknown
    "abuse_score": int,           # 0-100% confidence
    "reports": int,               # Total abuse reports
    "last_reported": str|None,    # ISO timestamp
    "country": str|None,          # Country code
    "isp": str|None,              # ISP/hosting provider
    "is_public": bool,            # Public IP flag
    "is_whitelisted": bool,       # Whitelisted status
    "flags": list[str],           # Human-readable warnings
}
```

## Future Enhancements

Potential improvements for future versions:

- [ ] IP geolocation visualization on map
- [ ] Historical trend analysis for IPs
- [ ] Integration with other threat intel sources (Shodan, GreyNoise)
- [ ] Automatic blocklist generation
- [ ] IP reputation caching in database
- [ ] Bulk IP analysis endpoint

## Questions & Support

For issues or questions:
1. Check the troubleshooting section above
2. Review AbuseIPDB documentation: https://docs.abuseipdb.com
3. Test with the included `test_ip_feature.py` script

---

**Built with ❤️ for cybersecurity professionals**
