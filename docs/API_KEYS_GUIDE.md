# API Keys Management Guide

## 🎯 Overview

PhishGuard now uses a centralized `api_keys.py` file to manage all API keys. This makes it easy to:
- ✅ Keep all API keys in one place
- ✅ Prevent accidental commits to git (via .gitignore)
- ✅ Add new API services in the future
- ✅ Enable/disable services without changing code
- ✅ Share code safely (api_keys.py stays local)

---

## 🚀 Quick Setup

### Step 1: Create Your API Keys File

```bash
cd phishguard

# Copy the template
cp api_keys.template.py api_keys.py
```

### Step 2: Add Your API Keys

Edit `api_keys.py`:

```python
# VirusTotal API Key
VIRUSTOTAL_API_KEY = "paste_your_key_here"

# AbuseIPDB API Key  
ABUSEIPDB_API_KEY = "paste_your_key_here"
```

### Step 3: Done!

```bash
python app.py
```

You'll see:
```
============================================================
  PhishGuard — AI-Powered Phishing Email Analyzer
============================================================
[*] Server: http://localhost:5000
[✓] ML model loaded and ready
[✓] API Services: VirusTotal, AbuseIPDB
============================================================
```

---

## 📁 File Structure

```
phishguard/
├── api_keys.template.py    ← Template (commit to git)
├── api_keys.py              ← Your keys (NEVER commit!)
├── .gitignore               ← Protects api_keys.py
├── app.py                   ← Uses api_keys module
└── app/
    └── threat_intel.py      ← Uses api_keys module
```

---

## 🔑 Getting API Keys

### VirusTotal (URL Scanning)

1. Go to: https://www.virustotal.com/gui/join-us
2. Create free account
3. Go to your profile → API Key
4. Copy the key

**Free Tier:**
- 500 requests per day
- 4 requests per minute

### AbuseIPDB (IP Reputation)

1. Go to: https://www.abuseipdb.com/register
2. Create free account
3. Go to Account → API
4. Copy the API key (v2)

**Free Tier:**
- 1,000 requests per day
- 90-day lookback window

---

## ⚙️ Configuration Options

### Enable/Disable Services

Even with a valid API key, you can disable a service:

```python
# In api_keys.py

VIRUSTOTAL_API_KEY = "your_key_here"
ENABLE_VIRUSTOTAL = False  # ← Disabled!

ABUSEIPDB_API_KEY = "your_key_here"
ENABLE_ABUSEIPDB = True    # ← Enabled
```

### Adjust Rate Limits

```python
# In api_keys.py

VIRUSTOTAL_RATE_LIMIT = 500   # Requests per day
ABUSEIPDB_RATE_LIMIT = 1000   # Requests per day
```

### Cache Duration

```python
# In api_keys.py

CACHE_TTL = 3600  # 1 hour (in seconds)
# Increase to reduce API calls
# Decrease for more real-time data
```

---

## 🔒 Security Best Practices

### ✅ DO:

- ✅ Keep `api_keys.py` local (never commit)
- ✅ Use `.gitignore` to protect it
- ✅ Rotate keys periodically
- ✅ Use free tier keys for development
- ✅ Share `api_keys.template.py` with team

### ❌ DON'T:

- ❌ Commit `api_keys.py` to git
- ❌ Share keys in chat/email
- ❌ Hardcode keys in code
- ❌ Use production keys for testing
- ❌ Post keys in screenshots

---

## 🆕 Adding New API Services

### Example: Adding Google Safe Browsing

**Step 1:** Add to `api_keys.py`:

```python
# In api_keys.py

# Google Safe Browsing API Key
GOOGLE_SAFE_BROWSING_API_KEY = "your_key_here"
ENABLE_GOOGLE_SAFE_BROWSING = True
```

**Step 2:** Update helper function:

```python
# In api_keys.py

def get_api_key(service_name):
    keys = {
        'virustotal': (VIRUSTOTAL_API_KEY, ENABLE_VIRUSTOTAL),
        'abuseipdb': (ABUSEIPDB_API_KEY, ENABLE_ABUSEIPDB),
        'google_safe_browsing': (GOOGLE_SAFE_BROWSING_API_KEY, ENABLE_GOOGLE_SAFE_BROWSING),  # NEW
    }
    # ... rest of function
```

**Step 3:** Use in your code:

```python
# In threat_intel.py or wherever

import api_keys

gsb_key = api_keys.get_api_key('google_safe_browsing')
if gsb_key:
    # Use the API
    result = check_google_safe_browsing(url, gsb_key)
```

---

## 🧪 Testing API Keys

### Check if Keys are Working

```python
# test_api_keys.py

import api_keys

print("Configured services:")
for service in api_keys.get_all_configured_services():
    print(f"  ✓ {service}")

print("\nIndividual checks:")
print(f"  VirusTotal: {'✓' if api_keys.is_service_enabled('virustotal') else '✗'}")
print(f"  AbuseIPDB: {'✓' if api_keys.is_service_enabled('abuseipdb') else '✗'}")
```

Run it:
```bash
python test_api_keys.py
```

Expected output:
```
Configured services:
  ✓ VirusTotal
  ✓ AbuseIPDB

Individual checks:
  VirusTotal: ✓
  AbuseIPDB: ✓
```

---

## 🔄 Migration from Environment Variables

**Old way (environment variables):**
```bash
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
python app.py
```

**New way (api_keys.py):**
```bash
# Edit api_keys.py once
python app.py  # Just works!
```

### Fallback Support

The code still supports environment variables as a fallback:

```python
# If api_keys.py doesn't exist, tries environment variables
vt_key = api_keys.get_api_key('virustotal')
# Returns os.getenv('VIRUSTOTAL_API_KEY') if api_keys.py missing
```

---

## 🐛 Troubleshooting

### "No API services configured"

**Problem:** Keys are not being loaded

**Solutions:**
1. Check `api_keys.py` exists in project root
2. Verify keys are not empty strings
3. Check `ENABLE_*` flags are `True`

```python
# api_keys.py

VIRUSTOTAL_API_KEY = "abc123..."  # ✓ Good
VIRUSTOTAL_API_KEY = ""           # ✗ Won't work
ENABLE_VIRUSTOTAL = True          # ✓ Must be True
```

### "api_keys.py not found"

**Problem:** File doesn't exist

**Solution:**
```bash
cp api_keys.template.py api_keys.py
# Then edit api_keys.py with your keys
```

### "403 Forbidden" errors

**Problem:** Invalid API key

**Solutions:**
1. Verify key is correct (no extra spaces)
2. Check key hasn't expired
3. Verify you're within rate limits

### Git is trying to commit api_keys.py

**Problem:** .gitignore not working

**Solution:**
```bash
# Remove from git if accidentally added
git rm --cached api_keys.py

# Verify .gitignore contains:
# api_keys.py

# Now it won't be tracked
```

---

## 📊 Monitoring API Usage

### Check Rate Limits

```python
# In api_keys.py - add usage tracking

_api_usage = {
    'virustotal': 0,
    'abuseipdb': 0
}

def track_usage(service_name):
    """Track API calls to monitor rate limits."""
    if service_name in _api_usage:
        _api_usage[service_name] += 1
        
def get_usage(service_name):
    """Get current usage count."""
    return _api_usage.get(service_name, 0)
```

Then in `threat_intel.py`:
```python
import api_keys

vt_key = api_keys.get_api_key('virustotal')
if vt_key:
    api_keys.track_usage('virustotal')
    result = call_virustotal_api(url, vt_key)
    
    # Check if approaching limit
    if api_keys.get_usage('virustotal') > 450:  # 90% of 500
        print("⚠️ Approaching VirusTotal rate limit!")
```

---

## 🎯 Best Practices Summary

1. **Always use `api_keys.py`** - Centralized management
2. **Never commit keys** - Use .gitignore
3. **Rotate keys periodically** - Every 3-6 months
4. **Monitor usage** - Stay within rate limits
5. **Use free tiers for dev** - Save paid tiers for production
6. **Document new services** - Update team when adding APIs
7. **Test after changes** - Verify keys work before deploying

---

## 📋 Checklist for Team Members

When setting up PhishGuard:

- [ ] Copy `api_keys.template.py` to `api_keys.py`
- [ ] Get VirusTotal API key (optional)
- [ ] Get AbuseIPDB API key (optional)
- [ ] Add keys to `api_keys.py`
- [ ] Verify `.gitignore` includes `api_keys.py`
- [ ] Test with `python app.py`
- [ ] Confirm services shown on startup

---

## 🚀 Future Services

Ready to add:

- [ ] Google Safe Browsing
- [ ] PhishTank API
- [ ] URLScan.io
- [ ] Shodan
- [ ] GreyNoise
- [ ] AlienVault OTX
- [ ] Hybrid Analysis

Just add to `api_keys.py` following the pattern!

---

**Need help?** Check the examples in `api_keys.template.py` or ask the team! 🔑
