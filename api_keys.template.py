"""
api_keys.template.py — API Keys Configuration Template

Instructions:
1. Copy this file to 'api_keys.py'
2. Fill in your API keys below
3. Never commit api_keys.py to git (it's in .gitignore)

To get API keys:
- VirusTotal: https://www.virustotal.com/gui/join-us (500 requests/day free)
- AbuseIPDB: https://www.abuseipdb.com/register (1000 requests/day free)
"""

# ══════════════════════════════════════════════════════════════════════════════
# Threat Intelligence API Keys
# ══════════════════════════════════════════════════════════════════════════════

# VirusTotal API Key (for URL scanning)
# Free tier: 500 requests/day
# Get yours at: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = ""  # Leave empty to disable

# AbuseIPDB API Key (for IP reputation checking)
# Free tier: 1000 requests/day  
# Get yours at: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY = ""  # Leave empty to disable


# ══════════════════════════════════════════════════════════════════════════════
# Future API Keys (add new services here)
# ══════════════════════════════════════════════════════════════════════════════

# Example: Google Safe Browsing (uncomment when needed)
# GOOGLE_SAFE_BROWSING_API_KEY = ""

# Example: PhishTank (uncomment when needed)
# PHISHTANK_API_KEY = ""

# Example: URLScan.io (uncomment when needed)
# URLSCAN_API_KEY = ""

# Example: Shodan (uncomment when needed)
# SHODAN_API_KEY = ""

# Example: GreyNoise (uncomment when needed)
# GREYNOISE_API_KEY = ""


# ══════════════════════════════════════════════════════════════════════════════
# Configuration Settings
# ══════════════════════════════════════════════════════════════════════════════

# Enable/disable specific features
ENABLE_VIRUSTOTAL = True   # Set to False to disable even if key is present
ENABLE_ABUSEIPDB = True    # Set to False to disable even if key is present

# Rate limiting (requests per day)
VIRUSTOTAL_RATE_LIMIT = 500
ABUSEIPDB_RATE_LIMIT = 1000

# Cache duration (seconds)
CACHE_TTL = 3600  # 1 hour


# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════

def get_api_key(service_name):
    """
    Get API key for a service.
    Returns None if key is not set or service is disabled.
    """
    keys = {
        'virustotal': (VIRUSTOTAL_API_KEY, ENABLE_VIRUSTOTAL),
        'abuseipdb': (ABUSEIPDB_API_KEY, ENABLE_ABUSEIPDB),
    }
    
    if service_name.lower() not in keys:
        return None
    
    key, enabled = keys[service_name.lower()]
    
    if not enabled:
        return None
    
    if not key or key.strip() == "":
        return None
    
    return key.strip()


def is_service_enabled(service_name):
    """Check if a service is enabled and has a valid API key."""
    return get_api_key(service_name) is not None


def get_all_configured_services():
    """Get list of all configured services with valid API keys."""
    services = []
    if is_service_enabled('virustotal'):
        services.append('VirusTotal')
    if is_service_enabled('abuseipdb'):
        services.append('AbuseIPDB')
    return services
