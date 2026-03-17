# PhishGuard 🛡️
### AI-Powered Phishing Email Analyzer

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange?style=flat-square&logo=scikit-learn)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A full-stack machine learning tool that analyzes emails for phishing indicators — combining a trained Random Forest classifier, NLP feature extraction, and real-time URL threat intelligence.

---

## Features

- **ML Classifier** — Random Forest + TF-IDF trained on SpamAssassin/Enron corpus
- **40+ Engineered Features** — header anomalies, urgency language, credential lures, HTML structure
- **URL Threat Intelligence** — heuristic scoring + optional VirusTotal API integration
- **IP Threat Intelligence** — AbuseIPDB integration to check sender IPs for previous attacks
- **Risk Scoring Engine** — weighted combination of ML output + feature signals (0–100 score)
- **Web Dashboard** — clean Flask UI, supports paste or `.eml` file upload
- **Zero-key Mode** — fully functional without any API keys (heuristic-only fallback)

---

## Architecture

```
Raw Email (.eml / text)
        │
        ▼
  [Email Parser]          ← Extract headers, body, URLs (parser.py)
        │
        ▼
[Feature Extractor]       ← 40+ signals: NLP, regex, heuristics (features.py)
        │              │
        ▼              ▼
 [ML Classifier]   [Threat Intel]   ← URL reputation scoring (threat_intel.py)
        │              │
        └──────┬────────┘
               ▼
     [Report Generator]   ← Risk score + verdict + flags (report.py)
               │
               ▼
       [Flask Dashboard]  ← Web UI with visualizations (app.py)
```

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
pip install -r requirements.txt
```

### 2. Train the model

**Option A — Demo mode (no dataset needed):**
```bash
python train.py --synthetic
```

**Option B — Full accuracy with SpamAssassin corpus:**
```bash
# Download from https://spamassassin.apache.org/old/publiccorpus/
# Extract easy_ham/ and spam/ into ./data/
python train.py
```

### 3. Start the web server

```bash
python app.py
# Open http://localhost:5000
```

---

## How It Works

### Feature Extraction (40+ signals)

| Category | Features |
|---|---|
| Header Analysis | Sender/Reply-To mismatch, Return-Path anomaly |
| Urgency Language | NLP keyword scoring (URGENT, Act Now, etc.) |
| Credential Lures | Password/login/SSN request detection |
| URL Signals | IP-based URLs, suspicious TLDs, @ obfuscation |
| HTML Structure | Hidden text, `<form>` tags, JavaScript, iframe |
| Attachments | Dangerous file types (.exe, .ps1, .bat, etc.) |

### ML Model

- **Algorithm**: Random Forest (200 estimators, balanced class weights)
- **Text Features**: TF-IDF vectorizer (3000 features, bigrams, sublinear TF)
- **Fusion**: Sparse matrix concatenation of TF-IDF + engineered features
- **Training data**: SpamAssassin Public Corpus (2500+ emails)
- **Typical accuracy**: 97–99% on held-out test set

### Risk Score (0–100)

The final score combines:
- ML model phishing probability (up to 50 points)
- URL threat intelligence findings (up to 25 points per high-risk URL)
- Rule-based feature bonuses (JavaScript: +20, dangerous attachment: +20, etc.)

---

## API Usage

The analyzer also exposes a JSON API:

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email": "From: attacker@evil.xyz\nSubject: URGENT: Verify account\n\nClick here: http://192.168.1.1/login"}'
```

Response:
```json
{
  "verdict": "Phishing",
  "risk_score": 87,
  "ml_label": "Phishing",
  "ml_confidence": 94.2,
  "flags": [
    "Reply-To domain differs from sender",
    "Subject uses urgency language",
    "1 URL(s) use raw IP addresses",
    "[IP: 185.220.101.5] High abuse score: 85% confidence",
    "[IP: 185.220.101.5] Reported 47 times for abuse"
  ],
  "url_details": [...],
  "ip_count": 2,
  "ip_details": [
    {
      "ip": "185.220.101.5",
      "source": "Received header",
      "risk": "high",
      "abuse_score": 85,
      "reports": 47,
      "country": "NL",
      "isp": "Evil Hosting Ltd"
    }
  ],
  "recommendation": "..."
}
```

---

## Optional: Threat Intelligence APIs

### VirusTotal (URL scanning)

Set your free VirusTotal API key (500 requests/day) for live URL scanning:

```bash
export VIRUSTOTAL_API_KEY=your_key_here
python app.py
```

Get a free key at [virustotal.com](https://www.virustotal.com/gui/join-us).

### AbuseIPDB (IP reputation)

Set your free AbuseIPDB API key (1000 requests/day) for IP abuse history checking:

```bash
export ABUSEIPDB_API_KEY=your_key_here
python app.py
```

Get a free key at [abuseipdb.com](https://www.abuseipdb.com/register).

**What it detects:**
- IPs previously reported for phishing attacks
- IPs with history of sending spam
- IPs associated with malware distribution
- Abuse confidence score (0-100%)
- Number of reports and last reported date
- Country and ISP information

---

## Project Structure

```
phishguard/
├── app/
│   ├── parser.py        # RFC 2822 email parser
│   ├── features.py      # 40+ feature engineering
│   ├── model.py         # ML training & inference
│   ├── threat_intel.py  # URL reputation scoring
│   └── report.py        # Risk report generation
├── templates/
│   └── index.html       # Web dashboard
├── data/                # Training corpus (not included)
├── models/              # Saved model (after training)
├── train.py             # Training script
├── app.py               # Flask entry point
└── requirements.txt
```

---

## Tech Stack

- **Python 3.10+** — core language
- **scikit-learn** — Random Forest + TF-IDF
- **Flask** — web framework
- **BeautifulSoup4** — HTML email parsing
- **scipy** — sparse matrix operations
- **requests** — HTTP / threat intel lookups

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built as a cybersecurity portfolio project demonstrating ML + security engineering skills.

> If you found this useful, give it a ⭐ on GitHub!
