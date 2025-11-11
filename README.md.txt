# Phishing URL Analyzer
A Python tool to detect suspicious and potentially phishing URLs using offline heuristics and optional VirusTotal integration.  
Designed for SOC trainees, blue-teamers, and cybersecurity portfolios.

---

## 🚀 Features
- Offline heuristic URL scoring (no API required)
- Detects:
  - IP addresses in hostname
  - Punycode / IDN homograph patterns
  - Excessive subdomains
  - Suspicious path keywords (`login`, `verify`, `secure`, etc.)
  - `@` symbol obfuscation
  - Very long URLs
  - Suspicious TLDs (configurable)
  - Simple brand-lookalike patterns
- Optional VirusTotal v3 URL reputation lookup (if `VIRUSTOTAL_API_KEY` set)
- Command-line interface: input file, output CSV, verbose mode, adjustable threshold
- CSV report for easy sharing and evidence in incident reports

---

## 🧰 Technologies & Libraries
- Python 3 (tested on 3.8+)
- `requests` — optional (VirusTotal API)
- `tldextract` — parsing domain parts (recommended)
- `validators` — URL validation (recommended)
- `colorama` — pretty CLI output (optional)
- Standard library: `argparse`, `csv`, `urllib.parse`, `re`, `time`, `os`

Install dependencies (recommended):
```bash
pip install -r requirements.txt
# or individually:
pip install requests tldextract validators colorama
