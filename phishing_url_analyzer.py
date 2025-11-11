#!/usr/bin/env python3
"""
Phishing URL Analyzer
- Heuristic-based URL scoring (works offline)
- Optional VirusTotal v3 URL check if VIRUSTOTAL_API_KEY environment variable is set
- Outputs results to CSV

Usage:
    python phishing_url_analyzer.py --input urls.txt --output results.csv --threshold 3

Notes:
- The script WILL NOT reveal targets or perform active attacks.
- If using VirusTotal, respect their API rate limits and terms of service.
"""

import os
import re
import csv
import time
import argparse
from urllib.parse import urlparse
import hashlib
import json

# optional libraries
try:
    import requests
except Exception:
    requests = None

try:
    import tldextract
except Exception:
    tldextract = None

try:
    import validators
except Exception:
    validators = None

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    Fore = Style = None

# --- Configuration ---
SUSPICIOUS_TLDS = {"ru", "tk", "ml", "cf", "ga"}  # example list - tune as needed
SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "update", "account", "password", "signin", "bank", "confirm"]
BRAND_SIMILAR_PATTERNS = r"(micros|microsof|paypa1|pay-pal|g00gle|gmai1|faceb00k|appleid|amazonc)"  # basic fuzzy-ish indicators
DEFAULT_THRESHOLD = 3  # score >= threshold -> "Investigate"
VT_SUBMIT_SLEEP = 2  # seconds to wait between VT calls (beware rate limits)
VT_POLL_RETRIES = 6   # how many times to poll analysis endpoint
VT_POLL_DELAY = 2     # seconds between polls

# --- Utility functions ---

def normalize_url(raw):
    """Fix typical obfuscations (hxxp, [.] ) and strip whitespace"""
    if not raw:
        return ""
    u = raw.strip()
    u = u.replace("hxxp://", "http://").replace("hxxps://", "https://")
    u = u.replace("hxxp", "http")
    u = u.replace("[.]", ".").replace("(.)", ".")
    # add scheme if missing (we'll parse but note missing scheme)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', u):
        u = "http://" + u
    return u

def is_ip(host):
    if not host:
        return False
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))

def has_punycode(host):
    return "xn--" in (host or "")

def count_subdomains(host):
    if not host:
        return 0
    parts = host.split('.')
    # exclude public suffix handling for simplicity if tldextract not installed
    try:
        if tldextract:
            e = tldextract.extract(host)
            if e.subdomain:
                return len(e.subdomain.split('.'))
            return 0
    except Exception:
        pass
    # fallback: count parts minus 2 (domain + tld)
    return max(0, len(parts) - 2)

def long_url(url):
    return len(url) > 100

def suspicious_keyword_in_path(path):
    p = (path or "").lower()
    return any(k in p for k in SUSPICIOUS_KEYWORDS)

def has_at_symbol(url):
    return "@" in (url or "")

def suspicious_tld(host):
    tld = (host or "").split('.')[-1].lower()
    return tld in SUSPICIOUS_TLDS

def looks_like_brand(host):
    return bool(re.search(BRAND_SIMILAR_PATTERNS, host or "", re.IGNORECASE))

def validate_url(url):
    if validators:
        try:
            return validators.url(url)
        except Exception:
            pass
    # basic fallback: parse and check netloc
    parsed = urlparse(url)
    return bool(parsed.netloc)

def heuristic_score(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    score = 0
    tags = []

    # IP in host
    if is_ip(host):
        score += 3
        tags.append("ip-in-host")

    # punycode lookalike
    if has_punycode(host):
        score += 3
        tags.append("punycode")

    # many subdomains
    sdcount = count_subdomains(host)
    if sdcount >= 3:
        score += 2
        tags.append(f"many-subdomains({sdcount})")

    # long URL
    if long_url(url):
        score += 1
        tags.append("long-url")

    # suspicious keywords in path
    if suspicious_keyword_in_path(path):
        score += 1
        tags.append("suspicious-keyword-in-path")

    # contains @
    if has_at_symbol(url):
        score += 2
        tags.append("contains-@")

    # suspicious tld
    if suspicious_tld(host):
        score += 2
        tags.append("suspicious-tld")

    # looks-like brand (naive)
    if looks_like_brand(host):
        score += 2
        tags.append("looks-like-brand")

    # scheme / https check (note: phishing can use https)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        score += 1
        tags.append(f"weird-scheme:{scheme}")

    # add note on missing/invalid url
    if not validate_url(url):
        score += 3
        tags.append("invalid-url")

    return score, tags

# --- VirusTotal integration (optional) ---
def vt_submit_and_get_analysis(vt_key, url):
    """
    Submit a URL to VirusTotal (v3) and poll for result.
    Returns a simplified dict: { 'status': 'ok'/'error', 'summary': {...} }
    NOTE: This function expects 'requests' to be available.
    """
    if not requests:
        return {"status": "error", "error": "requests library not installed"}

    headers = {"x-apikey": vt_key}
    submit_url = "https://www.virustotal.com/api/v3/urls"
    analyses_base = "https://www.virustotal.com/api/v3/analyses/"

    try:
        # Submit URL for analysis
        r = requests.post(submit_url, headers=headers, data={"url": url}, timeout=30)
        if r.status_code not in (200, 201):
            return {"status": "error", "error": f"submit_failed_{r.status_code}"}
        analysis_id = r.json().get("data", {}).get("id")
        if not analysis_id:
            return {"status": "error", "error": "no_analysis_id"}
        # Poll for result
        for _ in range(VT_POLL_RETRIES):
            time.sleep(VT_POLL_DELAY)
            r2 = requests.get(analyses_base + analysis_id, headers=headers, timeout=30)
            if r2.status_code == 200:
                # try to extract vendor detections summary
                data = r2.json().get("data", {})
                attributes = data.get("attributes", {}) or {}
                stats = attributes.get("stats", {})  # counts by malicious/suspicious/harmless
                # Build a useful small summary
                return {"status": "ok", "summary": {"analysis_stats": stats, "raw": data}}
        return {"status": "error", "error": "vt_poll_timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# --- Main processing routine ---
def analyze_file(input_file, output_file, vt_key=None, threshold=DEFAULT_THRESHOLD, verbose=False):
    urls = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line = normalize_url(line)
            urls.append(line)

    results = []
    for idx, url in enumerate(urls, 1):
        score, tags = heuristic_score(url)
        vt_status = ""
        vt_summary = None
        if vt_key:
            # careful with rate limiting; VirusTotal limits calls
            if not requests:
                vt_status = "vt_error:requests_missing"
            else:
                vt_summary = vt_submit_and_get_analysis(vt_key, url)
                if vt_summary.get("status") == "ok":
                    stats = vt_summary["summary"].get("analysis_stats", {})
                    # determine a short VT verdict
                    mal = stats.get("malicious", 0)
                    susp = stats.get("suspicious", 0)
                    if mal > 0 or susp > 0:
                        vt_status = f"vt_malicious:{mal}_susp:{susp}"
                        # boost score slightly if vt shows malicious
                        score += 4
                        tags.append("vt-detected-malicious")
                    else:
                        vt_status = f"vt_clean:{stats}"
                else:
                    vt_status = "vt_error:" + str(vt_summary.get("error"))
                # be polite with API: sleep a bit between submissions
                time.sleep(VT_SUBMIT_SLEEP)

        recommendation = "Investigate" if score >= threshold else "Probably safe (review)"
        findings = ";".join(tags) if tags else "none"

        results.append({
            "url": url,
            "heuristic_score": score,
            "tags": findings,
            "vt_status": vt_status,
            "recommendation": recommendation
        })

        if verbose:
            if Fore:
                print(f"{Fore.YELLOW}[{idx}/{len(urls)}]{Style.RESET_ALL} {url} -> score={score} tags={findings} vt={vt_status} rec={recommendation}")
            else:
                print(f"[{idx}/{len(urls)}] {url} -> score={score} tags={findings} vt={vt_status} rec={recommendation}")

    # write CSV
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["url", "heuristic_score", "tags", "vt_status", "recommendation"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    return results

# --- CLI entrypoint ---
def parse_args():
    p = argparse.ArgumentParser(description="Phishing URL Analyzer (heuristic + optional VirusTotal)")
    p.add_argument("--input", "-i", default="urls.txt", help="Input file (one URL per line)")
    p.add_argument("--output", "-o", default="results.csv", help="Output CSV file")
    p.add_argument("--threshold", "-t", type=int, default=DEFAULT_THRESHOLD, help="Score threshold to mark Investigate")
    p.add_argument("--vt", action="store_true", help="Use VirusTotal if API key set in VIRUSTOTAL_API_KEY")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose console output")
    return p.parse_args()

def main():
    args = parse_args()
    vt_key = None
    if args.vt:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not vt_key:
            print("Warning: --vt requested but VIRUSTOTAL_API_KEY not set. Running heuristics only.")
            vt_key = None
    results = analyze_file(args.input, args.output, vt_key=vt_key, threshold=args.threshold, verbose=args.verbose)
    print(f"Analysis complete. {len(results)} URLs processed. Results saved to {args.output}")

if __name__ == "__main__":
    main()
