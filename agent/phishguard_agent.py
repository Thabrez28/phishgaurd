#!/usr/bin/env python3
"""
PhishGuard Live - Autonomous External Device Security Agent.
Sends target URLs to the PhishGuard Live cloud API, parses threat telemetry,
and prints real-time SOC threat assessment reports.

Usage:
  python phishguard_agent.py "https://suspicious-domain.com"
  python phishguard_agent.py --api-url "https://my-render-app.onrender.com" "https://test.xyz"
"""
import sys
import os
import argparse
import json

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Run: pip install requests")
    sys.exit(1)

# Default to environment variable, then localhost fallback
DEFAULT_API_URL = os.environ.get("PHISHGUARD_API_URL", "http://127.0.0.1:5000")

def format_color(text, color_code):
    """Adds ANSI terminal colors."""
    if os.name == "nt":
        os.system("")
    return f"\033[{color_code}m{text}\033[0m"

def print_banner():
    banner = """
+------------------------------------------------------------------+
|           [#] PHISHGUARD LIVE -- THREAT DETECTOR AGENT           |
|            Cloud-Based Phishing & Structural URL Engine          |
+------------------------------------------------------------------+"""
    print(format_color(banner, "96"))

def scan_target(target_url: str, base_api_url: str):
    endpoint = f"{base_api_url.rstrip('/')}/api/scan"
    print(f"\n[*] Target URL        : {target_url}")
    print(f"[*] Dispatching to API: {endpoint}")
    print("[*] Analyzing lexical, structural, and cryptographic features...")

    headers = {
        "User-Agent": "PhishGuard-External-Agent/v5.2.0 (Device-CLI)",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            endpoint,
            json={"url": target_url},
            headers=headers,
            timeout=15
        )
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Connection Failed: Unable to reach PhishGuard at '{base_api_url}'.")
        print("    Ensure the Render server is running or set PHISHGUARD_API_URL env variable.")
        sys.exit(2)
    except requests.exceptions.Timeout:
        print("\n[!] Request Timed Out: Server did not respond within 15 seconds.")
        sys.exit(3)
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
        sys.exit(4)

    if response.status_code == 200:
        data = response.json()
        threat_score = data.get("threat_score", 0)
        verdict = data.get("verdict", "UNKNOWN")
        risk_level = data.get("risk_level", "UNKNOWN")
        indicators = data.get("indicators", [])
        explanation = data.get("explanation", "")
        recommendation = data.get("recommendation", "")

        # Color-coded verdict
        if verdict == "PHISHING":
            v_colored = format_color(f"[!] {verdict}", "91;1")  # Bright Red Bold
        elif verdict == "SUSPICIOUS":
            v_colored = format_color(f"[?] {verdict}", "93;1")  # Yellow Bold
        else:
            v_colored = format_color(f"[+] {verdict}", "92;1")  # Green Bold

        print("\n" + "="*66)
        print(f" THREAT ASSESSMENT REPORT")
        print("="*66)
        print(f" Normalized URL : {data.get('normalized_url')}")
        print(f" Verdict        : {v_colored}")
        print(f" Threat Score   : {threat_score} / 100")
        print(f" Risk Severity  : {risk_level}")
        print(f" Scanned At     : {data.get('scanned_at')}")
        print("-"*66)
        print(" DETECTED INDICATORS:")
        if indicators:
            for idx, ind in enumerate(indicators, 1):
                name = ind.get("name") if isinstance(ind, dict) else str(ind)
                sev = ind.get("severity", "INFO") if isinstance(ind, dict) else "INFO"
                desc = ind.get("description", "") if isinstance(ind, dict) else ""
                print(f"  [{idx}] [{sev}] {name}")
                if desc:
                    print(f"      -> {desc}")
        else:
            print("  None. No malicious heuristics or structural threats detected.")

        print("-"*66)
        print(f" SOC EXPLANATION:\n  {explanation}")
        print("-"*66)
        print(f" DEFENSIVE RECOMMENDATION:\n  {recommendation}")
        print("="*66 + "\n")

    else:
        print(f"\n[!] API Error [{response.status_code}]:")
        try:
            err = response.json()
            print(f"    {err.get('error', response.text)}")
        except Exception:
            print(f"    {response.text}")
        sys.exit(1)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="PhishGuard Live External Security Agent")
    parser.add_argument("url", nargs="?", help="Target URL to inspect for phishing indicators")
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"Base URL of the PhishGuard server (default: {DEFAULT_API_URL})"
    )

    args = parser.parse_args()

    target_url = args.url
    if not target_url:
        print("\n[?] Interactive Mode:")
        try:
            target_url = input("Enter target URL to scan: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not target_url:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    scan_target(target_url, args.api_url)

if __name__ == "__main__":
    main()
