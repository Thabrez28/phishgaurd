"""
Deterministic Threat Scoring Engine for PhishGuard Live.
Evaluates static lexical, architectural, and cryptographic heuristics to produce
a deterministic threat score (0-100), verdict, risk level, indicators, and defensive recommendations.
"""

def compute_threat_score(features: dict) -> dict:
    """
    Computes deterministic threat score from extracted URL features.
    
    Score Buckets:
      0-29:   SAFE        (Risk: LOW)
      30-59:  SUSPICIOUS  (Risk: MEDIUM / HIGH)
      60-100: PHISHING    (Risk: HIGH / CRITICAL)
    """
    score = 0
    indicators = []

    # 1. IP Address Hostname Check
    if features.get("is_ip_address"):
        score += 35
        indicators.append({
            "code": "IP_HOST",
            "name": "Direct IP Address Host",
            "description": "The URL uses a raw IP address instead of a registered domain, bypassing standard DNS reputation checks.",
            "severity": "HIGH",
            "weight": 35
        })

    # 2. @ Symbol Obfuscation Check
    if features.get("has_at_symbol"):
        score += 35
        indicators.append({
            "code": "AT_SYMBOL",
            "name": "@ Symbol Credential Obfuscation",
            "description": "Contains an '@' character, typically used to deceive users regarding the actual host destination.",
            "severity": "HIGH",
            "weight": 35
        })

    # 3. Brand Impersonation Check
    brand = features.get("impersonated_brand")
    if brand:
        score += 40
        indicators.append({
            "code": "BRAND_SPOOF",
            "name": f"Suspected Brand Impersonation ({brand.capitalize()})",
            "description": f"URL targets brand '{brand.capitalize()}' on a domain not owned or authorized by the official entity.",
            "severity": "CRITICAL",
            "weight": 40
        })

    # 4. Punycode / IDN Homograph Attack Check
    if features.get("is_punycode"):
        score += 30
        indicators.append({
            "code": "HOMOGRAPH_PUNYCODE",
            "name": "Punycode / IDN Homograph Domain",
            "description": "Domain uses punycode prefix ('xn--'), frequently employed for visual spoofing using lookalike characters.",
            "severity": "HIGH",
            "weight": 30
        })

    # 5. High-Risk / Abused TLD Check
    if features.get("is_suspicious_tld"):
        score += 15
        indicators.append({
            "code": "SUSPICIOUS_TLD",
            "name": f"High-Risk TLD (.{features.get('tld')})",
            "description": f"Top-level domain '.{features.get('tld')}' is statistically correlated with disposable phishing infrastructure.",
            "severity": "MEDIUM",
            "weight": 15
        })

    # 6. Excessive Subdomains Check
    subdomain_count = features.get("subdomain_count", 0)
    if subdomain_count >= 3:
        score += 20
        indicators.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "name": f"Excessive Subdomains ({subdomain_count})",
            "description": f"Domain contains {subdomain_count} nested subdomains, a hallmark of phishing kit multi-tenant hosting.",
            "severity": "HIGH",
            "weight": 20
        })
    elif subdomain_count == 2:
        score += 10
        indicators.append({
            "code": "MULTIPLE_SUBDOMAINS",
            "name": "Multiple Subdomains",
            "description": "Domain contains 2 subdomains used to structure target routing.",
            "severity": "LOW",
            "weight": 10
        })

    # 7. Subdomain Keyword Injection Check
    sub_keywords = features.get("keywords_in_subdomain", [])
    if sub_keywords:
        score += 20
        indicators.append({
            "code": "SUBDOMAIN_KEYWORDS",
            "name": "Security Keywords in Subdomain",
            "description": f"Security/authentication keywords ({', '.join(sub_keywords)}) detected in subdomain hierarchy.",
            "severity": "HIGH",
            "weight": 20
        })

    # 8. Suspicious Phishing Keywords in Path/Query
    all_keywords = features.get("matched_keywords", [])
    path_keywords = [k for k in all_keywords if k not in sub_keywords]
    if len(path_keywords) >= 3:
        score += 25
        indicators.append({
            "code": "MULTIPLE_PHISH_KEYWORDS",
            "name": f"Multiple Phishing / Urgency Keywords ({len(path_keywords)})",
            "description": f"Multiple high-risk keywords found: {', '.join(path_keywords[:5])}.",
            "severity": "HIGH",
            "weight": 25
        })
    elif len(path_keywords) in (1, 2):
        pts = len(path_keywords) * 8
        score += pts
        indicators.append({
            "code": "PHISH_KEYWORDS",
            "name": f"Targeting Keywords ({', '.join(path_keywords)})",
            "description": f"Keywords associated with account or credential harvesting present in URL: {', '.join(path_keywords)}.",
            "severity": "MEDIUM",
            "weight": pts
        })

    # 9. Non-standard Suspicious Port Check
    if features.get("has_suspicious_port"):
        score += 15
        indicators.append({
            "code": "NON_STANDARD_PORT",
            "name": f"Suspicious Port (:{features.get('port')})",
            "description": f"URL communicates via non-standard port {features.get('port')}, commonly used in rogue hosting.",
            "severity": "MEDIUM",
            "weight": 15
        })

    # 10. Insecure Protocol Check (HTTP without TLS)
    if not features.get("is_https"):
        score += 10
        indicators.append({
            "code": "INSECURE_HTTP",
            "name": "Unencrypted HTTP Scheme",
            "description": "URL uses plaintext HTTP instead of secure HTTPS, vulnerable to interception and identity forgery.",
            "severity": "LOW",
            "weight": 10
        })

    # 11. High Domain Entropy (DGA detection)
    entropy = features.get("domain_entropy", 0.0)
    if entropy >= 3.8 and not features.get("is_ip_address"):
        score += 15
        indicators.append({
            "code": "HIGH_ENTROPY",
            "name": f"High Domain Entropy ({entropy:.2f})",
            "description": "Domain displays high lexical randomness, indicating algorithmic generation (DGA) or anti-detection evasion.",
            "severity": "MEDIUM",
            "weight": 15
        })

    # 12. Abnormal URL Length
    url_len = features.get("url_length", 0)
    if url_len > 120:
        score += 15
        indicators.append({
            "code": "EXCESSIVE_URL_LENGTH",
            "name": f"Excessive URL Length ({url_len} chars)",
            "description": "Unusually long URL structure often utilized to conceal malicious payloads and tracking tokens.",
            "severity": "MEDIUM",
            "weight": 15
        })
    elif url_len > 75:
        score += 8
        indicators.append({
            "code": "LONG_URL",
            "name": f"Above Average URL Length ({url_len} chars)",
            "description": "URL length exceeds typical legitimate endpoint lengths.",
            "severity": "LOW",
            "weight": 8
        })

    # 13. Domain Hyphenation Abuse
    domain_hyphens = features.get("domain_hyphens", 0)
    if domain_hyphens >= 2:
        score += 12
        indicators.append({
            "code": "DOMAIN_HYPHENATION",
            "name": f"Multi-Hyphen Domain Structure ({domain_hyphens} hyphens)",
            "description": "Heavy use of hyphens in hostname to mimic legitimate multi-word services or trademarks.",
            "severity": "MEDIUM",
            "weight": 12
        })

    # 14. URL Encoding / Obfuscation
    encoded_count = features.get("url_encoded_chars", 0)
    has_double_enc = features.get("has_double_encoding", False)
    if has_double_enc or encoded_count >= 4:
        score += 15
        indicators.append({
            "code": "URL_OBFUSCATION",
            "name": "Hex URL Obfuscation / Double Encoding",
            "description": "URL contains multiple hexadecimal escape sequences or double encoding to bypass signature inspection.",
            "severity": "HIGH",
            "weight": 15
        })

    # Bound final score between 0 and 100
    final_score = min(100, max(0, score))

    # Determine Verdict and Risk Level
    if final_score >= 60:
        verdict = "PHISHING"
        risk_level = "CRITICAL" if final_score >= 80 else "HIGH"
        explanation = (
            f"PhishGuard detected {len(indicators)} severe threat indicators. "
            f"The URL exhibits characteristic deceptive markers indicative of credential harvesting, "
            f"impersonation, or malicious redirection."
        )
        recommendation = (
            "DANGER: Do NOT click this link, submit credentials, or download attachments. "
            "Block this domain at perimeter DNS/firewall gateways and submit for threat intelligence quarantine."
        )
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        risk_level = "HIGH" if final_score >= 45 else "MEDIUM"
        explanation = (
            f"PhishGuard detected {len(indicators)} suspicious structural anomalies. "
            f"While not conclusively proven malicious, the link deviates significantly from standard legitimate patterns."
        )
        recommendation = (
            "CAUTION: Verify the sender and destination through an independent, verified communication channel. "
            "Do not enter personal or banking information."
        )
    else:
        verdict = "SAFE"
        risk_level = "LOW"
        explanation = (
            "PhishGuard analyzed URL lexical patterns, domain hierarchy, and cryptographic indicators. "
            "No significant phishing heuristics or structural threats were identified."
        )
        recommendation = (
            "Standard security hygiene applies. Always ensure the browser address bar displays a valid TLS lock icon."
        )

    return {
        "threat_score": final_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
        "recommendation": recommendation
    }
