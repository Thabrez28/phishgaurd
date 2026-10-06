"""
Static URL and Domain Structure Feature Extraction Engine.
Extracts lexical, structural, and linguistic features without making outbound network requests.
Strictly static analysis to prevent Server-Side Request Forgery (SSRF) and malware execution.
"""
import re
import math
from urllib.parse import urlparse, unquote

# Well-known legitimate domains for brand impersonation detection
OFFICIAL_BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "coinbase": ["coinbase.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com"]
}

# High-risk TLDs commonly exploited in mass phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work",
    "loan", "click", "country", "kim", "science", "gdn", "mom", "vip",
    "racing", "surf", "rest", "cam", "icu", "monster", "quest"
}

# Security and urgency keywords targeted at phishing psychology
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "secure",
    "security", "update", "password", "bank", "banking", "wallet",
    "authentication", "confirm", "urgent", "suspended", "reward", "free",
    "billing", "recover", "webscr", "ebayisapi", "auth", "credential",
    "claim", "validate", "reactivate", "support-desk", "helpdesk-login"
]

# Non-standard web ports frequently used by ad-hoc phishing kits
SUSPICIOUS_PORTS = {81, 808, 888, 2082, 2083, 2086, 2087, 8000, 8080, 8443, 8888, 9000, 9999}

# IPv4 Regex pattern (standard, hex, or octal notation)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmic randomness (DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def extract_features(raw_url: str) -> dict:
    """
    Statically analyzes raw URL string and extracts deterministic structural features.
    Does NOT connect to or resolve the domain.
    """
    clean_url = raw_url.strip()
    
    # Prepend scheme if absent for parsing purposes
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    netloc = parsed.netloc.lower()
    
    # Extract host and port
    host = netloc
    port = parsed.port
    if ":" in host:
        host = host.split(":")[0]

    path = parsed.path
    query = parsed.query
    full_url = clean_url

    # Check for IP address in hostname
    is_ip = bool(IPV4_REGEX.match(host))

    # Dot counts
    total_dots = full_url.count(".")
    domain_dots = host.count(".")

    # Subdomains calculation
    # Example: 'sub.example.com' -> parts: ['sub', 'example', 'com'] -> subdomains: 1
    host_parts = host.split(".")
    if is_ip:
        subdomain_count = 0
        base_domain = host
        tld = "ip"
    elif len(host_parts) >= 2:
        tld = host_parts[-1]
        base_domain = ".".join(host_parts[-2:])
        subdomain_count = max(0, len(host_parts) - 2)
    else:
        tld = ""
        base_domain = host
        subdomain_count = 0

    # Hyphen counts
    total_hyphens = full_url.count("-")
    domain_hyphens = host.count("-")

    # Special characters check
    has_at_symbol = "@" in full_url
    special_chars = len(re.findall(r"[@%$!&~_=+;]", full_url))

    # Obfuscation checks: URL encoding (%xx), double encoding (%25), hex IP
    url_encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
    has_double_encoding = "%25" in full_url
    is_punycode = host.startswith("xn--") or ".xn--" in host

    # Shannon Entropy of domain
    domain_entropy = calculate_shannon_entropy(host)

    # Keyword searches (in host, path, query)
    lower_url = full_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    keywords_in_subdomain = [kw for kw in SUSPICIOUS_KEYWORDS if kw in ".".join(host_parts[:-2])] if len(host_parts) > 2 else []

    # Brand impersonation detection
    impersonated_brand = None
    for brand, legit_domains in OFFICIAL_BRANDS.items():
        if brand in lower_url:
            # Check if host actually matches the legitimate domain
            if not any(host == legit or host.endswith("." + legit) for legit in legit_domains):
                impersonated_brand = brand
                break

    # Suspicious port check
    has_suspicious_port = port is not None and port in SUSPICIOUS_PORTS

    # Protocol
    is_https = parsed.scheme.lower() == "https"

    # Suspicious TLD
    is_suspicious_tld = tld in HIGH_RISK_TLDS

    # Long random domain heuristic
    is_long_domain = len(host) > 30

    return {
        "raw_url": raw_url,
        "normalized_url": clean_url,
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "tld": tld,
        "base_domain": base_domain,
        "url_length": len(full_url),
        "domain_length": len(host),
        "total_dots": total_dots,
        "domain_dots": domain_dots,
        "subdomain_count": subdomain_count,
        "total_hyphens": total_hyphens,
        "domain_hyphens": domain_hyphens,
        "special_chars_count": special_chars,
        "has_at_symbol": has_at_symbol,
        "is_ip_address": is_ip,
        "has_suspicious_port": has_suspicious_port,
        "is_https": is_https,
        "url_encoded_chars": url_encoded_chars,
        "has_double_encoding": has_double_encoding,
        "is_punycode": is_punycode,
        "domain_entropy": domain_entropy,
        "is_suspicious_tld": is_suspicious_tld,
        "is_long_domain": is_long_domain,
        "matched_keywords": matched_keywords,
        "keywords_in_subdomain": keywords_in_subdomain,
        "impersonated_brand": impersonated_brand
    }
