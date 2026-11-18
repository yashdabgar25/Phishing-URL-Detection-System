from publicsuffix2 import get_sld
import re
import math
from urllib.parse import urlparse
from collections import Counter

import ipaddress


BRAND_NAMES = [
    "google", "facebook", "amazon", "microsoft",
    "apple", "paypal", "instagram", "whatsapp",
    "netflix", "linkedin", "twitter", "youtube",
    "sbi", "hdfc", "icici", "rbi"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification",
    "secure", "account", "update", "password",
    "banking", "confirm", "wallet", "suspended",
    "recover", "authentication"
]


def calculate_entropy(text):
    """Calculate character entropy of a string."""
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_features(url):
    """Extract URL and domain features for V6."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid URL.")

    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid URL: hostname not found.")

    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid URL: hostname format is incorrect.")

    if len(hostname) > 253:
        raise ValueError("Invalid URL: hostname is too long.")

    # Normalize the root URL
    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        url = parsed._replace(path="").geturl()

    parsed = urlparse(url)
    hostname = hostname.lower()

    if not hostname:
        raise ValueError("Invalid URL: hostname not found.")

    path = parsed.path or ""
    query = parsed.query or ""
    # Safely check URL port
    # Safely check URL port
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid URL: port number is incorrect.")

    has_port = int(port is not None)

    # Check IP address
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = 1
    except ValueError:
        is_ip_address = 0

    # Calculate subdomain count
    registrable_domain = None
    subdomain_count = 0

    if not is_ip_address:
        registrable_domain = get_sld(hostname, strict=False)

    if registrable_domain and hostname.endswith("." + registrable_domain):
        subdomain = hostname[:-len(registrable_domain)-1]
        subdomain_count = len(subdomain.split(".")) if subdomain else 0    
    else:
        subdomain_count = 0
    suspicious_count = sum(
        keyword in url.lower()
        for keyword in SUSPICIOUS_KEYWORDS
    )

    brand_matches = [
        brand for brand in BRAND_NAMES
        if brand in hostname
    ]

    features = {
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "no_of_subdomains": subdomain_count,
        "is_ip_address": is_ip_address,
        "digit_count": sum(char.isdigit() for char in url),
        "letter_count": sum(char.isalpha() for char in url),
        "special_count": sum(not char.isalnum() for char in url),
        "hyphen_count": url.count("-"),
        "dot_count": url.count("."),
        "slash_count": url.count("/"),
        "at_count": url.count("@"),
        "percent_count": url.count("%"),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_port": has_port,
        "has_fragment": int(bool(parsed.fragment)),
        "has_query": int(bool(query)),
        "has_suspicious_keyword": int(suspicious_count > 0),
        "suspicious_keyword_count": suspicious_count,
        "has_double_slash_path": int("//" in path),
        "has_encoded_characters": int("%" in url),
        "has_at_symbol": int("@" in url),
        "has_https_in_domain": int("https" in hostname),
        "digit_ratio": round(
            sum(char.isdigit() for char in hostname) / len(hostname), 4
        ),
        "special_ratio": round(
            sum(not char.isalnum() for char in hostname) / len(hostname), 4
        ),
        "hostname_entropy": calculate_entropy(hostname),
        "unique_hostname_chars": len(set(hostname)),
        "tld_length": len(hostname.rsplit(".",1)[-1]),
        "has_common_tld": int(
            hostname.rsplit(".", 1)[-1] in ["com", "org", "net", "edu", "gov", "in"]
        ),
        "has_many_hyphens": int(hostname.count("-") >= 3),
        "has_many_subdomains": int(subdomain_count >= 2),
        "has_long_domain": int(len(hostname) > 30),
        "has_brand_name": int(bool(brand_matches)),
        "brand_match_count": len(brand_matches),
        "has_digit_in_domain": int(any(c.isdigit() for c in hostname)),
        "has_repeated_hyphens": int("--" in hostname),
    }

    return features