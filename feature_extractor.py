from urllib.parse import urlparse
import re


def extract_ml_features(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    # 1. URL length
    url_length = len(url)

    # 2. Domain length
    domain_length = len(hostname)

    # 3. IP address
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    is_domain_ip = 1 if re.match(ip_pattern, hostname) else 0

    # 4. Number of subdomains
    parts = hostname.split(".") if hostname else []
    no_of_subdomain = max(len(parts) - 2, 0)

    # 5. Obfuscation
    obfuscation_chars = ["%", "@", "\\"]

    no_of_obfuscated_char = sum(
        url.count(char) for char in obfuscation_chars
    )

    has_obfuscation = 1 if no_of_obfuscated_char > 0 else 0

    obfuscation_ratio = (
        no_of_obfuscated_char / url_length
        if url_length > 0 else 0
    )

    # 6. Letters
    no_of_letters = sum(char.isalpha() for char in url)

    letter_ratio = (
        no_of_letters / url_length
        if url_length > 0 else 0
    )

    # 7. Digits
    no_of_digits = sum(char.isdigit() for char in url)

    digit_ratio = (
        no_of_digits / url_length
        if url_length > 0 else 0
    )

    # 8. Special characters
    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")

    no_of_other_special = 0

    for char in url:
        if not char.isalnum():
            if char not in [
                ".", "/", ":", "=", "?", "&",
                "-", "_", "%", "@"
            ]:
                no_of_other_special += 1

    special_char_ratio = (
        no_of_other_special / url_length
        if url_length > 0 else 0
    )

    # 9. HTTPS
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    return [
        url_length,
        domain_length,
        is_domain_ip,
        no_of_subdomain,
        has_obfuscation,
        no_of_obfuscated_char,
        obfuscation_ratio,
        no_of_letters,
        letter_ratio,
        no_of_digits,
        digit_ratio,
        no_of_equals,
        no_of_qmark,
        no_of_ampersand,
        no_of_other_special,
        special_char_ratio,
        is_https
    ]