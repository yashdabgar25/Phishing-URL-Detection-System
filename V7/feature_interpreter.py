"""
V7 Feature Interpreter
Converts extracted URL features into human-readable report entries.
"""

FEATURE_INFO = {
    "url_length": ("URL Length", "Total number of characters in the URL."),
    "domain_length": ("Domain Length", "Number of characters in the hostname."),
    "path_length": ("Path Length", "Number of characters in the URL path."),
    "query_length": ("Query Length", "Number of characters in URL query parameters."),
    "no_of_subdomains": ("Subdomain Count", "Number of subdomains before the registered domain."),
    "is_ip_address": ("IP Address Usage", "Whether the hostname is an IP address."),
    "digit_count": ("Digit Count", "Number of digits in the complete URL."),
    "letter_count": ("Letter Count", "Number of alphabetic characters in the URL."),
    "special_count": ("Special Character Count", "Number of non-alphanumeric characters in the URL."),
    "hyphen_count": ("Hyphen Count", "Number of hyphens in the URL."),
    "dot_count": ("Dot Count", "Number of dots in the URL."),
    "slash_count": ("Slash Count", "Number of slashes in the URL."),
    "at_count": ("@ Symbol Count", "Number of @ symbols in the URL."),
    "percent_count": ("Percent Symbol Count", "Number of percent symbols in the URL."),
    "has_https": ("HTTPS Usage", "Whether the URL uses the HTTPS scheme."),
    "has_port": ("Custom Port Usage", "Whether a port number is explicitly specified."),
    "has_fragment": ("URL Fragment", "Whether the URL contains a fragment."),
    "has_query": ("Query Parameters", "Whether query parameters are present."),
    "has_suspicious_keyword": ("Suspicious Keywords", "Whether recognized suspicious keywords occur in the URL."),
    "suspicious_keyword_count": ("Suspicious Keyword Count", "Number of recognized suspicious keywords found."),
    "has_double_slash_path": ("Double Slash in Path", "Whether the URL path contains consecutive slashes."),
    "has_encoded_characters": ("Encoded Characters", "Whether percent-encoded characters are present."),
    "has_at_symbol": ("@ Symbol Presence", "Whether the URL contains the @ symbol."),
    "has_https_in_domain": ("HTTPS Text in Hostname", "Whether the hostname contains the text 'https'."),
    "digit_ratio": ("Hostname Digit Ratio", "Proportion of hostname characters that are digits."),
    "special_ratio": ("Hostname Special Character Ratio", "Proportion of hostname characters classified as special."),
    "hostname_entropy": ("Hostname Entropy", "Character distribution complexity of the hostname."),
    "unique_hostname_chars": ("Unique Hostname Characters", "Number of distinct characters in the hostname."),
    "tld_length": ("TLD Length", "Number of characters in the final hostname label."),
    "has_common_tld": ("Common TLD", "Whether the hostname uses one of the recognized common TLDs."),
    "has_many_hyphens": ("Multiple Hyphens", "Whether the hostname contains three or more hyphens."),
    "has_many_subdomains": ("Many Subdomains", "Whether two or more subdomains are present."),
    "has_long_domain": ("Long Domain", "Whether the hostname exceeds 30 characters."),
    "has_brand_name": ("Brand Name Presence", "Whether a recognized brand name occurs in the hostname."),
    "brand_match_count": ("Brand Match Count", "Number of recognized brand names found in the hostname."),
    "has_digit_in_domain": ("Digits in Hostname", "Whether digits occur in the hostname."),
    "has_repeated_hyphens": ("Repeated Hyphens", "Whether the hostname contains consecutive hyphens."),
}


def interpret_feature(key, value):

    if key not in FEATURE_INFO:
        return {
            "key": key,
            "name": key.replace("_", " ").title(),
            "value": value,
            "description": "Extracted URL feature.",
            "interpretation": "Feature extracted.",
        }

    name, description = FEATURE_INFO[key]

    interpretation = "Observed value."

    # Boolean-like features
    if key in {
        "is_ip_address",
        "has_https",
        "has_port",
        "has_fragment",
        "has_query",
        "has_suspicious_keyword",
        "has_double_slash_path",
        "has_encoded_characters",
        "has_at_symbol",
        "has_https_in_domain",
        "has_common_tld",
        "has_many_hyphens",
        "has_many_subdomains",
        "has_long_domain",
        "has_brand_name",
        "has_digit_in_domain",
        "has_repeated_hyphens",
    }:
        interpretation = "Present" if value == 1 else "Not detected"

    elif key == "url_length":
        if value > 100:
            interpretation = "Long URL"
        else:
            interpretation = "URL length observed"

    elif key == "domain_length":
        if value > 30:
            interpretation = "Long hostname"
        else:
            interpretation = "Hostname length observed"

    elif key == "no_of_subdomains":
        if value >= 2:
            interpretation = "Multiple subdomains"
        else:
            interpretation = "Subdomain count observed"

    elif key == "suspicious_keyword_count":
        interpretation = (
            f"{value} recognized suspicious keyword(s) found"
            if value > 0 else "No recognized suspicious keywords found"
        )

    elif key == "brand_match_count":
        interpretation = (
            f"{value} recognized brand name(s) found"
            if value > 0 else "No recognized brand names found"
        )

    elif key == "has_many_hyphens":
        interpretation = (
            "Three or more hostname hyphens detected"
            if value == 1 else "Threshold not reached"
        )

    elif key == "digit_ratio":
        interpretation = f"{value:.2%} of hostname characters are digits"

    elif key == "special_ratio":
        interpretation = f"{value:.2%} special-character ratio in hostname"

    elif key == "hostname_entropy":
        interpretation = f"Entropy value: {value}"

    elif key == "unique_hostname_chars":
        interpretation = f"{value} unique hostname characters"

    elif key == "tld_length":
        interpretation = f"Final hostname label contains {value} character(s)"

    elif key in {
        "digit_count", "letter_count", "special_count",
        "hyphen_count", "dot_count", "slash_count",
        "at_count", "percent_count", "path_length",
        "query_length", "has_port"
    }:
        interpretation = f"Count/value: {value}"

    return {
        "key": key,
        "name": name,
        "value": value,
        "description": description,
        "interpretation": interpretation,
    }


def interpret_all_features(features):

    report = []

    for key, value in features.items():
        report.append(interpret_feature(key, value))

    return report


if __name__ == "__main__":

    sample_features = {
        "url_length": 125,
        "domain_length": 35,
        "is_ip_address": 0,
        "has_https": 1,
        "has_many_subdomains": 1,
        "has_brand_name": 1,
        "suspicious_keyword_count": 2,
    }

    result = interpret_all_features(sample_features)

    print("\n--- V7 Feature Interpreter Test ---")

    for item in result:
        print(f"\n{item['name']}: {item['value']}")
        print("Description:", item["description"])
        print("Interpretation:", item["interpretation"])