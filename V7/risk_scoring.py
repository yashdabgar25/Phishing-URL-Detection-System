"""
V7 Explainable Risk Scoring Engine
Phishing URL Detection System
"""

MAX_SCORE = 100

RISK_LEVELS = [
    (19, "Low Risk"),
    (39, "Moderate Risk"),
    (59, "Suspicious"),
    (79, "High Risk"),
    (100, "Critical Risk"),
]

# Each indicator has a unique key, points, category and explanation.
INDICATORS = {
    "http_not_https": {
        "points": 5,
        "category": "URL Security",
        "description": "URL does not use HTTPS."
    },
    "ip_address": {
        "points": 10,
        "category": "URL Structure",
        "description": "URL uses an IP address instead of a domain name."
    },
    "at_symbol": {
        "points": 8,
        "category": "URL Structure",
        "description": "URL contains the @ symbol, which may hide the actual destination."
    },
    "long_url": {
        "points": 5,
        "category": "URL Structure",
        "description": "URL length is unusually long."
    },
    "shortener": {
        "points": 8,
        "category": "URL Structure",
        "description": "URL uses a recognized URL shortening service."
    },
    "many_subdomains": {
        "points": 5,
        "category": "URL Structure",
        "description": "URL contains an unusually large number of subdomains."
    },
    "deceptive_domain": {
        "points": 8,
        "category": "Domain",
        "description": "Domain contains a potentially deceptive pattern."
    },
    "brand_impersonation": {
        "points": 15,
        "category": "Brand Security",
        "description": "Possible brand impersonation was detected."
    },
    "suspicious_redirect_parameter": {
        "points": 10,
        "category": "Redirect Security",
        "description": "URL contains a suspicious redirect parameter or destination."
    },
    "suspicious_redirect_chain": {
        "points": 8,
        "category": "Redirect Security",
        "description": "Live redirect analysis identified a suspicious redirect chain."
    },
    "tls_problem": {
        "points": 10,
        "category": "TLS Security",
        "description": "A TLS certificate or connection security problem was confirmed."
    },
    "suspicious_dns": {
        "points": 8,
        "category": "Domain Security",
        "description": "Suspicious DNS-related evidence was detected."
    },
    "google_safe_browsing_malicious": {
        "points": 15,
        "category": "Threat Intelligence",
        "description": "VirusTotal reported malicious detection evidence."
    },
}


def calculate_risk_score(indicators):
    """
    Calculate an explainable risk score.

    indicators:
        Dictionary of indicator keys mapped to True/False.

    Returns:
        Dictionary containing score, risk level and explanations.
    """

    triggered = []
    total_score = 0

    for key, config in INDICATORS.items():

        if indicators.get(key, False) is True:

            item = {
                "id": key,
                "category": config["category"],
                "points": config["points"],
                "description": config["description"],
            }

            triggered.append(item)
            total_score += config["points"]

    total_score = min(total_score, MAX_SCORE)

    risk_level = "Critical Risk"

    for threshold, level in RISK_LEVELS:
        if total_score <= threshold:
            risk_level = level
            break

    return {
        "score": total_score,
        "max_score": MAX_SCORE,
        "risk_level": risk_level,
        "triggered_indicators": triggered,
        "total_indicators": len(triggered),
    }


if __name__ == "__main__":

    # Sample test only
    test_indicators = {
        "http_not_https": True,
        "ip_address": True,
        "brand_impersonation": True,
        "tls_problem": False,
        "google_safe_browsing_malicious": True,
    }

    result = calculate_risk_score(test_indicators)

    print("\n--- V7 Risk Scoring Test ---")
    print("Risk Score:", result["score"], "/", result["max_score"])
    print("Risk Level:", result["risk_level"])

    print("\nTriggered Indicators:")

    for item in result["triggered_indicators"]:
        print(
            f"- {item['description']} "
            f"(+{item['points']} points)"
        )