"""
V7 Scan Engine
Integrates V6 ML with V7 security analysis and explainable risk scoring.
"""

import os
import sys
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from V6.feature_extractor_v6 import extract_features
from V6.predictor_v6 import PhishingPredictorV6

from V7.feature_interpreter import interpret_all_features
from V7.risk_scoring import calculate_risk_score
from V7.live_analysis import analyse_live_url
from V7.google_safe_browsing import check_google_safe_browsing
from V7.phishtank_checker import check_phishtank


MODEL_PATH = os.path.join(BASE_DIR, "phishing_model_v6.json")

predictor = PhishingPredictorV6(MODEL_PATH)

def detect_suspicious_redirect_parameter(url):

    redirect_parameters = {
        "redirect",
        "redirect_url",
        "redirect_uri",
        "url",
        "next",
        "return",
        "returnto",
        "return_to",
        "destination",
        "continue",
        "goto",
        "out",
        "link",
        "target",
    }

    try:

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for parameter, values in query_params.items():

            if parameter.lower() in redirect_parameters:

                for value in values:

                    parsed_value = value.strip().lower()

                    if (
                        parsed_value.startswith("http://")
                        or parsed_value.startswith("https://")
                        or parsed_value.startswith("//")
                    ):
                        return True

        return False

    except Exception:

        return False

def detect_deceptive_domain(url):

    from difflib import SequenceMatcher

    suspicious_brands = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "whatsapp",
        "netflix",
        "bankofamerica",
    ]

    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        domain_parts = hostname.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname

        original_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname

        # Normalize common lookalike characters
        main_domain = main_domain.replace("0", "o")
        main_domain = main_domain.replace("1", "I")

        if original_domain != main_domain:
            return True

        for brand in suspicious_brands:

            if main_domain == brand:
                return False

            # Brand name embedded in a longer domain
            if brand in main_domain:
                return True

            # Similar spelling detection
            similarity = SequenceMatcher(
                None, main_domain, brand
            ).ratio()

            if similarity >= 0.80:
                return True

        return False

    except Exception:
        return False


def scan_url_v7(url):

    result = {
        "success": False,
        "url": url,
        "error": None,
    }

    try:

        # Step 1: Feature extraction
        features = extract_features(url)

        # Step 2: ML prediction
        probabilities = predictor.predict_proba(features)
        predicted_class = predictor.predict(features)

        # Step 3: Feature interpretation
        interpreted_features = interpret_all_features(features)

        # Step 4: Live analysis
        live_data = analyse_live_url(url)

        # Step 5: Google Safe Browsing
        google_data = check_google_safe_browsing(url)

        # Step 6: PhishTank
        phishtank_data = check_phishtank(url)

        # Step 7: Create risk indicators
        indicators = {}

        # URL-based indicators
        indicators["http_not_https"] = not bool(
            features.get("has_https", 0)
        )

        indicators["ip_address"] = bool(
            features.get("is_ip_address", 0)
        )

        indicators["at_symbol"] = bool(
            features.get("has_at_symbol", 0)
        )

        indicators["long_url"] = (
            features.get("url_length", 0) > 75
        )

        indicators["many_subdomains"] = bool(
            features.get("has_many_subdomains", 0)
        )

        indicators["brand_impersonation"] = bool(
            features.get("has_brand_name", 0)
        )
        indicators["deceptive_domain"] = detect_deceptive_domain(url)

        indicators["suspicious_redirect_parameter"] = (
	    detect_suspicious_redirect_parameter(url)
	)

        # Live redirect indicator
        redirects = live_data.get("redirects", {})

        indicators["suspicious_redirect_chain"] = (
            redirects.get("success", False)
            and redirects.get("redirect_count", 0) > 3
        )

        # TLS indicator
        tls_data = live_data.get("tls", {})

        indicators["tls_problem"] = (
            tls_data.get("success", False)
            and not tls_data.get("available", True)
        )

        # Google Safe Browsing
        indicators["google_safe_browsing_malicious"] = (
            google_data.get("success", False)
            and google_data.get("threat_found", False)
        )

        # Risk scoring
        risk_data = calculate_risk_score(indicators)

        # Step 8: Final result
        result.update({

            "success": True,

            "features": features,

            "ml_prediction": predicted_class,

            "ml_probabilities": probabilities,

            "feature_interpretation": interpreted_features,

            "live_analysis": live_data,

            "google_safe_browsing": google_data,

            "phishtank": phishtank_data,

            "risk_indicators": indicators,

            "risk_score": risk_data,

        })

    except Exception as e:

        result["error"] = str(e)

    return result