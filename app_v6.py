import os
import re
import json
import time
import sqlite3
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from publicsuffix2 import get_sld

from V6.feature_extractor_v6 import extract_features
from V6.predictor_v6 import PhishingPredictorV6


# --------------------------------------------------
# 1. CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishing_history.db")
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model_v6.json")

load_dotenv(os.path.join(BASE_DIR, ".env"))

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

app = Flask(__name__)

# Load the V6 model once when the application starts.
predictor = PhishingPredictorV6(MODEL_PATH)


# --------------------------------------------------
# 2. DOMAIN INTELLIGENCE
# --------------------------------------------------

BRAND_DOMAINS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "linkedin": ["linkedin.com"],
    "youtube": ["youtube.com"],
    "whatsapp": ["whatsapp.com"],
    "sbi": ["sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "rbi": ["rbi.org.in"]
}

REDIRECT_KEYS = {
    "url", "q", "continue", "redirect", "next",
    "return", "target", "dest", "destination",
    "u", "to"
}


def get_domain_info(hostname):
    hostname = hostname.lower().strip(".")
    try:
        ipaddress.ip_address(hostname)
        return hostname, True
    except ValueError:
        pass

    try:
        registered = get_sld(hostname, strict=False)
        return (registered or hostname), False
    except Exception:
        return hostname, False


def check_brand_impersonation(hostname, registered_domain):
    detected = []

    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in hostname:
            if registered_domain not in official_domains:
                detected.append(brand)

    return detected


def check_external_redirect(parsed_url, registered_domain):
    try:
        query = parse_qs(parsed_url.query)

        for key, values in query.items():
            if key.lower() not in REDIRECT_KEYS:
                continue

            for value in values:
                candidate = unquote(value).strip()

                if candidate.startswith("//"):
                    candidate = "https:" + candidate
                elif candidate.startswith("/"):
                    continue
                elif not re.match(r"^https?://", candidate, re.I):
                    continue

                target = urlparse(candidate)
                target_host = (target.hostname or "").lower()

                if not target_host:
                    continue

                target_domain, target_is_ip = get_domain_info(target_host)

                if target_is_ip or target_domain != registered_domain:
                    return target_host

    except Exception:
        pass

    return None


# --------------------------------------------------
# 3. URL VALIDATION
# --------------------------------------------------

def normalize_url(url):
    if not isinstance(url, str):
        raise ValueError("Please enter a valid URL.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if any(char.isspace() for char in url):
        raise ValueError("URL must not contain spaces.")

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname not found.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")

    try:
        parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    try:
        parsed.hostname.encode("idna")
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    return url, parsed


# --------------------------------------------------
# 4. VIRUSTOTAL INTEGRATION
# --------------------------------------------------

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "unavailable",
            "message": "VirusTotal API key is not configured."
        }

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=15
        )

        if response.status_code not in (200, 201):
            return {
                "status": "error",
                "message": "VirusTotal submission failed."
            }

        analysis_id = response.json()["data"]["id"]
        analysis_url = (
            "https://www.virustotal.com/api/v3/analyses/"
            + analysis_id
        )

        for _ in range(10):
            time.sleep(2)

            result = requests.get(
                analysis_url,
                headers=headers,
                timeout=15
            )

            if result.status_code != 200:
                continue

            analysis = result.json()["data"]["attributes"]

            if analysis.get("status") == "completed":
                stats = analysis.get("stats", {})

                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }

        return {
            "status": "pending",
            "message": "VirusTotal analysis is still processing."
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": "Could not connect to VirusTotal."
        }
    except (KeyError, ValueError):
        return {
            "status": "error",
            "message": "Could not read VirusTotal results."
        }


# --------------------------------------------------
# 5. HYBRID RISK ANALYSIS
# --------------------------------------------------

def analyse_url(url, parsed, features, probabilities, vt):
    hostname = (parsed.hostname or "").lower()
    registered, is_ip = get_domain_info(hostname)

    phishing_index = predictor.classes.index(0)
    ml_probability = probabilities[phishing_index]

    impersonated_brands = check_brand_impersonation(
        hostname, registered
    )

    external_redirect = check_external_redirect(
        parsed, registered
    )

    is_official_domain = (
        not is_ip and
        any(
            registered in domains
            for domains in BRAND_DOMAINS.values()
        )
    )

    is_homepage = (
        parsed.path in ("", "/") and
        not parsed.query and
        not parsed.fragment
    )

    warnings = []
    checks = {}

    checks["URL Validation"] = {
        "status": "Passed",
        "details": "URL format is valid."
    }

    checks["Registered Domain"] = {
        "status": "Passed" if not is_ip else "Warning",
        "details": registered
    }

    checks["HTTPS"] = {
        "status": "Passed" if parsed.scheme == "https" else "Warning",
        "details": "HTTPS connection requested."
        if parsed.scheme == "https"
        else "URL does not use HTTPS."
    }

    checks["Machine Learning Model"] = {
        "status": "Warning" if ml_probability >= 0.5 else "Passed",
        "details": f"Estimated phishing probability: {ml_probability * 100:.2f}%"
    }

    if is_ip:
        warnings.append("URL uses an IP address instead of a domain name.")

    if parsed.scheme != "https":
        warnings.append("URL does not use HTTPS.")

    if impersonated_brands:
        warnings.append(
            "Possible brand impersonation: "
            + ", ".join(impersonated_brands)
        )

    if external_redirect:
        warnings.append(
            "URL contains a possible external redirect to: "
            + external_redirect
        )

    if impersonated_brands:
        checks["Brand Impersonation"] = {
            "status": "Warning",
            "details": ", ".join(impersonated_brands)
        }
    else:
        checks["Brand Impersonation"] = {
            "status": "Passed",
            "details": "No brand impersonation detected."
        }

    if external_redirect:
        checks["Redirect Destination"] = {
            "status": "Warning",
            "details": external_redirect
        }
    else:
        checks["Redirect Destination"] = {
            "status": "Passed",
            "details": "No external redirect detected in supported URL parameters."
        }

    vt_available = vt.get("status") == "success"
    malicious = vt.get("malicious", 0) if vt_available else 0
    suspicious = vt.get("suspicious", 0) if vt_available else 0
    harmless = vt.get("harmless", 0) if vt_available else 0

    if vt_available:
        checks["VirusTotal"] = {
            "status": "Warning" if malicious or suspicious else "Passed",
            "details": (
                f"Malicious: {malicious}, Suspicious: {suspicious}, "
                f"Harmless: {harmless}"
            )
        }
    else:
        checks["VirusTotal"] = {
            "status": "Unavailable",
            "details": vt.get("message", "No completed VirusTotal result.")
        }

    # A strong VirusTotal detection takes priority over domain trust.
    if malicious >= 3:
        result = "Potential Phishing"
        risk_score = 9

    elif malicious > 0:
        result = "Potential Phishing" if ml_probability >= 0.70 else "Suspicious"
        risk_score = 8 if result == "Potential Phishing" else 6

    elif suspicious > 0:
        result = "Suspicious"
        risk_score = 6

    elif impersonated_brands:
        if ml_probability >= 0.70:
            result = "Potential Phishing"
            risk_score = 8
        else:
            result = "Suspicious"
            risk_score = 6

    elif external_redirect:
        result = "Suspicious"
        risk_score = 5

    elif is_official_domain and is_homepage:
        result = "Likely Safe"
        risk_score = 1

        if ml_probability >= 0.50:
            warnings.append(
                "The ML model disagreed with the recognized official domain. "
                "The domain-level result was prioritized."
            )

    elif vt_available and harmless >= 10:
        if ml_probability >= 0.70:
            result = "Suspicious"
            risk_score = 6

            warnings.append(
                "The ML model indicates a high phishing probability, "
                "but VirusTotal reports no malicious detections. "
                "The URL is classified as Suspicious for further verification."
            )

        else:
            result = "Likely Safe"
            risk_score = 2

    elif is_ip:
        result = "Suspicious"
        risk_score = 5
        warnings.append(
            "This URL uses an IP address. Verify that it belongs "
            "to a trusted device or network before proceeding."
        )

    elif ml_probability >= 0.70:
        result = "Potential Phishing"
        risk_score = 8

    elif ml_probability >= 0.35:
        result = "Suspicious"
        risk_score = 5

    else:
        result = "Suspicious"
        risk_score = 3
        warnings.append(
            "There is insufficient evidence to confidently classify this URL as safe."
        )

    risk_level = (
        "Low Risk" if risk_score <= 2
        else "Medium Risk" if risk_score <= 5
        else "High Risk"
    )

    return {
        "result": result,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "checks": checks,
        "registered_domain": registered,
        "ml_phishing_probability": round(ml_probability * 100, 2)
    }


# --------------------------------------------------
# 6. DATABASE
# --------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            warnings TEXT,
            checks TEXT,
            virustotal TEXT,
            scan_time TEXT NOT NULL
        )
    """)

    cursor.execute("PRAGMA table_info(history)")
    columns = [row[1] for row in cursor.fetchall()]

    if "checks" not in columns:
        cursor.execute("ALTER TABLE history ADD COLUMN checks TEXT")

    if "virustotal" not in columns:
        cursor.execute("ALTER TABLE history ADD COLUMN virustotal TEXT")

    conn.commit()
    conn.close()


def save_history(url, result, risk_score, risk_level, warnings, checks, virustotal):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO history
        (url, result, risk_score, risk_level, warnings, checks, virustotal, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        result,
        risk_score,
        risk_level,
        json.dumps(warnings),
        json.dumps(checks),
        json.dumps(virustotal),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# 7. FLASK ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check-url", methods=["POST"])
def check_url():
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "")

        url, parsed = normalize_url(raw_url)

        features = extract_features(url)

        probabilities = predictor.predict_proba(features)

        vt = check_virustotal(url)

        analysis = analyse_url(
            url, parsed, features, probabilities, vt
        )

        save_history(
            url,
            analysis["result"],
            analysis["risk_score"],
            analysis["risk_level"],
            analysis["warnings"],
            analysis["checks"],
            vt
        )

        return jsonify({
            "status": "success",
            "url": url,
            "message": analysis["result"],
            "result": analysis["result"],
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "warnings": analysis["warnings"],
            "checks": analysis["checks"],
            "virustotal": vt,
            "registered_domain": analysis["registered_domain"],
            "ml_phishing_probability": analysis["ml_phishing_probability"]
        })

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    except Exception as error:
        app.logger.exception("URL scan failed")
        return jsonify({
            "status": "error",
            "message": "Unable to scan this URL. Please check the application logs."
        }), 500


@app.route("/history-page")
def history_page():
    return render_template("history.html")


@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM history
        ORDER BY id DESC
        LIMIT 100
    """)

    rows = cursor.fetchall()
    conn.close()

    records = []

    for row in rows:
        records.append({
            "id": row["id"],
            "url": row["url"],
            "result": row["result"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "warnings": json.loads(row["warnings"] or "[]"),
            "checks": json.loads(row["checks"] or "{}"),
            "virustotal": json.loads(row["virustotal"] or "{}"),
            "scan_time": row["scan_time"]
        })

    return jsonify(records)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history")
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Scan history cleared."
    })


@app.route("/test-virustotal")
def test_virustotal():
    if not VIRUSTOTAL_API_KEY:
        return jsonify({
            "status": "unavailable",
            "message": "VirusTotal API key is not configured."
        })

    return jsonify({
        "status": "configured",
        "message": "VirusTotal API key is configured."
    })


# --------------------------------------------------
# 8. START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    init_db()

    print("Starting Phishing URL Detection System V6...")
    print("Loading the V6 model: 200 trees, 37 features")
    print("Open: http://127.0.0.1:5000")

    app.run(host="0.0.0.0", port=5000, debug=False)