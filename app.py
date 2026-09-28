from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse 
import re
import sqlite3
from datetime import datetime
import json
import joblib
import requests
from dotenv import load_dotenv
import os
import time

load_dotenv()
VIRUSTOTAL_API_KEY= os.getenv("VIRUSTOTAL_API_KEY")

def check_virustotal(url):
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return {
                "status": "error",
                "status_code": response.status_code,
                "message": response.text
            }

        data = response.json()

        analysis_id = data["data"]["id"]

        # Wait for VirusTotal analysis
        for _ in range(10):

            time.sleep(2)

            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )

            if analysis_response.status_code != 200:
                return {
                    "status": "error",
                    "status_code": analysis_response.status_code,
                    "message": analysis_response.text
                }

            analysis_data = analysis_response.json()

            attributes = analysis_data["data"]["attributes"]

            analysis_status = attributes.get("status")

            if analysis_status == "completed":

                stats = attributes.get("stats", {})

                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }

        return {
            "status": "pending",
            "message": "VirusTotal analysis is still processing"
        }

    except Exception as e:

        print("VirusTotal Error:", e)

        return {
            "status": "error",
            "message": "VirusTotal check failed"
        }

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")

def extract_ml_features(url):
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # URL length
    url_length = len(url)

    # Domain length
    domain_length = len(hostname)

    # IP address check
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    is_domain_ip = 1 if re.match(ip_pattern, hostname) else 0

    # Subdomain count
    parts = hostname.split(".") if hostname else []
    no_of_subdomain = max(len(parts) - 2, 0)

    # Obfuscation
    special_obfuscation_chars = ["%", "@", "\\"]

    no_of_obfuscated_char = sum(
        url.count(char) for char in special_obfuscation_chars
    )

    has_obfuscation = 1 if no_of_obfuscated_char > 0 else 0

    obfuscation_ratio = (
        no_of_obfuscated_char / url_length
        if url_length > 0 else 0
    )

    # Letters
    no_of_letters = sum(char.isalpha() for char in url)

    letter_ratio = (
        no_of_letters / url_length
        if url_length > 0 else 0
    )

    # Digits
    no_of_digits = sum(char.isdigit() for char in url)

    digit_ratio = (
        no_of_digits / url_length
        if url_length > 0 else 0
    )

    # Special characters
    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")

    no_of_other_special = 0

    for char in url:
        if not char.isalnum():
            if char not in [".", "/", ":", "=", "?", "&", "-", "_", "%", "@"]:
                no_of_other_special += 1

    special_char_ratio = (
        no_of_other_special / url_length
        if url_length > 0 else 0
    )

    # HTTPS
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    return [[
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
    ]]

def init_db():
    conn = sqlite3.connect("phishing_history.db")
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
        scan_time TEXT NOT NULL
    )
""")
    conn.commit()

    try:
        cursor.execute("ALTER TABLE history ADD COLUMN checks TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    conn.close()

def detect_phishing(url):

    score = 0
    warnings = []

    checks = {
    "HTTPS": "Passed",
    "IP Address": "Passed",
    "Suspicious Keywords": "Passed",
    "URL Length": "Passed",
    "Multiple Hyphens": "Passed",
    "Subdomains": "Passed"
}

    parsed_url = urlparse(url)
    if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
        return "Invalid URL", 0, ["Please enter a valid website URL."], checks

    url_lower = url.lower()

    # Check URL length
    if len(url) > 75:
        score += 1
        warnings.append("URL is unusually long.")
        checks["URL Length"]="Failed"

    # Check HTTPS
    if not url_lower.startswith("https://"):
        score += 1
        warnings.append("URL does not use HTTPS.")
        checks["HTTPS"]="Failed"

    # Check suspicious symbols
    if "@" in url:
        score += 2
        warnings.append("URL contains an @ symbol.")

    try:
        hostname = urlparse(url).hostname

        if hostname:
            ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

            if re.match(ip_pattern, hostname):
                score += 2
                warnings.append("URL uses an IP address instead of a domain name.")
                checks["IP Address"]="Failed"

    except Exception:
        score += 1
        warnings.append("URL format could not be analyzed.")

    # Check suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "confirm",
        "bank",
        "free",
        "signin"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    if len(found_words) >= 2:
        score += 2
        warnings.append("URL contains multiple suspicious keywords.")
        checks["Suspicious Keywords"]="Failed"

    # Check number of subdomains
    try:
        hostname = urlparse(url).hostname

        if hostname:
            parts = hostname.split(".")

            if len(parts) > 4:
                score += 1
                warnings.append("URL contains an unusual number of subdomains.")
                checks["Subdomains"]="Failed"

    except Exception:
        pass

    if url_lower.count("-") >= 3:
        score += 1
        warnings.append("URL contains multiple hyphens.")
        checks["Multiple Hyphens"]="Failed"

    # Final result
    if score >= 5:
        result = "Potentially Phishing"
    elif score >= 2:
        result = "Suspicious"
    else:
        result = "Likely Safe"

    return result, score, warnings, checks

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check-url", methods=["POST"])
def check_url():

    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "Please enter a URL."
        })

    # URL validation
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
        return jsonify({
            "status": "error",
            "message": "Please enter a valid website URL."
        })

    # --------------------------------------------------
    # ML MODEL PREDICTION
    # --------------------------------------------------

    ml_features = extract_ml_features(url)

    prediction = model.predict(ml_features)[0]
    virustotal_result = check_virustotal(url)

    probabilities = model.predict_proba(ml_features)[0]

    # Model classes:
    # 0 = Phishing
    # 1 = Legitimate

    phishing_probability = probabilities[
        list(model.classes_).index(0)
    ]

    # Convert probability to 0-10 risk score
    risk_score = round(phishing_probability * 10)

    # --------------------------------------------------
    # Result classification
    # --------------------------------------------------

    # --------------------------------------------------
# --------------------------------------------------
# Hybrid ML + VirusTotal Decision
# --------------------------------------------------

    if virustotal_result.get("status") == "success":

        malicious = virustotal_result.get("malicious", 0)
        suspicious = virustotal_result.get("suspicious", 0)
        harmless = virustotal_result.get("harmless", 0)

        # VirusTotal has confirmed malicious detections
        if malicious > 0:
            result = "Potentially Phishing"
            risk_score = 10

        # VirusTotal has suspicious detections
        elif suspicious > 0:
            result = "Suspicious"
            risk_score = 5

        # VirusTotal has strong clean reputation
        elif malicious == 0 and suspicious == 0 and harmless >= 10:
            result = "Likely Safe"
            risk_score = 1

        # VirusTotal has limited reputation data
        else:
            if prediction == 0 and risk_score >= 7:
                result = "Potentially Phishing"
            elif prediction == 0:
                result = "Suspicious"
            else:
                result = "Likely Safe"

    else:
        # VirusTotal unavailable → use ML as a warning signal
        if prediction == 0 and risk_score >= 7:
            result = "Suspicious"
            risk_score = 5

        elif prediction == 0:
            result = "Suspicious"
            risk_score = 4

        else:
            result = "Likely Safe"
            risk_score = 1


    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if risk_score <= 2:
        risk_level = "Low Risk"

    elif risk_score <= 5:
        risk_level = "Medium Risk"

    else:
        risk_level = "High Risk"


    # --------------------------------------------------
    # Existing rule-based checks
    # --------------------------------------------------

    old_result, old_score, warnings, checks = detect_phishing(url)


    # Add ML information to warnings
        # --------------------------------------------------
    # Detection Details
    # --------------------------------------------------

    ml_checks = {}

    # ML Model
    if prediction == 0:
        ml_checks["ML Model"] = "High Risk Pattern Detected"
    else:
        ml_checks["ML Model"] = "No Major Phishing Pattern Detected"


    # HTTPS
    if parsed_url.scheme.lower() == "https":
        ml_checks["HTTPS"] = "Enabled"
    else:
        ml_checks["HTTPS"] = "Not Enabled"


    # IP Address
    hostname = parsed_url.hostname or ""

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):
        ml_checks["IP Address"] = "IP Based URL"
    else:
        ml_checks["IP Address"] = "Domain Based"


    # URL Length
    ml_checks["URL Length"] = f"{len(url)} characters"


    # Subdomains
    parts = hostname.split(".") if hostname else []
    subdomain_count = max(len(parts) - 2, 0)

    ml_checks["Subdomains"] = f"{subdomain_count} detected"


    # Obfuscation
    if "%" in url or "@" in url or "\\" in url:
        ml_checks["Obfuscation"] = "Detected"
    else:
        ml_checks["Obfuscation"] = "Not Detected"


    # Query Parameters
    if "?" in url:
        ml_checks["Query Parameters"] = "Present"
    else:
        ml_checks["Query Parameters"] = "Not Present"


    checks = ml_checks


    # ML model information
    if (
        virustotal_result.get("status") == "success"
        and virustotal_result.get("malicious", 0) == 0
        and virustotal_result.get("suspicious", 0) == 0
        and virustotal_result.get("harmless", 0) >= 10
    ):
        warnings.insert(
            0,
            "ML model flagged this URL, but VirusTotal found no malicious or suspicious detections."
        )
    else:
        warnings.insert(
            0,
            f"ML model phishing signal: {round(phishing_probability * 100, 2)}%"
        )


    # --------------------------------------------------
    # Save result in SQLite
    # --------------------------------------------------

    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO history
        (url, result, risk_score, risk_level, warnings, checks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        result,
        risk_score,
        risk_level,
        json.dumps(warnings),
        json.dumps(checks),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


    # --------------------------------------------------
    # Send result to frontend
    # --------------------------------------------------

    return jsonify({
        "status": "success",
        "virustotal": virustotal_result,
        "message": result,
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "checks": checks
    })

@app.route("/history-page")
def history_page():
    return render_template("history.html")

@app.route("/clear-history", methods=["POST"])
def clear_history():

    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM history")

    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "History cleared successfully."
    })

@app.route("/history", methods=["GET"])
def history():

    conn = sqlite3.connect("phishing_history.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM history 
        ORDER BY id DESC
""")

    records = cursor.fetchall()

    conn.close()

    history_data = []

    for record in records:
        history_data.append({
            "id":record["id"],
            "url":record["url"],
            "result":record["result"],
            "risk_score":record["risk_score"],
            "risk_level":record["risk_level"],
            "warnings":json.loads(record["warnings"]) if record["warnings"]else[],
            "checks": json.loads(record["checks"]) if record["checks"] else {},
            "scan_time":record["scan_time"],
        })

    return jsonify(history_data)

@app.route("/test-virustotal")
def test_virustotal():

    test_url = "https://www.python.org/"

    result = check_virustotal(test_url)

    return jsonify(result)

if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000,debug=True)