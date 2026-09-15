from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse 
import re
import sqlite3
from datetime import datetime
import json

app = Flask(__name__)

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
    
    result, score, warnings, checks = detect_phishing(url)

    if result == "Invalid URL":
        return jsonify({
            "status":"error",
            "message":warnings[0]
        })

    if score <= 1:
        risk_level = "Low Risk"
    elif score <= 4:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"


    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO history (url, result, risk_score, risk_level, warnings, checks, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?)
""",(
    url,
    result,
    score,
    risk_level,
    json.dumps(warnings),
    json.dumps(checks),
    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
))
    conn.commit()
    conn.close()

    
    return jsonify({
        "status": "success",
        "message": result,
        "url": url,
        "risk_score": score,
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


if __name__=="__main__":
    init_db()
    app.run(debug=True)