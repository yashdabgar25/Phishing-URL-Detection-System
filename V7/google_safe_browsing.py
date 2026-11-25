import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_google_safe_browsing(url):

    if not API_KEY:
        return {
            "success": False,
            "threat_found": None,
            "message": "Google Safe Browsing API key not configured."
        }

    payload = {
        "client": {
            "clientId": "phishing-url-detection",
            "clientVersion": "7.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:

        response = requests.post(
            API_URL,
            params={"key": API_KEY},
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        if data.get("matches"):

            threats = []

            for match in data["matches"]:
                threats.append({
                    "threat_type": match.get("threatType"),
                    "platform": match.get("platformType"),
                    "threat_entry_type": match.get("threatEntryType")
                })

            return {
                "success": True,
                "threat_found": True,
                "threats": threats,
                "message": "Google Safe Browsing detected a threat."
            }

        return {
            "success": True,
            "threat_found": False,
            "threats": [],
            "message": "No threat found in Google Safe Browsing database."
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "threat_found": None,
            "message": "Google Safe Browsing request timed out."
        }

    except requests.exceptions.RequestException as e:

        return {
            "success": False,
            "threat_found": None,
            "message": f"API request failed: {str(e)}"
        }

    except Exception as e:

        return {
            "success": False,
            "threat_found": None,
            "message": f"Unexpected error: {str(e)}"
        }


if __name__ == "__main__":

    test_url = "https://example.com"

    print("\n--- Google Safe Browsing Test ---")

    result = check_google_safe_browsing(test_url)

    for key, value in result.items():
        print(f"{key}: {value}")