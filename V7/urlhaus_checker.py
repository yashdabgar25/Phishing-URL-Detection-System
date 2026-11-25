import requests


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/api/v1/url/"


def check_urlhaus(url):

    try:
        response = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        if data.get("query_status") == "ok":

            return {
                "success": True,
                "listed": True,
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "date_added": data.get("date_added"),
                "reporter": data.get("reporter"),
                "message": "URL found in URLhaus database."
            }

        elif data.get("query_status") == "no_results":

            return {
                "success": True,
                "listed": False,
                "url_status": None,
                "threat": None,
                "tags": [],
                "date_added": None,
                "reporter": None,
                "message": "URL not found in URLhaus database."
            }

        return {
            "success": False,
            "listed": None,
            "message": f"URLhaus response: {data.get('query_status')}"
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "listed": None,
            "message": "URLhaus request timed out."
        }

    except requests.exceptions.RequestException as e:

        return {
            "success": False,
            "listed": None,
            "message": f"URLhaus request failed: {str(e)}"
        }

    except Exception as e:

        return {
            "success": False,
            "listed": None,
            "message": f"Unexpected error: {str(e)}"
        }


if __name__ == "__main__":

    test_url = "https://example.com"

    print("\n--- URLhaus Test ---")

    result = check_urlhaus(test_url)

    for key, value in result.items():
        print(f"{key}: {value}")