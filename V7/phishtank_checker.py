import requests
import json
import os
import time
from urllib.parse import urlparse

FEED_URL = "https://data.phishtank.com/data/online-valid.json"

CACHE_FILE = os.path.join(os.path.dirname(__file__), "phishtank_cache.json")
CACHE_DURATION = 24 * 60 * 60  # 24 hours

USER_AGENT = "PhishingURLDetectionSystem/7.0 (student security research)"


def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url.rstrip("/")


def download_feed():
    headers = {
        "User-Agent": USER_AGENT
    }

    response = requests.get(
        FEED_URL,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(data, list):
        raise ValueError("Unexpected PhishTank feed format.")

    return data


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return None

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as file:
            cache = json.load(file)

        if time.time() - cache.get("updated_at", 0) < CACHE_DURATION:
            return cache.get("urls", [])

    except (json.JSONDecodeError, OSError):
        return None

    return None


def save_cache(data):
    urls = []

    for entry in data:
        if isinstance(entry, dict) and entry.get("url"):
            urls.append(entry["url"])

    cache = {
        "updated_at": time.time(),
        "urls": urls
    }

    with open(CACHE_FILE, "w", encoding="utf-8") as file:
        json.dump(cache, file)

    return urls


def get_phishtank_database():
    cached_urls = load_cache()

    if cached_urls is not None:
        return cached_urls, "cache"

    try:
        data = download_feed()
        urls = save_cache(data)

        return urls, "download"

    except Exception as e:
        return None, str(e)


def check_phishtank(url):
    url = normalize_url(url)

    database, source = get_phishtank_database()

    if database is None:
        return {
            "success": False,
            "found": False,
            "message": "PhishTank database unavailable.",
            "error": source
        }

    database_normalized = {
        normalize_url(item).lower()
        for item in database
    }

    if url.lower() in database_normalized:
        return {
            "success": True,
            "found": True,
            "message": "URL found in PhishTank's verified online phishing database.",
            "source": source
        }

    return {
        "success": True,
        "found": False,
        "message": "URL not found in PhishTank's current database.",
        "source": source
    }