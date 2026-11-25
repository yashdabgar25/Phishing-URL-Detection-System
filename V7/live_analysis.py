"""
V7 Live Analysis Module
DNS, TLS, HTTP and redirect analysis.

This is a local student-project scanner.
It blocks private/internal IP destinations as a basic SSRF precaution.
"""

import socket
import ssl
import ipaddress
import requests
import certifi

from urllib.parse import urlparse, urljoin


TIMEOUT = 5
MAX_REDIRECTS = 5


def normalize_url(url):
    url = url.strip()

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported URL scheme.")

    if not parsed.hostname:
        raise ValueError("Hostname not found.")

    return url


def resolve_public_ips(hostname):
    """
    Resolve hostname and reject non-public IP addresses.
    """

    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = list(set(
            result[4][0] for result in results
        ))

    if not addresses:
        raise ValueError("DNS resolution returned no addresses.")

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if not ip.is_global:
            raise ValueError(
                "Blocked: destination is not a public IP address."
            )

    return addresses


def dns_analysis(url):
    parsed = urlparse(normalize_url(url))
    hostname = parsed.hostname

    try:
        addresses = resolve_public_ips(hostname)

        return {
            "success": True,
            "hostname": hostname,
            "ip_addresses": addresses,
            "message": "DNS resolution successful."
        }

    except Exception as e:
        return {
            "success": False,
            "hostname": hostname,
            "ip_addresses": [],
            "message": str(e)
        }


def tls_analysis(url):
    parsed = urlparse(normalize_url(url))

    if parsed.scheme != "https":
        return {
            "success": False,
            "available": False,
            "message": "URL does not use HTTPS."
        }

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        resolve_public_ips(hostname)

        context = ssl.create_default_context(
            cafile=str(certifi.where())
        )

        with socket.create_connection(
            (hostname, port),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                return {
                    "success": True,
                    "available": True,
                    "tls_version": secure_socket.version(),
                    "certificate_subject": str(
                        certificate.get("subject", "")
                    ),
                    "certificate_issuer": str(
                        certificate.get("issuer", "")
                    ),
                    "message": "TLS connection verified successfully."
                }

    except Exception as e:
        return {
            "success": False,
            "available": True,
            "message": str(e)
        }


def http_analysis(url):
    url = normalize_url(url)

    try:
        resolve_public_ips(urlparse(url).hostname)

        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=True,
            headers={
                "User-Agent": "PhishingURLDetectionStudentProject/7.0"
            },
            stream=True
        )

        result = {
            "success": True,
            "status_code": response.status_code,
            "status_text": response.reason,
            "server": response.headers.get("Server"),
            "content_type": response.headers.get("Content-Type"),
            "message": "HTTP response received."
        }

        response.close()
        return result

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }


def redirect_analysis(url):
    current_url = normalize_url(url)
    chain = []

    try:
        for _ in range(MAX_REDIRECTS + 1):

            parsed = urlparse(current_url)

            resolve_public_ips(parsed.hostname)

            response = requests.get(
                current_url,
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=True,
                headers={
                    "User-Agent": "PhishingURLDetectionStudentProject/7.0"
                },
                stream=True
            )

            status_code = response.status_code
            location = response.headers.get("Location")

            chain.append({
                "url": current_url,
                "status_code": status_code
            })

            response.close()

            if status_code not in (301, 302, 303, 307, 308):
                return {
                    "success": True,
                    "redirect_count": len(chain) - 1,
                    "chain": chain,
                    "final_url": current_url,
                    "message": "Redirect analysis completed."
                }

            if not location:
                break

            next_url = urljoin(current_url, location)
            next_parsed = urlparse(next_url)

            if next_parsed.scheme not in ("http", "https"):
                raise ValueError("Blocked unsupported redirect scheme.")

            if not next_parsed.hostname:
                raise ValueError("Invalid redirect destination.")

            resolve_public_ips(next_parsed.hostname)

            current_url = next_url

        return {
            "success": True,
            "redirect_count": len(chain) - 1,
            "chain": chain,
            "final_url": current_url,
            "message": "Redirect limit reached or chain completed."
        }

    except Exception as e:
        return {
            "success": False,
            "chain": chain,
            "message": str(e)
        }


def analyse_live_url(url):

    url = normalize_url(url)

    return {
        "dns": dns_analysis(url),
        "tls": tls_analysis(url),
        "http": http_analysis(url),
        "redirects": redirect_analysis(url)
    }


if __name__ == "__main__":

    test_url = "https://example.com"

    print("\n--- V7 Live Analysis Test ---")

    result = analyse_live_url(test_url)

    for section, data in result.items():

        print(f"\n{section.upper()}")

        for key, value in data.items():
            print(f"{key}: {value}")