"""Fingerprint verification — validates JA4/TLS fingerprints through the Thermoptic proxy."""
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

FINGERPRINT_API = "https://tls.peet.ws/api/all"
CHROME_JA4_PREFIX = "t13d"


def verify_fingerprint(proxy_url: str = "http://changeme:changeme@127.0.0.1:1234") -> dict:
    """Send a request through the proxy and validate the TLS fingerprint.

    Returns dict with ip, ja4, ja4h, ja4t, ja4x, user_agent, valid, issues.
    """
    try:
        resp = requests.get(
            FINGERPRINT_API,
            proxies={"https": proxy_url},
            timeout=10,
            verify=False,
        )
        data = resp.json()

        ip_raw = data.get("ip", "unknown")
        ip = ip_raw.split(":")[0] if ":" in ip_raw else ip_raw

        tls = data.get("tls", {})
        http_data = data.get("http", {})
        tcp = data.get("tcp", {})

        result = {
            "ip": ip,
            "ja4": tls.get("ja4", "N/A"),
            "ja4h": http_data.get("ja4h", "N/A"),
            "ja4t": tcp.get("ja4t", "N/A"),
            "ja4x": tls.get("ja4x", "N/A"),
            "tls_version": tls.get("version", "N/A"),
            "cipher_suite": tls.get("cipher_suite", "N/A"),
            "user_agent": data.get("user_agent", "N/A"),
            "valid": True,
            "issues": [],
        }

        if not result["ja4"].startswith(CHROME_JA4_PREFIX):
            result["issues"].append(f"JA4 doesn't match Chrome pattern (got {result['ja4'][:10]})")

        if "HeadlessChrome" in result["user_agent"]:
            result["issues"].append("User-Agent contains 'HeadlessChrome' — detectable")

        if result["issues"]:
            result["valid"] = False

        return result

    except requests.RequestException as e:
        return {
            "ip": "error",
            "ja4": "error",
            "valid": False,
            "issues": [f"Proxy connection failed: {e}"],
        }
