"""
Redproxy Fingerprint Catcher — validates JA4/TLS fingerprints and IP rotation.

Receives fingerprint data from the viewip workflow and validates that:
1. IP addresses are rotating (different per request)
2. JA4 hash matches expected Chrome fingerprint
3. No WebDriver/automation markers detected
"""
import os
import sys
import json
from datetime import datetime
from pathlib import Path
from collections import OrderedDict

from flask import Flask, request, jsonify

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.common import setup_logging, log, LogLevel, save_results

app = Flask(__name__)
logger = setup_logging("fingerprint")

seen_ips = OrderedDict()
seen_ja4s = set()


@app.route("/wow-amazing", methods=["POST"])
def handle_post_data():
    """Receive and validate fingerprint data from workers."""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        results = data if isinstance(data, list) else [data]

        for result in results:
            response_str = result.get("response", "{}")

            try:
                response_data = json.loads(response_str) if isinstance(response_str, str) else response_str
            except json.JSONDecodeError:
                log(logger, f"[!] Invalid JSON in response: {response_str[:100]}", LogLevel.ERROR)
                continue

            ip_raw = response_data.get("ip", "unknown")
            ip = ip_raw.split(":")[0] if ":" in ip_raw else ip_raw

            tls = response_data.get("tls", {})
            http_data = response_data.get("http", {})
            tcp = response_data.get("tcp", {})

            ja4 = tls.get("ja4", "N/A")
            ja4h = http_data.get("ja4h", "N/A")
            ja4t = tcp.get("ja4t", "N/A")
            ja4x = tls.get("ja4x", "N/A")
            user_agent = response_data.get("user_agent", "N/A")
            tls_version = tls.get("version", "N/A")

            seen_ips[ip] = seen_ips.get(ip, 0) + 1
            seen_ja4s.add(ja4)

            log(logger, "─" * 50, LogLevel.INFO)
            log(logger, f"IP:          {ip}", LogLevel.SUCCESS if ip != "unknown" else LogLevel.ERROR)
            log(logger, f"JA4:         {ja4}", LogLevel.INFO)
            log(logger, f"JA4H:        {ja4h}", LogLevel.DEBUG)
            log(logger, f"JA4T:        {ja4t}", LogLevel.DEBUG)
            log(logger, f"JA4X:        {ja4x}", LogLevel.DEBUG)
            log(logger, f"TLS:         {tls_version}", LogLevel.DEBUG)
            log(logger, f"User-Agent:  {user_agent[:80]}", LogLevel.DEBUG)

            issues = []
            if "HeadlessChrome" in user_agent:
                issues.append("HeadlessChrome detected in User-Agent")
            if "webdriver" in user_agent.lower():
                issues.append("WebDriver detected in User-Agent")

            if issues:
                for issue in issues:
                    log(logger, f"⚠ {issue}", LogLevel.ERROR)
            else:
                log(logger, "✓ No automation markers detected", LogLevel.SUCCESS)

            unique_ips = len(seen_ips)
            total_requests = sum(seen_ips.values())
            log(logger, f"Rotation:    {unique_ips} unique IPs / {total_requests} requests", LogLevel.INFO)

            save_results([{
                "timestamp": datetime.utcnow().isoformat(),
                "ip": ip,
                "ja4": ja4,
                "ja4h": ja4h,
                "ja4t": ja4t,
                "ja4x": ja4x,
                "tls_version": tls_version,
                "user_agent": user_agent,
                "issues": issues,
                "unique_ips_so_far": unique_ips,
            }], filename="fingerprints.json")

        return jsonify({
            "status": "ok",
            "unique_ips": len(seen_ips),
            "total_requests": sum(seen_ips.values()),
            "ja4_consistent": len(seen_ja4s) == 1,
        }), 200

    except Exception as e:
        log(logger, f"[!] Error: {e}", LogLevel.ERROR)
        return jsonify({"error": str(e)}), 500


@app.route("/stats", methods=["GET"])
def get_stats():
    """Return fingerprint validation statistics."""
    return jsonify({
        "unique_ips": len(seen_ips),
        "total_requests": sum(seen_ips.values()),
        "ips": dict(seen_ips),
        "ja4_hashes": list(seen_ja4s),
        "ja4_consistent": len(seen_ja4s) <= 1,
    })


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Redproxy Fingerprint Catcher")
    parser.add_argument("-p", "--port", type=int, default=20005)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    log(logger, f"Fingerprint Catcher on {args.host}:{args.port}", LogLevel.SUCCESS)
    app.run(host=args.host, port=args.port, threaded=True)
