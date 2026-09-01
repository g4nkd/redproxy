"""
Redproxy Sprayer — Fingerprint verification mode.
Sends a request through Thermoptic and reports fingerprint data back to catcher.
"""
import os
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.common import load_env_vars
from lib.fingerprint import verify_fingerprint


def main():
    env = load_env_vars(["CATCHERURL", "CATCHERTLS"])

    catcher_url = env["CATCHERURL"]
    use_tls = env["CATCHERTLS"].lower() == "true"
    proxy_url = os.getenv("PROXY_URL", "http://changeme:changeme@127.0.0.1:1234")

    print("[*] Verifying fingerprint through Thermoptic proxy...")
    fp = verify_fingerprint(proxy_url=proxy_url)

    if fp.get("valid"):
        print(f"[+] Fingerprint valid — IP: {fp['ip']}, JA4: {fp['ja4']}")
    else:
        print(f"[!] Fingerprint issues: {', '.join(fp.get('issues', []))}")

    results = [{
        "status_code": 200 if fp.get("ip") != "error" else 500,
        "response": json.dumps({
            "ip": fp.get("ip", "error"),
            "tls": {"ja4": fp.get("ja4", "N/A")},
            "http": {"ja4h": fp.get("ja4h", "N/A")},
            "tcp": {"ja4t": fp.get("ja4t", "N/A")},
            "user_agent": fp.get("user_agent", "N/A"),
        }),
    }]

    try:
        resp = requests.post(catcher_url, json=results, timeout=10, verify=use_tls)
        print(f"[+] Fingerprint sent to catcher (HTTP {resp.status_code})")
    except requests.RequestException as e:
        print(f"[-] Failed to send to catcher: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
