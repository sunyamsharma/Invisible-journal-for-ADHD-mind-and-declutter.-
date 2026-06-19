# VAPT Orchestrator

Single-URL VAPT (Vulnerability Assessment & Penetration Testing) wrapper.
Give it one target URL; it drives **Invicti** and the **Burp Suite Professional**
REST APIs, then combines both result sets into one Markdown report with
proof-of-concept (request/response/curl) evidence per finding.

This tool does not contain its own vulnerability-detection logic — it
orchestrates Invicti and Burp Suite, which already do that, and aggregates
their output.

## ⚠️ Authorization

Only point this at systems you own or have explicit written authorization
to test (e.g. a signed pentest engagement or your own infrastructure).
Both Invicti and Burp Suite send active scan traffic to the target —
running this against third-party systems without permission is illegal in
most jurisdictions. The CLI requires you to confirm authorization before it
runs.

## Prerequisites

- Python 3.10+
- An **Invicti** (Enterprise or Cloud) license with API access enabled.
  Get your API ID/key and base URL from Settings → API in the Invicti web
  UI. **Invicti has separate Cloud and on-premises Enterprise editions, and
  the exact REST endpoint paths/field names have changed across versions —
  check your tenant's own API docs and adjust `vapt/invicti_scanner.py` if
  it doesn't match** (the scanner is written against the documented
  `POST /scans/new`, `GET /scans/{id}`, `GET /vulnerabilities/list` shape).
- Burp Suite **Professional** running locally with its REST API enabled:
  Settings → Suite → REST API → enable, set a port (default `1337`) and
  generate an API key. (Burp Community Edition does not expose the active
  scan API.)

## Setup

```bash
cd vapt-orchestrator
pip install -r requirements.txt
cp .env.example .env   # fill in Invicti and Burp credentials
```

## Usage

```bash
export $(grep -v '^#' .env | xargs)   # or just pass flags directly
python -m vapt.cli https://your-authorized-target.example.com
```

You'll be asked to confirm authorization unless you pass `-y/--yes`.

Useful flags:

| Flag | Purpose |
|------|---------|
| `--skip-invicti` | Only run the Burp Suite scan |
| `--skip-burp` | Only run Invicti (no Burp API key needed) |
| `--output-dir DIR` | Where `report.md` and `poc/` artifacts are written (default `vapt-report/`) |
| `--timeout SECONDS` | Per-scanner timeout (default 3600s) |
| `--invicti-api-url URL`, `--invicti-api-id ID`, `--invicti-api-key KEY`, `--invicti-profile-id ID` | Invicti API location/credentials/scan profile |
| `--burp-api-url URL`, `--burp-api-key KEY` | Burp REST API location/key |

## Output

```
vapt-report/
├── report.md            # Aggregated findings, sorted by severity
└── poc/
    ├── 001-xss.request.txt
    ├── 001-xss.response.txt
    └── 001-xss.curl.sh
```

Findings that include captured request/response evidence (from either
scanner) get full PoC artifacts: raw HTTP request, raw response, and a
ready-to-run `curl` command.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Limitations

- Burp's active-scan REST API requires Burp Suite **Professional**;
  Community Edition can't be driven this way.
- Invicti's exact API surface depends on your edition/version — verify
  against your tenant's own docs before relying on this in production.
- Burp scans run against whatever scope/login macros are already
  configured in your running Burp instance — this tool doesn't configure
  authentication for you.
- This is an orchestration layer, not a scanning engine: detection
  accuracy and coverage are entirely Invicti's and Burp's.
