# VAPT Orchestrator

Single-URL VAPT (Vulnerability Assessment & Penetration Testing) wrapper.
Give it one target URL; it drives **Nikto** and the **Burp Suite Professional**
REST API, then combines both result sets into one Markdown report with
proof-of-concept (request/response/curl) evidence per finding.

This tool does not contain its own vulnerability-detection logic — it
orchestrates Nikto and Burp Suite, which already do that, and aggregates
their output.

## ⚠️ Authorization

Only point this at systems you own or have explicit written authorization
to test (e.g. a signed pentest engagement or your own infrastructure).
Both Nikto and Burp Suite send active scan traffic to the target — running
this against third-party systems without permission is illegal in most
jurisdictions. The CLI requires you to confirm authorization before it runs.

## Prerequisites

- Python 3.10+
- [Nikto](https://github.com/sullo/nikto) installed and on `PATH` (`apt install nikto`, `brew install nikto`, or run from source).
- Burp Suite **Professional** running locally with its REST API enabled:
  Settings → Suite → REST API → enable, set a port (default `1337`) and
  generate an API key. (Burp Community Edition does not expose the active
  scan API.)

## Setup

```bash
cd vapt-orchestrator
pip install -r requirements.txt
cp .env.example .env   # fill in BURP_API_KEY, adjust paths
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
| `--skip-nikto` | Only run the Burp Suite scan |
| `--skip-burp` | Only run Nikto (no Burp API key needed) |
| `--output-dir DIR` | Where `report.md` and `poc/` artifacts are written (default `vapt-report/`) |
| `--timeout SECONDS` | Per-scanner timeout (default 1800s) |
| `--burp-api-url URL`, `--burp-api-key KEY` | Override Burp REST API location/key |

## Output

```
vapt-report/
├── report.md            # Aggregated findings, sorted by severity
└── poc/
    ├── 001-xss.request.txt
    ├── 001-xss.response.txt
    └── 001-xss.curl.sh
```

Burp issues that include `request_response` evidence get full PoC
artifacts (raw HTTP request, raw response, ready-to-run `curl` command).
Nikto findings are informational signature matches and are listed without
a captured request/response.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Limitations

- Burp's active-scan REST API requires Burp Suite **Professional**;
  Community Edition can't be driven this way.
- Burp scans run against whatever scope/login macros are already
  configured in your running Burp instance — this tool doesn't configure
  authentication for you.
- This is an orchestration layer, not a scanning engine: detection
  accuracy and coverage are entirely Nikto's and Burp's.
