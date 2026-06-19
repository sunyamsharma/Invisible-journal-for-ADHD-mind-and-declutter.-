import argparse
import os
import sys

from .burp_scanner import BurpAPIError, BurpScanner
from .invicti_scanner import InvictiAPIError, InvictiScanner
from .poc_capture import save_poc_artifacts
from .report import build_report

DISCLAIMER = (
    "This tool sends active scan traffic (Invicti + Burp Suite) to the target.\n"
    "Only run it against systems you own or have explicit written authorization to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Single-URL VAPT orchestrator: runs Invicti + Burp Suite and produces one PoC report."
    )
    parser.add_argument("url", help="Target URL to scan, e.g. https://example.com")
    parser.add_argument("--output-dir", default="vapt-report", help="Where to write report.md and poc/")
    parser.add_argument("--skip-invicti", action="store_true", help="Don't run Invicti")
    parser.add_argument("--skip-burp", action="store_true", help="Don't run Burp Suite")
    parser.add_argument("--invicti-api-url", default=os.environ.get("INVICTI_API_URL", ""))
    parser.add_argument("--invicti-api-id", default=os.environ.get("INVICTI_API_ID", ""))
    parser.add_argument("--invicti-api-key", default=os.environ.get("INVICTI_API_KEY", ""))
    parser.add_argument("--invicti-profile-id", default=os.environ.get("INVICTI_PROFILE_ID", ""))
    parser.add_argument("--burp-api-url", default=os.environ.get("BURP_API_URL", "http://127.0.0.1:1337"))
    parser.add_argument("--burp-api-key", default=os.environ.get("BURP_API_KEY", ""))
    parser.add_argument("--timeout", type=int, default=3600, help="Per-scanner timeout in seconds")
    parser.add_argument("-y", "--yes", action="store_true", help="Confirm authorization non-interactively")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.yes:
        print(DISCLAIMER)
        answer = input(f"Confirm you are authorized to scan {args.url}? [y/N] ")
        if answer.strip().lower() != "y":
            print("Aborted.")
            return 1

    os.makedirs(args.output_dir, exist_ok=True)
    findings = []

    if not args.skip_invicti:
        if not (args.invicti_api_url and args.invicti_api_id and args.invicti_api_key):
            print("[!] Skipping Invicti: missing API URL/ID/key (set INVICTI_API_URL/_API_ID/_API_KEY)")
        else:
            print("[*] Running Invicti scan (this can take a while)...")
            try:
                scanner = InvictiScanner(
                    args.invicti_api_url,
                    args.invicti_api_id,
                    args.invicti_api_key,
                    profile_id=args.invicti_profile_id or None,
                    timeout=args.timeout,
                )
                findings.extend(scanner.scan(args.url))
            except InvictiAPIError as e:
                print(f"[!] Invicti scan failed: {e}")

    if not args.skip_burp:
        if not args.burp_api_key:
            print("[!] Skipping Burp Suite: no API key (set BURP_API_KEY or pass --burp-api-key)")
        else:
            print("[*] Running Burp Suite scan (this can take a while)...")
            try:
                scanner = BurpScanner(args.burp_api_url, args.burp_api_key, timeout=args.timeout)
                findings.extend(scanner.scan(args.url))
            except BurpAPIError as e:
                print(f"[!] Burp Suite scan failed: {e}")

    print(f"[*] Total findings: {len(findings)}")
    save_poc_artifacts(findings, args.output_dir)

    report_md = build_report(args.url, findings)
    report_path = os.path.join(args.output_dir, "report.md")
    with open(report_path, "w") as f:
        f.write(report_md)
    print(f"[+] Report written to {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
