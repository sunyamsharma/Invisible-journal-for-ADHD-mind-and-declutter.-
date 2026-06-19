import argparse
import os
import sys

from .burp_scanner import BurpAPIError, BurpScanner
from .nikto_scanner import NiktoNotFoundError, run_nikto
from .poc_capture import save_poc_artifacts
from .report import build_report

DISCLAIMER = (
    "This tool sends active scan traffic (Nikto + Burp Suite) to the target.\n"
    "Only run it against systems you own or have explicit written authorization to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Single-URL VAPT orchestrator: runs Nikto + Burp Suite and produces one PoC report."
    )
    parser.add_argument("url", help="Target URL to scan, e.g. https://example.com")
    parser.add_argument("--output-dir", default="vapt-report", help="Where to write report.md and poc/")
    parser.add_argument("--skip-nikto", action="store_true", help="Don't run Nikto")
    parser.add_argument("--skip-burp", action="store_true", help="Don't run Burp Suite")
    parser.add_argument("--nikto-path", default=os.environ.get("NIKTO_PATH", "nikto"))
    parser.add_argument("--burp-api-url", default=os.environ.get("BURP_API_URL", "http://127.0.0.1:1337"))
    parser.add_argument("--burp-api-key", default=os.environ.get("BURP_API_KEY", ""))
    parser.add_argument("--timeout", type=int, default=1800, help="Per-scanner timeout in seconds")
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

    if not args.skip_nikto:
        print("[*] Running Nikto scan...")
        try:
            findings.extend(run_nikto(args.url, nikto_path=args.nikto_path, timeout=args.timeout))
        except NiktoNotFoundError as e:
            print(f"[!] Skipping Nikto: {e}")
        except Exception as e:
            print(f"[!] Nikto scan failed: {e}")

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
