import os
import re

from .models import Finding


def slugify(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-").lower()[:80] or "finding"


def save_poc_artifacts(findings: list[Finding], output_dir: str) -> None:
    """Writes request/response/curl PoC artifacts to <output_dir>/poc/."""
    poc_dir = os.path.join(output_dir, "poc")
    has_poc = any(f.poc for f in findings)
    if not has_poc:
        return
    os.makedirs(poc_dir, exist_ok=True)

    for idx, finding in enumerate(findings, start=1):
        if not finding.poc:
            continue
        base = os.path.join(poc_dir, f"{idx:03d}-{slugify(finding.name)}")
        with open(f"{base}.request.txt", "w") as f:
            f.write(finding.poc.request)
        if finding.poc.response:
            with open(f"{base}.response.txt", "w") as f:
                f.write(finding.poc.response)
        if finding.poc.curl_command:
            with open(f"{base}.curl.sh", "w") as f:
                f.write("#!/bin/sh\n" + finding.poc.curl_command + "\n")
        finding.poc.artifact_path = base


def capture_screenshot(url: str, output_path: str) -> bool:
    """Optional visual PoC. Returns False (no-op) if Playwright isn't installed."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=15000)
            page.screenshot(path=output_path, full_page=True)
            browser.close()
        return True
    except Exception:
        return False
