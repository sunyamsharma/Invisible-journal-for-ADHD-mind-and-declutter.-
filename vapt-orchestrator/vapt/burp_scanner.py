import base64
import re
import time

import requests

from .models import Finding, PoC


class BurpAPIError(RuntimeError):
    pass


class BurpScanner:
    """Drives a Burp Suite Professional scan via its REST API.

    Requires Burp Suite Professional running locally with the REST API
    enabled (Settings > Suite > REST API) and Burp's own active-scan
    permissions configured for the target.
    """

    def __init__(self, api_url: str, api_key: str, timeout: int = 1800, poll_interval: int = 5):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.poll_interval = poll_interval

    def _scan_endpoint(self, task_id: str = "") -> str:
        base = f"{self.api_url}/{self.api_key}/v0.1/scan"
        return f"{base}/{task_id}" if task_id else base

    def start_scan(self, target_url: str) -> str:
        resp = requests.post(
            self._scan_endpoint(),
            json={"urls": [target_url]},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code != 201:
            raise BurpAPIError(f"Failed to start Burp scan: {resp.status_code} {resp.text}")
        location = resp.headers.get("Location", "")
        task_id = location.rstrip("/").split("/")[-1]
        if not task_id:
            raise BurpAPIError("Burp Suite did not return a scan task id")
        return task_id

    def wait_for_scan(self, task_id: str) -> dict:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            resp = requests.get(self._scan_endpoint(task_id), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("scan_status") in ("succeeded", "failed"):
                return data
            time.sleep(self.poll_interval)
        raise BurpAPIError(f"Burp scan {task_id} did not complete within {self.timeout}s")

    def scan(self, target_url: str) -> list[Finding]:
        task_id = self.start_scan(target_url)
        result = self.wait_for_scan(task_id)
        return parse_issues(result)


def parse_issues(result: dict) -> list[Finding]:
    findings: list[Finding] = []
    for event in result.get("issue_events", []):
        issue = event.get("issue", {})
        poc = _extract_poc(issue.get("evidence", []))
        findings.append(
            Finding(
                source="burp",
                name=issue.get("name", "Unknown issue"),
                severity=(issue.get("severity") or "info").lower(),
                confidence=(issue.get("confidence") or "unknown").lower(),
                url=f"{issue.get('origin', '')}{issue.get('path', '')}",
                description=_strip_html(issue.get("description", "")),
                poc=poc,
            )
        )
    return findings


def _extract_poc(evidence: list) -> PoC | None:
    for item in evidence:
        for rr in item.get("request_response", []):
            req_b64 = rr.get("request")
            if not req_b64:
                continue
            resp_b64 = rr.get("response")
            request_raw = base64.b64decode(req_b64).decode("utf-8", errors="replace")
            response_raw = (
                base64.b64decode(resp_b64).decode("utf-8", errors="replace") if resp_b64 else ""
            )
            return PoC(
                request=request_raw,
                response=response_raw,
                curl_command=_request_to_curl(request_raw),
            )
    return None


def _request_to_curl(raw_request: str) -> str:
    lines = raw_request.splitlines()
    if not lines:
        return ""
    parts = lines[0].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("GET", "/")
    host = ""
    header_args = []
    for line in lines[1:]:
        if not line:
            break
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
        else:
            header_args.append(f"-H '{line}'")
    url = f"https://{host}{path}"
    return f"curl -X {method} {' '.join(header_args)} '{url}'".strip()


def _strip_html(text: str) -> str:
    return re.sub("<[^<]+?>", "", text or "").strip()
