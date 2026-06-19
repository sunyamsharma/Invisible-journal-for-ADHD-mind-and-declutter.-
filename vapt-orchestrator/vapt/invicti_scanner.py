import time

import requests

from .models import Finding, PoC


class InvictiAPIError(RuntimeError):
    pass


class InvictiScanner:
    """Drives an Invicti (Enterprise/Cloud) scan via its REST API.

    Endpoint paths and field names below follow Invicti's documented
    "start scan" / "scan status" / "vulnerability list" API shape, but
    Invicti has separate Cloud and on-premises Enterprise editions whose
    exact paths and JSON field casing can differ by version. Check
    Settings > API in your own Invicti instance and adjust
    `start_scan`/`_parse_vulnerabilities` if your tenant differs.

    Auth: HTTP Basic, using your Invicti API ID as the username and the
    API key as the password.
    """

    def __init__(
        self,
        api_url: str,
        api_id: str,
        api_key: str,
        profile_id: str | None = None,
        timeout: int = 3600,
        poll_interval: int = 10,
    ):
        self.api_url = api_url.rstrip("/")
        self.auth = (api_id, api_key)
        self.profile_id = profile_id
        self.timeout = timeout
        self.poll_interval = poll_interval

    def start_scan(self, target_url: str) -> str:
        body = {"TargetUrl": target_url, "Name": f"vapt-orchestrator: {target_url}"}
        if self.profile_id:
            body["ProfileId"] = self.profile_id

        resp = requests.post(f"{self.api_url}/scans/new", json=body, auth=self.auth, timeout=30)
        if resp.status_code not in (200, 201):
            raise InvictiAPIError(f"Failed to start Invicti scan: {resp.status_code} {resp.text}")
        data = resp.json()
        scan_id = data.get("Id") or data.get("id")
        if not scan_id:
            raise InvictiAPIError(f"Invicti did not return a scan id: {data}")
        return scan_id

    def wait_for_scan(self, scan_id: str) -> dict:
        deadline = time.time() + self.timeout
        terminal_states = {"completed", "failed", "cancelled", "failedtostart"}
        while time.time() < deadline:
            resp = requests.get(f"{self.api_url}/scans/{scan_id}", auth=self.auth, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            status = str(data.get("Status") or data.get("status") or "").lower()
            if status in terminal_states:
                return data
            time.sleep(self.poll_interval)
        raise InvictiAPIError(f"Invicti scan {scan_id} did not complete within {self.timeout}s")

    def get_vulnerabilities(self, scan_id: str) -> list[dict]:
        resp = requests.get(
            f"{self.api_url}/vulnerabilities/list",
            params={"scanId": scan_id},
            auth=self.auth,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("Vulnerabilities", data.get("List", []))

    def scan(self, target_url: str) -> list[Finding]:
        scan_id = self.start_scan(target_url)
        result = self.wait_for_scan(scan_id)
        status = str(result.get("Status") or result.get("status") or "").lower()
        if status != "completed":
            raise InvictiAPIError(f"Invicti scan {scan_id} ended with status: {status}")
        vulnerabilities = self.get_vulnerabilities(scan_id)
        return parse_vulnerabilities(vulnerabilities)


def parse_vulnerabilities(vulnerabilities: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vulnerabilities:
        poc = _extract_poc(vuln)
        findings.append(
            Finding(
                source="invicti",
                name=vuln.get("Type") or vuln.get("Name") or vuln.get("name") or "Unknown issue",
                severity=str(vuln.get("Severity") or vuln.get("severity") or "info").lower(),
                confidence="confirmed" if vuln.get("Confirmed") else "unconfirmed",
                url=vuln.get("Url") or vuln.get("url") or "",
                description=vuln.get("Description") or vuln.get("description") or "",
                poc=poc,
            )
        )
    return findings


def _extract_poc(vuln: dict) -> PoC | None:
    request_raw = vuln.get("HttpRequest") or vuln.get("RawRequest") or vuln.get("httpRequest")
    if not request_raw:
        return None
    response_raw = vuln.get("HttpResponse") or vuln.get("RawResponse") or vuln.get("httpResponse") or ""
    return PoC(
        request=request_raw,
        response=response_raw,
        curl_command=_request_to_curl(request_raw, vuln.get("Url") or vuln.get("url") or ""),
    )


def _request_to_curl(raw_request: str, url: str) -> str:
    lines = raw_request.splitlines()
    if not lines:
        return ""
    parts = lines[0].split(" ")
    method = parts[0] if parts else "GET"
    header_args = [f"-H '{line}'" for line in lines[1:] if line and not line.lower().startswith("host:")]
    return f"curl -X {method} {' '.join(header_args)} '{url}'".strip()
