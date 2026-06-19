import base64

from vapt.burp_scanner import _request_to_curl, _strip_html, parse_issues

RAW_REQUEST = "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
RAW_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>reflected</html>"


def _sample_result():
    return {
        "scan_status": "succeeded",
        "issue_events": [
            {
                "issue": {
                    "name": "Cross-site scripting (reflected)",
                    "severity": "High",
                    "confidence": "Certain",
                    "origin": "https://example.com",
                    "path": "/search",
                    "description": "<p>The value of <b>q</b> is reflected.</p>",
                    "evidence": [
                        {
                            "request_response": [
                                {
                                    "request": base64.b64encode(RAW_REQUEST.encode()).decode(),
                                    "response": base64.b64encode(RAW_RESPONSE.encode()).decode(),
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


def test_parse_issues_extracts_finding_and_poc():
    findings = parse_issues(_sample_result())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "burp"
    assert finding.severity == "high"
    assert finding.url == "https://example.com/search"
    assert "reflected" in finding.description.lower()
    assert finding.poc is not None
    assert "Host: example.com" in finding.poc.request
    assert "reflected" in finding.poc.response


def test_strip_html_removes_tags():
    assert _strip_html("<p>The value of <b>q</b> is reflected.</p>") == "The value of q is reflected."


def test_request_to_curl_builds_command():
    curl = _request_to_curl(RAW_REQUEST)
    assert curl.startswith("curl -X GET")
    assert "https://example.com/search" in curl
    assert "-H 'User-Agent: test'" in curl
