from vapt.invicti_scanner import _request_to_curl, parse_vulnerabilities

RAW_REQUEST = "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
RAW_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>reflected</html>"


def _sample_vulnerabilities():
    return [
        {
            "Type": "Cross-site Scripting (Reflected)",
            "Severity": "High",
            "Confirmed": True,
            "Url": "https://example.com/search",
            "Description": "The q parameter is reflected without encoding.",
            "HttpRequest": RAW_REQUEST,
            "HttpResponse": RAW_RESPONSE,
        },
        {
            "Type": "Missing security header",
            "Severity": "BestPractice",
            "Confirmed": False,
            "Url": "https://example.com/",
            "Description": "X-Content-Type-Options is missing.",
        },
    ]


def test_parse_vulnerabilities_builds_findings_and_poc():
    findings = parse_vulnerabilities(_sample_vulnerabilities())

    assert len(findings) == 2
    xss = findings[0]
    assert xss.source == "invicti"
    assert xss.severity == "high"
    assert xss.confidence == "confirmed"
    assert xss.url == "https://example.com/search"
    assert xss.poc is not None
    assert "Host: example.com" in xss.poc.request
    assert "reflected" in xss.poc.response

    header_finding = findings[1]
    assert header_finding.severity == "bestpractice"
    assert header_finding.confidence == "unconfirmed"
    assert header_finding.poc is None


def test_request_to_curl_builds_command():
    curl = _request_to_curl(RAW_REQUEST, "https://example.com/search")
    assert curl.startswith("curl -X GET")
    assert "https://example.com/search" in curl
    assert "-H 'User-Agent: test'" in curl
