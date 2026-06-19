from vapt.models import Finding, PoC
from vapt.report import build_report


def test_build_report_sorts_by_severity_and_includes_poc():
    findings = [
        Finding(source="nikto", name="Low item", severity="low", confidence="reported", url="https://x/a", description="d1"),
        Finding(
            source="burp",
            name="XSS",
            severity="high",
            confidence="certain",
            url="https://x/b",
            description="d2",
            poc=PoC(request="GET /b HTTP/1.1", response="HTTP/1.1 200 OK", curl_command="curl https://x/b"),
        ),
    ]

    report = build_report("https://x", findings)

    assert report.index("XSS") < report.index("Low item")
    assert "Proof of Concept" in report
    assert "curl https://x/b" in report
