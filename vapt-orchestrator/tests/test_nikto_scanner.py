import os

from vapt.nikto_scanner import parse_nikto_xml

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "nikto_sample.xml")


def test_parse_nikto_xml_extracts_findings():
    findings = parse_nikto_xml(FIXTURE, "https://example.com")

    assert len(findings) == 2
    assert findings[0].source == "nikto"
    assert findings[0].url == "https://example.com/admin/"
    assert "OSVDB-3092" in findings[0].name
    assert "admin" in findings[0].description.lower()


def test_parse_nikto_xml_handles_missing_osvdb_id():
    findings = parse_nikto_xml(FIXTURE, "https://example.com")

    assert findings[1].name == "Nikto finding"
    assert "x-content-type-options" in findings[1].description.lower()
