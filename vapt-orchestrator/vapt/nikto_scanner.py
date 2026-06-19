import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from .models import Finding


class NiktoNotFoundError(RuntimeError):
    pass


def run_nikto(target_url: str, nikto_path: str = "nikto", timeout: int = 1800) -> list[Finding]:
    if not shutil.which(nikto_path):
        raise NiktoNotFoundError(f"Nikto executable not found on PATH: {nikto_path}")

    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    cmd = [nikto_path, "-h", target_url, "-Format", "xml", "-output", xml_path]
    try:
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True, text=True)
        return parse_nikto_xml(xml_path, target_url)
    finally:
        if os.path.exists(xml_path):
            os.remove(xml_path)


def parse_nikto_xml(xml_path: str, target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for item in root.iter("item"):
        description = (item.findtext("description") or "").strip()
        uri = (item.findtext("uri") or "").strip()
        osvdb = item.get("osvdbid", "")
        if not description:
            continue
        findings.append(
            Finding(
                source="nikto",
                name=f"Nikto finding{f' (OSVDB-{osvdb})' if osvdb else ''}",
                severity="info",
                confidence="reported",
                url=target_url.rstrip("/") + uri if uri else target_url,
                description=description,
            )
        )
    return findings
