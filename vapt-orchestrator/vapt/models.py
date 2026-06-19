from dataclasses import dataclass
from typing import Optional


@dataclass
class PoC:
    request: str
    response: str = ""
    curl_command: str = ""
    artifact_path: Optional[str] = None


@dataclass
class Finding:
    source: str  # "nikto" or "burp"
    name: str
    severity: str
    confidence: str
    url: str
    description: str
    poc: Optional[PoC] = None
