from datetime import datetime, timezone

from .models import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def build_report(target_url: str, findings: list[Finding]) -> str:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))
    nikto_count = sum(1 for f in findings_sorted if f.source == "nikto")
    burp_count = sum(1 for f in findings_sorted if f.source == "burp")

    lines = [
        f"# VAPT Report — {target_url}",
        f"\nGenerated: {datetime.now(timezone.utc).isoformat()}",
        f"\nTotal findings: {len(findings_sorted)} (Nikto: {nikto_count}, Burp Suite: {burp_count})",
        "\n## Summary\n",
        "| # | Source | Severity | Name | URL |",
        "|---|--------|----------|------|-----|",
    ]
    for i, f in enumerate(findings_sorted, start=1):
        lines.append(f"| {i} | {f.source} | {f.severity} | {f.name} | {f.url} |")

    lines.append("\n## Detailed Findings\n")
    for i, f in enumerate(findings_sorted, start=1):
        lines.append(f"### {i}. {f.name} ({f.source}, {f.severity})\n")
        lines.append(f"- **URL:** {f.url}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"\n{f.description}\n")
        if f.poc:
            lines.append("**Proof of Concept**\n")
            lines.append("```http\n" + f.poc.request.strip() + "\n```")
            if f.poc.response:
                lines.append("\nResponse (truncated):\n")
                lines.append("```http\n" + f.poc.response.strip()[:2000] + "\n```")
            if f.poc.curl_command:
                lines.append(f"\nReproduce: `{f.poc.curl_command}`\n")
            if f.poc.artifact_path:
                lines.append(f"\nArtifacts saved to: `{f.poc.artifact_path}.*`\n")

    return "\n".join(lines)
