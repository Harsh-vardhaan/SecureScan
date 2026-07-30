"""Build presentation-ready HTML report data from a saved SecureScan record.

This module is deliberately independent of Flask, SQLite, and the scanner. Its
only input is the dictionary returned by the persistence layer for a saved scan.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_LEVELS)}
REPORT_VERSION = "1.0"
REPORT_CLASSIFICATION = "Authorized Security Assessment"

LIMITATIONS = [
    "The assessment is limited to the top 100 TCP ports captured by the original saved scan.",
    "UDP ports and services were not assessed.",
    "Service-version probing was limited and may not identify every product or version.",
    "No authenticated security checks were performed.",
    "No exploitation or intrusive validation was performed.",
    "No external CVE or threat-intelligence correlation was performed.",
    "Results are point-in-time observations and may not reflect the target's current state.",
    "Rule-based findings indicate potential exposure or configuration risk and do not prove exploitability.",
    "Missing findings do not prove complete security or that every vulnerability was identified.",
]

DISCLAIMER = (
    "SecureScan produces transparent rule-based observations from limited saved "
    "network scan data. These findings indicate potential exposure or configuration "
    "risk and do not prove exploitability, compromise, or complete security."
)


def _text(value: Any, default: str = "N/A") -> str:
    """Return a display-safe string without changing the source value."""
    if value is None:
        return default
    rendered = str(value).strip()
    return rendered if rendered else default


def _integer(value: Any, default: int = 0) -> int:
    """Return a non-negative integer for report counters and identifiers."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _normalized_ports(value: Any) -> List[Dict[str, Any]]:
    """Create new, normalized dictionaries for persisted open-port records."""
    if not isinstance(value, list):
        return []

    ports = []
    for item in value:
        if not isinstance(item, dict):
            continue
        ports.append(
            {
                "port": _integer(item.get("port")),
                "protocol": _text(item.get("protocol"), "TCP").upper(),
                "state": _text(item.get("state"), "unknown"),
                "service": _text(item.get("service")),
                "product": _text(item.get("product")),
                "version": _text(item.get("version")),
            }
        )
    return ports


def _normalized_findings(value: Any) -> List[Dict[str, Any]]:
    """Create new, normalized dictionaries for persisted finding records."""
    if not isinstance(value, list):
        return []

    findings = []
    for item in value:
        if not isinstance(item, dict):
            continue
        severity = _text(item.get("severity"), "Info")
        if severity not in SEVERITY_LEVELS:
            severity = "Info"
        findings.append(
            {
                "rule_id": _text(item.get("rule_id"), "UNKNOWN"),
                "title": _text(item.get("title"), "Security observation"),
                "severity": severity,
                "category": _text(item.get("category")),
                "port": _integer(item.get("port")),
                "protocol": _text(item.get("protocol"), "TCP").upper(),
                "service": _text(item.get("service")),
                "evidence": _text(item.get("evidence")),
                "description": _text(item.get("description")),
                "recommendation": _text(item.get("recommendation")),
                "confidence": _text(item.get("confidence")),
            }
        )
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_RANK.get(finding["severity"], len(SEVERITY_LEVELS)),
            finding["port"],
            finding["title"].casefold(),
        ),
    )


def _severity_counts(saved_counts: Any, findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Normalize saved counts, falling back to counts reconstructed from findings."""
    reconstructed = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        reconstructed[finding["severity"]] += 1

    if not isinstance(saved_counts, dict):
        return reconstructed
    return {
        level: _integer(saved_counts.get(level), reconstructed[level])
        for level in SEVERITY_LEVELS
    }


def _recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return stable, prioritized recommendations deduplicated by normalized text."""
    recommendations = []
    seen = set()
    for finding in findings:
        recommendation = finding["recommendation"]
        normalized = " ".join(recommendation.split()).casefold()
        if recommendation == "N/A" or not normalized or normalized in seen:
            continue
        seen.add(normalized)
        display_recommendation = " ".join(recommendation.split())
        recommendations.append(
            {
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "port": finding["port"],
                "protocol": finding["protocol"],
                "recommendation": display_recommendation,
            }
        )
    return recommendations


def build_report_context(saved_scan: Dict[str, Any]) -> Dict[str, Any]:
    """Build a normalized report context without mutating ``saved_scan``.

    Args:
        saved_scan: Nested saved-scan dictionary returned by ``get_scan_by_id``.

    Returns:
        A new dictionary containing metadata, summary, ports, findings,
        recommendations, limitations, and disclaimer text.

    Raises:
        ValueError: If the input is not a saved-scan dictionary.
    """
    if not isinstance(saved_scan, dict):
        raise ValueError("saved_scan must be a dictionary")

    scan_id = _integer(saved_scan.get("id"))
    target = _text(saved_scan.get("target"), "Unknown target")
    ports = _normalized_ports(saved_scan.get("open_ports"))
    findings = _normalized_findings(saved_scan.get("findings"))
    counts = _severity_counts(saved_scan.get("severity_counts"), findings)
    overall_risk = _text(saved_scan.get("overall_risk"), "Info")
    if overall_risk not in SEVERITY_LEVELS:
        overall_risk = "Info"

    finding_count = len(findings)
    port_count = len(ports)
    host_status = _text(saved_scan.get("host_status"), "unknown")
    executive_summary = (
        f"The saved assessment of {target}, with host status recorded as {host_status}, "
        f"identified {port_count} open {'port' if port_count == 1 else 'ports'} within "
        f"the limited top-100 TCP-port scope and {finding_count} rule-based "
        f"{'finding' if finding_count == 1 else 'findings'}. "
    )
    if findings:
        concern = findings[0]
        executive_summary += (
            f"{overall_risk} was the highest recorded severity. "
            f"The highest-priority recorded concern was {concern['title']} on "
            f"{concern['protocol']}/{concern['port']}."
        )
    else:
        executive_summary += (
            f"The overall recorded risk rating was {overall_risk}. "
            "No rule-based security concerns were recorded for this limited "
            "assessment; this does not prove that the target is fully secure."
        )
    executive_summary += (
        " Unnecessary services should be restricted, exposed services reviewed, "
        "and saved finding recommendations applied by an authorized administrator."
    )

    return {
        "metadata": {
            "report_id": f"SSR-{scan_id:06d}",
            "report_version": REPORT_VERSION,
            "classification": REPORT_CLASSIFICATION,
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_started_at": _text(saved_scan.get("scan_started_at")),
            "created_at": _text(saved_scan.get("created_at")),
        },
        "target": {
            "name": target,
            "hostname": _text(saved_scan.get("hostname")),
            "resolved_address": _text(saved_scan.get("resolved_address")),
            "host_status": host_status,
            "scan_duration_seconds": _text(saved_scan.get("scan_duration_seconds"), "0"),
        },
        "executive_summary": executive_summary,
        "overall_risk": overall_risk,
        "severity_counts": counts,
        "open_ports": ports,
        "findings": findings,
        "recommendations": _recommendations(findings),
        "limitations": list(LIMITATIONS),
        "disclaimer": DISCLAIMER,
    }
