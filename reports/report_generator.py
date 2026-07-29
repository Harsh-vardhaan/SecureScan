"""Build presentation-ready HTML report data from a saved SecureScan record.

This module is deliberately independent of Flask, SQLite, and the scanner. Its
only input is the dictionary returned by the persistence layer for a saved scan.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Info")

LIMITATIONS = [
    "The assessment is limited to the ports and service information captured by the original scan.",
    "Rule-based findings describe observable exposure or configuration risk and do not confirm exploitability.",
    "Services that were filtered, unavailable, or outside the configured scan scope may not appear in this report.",
    "Results represent a point-in-time assessment and may no longer reflect the target's current state.",
]

DISCLAIMER = (
    "SecureScan is intended for authorized defensive security assessment only. "
    "This report does not certify that the target is secure and should be reviewed "
    "by a qualified security professional in the context of the target environment."
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
    return findings


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


def _recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Return unique, actionable recommendations in finding order."""
    recommendations = []
    seen = set()
    for finding in findings:
        recommendation = finding["recommendation"]
        if recommendation == "N/A" or recommendation in seen:
            continue
        seen.add(recommendation)
        recommendations.append(
            {
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "recommendation": recommendation,
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
    executive_summary = (
        f"The saved assessment of {target} recorded {port_count} open "
        f"{'port' if port_count == 1 else 'ports'} and {finding_count} rule-based "
        f"{'finding' if finding_count == 1 else 'findings'}. "
        f"The overall recorded risk rating is {overall_risk}."
    )

    return {
        "metadata": {
            "report_id": f"SSR-{scan_id:06d}",
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_started_at": _text(saved_scan.get("scan_started_at")),
            "created_at": _text(saved_scan.get("created_at")),
        },
        "target": {
            "name": target,
            "hostname": _text(saved_scan.get("hostname")),
            "resolved_address": _text(saved_scan.get("resolved_address")),
            "host_status": _text(saved_scan.get("host_status"), "unknown"),
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
