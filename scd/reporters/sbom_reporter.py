"""CycloneDX JSON SBOM reporter.

Generates a CycloneDX 1.5 SBOM from scan results. Includes:
- All scanned components (from findings)
- Vulnerabilities section for CRITICAL/HIGH findings
- Metadata with scan tool info

Spec: https://cyclonedx.org/specification/overview/
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

from scd.models import Finding, FindingCategory, ScanResult, Severity


class SBOMReporter:
    """Output CycloneDX 1.5 JSON SBOM."""

    TOOL_NAME = "supply-chain-defender"
    TOOL_VERSION = "0.1.0"
    TOOL_VENDOR = "Internal Security"

    SEVERITY_MAP = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
    }

    def __init__(self, output: Path | None = None) -> None:
        self.output = output

    def report(self, result: ScanResult) -> str:
        sbom = self._build_sbom(result)
        formatted = json.dumps(sbom, indent=2, default=str)

        if self.output:
            self.output.write_text(formatted)
        else:
            sys.stdout.write(formatted + "\n")

        return formatted

    def _build_sbom(self, result: ScanResult) -> dict:
        components = self._extract_components(result.findings)
        vulnerabilities = self._extract_vulnerabilities(result.findings)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": _epoch_to_iso(result.timestamp),
                "tools": [
                    {
                        "vendor": self.TOOL_VENDOR,
                        "name": self.TOOL_NAME,
                        "version": self.TOOL_VERSION,
                    }
                ],
                "component": {
                    "type": "application",
                    "name": result.target,
                    "version": "unknown",
                },
                "properties": [
                    {"name": "scd:scan_type", "value": result.scan_type.value},
                    {"name": "scd:platform", "value": result.platform},
                    {"name": "scd:total_findings", "value": str(len(result.findings))},
                ],
            },
            "components": components,
            "vulnerabilities": vulnerabilities,
        }

    def _extract_components(self, findings: list[Finding]) -> list[dict]:
        """Deduplicate findings into unique components."""
        seen: set[tuple[str, str]] = set()
        components = []
        for f in findings:
            if not f.package_name:
                continue
            key = (f.package_name, f.version)
            if key in seen:
                continue
            seen.add(key)
            components.append({
                "type": "library",
                "name": f.package_name,
                "version": f.version or "unknown",
                "purl": _make_purl(f.package_name, f.version, f.ecosystem.value),
                "properties": [
                    {"name": "scd:ecosystem", "value": f.ecosystem.value},
                    {"name": "scd:exposure_level", "value": f.exposure_level.value},
                    {"name": "scd:confidence", "value": f.confidence.value},
                ],
            })
        return components

    def _extract_vulnerabilities(self, findings: list[Finding]) -> list[dict]:
        vulns = []
        for i, f in enumerate(findings):
            if f.severity < Severity.MEDIUM:
                continue
            affects = []
            if f.package_name and f.version:
                affects.append({
                    "ref": _make_purl(f.package_name, f.version, f.ecosystem.value),
                    "versions": [{"version": f.version, "status": "affected"}],
                })
            vuln: dict = {
                "id": f"SCD-{i+1:04d}",
                "source": {"name": self.TOOL_NAME},
                "ratings": [
                    {
                        "severity": self.SEVERITY_MAP.get(f.severity, "unknown"),
                        "method": "other",
                    }
                ],
                "description": f.description,
                "recommendation": f.remediation,
                "properties": [
                    {"name": "scd:category", "value": f.category.value},
                    {"name": "scd:confidence", "value": f.confidence.value},
                ],
            }
            if affects:
                vuln["affects"] = affects
            if f.evidence:
                vuln["properties"].append({
                    "name": "scd:evidence",
                    "value": f.evidence[0].detail[:200],
                })
            vulns.append(vuln)
        return vulns


def _make_purl(name: str, version: str, ecosystem: str) -> str:
    """Construct a package URL (PURL) for a component."""
    eco_map = {
        "npm": "npm",
        "python": "pypi",
        "go": "golang",
        "cargo": "cargo",
        "ruby": "gem",
        "nuget": "nuget",
        "maven": "maven",
        "gradle": "maven",
        "docker": "docker",
    }
    purl_type = eco_map.get(ecosystem, "generic")
    safe_name = name.replace("/", "%2F").replace("@", "%40")
    if version:
        return f"pkg:{purl_type}/{safe_name}@{version}"
    return f"pkg:{purl_type}/{safe_name}"


def _epoch_to_iso(ts: float) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
