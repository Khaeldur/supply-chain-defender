"""Scan for network and filesystem IOCs indicating active compromise."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence,
    Evidence,
    ExposureLevel,
    Finding,
    FindingCategory,
    Severity,
)


class IOCScanner:
    """Search for active compromise indicators beyond package presence."""

    def __init__(self, ioc_db: IOCDatabase) -> None:
        self.ioc_db = ioc_db
        self.home = Path.home()

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_dns_cache())
        findings.extend(self._scan_network_connections())
        findings.extend(self._scan_recent_files())
        findings.extend(self._scan_cron_persistence())
        return findings

    def _scan_dns_cache(self) -> list[Finding]:
        """Check if malicious domains appear in DNS cache (macOS)."""
        findings = []
        try:
            # macOS
            result = subprocess.run(
                ["log", "show", "--predicate", 'process == "mDNSResponder"',
                 "--last", "24h", "--style", "compact"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for ioc in self.ioc_db.all_network_iocs:
                    if ioc.value in result.stdout:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=FindingCategory.HOST_IOC,
                            exposure_level=ExposureLevel.EXECUTED,
                            package_name="",
                            version="",
                            description=f"DNS resolution of malicious domain: {ioc.value}. {ioc.context}",
                            evidence=[Evidence(
                                source="dns_cache",
                                detail=f"Resolved: {ioc.value}",
                            )],
                            confidence=Confidence.HIGH,
                            remediation="CONFIRMED EXFILTRATION ATTEMPT. Rotate all secrets immediately.",
                        ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _scan_network_connections(self) -> list[Finding]:
        """Check active/recent network connections for IOC domains."""
        findings = []
        try:
            # Check /etc/hosts for IOC domains (unlikely but possible persistence)
            hosts_file = Path("/etc/hosts")
            if hosts_file.exists():
                content = hosts_file.read_text()
                for ioc in self.ioc_db.all_network_iocs:
                    if ioc.value in content:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=FindingCategory.HOST_IOC,
                            exposure_level=ExposureLevel.EXECUTED,
                            package_name="",
                            version="",
                            description=f"Malicious domain in /etc/hosts: {ioc.value}",
                            evidence=[Evidence(source="/etc/hosts", detail=ioc.value)],
                            confidence=Confidence.HIGH,
                            remediation="Remove entry. Investigate how it was added.",
                        ))

            # Check for active connections
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for ioc in self.ioc_db.all_network_iocs:
                    if ioc.value in result.stdout:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=FindingCategory.HOST_IOC,
                            exposure_level=ExposureLevel.EXECUTED,
                            package_name="",
                            version="",
                            description=f"Active connection to malicious endpoint: {ioc.value}",
                            evidence=[Evidence(source="lsof", detail=ioc.value)],
                            confidence=Confidence.HIGH,
                            remediation="Kill process immediately. Isolate host from network.",
                        ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _scan_recent_files(self) -> list[Finding]:
        """Look for recently created suspicious files in common locations."""
        findings = []
        import tempfile
        scan_dirs = [
            Path(tempfile.gettempdir()),
            self.home / ".config",
            self.home / ".local" / "share",
        ]

        for artifact in self.ioc_db.all_file_artifacts:
            for scan_dir in scan_dirs:
                if not scan_dir.exists():
                    continue
                for match in scan_dir.glob(artifact.pattern):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category=FindingCategory.HOST_IOC,
                        exposure_level=ExposureLevel.EXECUTED,
                        package_name="",
                        version="",
                        description=f"Malicious artifact: {match}. {artifact.context}",
                        evidence=[Evidence(
                            source=str(match),
                            detail=f"Size: {match.stat().st_size if match.exists() else '?'} bytes",
                        )],
                        confidence=Confidence.HIGH,
                        remediation="Preserve for forensics. Do not delete yet.",
                    ))
        return findings

    def _scan_cron_persistence(self) -> list[Finding]:
        """Check for persistence mechanisms planted by malicious packages."""
        findings = []
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                for ioc in self.ioc_db.all_network_iocs:
                    if ioc.value in result.stdout:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=FindingCategory.HOST_IOC,
                            exposure_level=ExposureLevel.EXECUTED,
                            package_name="",
                            version="",
                            description=f"Malicious cron entry referencing {ioc.value}",
                            evidence=[Evidence(source="crontab", detail=ioc.value)],
                            confidence=Confidence.HIGH,
                            remediation="Remove cron entry. Investigate full persistence chain.",
                        ))
                # Also check for suspicious node/npm invocations
                for line in result.stdout.splitlines():
                    if any(x in line.lower() for x in ["node ", "npm ", "npx ", "crypto"]):
                        if not line.strip().startswith("#"):
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                category=FindingCategory.SUSPICIOUS_PATTERN,
                                exposure_level=ExposureLevel.UNKNOWN,
                                package_name="",
                                version="",
                                description=f"Suspicious cron entry with node/npm: {line.strip()[:100]}",
                                evidence=[Evidence(source="crontab", detail=line.strip()[:200])],
                                confidence=Confidence.LOW,
                                remediation="Verify this cron job is legitimate.",
                            ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings
