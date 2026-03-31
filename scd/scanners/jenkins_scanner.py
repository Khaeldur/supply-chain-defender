"""Scan Jenkinsfiles and Jenkins configuration for supply chain risks.

Uses regex-based analysis (Groovy is a full language; full parsing is impractical).

Detects:
- Suspicious library includes
- curl-pipe-bash patterns
- Credential exposure patterns
- HTTP (not HTTPS) artifact fetching
- Dynamic code execution patterns
- Agent/node configuration risks
"""
from __future__ import annotations

import re
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy

DANGEROUS_PATTERNS = [
    (Severity.CRITICAL, r"curl[^|\"']*\|\s*(ba)?sh", "curl-pipe-bash in Jenkinsfile"),
    (Severity.CRITICAL, r"wget[^|\"']*\|\s*(ba)?sh", "wget-pipe-bash in Jenkinsfile"),
    (Severity.HIGH, r"sh\s*['\"]curl\s+http://", "curl over HTTP"),
    (Severity.HIGH, r"load\s*\(\s*['\"]http", "load() from remote URL"),
    (Severity.HIGH, r"evaluate\s*\(", "evaluate() — dynamic code execution"),
    (Severity.HIGH, r"Groovy\.evaluate", "Groovy.evaluate — dynamic code execution"),
    (Severity.HIGH, r"@Library\s*\(\s*['\"][^'\"]+@(?!main|master|stable)[^'\"]+['\"]", "Library pinned to non-standard ref"),
    (Severity.MEDIUM, r"withCredentials.*echo\s+\$", "Potential credential echo in withCredentials block"),
    (Severity.MEDIUM, r"env\.\w*(TOKEN|KEY|SECRET|PASSWORD)\w*\s*=", "Credential assigned from env in script"),
    (Severity.MEDIUM, r"http://\S+/artifactory", "HTTP Artifactory endpoint (use HTTPS)"),
    (Severity.MEDIUM, r"--no-check-certificate", "Disabled SSL verification"),
    (Severity.LOW, r"agent\s+any", "agent: any — no specific node isolation"),
    (Severity.LOW, r"node\s*\(\s*['\"]master['\"]", "Running on Jenkins master (security risk)"),
]

CREDENTIAL_EXPOSURE = [
    (r"echo\s+\$\{?\w*(TOKEN|KEY|SECRET|PASSWORD)\w*\}?", "Echoing credential variable"),
    (r"printenv\s*\|\s*", "printenv piped — may expose secrets"),
    (r"sh\s+['\"]env['\"]", "Printing all environment variables"),
    (r"set\s*\+x.*\$\{?\w*(TOKEN|KEY|SECRET)\w*", "Credential in traced command"),
]


class JenkinsScanner:
    """Scan Jenkinsfiles for supply chain and security risks."""

    JENKINSFILE_NAMES = {"Jenkinsfile", "Jenkinsfile.groovy"}

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for jf in self._find_jenkinsfiles():
            findings.extend(self._scan_jenkinsfile(jf))
        return findings

    def _find_jenkinsfiles(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target] if self.target.name in self.JENKINSFILE_NAMES else []
        for name in self.JENKINSFILE_NAMES:
            for f in self.target.rglob(name):
                results.append(f)
        # Also check for *.jenkinsfile
        for f in self.target.rglob("*.jenkinsfile"):
            results.append(f)
        return sorted(set(results))

    def _scan_jenkinsfile(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []

        findings = []
        lines = content.splitlines()

        for pattern_severity, pattern, desc in DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=pattern_severity,
                    category=FindingCategory.SUSPICIOUS_PATTERN,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Jenkinsfile risk: {desc} (line {line_num})",
                    evidence=[Evidence(
                        source=str(path),
                        detail=content[match.start():match.start()+150].split("\n")[0],
                        raw=f"line {line_num}",
                    )],
                    confidence=Confidence.HIGH,
                    remediation="Review and remediate this Jenkinsfile pattern",
                    ecosystem=EcosystemType.JENKINS,
                ))

        for pattern, desc in CREDENTIAL_EXPOSURE:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.CREDENTIAL_RISK,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Credential exposure risk in Jenkinsfile: {desc} (line {line_num})",
                    evidence=[Evidence(
                        source=str(path),
                        detail=content[match.start():match.start()+150].split("\n")[0],
                        raw=f"line {line_num}",
                    )],
                    confidence=Confidence.MEDIUM,
                    remediation="Use withCredentials block and avoid echoing secrets",
                    ecosystem=EcosystemType.JENKINS,
                ))

        # Check IOC domains
        for ioc in self.ioc_db.all_network_iocs:
            if ioc.value in content:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.KNOWN_MALICIOUS,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Malicious IOC domain in Jenkinsfile: {ioc.value}. {ioc.context}",
                    evidence=[Evidence(source=str(path), detail=f"Contains: {ioc.value}")],
                    confidence=Confidence.HIGH,
                    remediation="Investigate and remove all references to this domain.",
                    ecosystem=EcosystemType.JENKINS,
                ))

        return findings
