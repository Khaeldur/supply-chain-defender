"""Scan Maven and Gradle projects for malicious or suspicious dependencies.

Supports: pom.xml, build.gradle, build.gradle.kts, settings.gradle
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy

# Known malicious/suspicious Maven repos
SUSPICIOUS_MAVEN_REPOS = {
    "http://": "Insecure HTTP Maven repository",
    "jitpack.io": "JitPack — dynamic builds from GitHub, not audited",
}

# Dangerous Gradle patterns
DANGEROUS_GRADLE_PATTERNS = [
    (r"new\s+URL\s*\(['\"]https?://", "Dynamic URL fetching in build script"),
    (r"Runtime\.getRuntime\(\)\.exec", "Runtime exec in build script (RCE risk)"),
    (r"ProcessBuilder", "ProcessBuilder in build script"),
    (r"apply\s+from:\s+['\"]https?://", "Remote script application in Gradle"),
    (r"['\"]\s*http://", "Insecure HTTP dependency repository"),
]


class MavenScanner:
    """Scan Maven pom.xml files for supply chain risks."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for pom in self._find_poms():
            findings.extend(self._scan_pom(pom))
        for gradle in self._find_gradle_files():
            findings.extend(self._scan_gradle(gradle))
        return findings

    def _find_poms(self) -> list[Path]:
        if self.target.is_file() and self.target.name == "pom.xml":
            return [self.target]
        results = []
        for f in self.target.rglob("pom.xml"):
            parts = f.relative_to(self.target).parts
            if "target" not in parts and ".m2" not in parts:
                results.append(f)
        return sorted(results)

    def _find_gradle_files(self) -> list[Path]:
        results = []
        for pattern in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
            for f in self.target.rglob(pattern):
                parts = f.relative_to(self.target).parts
                if "build" not in parts and ".gradle" not in parts:
                    results.append(f)
        return sorted(results)

    def _scan_pom(self, path: Path) -> list[Finding]:
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return []
        root = tree.getroot()
        # Strip XML namespace
        for elem in root.iter():
            elem.tag = re.sub(r"\{[^}]+\}", "", elem.tag)

        findings = []

        # Check repositories for HTTP usage
        for repo in root.iter("repository"):
            url_elem = repo.find("url")
            if url_elem is not None and url_elem.text:
                url = url_elem.text.strip()
                if url.startswith("http://"):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name="",
                        version="",
                        description=f"Insecure HTTP Maven repository: {url}",
                        evidence=[Evidence(source=str(path), detail=f"<url>{url}</url>")],
                        confidence=Confidence.CONFIRMED,
                        remediation="Replace HTTP with HTTPS for all Maven repositories",
                        ecosystem=EcosystemType.MAVEN,
                    ))

        # Check dependencies
        for dep in root.iter("dependency"):
            group_id = _pom_text(dep, "groupId")
            artifact_id = _pom_text(dep, "artifactId")
            version = _pom_text(dep, "version")

            if not group_id or not artifact_id:
                continue

            # Maven uses groupId:artifactId as package identifier
            full_name = f"{group_id}:{artifact_id}"
            findings.extend(self._check(full_name, artifact_id, version, path))

        return findings

    def _scan_gradle(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []

        # Dangerous patterns
        for pattern, desc in DANGEROUS_GRADLE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.SUSPICIOUS_PATTERN,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Dangerous Gradle pattern: {desc} (line {line_num})",
                    evidence=[Evidence(
                        source=str(path),
                        detail=content[match.start():match.start()+120],
                        raw=f"line {line_num}",
                    )],
                    confidence=Confidence.HIGH,
                    remediation="Review build script for supply chain risks",
                    ecosystem=EcosystemType.GRADLE,
                ))

        # Extract dependencies: implementation 'group:artifact:version'
        dep_pattern = re.compile(
            r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s+['"]([^'"]+)['"]"""
        )
        for match in dep_pattern.finditer(content):
            dep_str = match.group(1)
            parts = dep_str.split(":")
            if len(parts) >= 2:
                full_name = f"{parts[0]}:{parts[1]}"
                artifact = parts[1]
                version = parts[2] if len(parts) >= 3 else ""
                findings.extend(self._check(full_name, artifact, version, path))

        return findings

    def _check(self, full_name: str, artifact: str, version: str, source: Path) -> list[Finding]:
        findings = []
        bad = self.ioc_db.is_known_bad(full_name, version) or self.ioc_db.is_known_bad(artifact, version)
        if bad:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=full_name,
                version=version,
                description=f"Known malicious Maven artifact: {full_name}:{version}. {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"{full_name}:{version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {full_name} from build file",
                ecosystem=EcosystemType.MAVEN,
            ))
        return findings


def _pom_text(elem: ET.Element, tag: str) -> str:
    child = elem.find(tag)
    return child.text.strip() if child is not None and child.text else ""
