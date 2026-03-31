"""Scan .NET/NuGet projects for malicious or suspicious packages.

Supports: *.csproj, *.vbproj, *.fsproj, packages.config, packages.lock.json
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy


class NuGetScanner:
    """Scan .NET project files for known-bad NuGet packages."""

    PROJ_EXTENSIONS = {".csproj", ".vbproj", ".fsproj", ".props", ".targets"}

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for f in self._find_manifests():
            if f.name == "packages.lock.json":
                findings.extend(self._scan_packages_lock(f))
            elif f.name == "packages.config":
                findings.extend(self._scan_packages_config(f))
            elif f.suffix in self.PROJ_EXTENSIONS:
                findings.extend(self._scan_csproj(f))
        return findings

    def _find_manifests(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target]
        patterns = ["packages.lock.json", "packages.config"] + [f"*{ext}" for ext in self.PROJ_EXTENSIONS]
        for pat in patterns:
            for f in self.target.rglob(pat):
                parts = f.relative_to(self.target).parts
                if not any(p in parts for p in ("bin", "obj", ".vs", "packages")):
                    results.append(f)
        return sorted(set(results))

    def _scan_csproj(self, path: Path) -> list[Finding]:
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return []
        findings = []
        root = tree.getroot()
        # Strip namespace
        for elem in root.iter():
            elem.tag = re.sub(r"\{[^}]+\}", "", elem.tag)
        for ref in root.iter("PackageReference"):
            name = ref.get("Include", "")
            version = ref.get("Version", "") or (ref.find("Version").text if ref.find("Version") is not None else "")
            if name:
                findings.extend(self._check(name, version or "", path))
        return findings

    def _scan_packages_config(self, path: Path) -> list[Finding]:
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return []
        findings = []
        for pkg in tree.getroot().iter("package"):
            name = pkg.get("id", "")
            version = pkg.get("version", "")
            if name:
                findings.extend(self._check(name, version, path))
        return findings

    def _scan_packages_lock(self, path: Path) -> list[Finding]:
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return []
        findings = []
        for framework, packages in data.get("dependencies", {}).items():
            for name, info in packages.items():
                version = info.get("resolved", "")
                findings.extend(self._check(name, version, path))
        return findings

    def _check(self, name: str, version: str, source: Path) -> list[Finding]:
        findings = []
        if self.policy.is_allowed(name):
            return findings

        bad = self.ioc_db.is_known_bad(name, version)
        if bad:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"Known malicious NuGet package: {name} {version}. {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"PackageReference {name} {version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} from project file. Run dotnet restore.",
                ecosystem=EcosystemType.NUGET,
            ))
            return findings

        sus = self.ioc_db.check_suspicious_pattern(name)
        if sus:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=name,
                version=version,
                description=f"Suspicious NuGet package: {name} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"{name} {version}")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {name} on nuget.org",
                ecosystem=EcosystemType.NUGET,
            ))

        return findings
