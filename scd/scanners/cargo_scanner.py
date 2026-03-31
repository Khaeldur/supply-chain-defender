"""Scan Rust/Cargo projects for malicious or suspicious dependencies.

Supports: Cargo.toml, Cargo.lock
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy


class CargoScanner:
    """Scan Cargo files for known-bad crates."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in self._find_manifests():
            if manifest.name == "Cargo.lock":
                findings.extend(self._scan_cargo_lock(manifest))
            else:
                findings.extend(self._scan_cargo_toml(manifest))
        return findings

    def _find_manifests(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target] if self.target.name in ("Cargo.toml", "Cargo.lock") else []
        for name in ("Cargo.lock", "Cargo.toml"):
            for f in self.target.rglob(name):
                parts = f.relative_to(self.target).parts
                if "target" not in parts:  # skip build output
                    results.append(f)
        return sorted(results)

    def _scan_cargo_toml(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[dev-dependencies]",
                             "[build-dependencies]", "[target.dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in stripped and not stripped.startswith("#"):
                name, version = _parse_toml_dep(stripped)
                if name:
                    findings.extend(self._check(name, version, path))
        return findings

    def _scan_cargo_lock(self, path: Path) -> list[Finding]:
        """Cargo.lock uses TOML with [[package]] sections."""
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        current_name = ""
        current_version = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[[package]]":
                if current_name:
                    findings.extend(self._check(current_name, current_version, path))
                current_name = ""
                current_version = ""
            elif stripped.startswith("name = "):
                current_name = stripped.split("=", 1)[1].strip().strip('"')
            elif stripped.startswith("version = "):
                current_version = stripped.split("=", 1)[1].strip().strip('"')
        if current_name:
            findings.extend(self._check(current_name, current_version, path))
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
                description=f"Known malicious crate: {name}@{version}. {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"{name} = \"{version}\"")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} from Cargo.toml. Run cargo update.",
                ecosystem=EcosystemType.CARGO,
            ))
            return findings

        bad_name = self.ioc_db.is_known_bad_name(name)
        if bad_name and not bad_name.versions:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"Known malicious crate: {name}. {bad_name.notes}",
                evidence=[Evidence(source=str(source), detail=f"{name} = \"{version}\"")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} immediately.",
                ecosystem=EcosystemType.CARGO,
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
                description=f"Suspicious crate name: {name} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"{name} = \"{version}\"")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {name} on crates.io",
                ecosystem=EcosystemType.CARGO,
            ))

        return findings


def _parse_toml_dep(line: str) -> tuple[str, str]:
    """Parse Cargo.toml dependency line. Returns (name, version)."""
    # name = "1.0"  or  name = { version = "1.0", features = [...] }
    match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"', line)
    if match:
        return match.group(1), match.group(2).lstrip("^~>=<")
    match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{', line)
    if match:
        name = match.group(1)
        ver_match = re.search(r'version\s*=\s*"([^"]*)"', line)
        version = ver_match.group(1).lstrip("^~>=<") if ver_match else ""
        return name, version
    return "", ""
