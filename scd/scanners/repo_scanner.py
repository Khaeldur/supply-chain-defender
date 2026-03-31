"""Scan package.json files for known-bad dependencies."""
from __future__ import annotations

import json
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
from scd.policies.loader import Policy


class RepoScanner:
    """Scans package.json files for malicious or suspicious dependencies."""

    def __init__(
        self,
        target: Path,
        ioc_db: IOCDatabase,
        policy: Policy,
        max_depth: int = 10,
    ) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy
        self.max_depth = max_depth

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        pkg_files = self._find_package_jsons()
        for pkg_file in pkg_files:
            findings.extend(self._scan_package_json(pkg_file))
        return findings

    def _find_package_jsons(self) -> list[Path]:
        results = []
        if self.target.is_file() and self.target.name == "package.json":
            return [self.target]

        for pkg in self.target.rglob("package.json"):
            # skip node_modules — handled by node_modules_scanner
            parts = pkg.relative_to(self.target).parts
            if "node_modules" in parts:
                continue
            depth = len(parts)
            if depth <= self.max_depth:
                results.append(pkg)
        return sorted(results)

    def _scan_package_json(self, path: Path) -> list[Finding]:
        findings = []
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return [Finding(
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name="",
                version="",
                description=f"Failed to parse {path}: {e}",
                evidence=[Evidence(source=str(path), detail=str(e))],
                confidence=Confidence.LOW,
                remediation="Check file integrity",
            )]

        dep_sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
        for section in dep_sections:
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, version_spec in deps.items():
                findings.extend(self._check_dependency(name, version_spec, path, section))

        return findings

    def _check_dependency(
        self, name: str, version_spec: str, source: Path, section: str
    ) -> list[Finding]:
        findings = []

        # Check policy allowlist
        if self.policy.is_allowed(name):
            return findings

        # Check exact known-bad (if version is pinned)
        clean_version = version_spec.lstrip("^~>=<")
        bad = self.ioc_db.is_known_bad(name, clean_version)
        if bad:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=clean_version,
                description=f"KNOWN MALICIOUS: {name}@{clean_version} found in {section}. {bad.notes}",
                evidence=[Evidence(
                    source=str(source),
                    detail=f"{section}.{name}: {version_spec}",
                )],
                confidence=Confidence.CONFIRMED,
                remediation=f"Immediately remove {name}@{clean_version}. "
                            f"If npm install was run, treat as COMPROMISED — rotate all secrets.",
            ))
            return findings

        # Check known-bad package name — distinguish "all versions bad" from "some versions bad"
        bad_name = self.ioc_db.is_known_bad_name(name)
        if bad_name:
            # If the IOC lists specific bad versions, check if the range could match
            if bad_name.versions:
                for bad_ver in bad_name.versions:
                    if self._range_could_match(version_spec, bad_ver):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=FindingCategory.KNOWN_MALICIOUS,
                            exposure_level=ExposureLevel.UNKNOWN,
                            package_name=name,
                            version=version_spec,
                            description=f"Version range {version_spec} could resolve to known-bad {bad_ver}. {bad_name.notes}",
                            evidence=[Evidence(
                                source=str(source),
                                detail=f"{section}.{name}: {version_spec} — bad version {bad_ver} may be in range",
                            )],
                            confidence=Confidence.MEDIUM,
                            remediation=f"Check lockfile for actual resolved version of {name}",
                        ))
            else:
                # No specific versions listed = entire package is malicious
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.KNOWN_MALICIOUS,
                    exposure_level=ExposureLevel.LOCKFILE_ONLY,
                    package_name=name,
                    version=version_spec,
                    description=f"Known malicious package: {name}. {bad_name.notes}",
                    evidence=[Evidence(
                        source=str(source),
                        detail=f"{section}.{name}: {version_spec}",
                    )],
                    confidence=Confidence.HIGH,
                    remediation=f"Remove {name} immediately.",
                ))

        # Check policy blocklist
        blocked = self.policy.is_blocked(name, clean_version)
        if blocked:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.POLICY_VIOLATION,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version_spec,
                description=f"Policy blocked: {name}. Reason: {blocked.reason}",
                evidence=[Evidence(source=str(source), detail=f"{section}.{name}: {version_spec}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} per security policy",
            ))

        # Check suspicious patterns
        sus = self.ioc_db.check_suspicious_pattern(name)
        if sus:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=name,
                version=version_spec,
                description=f"Suspicious package name pattern: {name} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"{section}.{name}: {version_spec}")],
                confidence=Confidence.MEDIUM,
                remediation=f"Manually verify {name} is legitimate",
            ))

        return findings

    @staticmethod
    def _range_could_match(spec: str, target_version: str) -> bool:
        """Rough check if a semver range could include the target version."""
        spec = spec.strip()
        if spec == "*" or spec == "latest" or spec == "":
            return True
        if spec.startswith("^"):
            base = spec[1:]
            return _same_major(base, target_version)
        if spec.startswith("~"):
            base = spec[1:]
            return _same_major_minor(base, target_version)
        if spec.startswith(">=") or spec.startswith(">"):
            return True  # conservative — could match
        # exact match
        clean = spec.lstrip("=")
        return clean == target_version


def _parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p.split("-")[0]))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _same_major(base: str, target: str) -> bool:
    b = _parse_version(base)
    t = _parse_version(target)
    return len(b) > 0 and len(t) > 0 and b[0] == t[0]


def _same_major_minor(base: str, target: str) -> bool:
    b = _parse_version(base)
    t = _parse_version(target)
    return len(b) >= 2 and len(t) >= 2 and b[0] == t[0] and b[1] == t[1]
