"""Scan Go modules for malicious or suspicious dependencies.

Supports: go.mod, go.sum
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


class GoScanner:
    """Scan Go module files for known-bad dependencies."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for go_mod in self._find_go_mods():
            findings.extend(self._scan_go_mod(go_mod))
            go_sum = go_mod.parent / "go.sum"
            if go_sum.exists():
                findings.extend(self._scan_go_sum(go_sum))
        return findings

    def _find_go_mods(self) -> list[Path]:
        if self.target.is_file() and self.target.name == "go.mod":
            return [self.target]
        results = []
        for f in self.target.rglob("go.mod"):
            parts = f.relative_to(self.target).parts
            if "vendor" not in parts:
                results.append(f)
        return sorted(results)

    def _scan_go_mod(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "require (":
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue
            if stripped.startswith("require ") and not stripped.endswith("("):
                # single-line: require module/path v1.2.3
                parts = stripped.split()
                if len(parts) >= 3:
                    findings.extend(self._check(parts[1], parts[2], path))
            elif in_require and stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2:
                    findings.extend(self._check(parts[0], parts[1], path))
        return findings

    def _scan_go_sum(self, path: Path) -> list[Finding]:
        """go.sum has format: module version hash"""
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        seen: set[tuple[str, str]] = set()
        for line in content.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            module = parts[0]
            version = parts[1].split("/")[0]  # strip /go.mod suffix
            key = (module, version)
            if key not in seen:
                seen.add(key)
                findings.extend(self._check(module, version, path))
        return findings

    def _check(self, module: str, version: str, source: Path) -> list[Finding]:
        findings = []
        # Go modules use full path like github.com/foo/bar
        # Check both full path and just the last segment
        short_name = module.split("/")[-1]

        bad = self.ioc_db.is_known_bad(module, version) or self.ioc_db.is_known_bad(short_name, version)
        if bad:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=module,
                version=version,
                description=f"Known malicious Go module: {module}@{version}. {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"{module} {version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {module} from go.mod. Run go mod tidy.",
                ecosystem=EcosystemType.GO,
            ))
            return findings

        sus = self.ioc_db.check_suspicious_pattern(short_name)
        if sus:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=module,
                version=version,
                description=f"Suspicious Go module name: {module} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"{module} {version}")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {module} on pkg.go.dev",
                ecosystem=EcosystemType.GO,
            ))

        # Go-specific: check for replaced modules (could hide malicious substitutions)
        return findings
