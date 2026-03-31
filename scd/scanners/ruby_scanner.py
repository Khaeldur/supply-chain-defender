"""Scan Ruby/Bundler projects for malicious or suspicious gems.

Supports: Gemfile, Gemfile.lock
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


class RubyScanner:
    """Scan Ruby Gemfile and Gemfile.lock for known-bad gems."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in self._find_manifests():
            if manifest.name == "Gemfile.lock":
                findings.extend(self._scan_gemfile_lock(manifest))
            else:
                findings.extend(self._scan_gemfile(manifest))
        return findings

    def _find_manifests(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target] if self.target.name in ("Gemfile", "Gemfile.lock") else []
        for name in ("Gemfile.lock", "Gemfile"):
            for f in self.target.rglob(name):
                parts = f.relative_to(self.target).parts
                if "vendor" not in parts and ".bundle" not in parts:
                    results.append(f)
        return sorted(results)

    def _scan_gemfile(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            # gem 'name', '~> 1.0'  or  gem "name"
            match = re.match(r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", stripped)
            if match:
                name = match.group(1)
                version = match.group(2) or ""
                version = version.lstrip("~>= ")
                findings.extend(self._check(name, version, path))
        return findings

    def _scan_gemfile_lock(self, path: Path) -> list[Finding]:
        """Gemfile.lock format: GEM section with specs."""
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        in_specs = False
        for line in content.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and line and not line.startswith(" "):
                in_specs = False
                continue
            if in_specs:
                # "    name (version)"
                match = re.match(r"\s{4}([A-Za-z0-9_\-\.]+)\s+\(([^)]+)\)", line)
                if match:
                    name = match.group(1)
                    version = match.group(2).split("-")[0]  # strip platform suffix
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
                description=f"Known malicious Ruby gem: {name} ({version}). {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"gem '{name}', '{version}'")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} from Gemfile. Run bundle install.",
                ecosystem=EcosystemType.RUBY,
            ))
            return findings

        bad_name = self.ioc_db.is_known_bad_name(name)
        if bad_name and not bad_name.versions:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"Known malicious gem: {name}. {bad_name.notes}",
                evidence=[Evidence(source=str(source), detail=f"gem '{name}'")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} immediately.",
                ecosystem=EcosystemType.RUBY,
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
                description=f"Suspicious gem name: {name} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"gem '{name}'")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {name} on rubygems.org",
                ecosystem=EcosystemType.RUBY,
            ))

        return findings
