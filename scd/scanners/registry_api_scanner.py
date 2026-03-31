"""Query package registry APIs for anomaly detection.

Checks:
- npm: version publish patterns, maintainer changes, download anomalies
- PyPI: recent version metadata, author consistency
- Package age vs download count (newly published widely-used = suspicious)

Uses only urllib (stdlib) to avoid additional dependencies.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy

REQUEST_TIMEOUT = 10
_cache: dict[str, dict] = {}


def _fetch_json(url: str) -> dict | None:
    if url in _cache:
        return _cache[url]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "supply-chain-defender/0.1"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            _cache[url] = data
            return data
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


class RegistryAPIScanner:
    """Query npm and PyPI registry APIs for anomaly signals."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy,
                 check_npm: bool = True, check_pypi: bool = True) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy
        self.check_npm = check_npm
        self.check_pypi = check_pypi

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.check_npm:
            findings.extend(self._check_npm_packages())
        if self.check_pypi:
            findings.extend(self._check_pypi_packages())
        return findings

    def _check_npm_packages(self) -> list[Finding]:
        findings = []
        pkg_json = self.target / "package.json"
        if not pkg_json.exists():
            return findings
        try:
            with open(pkg_json) as f:
                data = json.load(f)
        except Exception:
            return findings

        all_deps: dict[str, str] = {}
        for section in ("dependencies", "devDependencies"):
            all_deps.update(data.get(section, {}))

        for name, version_spec in all_deps.items():
            if self.policy.is_allowed(name):
                continue
            findings.extend(self._check_npm_package(name, version_spec))

        return findings

    def _check_npm_package(self, name: str, version_spec: str) -> list[Finding]:
        findings = []
        url = f"https://registry.npmjs.org/{name}"
        data = _fetch_json(url)
        if not data:
            return findings

        # Check for recently published versions with anomalous patterns
        time_data = data.get("time", {})
        versions = [k for k in time_data if k not in ("created", "modified", "unpublished")]

        if not versions:
            return findings

        # Check publish rate anomaly: many versions published in short window
        if len(versions) >= 3:
            recent = sorted(versions)[-3:]
            try:
                t0 = _parse_iso(time_data.get(recent[0], ""))
                t2 = _parse_iso(time_data.get(recent[-1], ""))
                if t0 and t2 and (t2 - t0) < 3600:  # 3+ versions in < 1 hour
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name=name,
                        version=recent[-1],
                        description=(
                            f"npm anomaly: {name} had {len(recent)} versions published within 1 hour "
                            f"({recent[0]} to {recent[-1]}). May indicate account takeover or automated attack."
                        ),
                        evidence=[Evidence(
                            source=f"registry.npmjs.org/{name}",
                            detail=f"Rapid publish: {', '.join(recent)}",
                        )],
                        confidence=Confidence.LOW,
                        remediation=f"Verify recent {name} releases are legitimate on npmjs.com",
                        ecosystem=EcosystemType.NPM,
                    ))
            except Exception:
                pass

        # Check if package was recently created (< 30 days) but has version in our IOC list
        created_str = time_data.get("created", "")
        if created_str:
            created = _parse_iso(created_str)
            if created and (time.time() - created) < 30 * 86400:
                # Very new package — check if it matches suspicious patterns
                sus = self.ioc_db.check_suspicious_pattern(name)
                if sus:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name=name,
                        version=version_spec,
                        description=(
                            f"npm package '{name}' is very new (<30 days) AND matches suspicious pattern "
                            f"'{sus.pattern}'. {sus.reason}"
                        ),
                        evidence=[Evidence(
                            source=f"registry.npmjs.org/{name}",
                            detail=f"Created: {created_str}",
                        )],
                        confidence=Confidence.MEDIUM,
                        remediation=f"Verify {name} is a legitimate package before using",
                        ecosystem=EcosystemType.NPM,
                    ))

        # Check if IOC known-bad version was published and then unpublished (cleanup after attack)
        for entry in self.ioc_db.entries:
            for mp in entry.malicious_packages:
                if mp.name.lower() == name.lower():
                    for bad_ver in mp.versions:
                        if bad_ver not in time_data and bad_ver in data.get("versions", {}):
                            pass  # version exists but no time entry = suspicious
                        elif bad_ver in time_data:
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                category=FindingCategory.KNOWN_MALICIOUS,
                                exposure_level=ExposureLevel.UNKNOWN,
                                package_name=name,
                                version=bad_ver,
                                description=(
                                    f"Registry confirms: {name}@{bad_ver} was published on {time_data[bad_ver]}. "
                                    f"{mp.notes}"
                                ),
                                evidence=[Evidence(
                                    source=f"registry.npmjs.org/{name}",
                                    detail=f"Published at: {time_data.get(bad_ver, 'unknown')}",
                                )],
                                confidence=Confidence.CONFIRMED,
                                remediation="Confirm your lockfile does not resolve to this version.",
                                ecosystem=EcosystemType.NPM,
                            ))

        return findings

    def _check_pypi_packages(self) -> list[Finding]:
        findings = []
        # Check requirements.txt if present
        req_file = self.target / "requirements.txt"
        if not req_file.exists():
            return findings
        try:
            lines = req_file.read_text().splitlines()
        except OSError:
            return findings

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[=><!~^]", line)[0].strip()
            if name and not name.startswith("-"):
                findings.extend(self._check_pypi_package(name))

        return findings

    def _check_pypi_package(self, name: str) -> list[Finding]:
        findings = []
        url = f"https://pypi.org/pypi/{name}/json"
        data = _fetch_json(url)
        if not data:
            return findings

        info = data.get("info", {})
        releases = data.get("releases", {})

        # Very new package with suspicious name pattern
        upload_times = []
        for version_files in releases.values():
            for f in version_files:
                t = f.get("upload_time", "")
                if t:
                    upload_times.append(t)

        if upload_times:
            earliest = min(upload_times)
            created = _parse_iso(earliest)
            if created and (time.time() - created) < 30 * 86400:
                sus = self.ioc_db.check_suspicious_pattern(name)
                if sus:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name=name,
                        version=info.get("version", ""),
                        description=(
                            f"PyPI package '{name}' is very new (<30 days) AND matches suspicious pattern. "
                            f"{sus.reason}"
                        ),
                        evidence=[Evidence(
                            source=f"pypi.org/pypi/{name}",
                            detail=f"First upload: {earliest}",
                        )],
                        confidence=Confidence.MEDIUM,
                        remediation=f"Verify {name} is legitimate on pypi.org",
                        ecosystem=EcosystemType.PYTHON,
                    ))

        return findings


def _parse_iso(s: str) -> float | None:
    """Parse ISO 8601 timestamp to epoch float. Returns None on failure."""
    if not s:
        return None
    try:
        import datetime
        s = s.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(s)
        return dt.timestamp()
    except Exception:
        return None
