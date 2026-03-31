"""Scan Python projects for malicious or suspicious dependencies.

Supports: requirements.txt, Pipfile.lock, poetry.lock, pyproject.toml, setup.cfg
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


class PythonScanner:
    """Scan Python dependency files for known-bad packages."""

    MANIFEST_FILES = {
        "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
        "requirements-prod.txt", "dev-requirements.txt", "test-requirements.txt",
        "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
        "poetry.lock",
    }

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in self._find_manifests():
            findings.extend(self._scan_file(manifest))
        return findings

    def _find_manifests(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target] if self.target.name in self.MANIFEST_FILES else []
        for name in self.MANIFEST_FILES:
            for f in self.target.rglob(name):
                parts = f.relative_to(self.target).parts
                # skip venv/site-packages
                if any(p in parts for p in (".venv", "venv", "env", "site-packages", "__pycache__")):
                    continue
                results.append(f)
        return sorted(results)

    def _scan_file(self, path: Path) -> list[Finding]:
        name = path.name
        if name == "Pipfile.lock":
            return list(self._scan_pipfile_lock(path))
        elif name == "poetry.lock":
            return list(self._scan_poetry_lock(path))
        elif name == "pyproject.toml":
            return list(self._scan_pyproject_toml(path))
        elif name == "setup.cfg":
            return list(self._scan_setup_cfg(path))
        else:
            return list(self._scan_requirements_txt(path))

    def _scan_requirements_txt(self, path: Path) -> Iterator[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle -r includes
            if line.startswith("-r "):
                continue
            name, version = _parse_req_line(line)
            if name:
                yield from self._check(name, version, path)

    def _scan_pipfile_lock(self, path: Path) -> Iterator[Finding]:
        import json
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                yield from self._check(name, version, path)

    def _scan_poetry_lock(self, path: Path) -> Iterator[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return
        # poetry.lock is TOML-like; parse [[package]] sections
        current_name = ""
        current_version = ""
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current_name:
                    yield from self._check(current_name, current_version, path)
                current_name = ""
                current_version = ""
            elif line.startswith("name = "):
                current_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current_version = line.split("=", 1)[1].strip().strip('"')
        if current_name:
            yield from self._check(current_name, current_version, path)

    def _scan_pyproject_toml(self, path: Path) -> Iterator[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return
        # Extract dependencies from [project.dependencies] and [tool.poetry.dependencies]
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[project.dependencies]", "[tool.poetry.dependencies]",
                             "[tool.poetry.dev-dependencies]", "[project.optional-dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in stripped and not stripped.startswith("#"):
                # name = ">=1.0"  or  name = {version = "^1.0"}
                parts = stripped.split("=", 1)
                name = parts[0].strip().strip('"')
                version = parts[1].strip().strip('"').strip("'").lstrip("^~>=<").split(",")[0].strip()
                if name and not name.startswith("{"):
                    yield from self._check(name, version, path)

    def _scan_setup_cfg(self, path: Path) -> Iterator[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return
        in_install = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[options]", "[options.extras_require]"):
                in_install = True
                continue
            if stripped.startswith("[") and in_install:
                in_install = False
            if in_install and stripped.startswith("install_requires"):
                continue
            if in_install and stripped and not stripped.startswith("#") and not stripped.startswith("["):
                name, version = _parse_req_line(stripped)
                if name:
                    yield from self._check(name, version, path)

    def _check(self, name: str, version: str, source: Path) -> Iterator[Finding]:
        if self.policy.is_allowed(name):
            return

        # Normalize package name: pip normalizes hyphens/underscores
        norm = name.lower().replace("-", "_")

        bad = self.ioc_db.is_known_bad(name, version) or self.ioc_db.is_known_bad(norm, version)
        if bad:
            yield Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"KNOWN MALICIOUS PyPI package: {name}@{version}. {bad.notes}",
                evidence=[Evidence(source=str(source), detail=f"{name}=={version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} immediately. Rotate any secrets exposed during install.",
                ecosystem=EcosystemType.PYTHON,
            )
            return

        bad_name = self.ioc_db.is_known_bad_name(name) or self.ioc_db.is_known_bad_name(norm)
        if bad_name and not bad_name.versions:
            yield Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"Known malicious PyPI package: {name}. {bad_name.notes}",
                evidence=[Evidence(source=str(source), detail=f"{name}=={version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} immediately.",
                ecosystem=EcosystemType.PYTHON,
            )
            return

        sus = self.ioc_db.check_suspicious_pattern(name)
        if sus:
            yield Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=name,
                version=version,
                description=f"Suspicious PyPI package name: {name} matches '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"{name}=={version}")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {name} on pypi.org",
                ecosystem=EcosystemType.PYTHON,
            )

        blocked = self.policy.is_blocked(name, version)
        if blocked:
            yield Finding(
                severity=Severity.HIGH,
                category=FindingCategory.POLICY_VIOLATION,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=name,
                version=version,
                description=f"Policy blocked: {name}. {blocked.reason}",
                evidence=[Evidence(source=str(source), detail=f"{name}=={version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {name} per policy",
                ecosystem=EcosystemType.PYTHON,
            )


def _parse_req_line(line: str) -> tuple[str, str]:
    """Parse a requirements.txt line into (name, version). Returns ('','') on failure."""
    # Strip extras, environment markers
    line = re.split(r";|#", line)[0].strip()
    if not line:
        return "", ""
    # name==version, name>=version, name~=version, etc.
    match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[=><!~^]+\s*([A-Za-z0-9_\.\-\*]+))?", line)
    if match:
        name = match.group(1)
        version = match.group(2) or ""
        return name, version
    return "", ""
