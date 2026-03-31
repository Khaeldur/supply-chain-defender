"""Scan lockfiles for exact resolved versions of known-bad packages."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
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

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class ResolvedDep:
    name: str
    version: str
    integrity: str = ""
    resolved_url: str = ""
    dependencies: list[str] | None = None


class LockfileScanner:
    """Parse and scan lockfiles for known-bad resolved versions."""

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
        lockfiles = self._find_lockfiles()
        for lockfile in lockfiles:
            findings.extend(self._scan_lockfile(lockfile))
        return findings

    def _find_lockfiles(self) -> list[Path]:
        names = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"]
        results = []
        if self.target.is_file() and self.target.name in names:
            return [self.target]
        for name in names:
            for f in self.target.rglob(name):
                parts = f.relative_to(self.target).parts
                if "node_modules" in parts:
                    continue
                if len(parts) <= self.max_depth:
                    results.append(f)
        return sorted(results)

    def _scan_lockfile(self, path: Path) -> list[Finding]:
        deps = self._parse_lockfile(path)
        if deps is None:
            return [Finding(
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name="",
                version="",
                description=f"Failed to parse lockfile: {path}",
                evidence=[Evidence(source=str(path), detail="Parse error")],
                confidence=Confidence.LOW,
                remediation="Verify lockfile integrity",
            )]

        findings = []
        for dep in deps:
            findings.extend(self._check_dep(dep, path))
        return findings

    def _check_dep(self, dep: ResolvedDep, source: Path) -> list[Finding]:
        findings = []

        if self.policy.is_allowed(dep.name):
            return findings

        # Exact known-bad match — this is the critical check
        bad = self.ioc_db.is_known_bad(dep.name, dep.version)
        if bad:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.KNOWN_MALICIOUS,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=dep.name,
                version=dep.version,
                description=f"CONFIRMED MALICIOUS: {dep.name}@{dep.version} resolved in lockfile. {bad.notes}",
                evidence=[Evidence(
                    source=str(source),
                    detail=f"Resolved: {dep.name}@{dep.version}",
                    raw=f"integrity={dep.integrity}" if dep.integrity else "",
                )],
                confidence=Confidence.CONFIRMED,
                remediation=(
                    f"1. Remove {dep.name}@{dep.version} from lockfile immediately.\n"
                    f"2. If 'npm install' was ever run with this lockfile, treat host as COMPROMISED.\n"
                    f"3. Rotate ALL credentials that were in environment variables.\n"
                    f"4. Check CI/CD pipelines — if this lockfile was used in CI, rotate CI secrets."
                ),
            ))

        # Policy blocklist
        blocked = self.policy.is_blocked(dep.name, dep.version)
        if blocked and not bad:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.POLICY_VIOLATION,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=dep.name,
                version=dep.version,
                description=f"Policy blocked: {dep.name}@{dep.version}. {blocked.reason}",
                evidence=[Evidence(source=str(source), detail=f"Resolved: {dep.name}@{dep.version}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Remove {dep.name} per security policy",
            ))

        # Suspicious patterns
        sus = self.ioc_db.check_suspicious_pattern(dep.name)
        if sus and not bad:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.LOCKFILE_ONLY,
                package_name=dep.name,
                version=dep.version,
                description=f"Suspicious name: {dep.name} matches pattern '{sus.pattern}'. {sus.reason}",
                evidence=[Evidence(source=str(source), detail=f"Resolved: {dep.name}@{dep.version}")],
                confidence=Confidence.MEDIUM,
                remediation=f"Verify {dep.name} is legitimate on npmjs.com",
            ))

        return findings

    def _parse_lockfile(self, path: Path) -> list[ResolvedDep] | None:
        name = path.name
        try:
            if name == "package-lock.json" or name == "npm-shrinkwrap.json":
                return self._parse_npm_lockfile(path)
            elif name == "yarn.lock":
                return self._parse_yarn_lock(path)
            elif name == "pnpm-lock.yaml":
                return self._parse_pnpm_lock(path)
        except Exception:
            return None
        return None

    def _parse_npm_lockfile(self, path: Path) -> list[ResolvedDep]:
        with open(path) as f:
            data = json.load(f)

        deps = []
        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2 and "packages" in data:
            # npm v2/v3 format
            for key, info in data.get("packages", {}).items():
                if not key:  # root package
                    continue
                # key is like "node_modules/axios" or "node_modules/foo/node_modules/bar"
                name = key.split("node_modules/")[-1]
                version = info.get("version", "")
                if name and version:
                    deps.append(ResolvedDep(
                        name=name,
                        version=version,
                        integrity=info.get("integrity", ""),
                        resolved_url=info.get("resolved", ""),
                    ))

        if "dependencies" in data:
            # npm v1 format / fallback
            self._extract_npm_v1_deps(data["dependencies"], deps)

        return deps

    def _extract_npm_v1_deps(
        self, deps_dict: dict, result: list[ResolvedDep], seen: set | None = None
    ) -> None:
        if seen is None:
            seen = set()
        for name, info in deps_dict.items():
            version = info.get("version", "")
            key = f"{name}@{version}"
            if key not in seen:
                seen.add(key)
                result.append(ResolvedDep(
                    name=name,
                    version=version,
                    integrity=info.get("integrity", ""),
                    resolved_url=info.get("resolved", ""),
                ))
            # recurse nested
            nested = info.get("dependencies", {})
            if nested:
                self._extract_npm_v1_deps(nested, result, seen)

    def _parse_yarn_lock(self, path: Path) -> list[ResolvedDep]:
        """Parse yarn.lock (classic v1 format — indentation-based)."""
        content = path.read_text()
        deps = []
        current_name = ""
        current_version = ""
        current_integrity = ""
        current_resolved = ""

        for line in content.splitlines():
            if not line or line.startswith("#"):
                continue

            # New entry: "package@version:"
            if not line.startswith(" ") and not line.startswith("\t"):
                # Save previous
                if current_name and current_version:
                    deps.append(ResolvedDep(
                        name=current_name,
                        version=current_version,
                        integrity=current_integrity,
                        resolved_url=current_resolved,
                    ))
                current_version = ""
                current_integrity = ""
                current_resolved = ""
                # Parse: "axios@^1.0.0, axios@^1.14.0":
                entry = line.rstrip(":")
                # Get package name from first specifier
                match = re.match(r'"?(@?[^@"]+)@', entry)
                if match:
                    current_name = match.group(1)
                else:
                    current_name = ""
            else:
                stripped = line.strip()
                if stripped.startswith("version "):
                    current_version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
                elif stripped.startswith("integrity "):
                    current_integrity = stripped.split()[-1]
                elif stripped.startswith("resolved "):
                    current_resolved = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]

        # Last entry
        if current_name and current_version:
            deps.append(ResolvedDep(
                name=current_name,
                version=current_version,
                integrity=current_integrity,
                resolved_url=current_resolved,
            ))

        return deps

    def _parse_pnpm_lock(self, path: Path) -> list[ResolvedDep]:
        """Parse pnpm-lock.yaml."""
        if not HAS_YAML:
            return []
        with open(path) as f:
            data = yaml.safe_load(f)

        deps = []
        packages = data.get("packages", {})
        for key, info in packages.items():
            if not info:
                continue
            # pnpm v9 key format: /@scope/name@version or /name@version
            match = re.match(r"/?(@?[^@]+)@(.+)", key)
            if match:
                name = match.group(1).lstrip("/")
                version = match.group(2)
                deps.append(ResolvedDep(
                    name=name,
                    version=version,
                    integrity=info.get("integrity", "") if isinstance(info, dict) else "",
                    resolved_url=info.get("resolved", "") if isinstance(info, dict) else "",
                ))

        return deps
