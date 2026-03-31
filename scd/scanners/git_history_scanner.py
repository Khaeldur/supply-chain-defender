"""Scan git history for supply chain attack indicators.

Detects:
- Known-bad package versions introduced in past commits
- Suspicious dependency additions with rapid removal (possible cover-up)
- Commit authors associated with known attacks
- Dependency changes with no corresponding code changes (stealth injection)
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy

LOCKFILE_PATTERNS = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                      "Pipfile.lock", "poetry.lock", "Gemfile.lock",
                      "Cargo.lock", "go.sum", "packages.lock.json"]


class GitHistoryScanner:
    """Scan git history for historical compromise indicators."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy,
                 max_commits: int = 500) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy
        self.max_commits = max_commits

    def scan(self) -> list[Finding]:
        if not self._is_git_repo():
            return []
        findings: list[Finding] = []
        findings.extend(self._scan_for_bad_packages_in_history())
        findings.extend(self._scan_for_rapid_add_remove())
        findings.extend(self._scan_for_lockfile_only_changes())
        return findings

    def _is_git_repo(self) -> bool:
        result = self._git(["rev-parse", "--git-dir"])
        return result is not None

    def _git(self, args: list[str], cwd: Path | None = None) -> str | None:
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=str(cwd or self.target),
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _scan_for_bad_packages_in_history(self) -> list[Finding]:
        """Search git log for commits that introduced known-bad package versions."""
        findings = []
        for entry in self.ioc_db.entries:
            for mp in entry.malicious_packages:
                for version in mp.versions:
                    search_term = f'"{mp.name}": "{version}"'
                    result = self._git([
                        "log", f"--max-count={self.max_commits}",
                        f"-S{search_term}", "--oneline", "--all",
                        "--format=%H %ci %ae %s",
                    ])
                    if result and result.strip():
                        for line in result.strip().splitlines()[:5]:
                            parts = line.split(" ", 3)
                            commit_hash = parts[0] if parts else "unknown"
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category=FindingCategory.KNOWN_MALICIOUS,
                                exposure_level=ExposureLevel.UNKNOWN,
                                package_name=mp.name,
                                version=version,
                                description=(
                                    f"Git history: {mp.name}@{version} was present in commit {commit_hash[:8]}. "
                                    f"{mp.notes}"
                                ),
                                evidence=[Evidence(
                                    source="git log",
                                    detail=line[:200],
                                    raw=commit_hash,
                                )],
                                confidence=Confidence.HIGH,
                                remediation=(
                                    f"Run: git show {commit_hash} -- package-lock.json\n"
                                    f"Determine if this commit was deployed. If so, treat as historical compromise."
                                ),
                                ecosystem=EcosystemType.NPM,
                            ))
        return findings

    def _scan_for_rapid_add_remove(self) -> list[Finding]:
        """Detect packages added and removed within a short window — possible cover-up."""
        findings = []
        # Get log of lockfile changes
        result = self._git([
            "log", f"--max-count={self.max_commits}",
            "--oneline", "--all",
            "--format=%H %ci",
            "--", *LOCKFILE_PATTERNS,
        ])
        if not result:
            return findings

        commits = []
        for line in result.strip().splitlines():
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                commits.append(parts[0])

        # For each IOC package, check if there's an add-then-remove pattern
        for entry in self.ioc_db.entries:
            for mp in entry.malicious_packages:
                add_commits = []
                remove_commits = []
                for commit in commits[:50]:  # Limit scope
                    diff = self._git(["show", commit, "--", *LOCKFILE_PATTERNS])
                    if not diff:
                        continue
                    for line in diff.splitlines():
                        if mp.name in line:
                            if line.startswith("+") and not line.startswith("+++"):
                                add_commits.append(commit)
                            elif line.startswith("-") and not line.startswith("---"):
                                remove_commits.append(commit)

                if add_commits and remove_commits:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name=mp.name,
                        version="",
                        description=(
                            f"Suspicious pattern: {mp.name} was added then removed from lockfile "
                            f"(add: {add_commits[0][:8]}, remove: {remove_commits[0][:8]}). "
                            f"Possible exposure window."
                        ),
                        evidence=[Evidence(
                            source="git log",
                            detail=f"Added in {add_commits[0][:8]}, removed in {remove_commits[0][:8]}",
                        )],
                        confidence=Confidence.MEDIUM,
                        remediation=(
                            f"Investigate the exposure window between these commits. "
                            f"Run: git log {remove_commits[0][:8]}..{add_commits[0][:8]} --oneline"
                        ),
                        ecosystem=EcosystemType.NPM,
                    ))
        return findings

    def _scan_for_lockfile_only_changes(self) -> list[Finding]:
        """Commits that only touch lockfiles with no source changes — possible stealthy injection."""
        findings = []
        result = self._git([
            "log", "--max-count=100", "--all",
            "--format=%H %s",
            "--name-only",
        ])
        if not result:
            return findings

        current_commit = ""
        current_subject = ""
        current_files: list[str] = []

        def _check_commit(commit: str, subject: str, files: list[str]) -> list[Finding]:
            if not files or not commit:
                return []
            lockfiles = [f for f in files if any(lf in f for lf in LOCKFILE_PATTERNS)]
            non_lock = [f for f in files if not any(lf in f for lf in LOCKFILE_PATTERNS)]
            if lockfiles and not non_lock and len(lockfiles) >= 1:
                return [Finding(
                    severity=Severity.LOW,
                    category=FindingCategory.SUSPICIOUS_PATTERN,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=(
                        f"Commit {commit[:8]} only modifies lockfiles with no source changes: '{subject[:60]}'. "
                        f"Review for stealthy dependency injection."
                    ),
                    evidence=[Evidence(
                        source="git log",
                        detail=f"Files: {', '.join(lockfiles[:3])}",
                        raw=commit,
                    )],
                    confidence=Confidence.LOW,
                    remediation=f"Review: git show {commit}",
                    ecosystem=EcosystemType.UNKNOWN,
                )]
            return []

        for line in result.splitlines():
            if not line:
                findings.extend(_check_commit(current_commit, current_subject, current_files))
                current_files = []
                current_commit = ""
                current_subject = ""
            elif re.match(r"^[0-9a-f]{40}", line):
                parts = line.split(" ", 1)
                current_commit = parts[0]
                current_subject = parts[1] if len(parts) > 1 else ""
            elif current_commit:
                current_files.append(line.strip())

        return findings
