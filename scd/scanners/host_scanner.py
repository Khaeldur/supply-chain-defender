"""Scan host for npm supply-chain attack IOCs."""
from __future__ import annotations

import os
import platform
import subprocess
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


class HostScanner:
    """Platform-aware host-level IOC scanning."""

    def __init__(self, ioc_db: IOCDatabase) -> None:
        self.ioc_db = ioc_db
        self.system = platform.system().lower()  # darwin, linux, windows
        self.home = Path.home()

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_npm_cache())
        findings.extend(self._scan_global_installs())
        findings.extend(self._scan_temp_dirs())
        findings.extend(self._scan_npm_logs())
        findings.extend(self._scan_shell_history())
        findings.extend(self._check_env_var_exposure())
        return findings

    def _scan_npm_cache(self) -> list[Finding]:
        findings = []
        cache_dirs = self._get_npm_cache_dirs()
        for cache_dir in cache_dirs:
            if not cache_dir.exists():
                continue
            # Search content-v2 for package tarballs
            content_dir = cache_dir / "_cacache" / "content-v2"
            if not content_dir.exists():
                content_dir = cache_dir
            findings.extend(self._search_dir_for_iocs(content_dir, "npm-cache"))
        return findings

    def _scan_global_installs(self) -> list[Finding]:
        findings = []
        global_dirs = self._get_global_dirs()
        for gdir in global_dirs:
            if not gdir.exists():
                continue
            for item in gdir.iterdir():
                if item.name.startswith("."):
                    continue
                if item.is_dir():
                    name = item.name
                    bad = self.ioc_db.is_known_bad_name(name)
                    if bad:
                        pkg_json = item / "package.json"
                        version = self._read_version(pkg_json)
                        exact_bad = self.ioc_db.is_known_bad(name, version) if version else None
                        severity = Severity.CRITICAL if exact_bad else Severity.HIGH
                        findings.append(Finding(
                            severity=severity,
                            category=FindingCategory.KNOWN_MALICIOUS,
                            exposure_level=ExposureLevel.INSTALLED,
                            package_name=name,
                            version=version or "unknown",
                            description=f"Known malicious package in global installs: {name}@{version or '?'}",
                            evidence=[Evidence(
                                source=str(item),
                                detail="Global npm installation",
                            )],
                            confidence=Confidence.CONFIRMED if exact_bad else Confidence.HIGH,
                            remediation=f"Remove with: npm uninstall -g {name}. Rotate secrets.",
                        ))
        return findings

    def _scan_temp_dirs(self) -> list[Finding]:
        findings = []
        temp_dirs = self._get_temp_dirs()
        for tdir in temp_dirs:
            if not tdir.exists():
                continue
            for artifact in self.ioc_db.all_file_artifacts:
                for match in tdir.glob(artifact.pattern):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category=FindingCategory.HOST_IOC,
                        exposure_level=ExposureLevel.EXECUTED,
                        package_name="",
                        version="",
                        description=f"Malicious file artifact found: {match}. {artifact.context}",
                        evidence=[Evidence(
                            source=str(match),
                            detail=artifact.context,
                        )],
                        confidence=Confidence.HIGH,
                        remediation="Preserve file for forensics. Host is COMPROMISED.",
                    ))
        return findings

    # npm argv verbs that mean a package was actually installed/executed
    _INSTALL_VERBS = frozenset(["install", "i", "add", "ci", "install-test", "it"])

    def _scan_npm_logs(self) -> list[Finding]:
        findings = []
        log_dirs = [
            self.home / ".npm" / "_logs",
            self.home / ".npm",
        ]
        for log_dir in log_dirs:
            if not log_dir.exists():
                continue
            for log_file in log_dir.glob("*.log"):
                try:
                    content = log_file.read_text(errors="replace")
                except OSError:
                    continue

                # Only flag if the log was for an actual install command.
                # npm debug logs contain a line like:
                #   N verbose argv "install" "axios@1.14.1"
                # A lookup like `npm view axios@1.14.1` will also contain the
                # marker string but its argv verb is "view" — not an install.
                is_install_log = any(
                    f'"{verb}"' in content or f"'{verb}'" in content
                    for verb in self._INSTALL_VERBS
                )
                if not is_install_log:
                    continue

                for entry in self.ioc_db.entries:
                    for mp in entry.malicious_packages:
                        for ver in mp.versions:
                            marker = f"{mp.name}@{ver}"
                            if marker in content:
                                findings.append(Finding(
                                    severity=Severity.HIGH,
                                    category=FindingCategory.HOST_IOC,
                                    exposure_level=ExposureLevel.EXECUTED,
                                    package_name=mp.name,
                                    version=ver,
                                    description=f"npm log references {marker} — indicates install was attempted",
                                    evidence=[Evidence(
                                        source=str(log_file),
                                        detail=f"Found '{marker}' in npm log",
                                    )],
                                    confidence=Confidence.HIGH,
                                    remediation="Confirm install occurred. Rotate secrets if so.",
                                ))
        return findings

    def _scan_shell_history(self) -> list[Finding]:
        findings = []
        history_files = [
            self.home / ".bash_history",
            self.home / ".zsh_history",
            self.home / ".local" / "share" / "fish" / "fish_history",
        ]
        network_iocs = self.ioc_db.all_network_iocs
        for hf in history_files:
            if not hf.exists():
                continue
            try:
                content = hf.read_text(errors="replace")
            except OSError:
                continue
            for ioc in network_iocs:
                if ioc.value in content:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.HOST_IOC,
                        exposure_level=ExposureLevel.EXECUTED,
                        package_name="",
                        version="",
                        description=f"Network IOC '{ioc.value}' found in shell history. {ioc.context}",
                        evidence=[Evidence(source=str(hf), detail=f"Contains: {ioc.value}")],
                        confidence=Confidence.MEDIUM,
                        remediation="Investigate context. May indicate active exfiltration.",
                    ))
        return findings

    def _check_env_var_exposure(self) -> list[Finding]:
        findings = []
        targeted = self.ioc_db.all_targeted_env_vars
        exposed = []
        for var in targeted:
            if os.environ.get(var):
                exposed.append(var)
        if exposed:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.CREDENTIAL_RISK,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name="",
                version="",
                description=(
                    f"{len(exposed)} targeted credentials found in environment. "
                    f"If malicious code executed, these may have been exfiltrated."
                ),
                evidence=[Evidence(
                    source="environment",
                    detail=f"Exposed vars: {', '.join(exposed)}",
                )],
                confidence=Confidence.MEDIUM,
                remediation=(
                    "If compromise is confirmed, rotate ALL of these immediately:\n"
                    + "\n".join(f"  - {v}" for v in exposed)
                ),
            ))
        return findings

    def _search_dir_for_iocs(self, directory: Path, label: str) -> list[Finding]:
        """Search npm cache for known-bad package tarballs.

        Searches for the package name as a quoted JSON value (``"name":"foo"`` or
        ``"_id":"foo@version"``) to avoid substring false-positives.  Short names
        like ``rc``, ``coa``, ``colors`` appear as substrings inside many other
        package names, so a bare ``grep rc`` produces massive noise.
        """
        findings = []
        try:
            for entry in self.ioc_db.entries:
                for mp in entry.malicious_packages:
                    name = mp.name
                    # Build patterns that require the name to appear as a discrete
                    # JSON token, not as a substring of another name.
                    # Matches: "name":"coa"  "_id":"coa@1.0.4"  "coa":
                    patterns = [
                        f'"name":"{name}"',
                        f'"_id":"{name}@',
                    ]
                    for pattern in patterns:
                        try:
                            result = subprocess.run(
                                ["grep", "-rl", pattern, str(directory)],
                                capture_output=True, text=True, timeout=30,
                            )
                            if result.returncode == 0 and result.stdout.strip():
                                matches = result.stdout.strip().splitlines()[:5]
                                findings.append(Finding(
                                    severity=Severity.HIGH,
                                    category=FindingCategory.HOST_IOC,
                                    exposure_level=ExposureLevel.INSTALLED,
                                    package_name=name,
                                    version="",
                                    description=f"Package '{name}' found in {label} ({len(matches)} cached files)",
                                    evidence=[
                                        Evidence(source=m, detail=f"Contains '{pattern}'")
                                        for m in matches
                                    ],
                                    confidence=Confidence.MEDIUM,
                                    remediation="Clear npm cache: npm cache clean --force",
                                ))
                                break  # one finding per package, don't double-report
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            pass
        except OSError:
            pass
        return findings

    def _get_npm_cache_dirs(self) -> list[Path]:
        dirs = [self.home / ".npm"]
        # Try to get actual npm cache path
        try:
            result = subprocess.run(
                ["npm", "config", "get", "cache"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                p = Path(result.stdout.strip())
                if p not in dirs:
                    dirs.append(p)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return dirs

    def _get_global_dirs(self) -> list[Path]:
        dirs = []
        if self.system == "darwin":
            dirs.extend([
                Path("/opt/homebrew/lib/node_modules"),
                Path("/usr/local/lib/node_modules"),
                self.home / ".nvm" / "versions",
            ])
        elif self.system == "linux":
            dirs.extend([
                Path("/usr/lib/node_modules"),
                Path("/usr/local/lib/node_modules"),
                self.home / ".nvm" / "versions",
            ])
        elif self.system == "windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                dirs.append(Path(appdata) / "npm" / "node_modules")
        # npm prefix
        try:
            result = subprocess.run(
                ["npm", "root", "-g"], capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                p = Path(result.stdout.strip())
                if p not in dirs:
                    dirs.append(p)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return dirs

    def _get_temp_dirs(self) -> list[Path]:
        import tempfile
        dirs = [Path(tempfile.gettempdir())]
        if self.system == "darwin":
            dirs.extend([
                Path("/tmp"),
                self.home / "Library" / "Caches",
            ])
        elif self.system == "linux":
            dirs.extend([
                Path("/tmp"),
                Path("/var/tmp"),
                self.home / ".cache",
            ])
        elif self.system == "windows":
            temp = os.environ.get("TEMP", "")
            if temp:
                dirs.append(Path(temp))
            localappdata = os.environ.get("LOCALAPPDATA", "")
            if localappdata:
                dirs.append(Path(localappdata) / "Temp")
        return dirs

    @staticmethod
    def _read_version(pkg_json: Path) -> str:
        if not pkg_json.exists():
            return ""
        try:
            with open(pkg_json) as f:
                data = __import__("json").load(f)
            return data.get("version", "")
        except Exception:
            return ""
