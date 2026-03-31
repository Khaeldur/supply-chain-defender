"""IOC database loader and query engine."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MaliciousPackage:
    name: str
    versions: list[str]
    severity: str
    notes: str = ""


@dataclass
class SuspiciousPattern:
    pattern: str
    reason: str
    severity: str
    _compiled: re.Pattern | None = field(default=None, repr=False)

    def matches(self, package_name: str) -> bool:
        if self._compiled is None:
            regex = self.pattern.replace("*", ".*").replace("?", ".")
            self._compiled = re.compile(f"^{regex}$", re.IGNORECASE)
        return bool(self._compiled.match(package_name))


@dataclass
class NetworkIOC:
    type: str  # domain, ip, url
    value: str
    context: str = ""


@dataclass
class FileArtifact:
    pattern: str
    location: str
    context: str = ""


@dataclass
class IOCEntry:
    id: str
    name: str
    description: str
    malicious_packages: list[MaliciousPackage]
    suspicious_patterns: list[SuspiciousPattern]
    network_iocs: list[NetworkIOC]
    targeted_env_vars: list[str]
    file_artifacts: list[FileArtifact]
    postinstall_indicators: list[str]


class IOCDatabase:
    """Loads and queries IOC definitions from JSON files."""

    def __init__(self) -> None:
        self.entries: list[IOCEntry] = []
        self._bad_lookup: dict[tuple[str, str], MaliciousPackage] = {}
        self._bad_names: dict[str, MaliciousPackage] = {}

    def load_directory(self, directory: Path | None = None) -> None:
        if directory is None:
            directory = Path(__file__).parent
        for json_file in sorted(directory.glob("*.json")):
            self.load_file(json_file)

    def load_file(self, path: Path) -> None:
        with open(path) as f:
            data = json.load(f)
        entry = self._parse_entry(data)
        self.entries.append(entry)
        for mp in entry.malicious_packages:
            self._bad_names[mp.name.lower()] = mp
            for ver in mp.versions:
                self._bad_lookup[(mp.name.lower(), ver)] = mp

    def _parse_entry(self, data: dict[str, Any]) -> IOCEntry:
        return IOCEntry(
            id=data.get("id", "unknown"),
            name=data.get("name", ""),
            description=data.get("description", ""),
            malicious_packages=[
                MaliciousPackage(**p) for p in data.get("malicious_packages", [])
            ],
            suspicious_patterns=[
                SuspiciousPattern(
                    pattern=p["pattern"], reason=p["reason"], severity=p["severity"]
                )
                for p in data.get("suspicious_packages", [])
            ],
            network_iocs=[
                NetworkIOC(**n) for n in data.get("network_iocs", [])
            ],
            targeted_env_vars=data.get("targeted_env_vars", []),
            file_artifacts=[
                FileArtifact(**f) for f in data.get("file_artifacts", [])
            ],
            postinstall_indicators=data.get("postinstall_indicators", []),
        )

    def is_known_bad(self, name: str, version: str) -> MaliciousPackage | None:
        return self._bad_lookup.get((name.lower(), version))

    def is_known_bad_name(self, name: str) -> MaliciousPackage | None:
        return self._bad_names.get(name.lower())

    def check_suspicious_pattern(self, name: str) -> SuspiciousPattern | None:
        for entry in self.entries:
            for pat in entry.suspicious_patterns:
                if pat.matches(name):
                    return pat
        return None

    @property
    def all_network_iocs(self) -> list[NetworkIOC]:
        result = []
        for entry in self.entries:
            result.extend(entry.network_iocs)
        return result

    @property
    def all_targeted_env_vars(self) -> list[str]:
        result = []
        for entry in self.entries:
            result.extend(entry.targeted_env_vars)
        return sorted(set(result))

    @property
    def all_file_artifacts(self) -> list[FileArtifact]:
        result = []
        for entry in self.entries:
            result.extend(entry.file_artifacts)
        return result

    @property
    def all_postinstall_indicators(self) -> list[str]:
        result = []
        for entry in self.entries:
            result.extend(entry.postinstall_indicators)
        return result


def get_default_ioc_db() -> IOCDatabase:
    db = IOCDatabase()
    db.load_directory()
    return db
