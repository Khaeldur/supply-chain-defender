"""Policy loader — merges default policy with optional user overrides."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BlockedPackage:
    name: str
    reason: str
    versions: list[str] = field(default_factory=list)  # empty = all versions


@dataclass
class CIOptions:
    fail_on_severity: str = "HIGH"
    block_new_postinstall_scripts: bool = True
    require_lockfile: bool = True
    lockfile_frozen: bool = True


@dataclass
class ScanOptions:
    scan_node_modules: bool = True
    scan_lockfiles: bool = True
    scan_package_json: bool = True
    max_depth: int = 10
    follow_symlinks: bool = False


@dataclass
class Policy:
    name: str
    blocked_packages: list[BlockedPackage]
    blocked_scopes: list[str]
    suspicious_name_patterns: list[str]
    ci_options: CIOptions
    scan_options: ScanOptions
    allowlist: list[str]

    def is_blocked(self, name: str, version: str = "") -> BlockedPackage | None:
        for bp in self.blocked_packages:
            if bp.name.lower() == name.lower():
                if not bp.versions or version in bp.versions:
                    return bp
        return None

    def is_allowed(self, name: str) -> bool:
        return name.lower() in [a.lower() for a in self.allowlist]


def load_policy(path: Path | None = None) -> Policy:
    default_path = Path(__file__).parent / "default_policy.json"
    with open(default_path) as f:
        data = json.load(f)

    if path and path.exists():
        with open(path) as f:
            override = json.load(f)
        data = _merge(data, override)

    return _parse(data)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], list) and isinstance(val, list):
            existing = {json.dumps(i, sort_keys=True) if isinstance(i, dict) else i for i in result[key]}
            for item in val:
                k = json.dumps(item, sort_keys=True) if isinstance(item, dict) else item
                if k not in existing:
                    result[key].append(item)
        elif key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _merge(result[key], val)
        else:
            result[key] = val
    return result


def _parse(data: dict[str, Any]) -> Policy:
    ci_raw = data.get("ci_options", {})
    scan_raw = data.get("scan_options", {})
    return Policy(
        name=data.get("name", "custom"),
        blocked_packages=[
            BlockedPackage(
                name=p["name"],
                reason=p.get("reason", ""),
                versions=p.get("versions", []),
            )
            for p in data.get("blocked_packages", [])
        ],
        blocked_scopes=data.get("blocked_scopes", []),
        suspicious_name_patterns=data.get("suspicious_name_patterns", []),
        ci_options=CIOptions(
            fail_on_severity=ci_raw.get("fail_on_severity", "HIGH"),
            block_new_postinstall_scripts=ci_raw.get("block_new_postinstall_scripts", True),
            require_lockfile=ci_raw.get("require_lockfile", True),
            lockfile_frozen=ci_raw.get("lockfile_frozen", True),
        ),
        scan_options=ScanOptions(
            scan_node_modules=scan_raw.get("scan_node_modules", True),
            scan_lockfiles=scan_raw.get("scan_lockfiles", True),
            scan_package_json=scan_raw.get("scan_package_json", True),
            max_depth=scan_raw.get("max_depth", 10),
            follow_symlinks=scan_raw.get("follow_symlinks", False),
        ),
        allowlist=data.get("allowlist", []),
    )
