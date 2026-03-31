"""Core data models for Supply Chain Defender."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ExposureLevel(enum.Enum):
    UNKNOWN = "unknown"
    LOCKFILE_ONLY = "lockfile_only"
    INSTALLED = "installed"
    EXECUTED = "executed"


class FindingCategory(enum.Enum):
    KNOWN_MALICIOUS = "known_malicious"
    SUSPICIOUS_DEPENDENCY = "suspicious_dependency"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    HOST_IOC = "host_ioc"
    CREDENTIAL_RISK = "credential_risk"
    POLICY_VIOLATION = "policy_violation"


class Confidence(enum.Enum):
    CONFIRMED = "confirmed"       # exact IOC match
    HIGH = "high"                 # strong heuristic signal
    MEDIUM = "medium"             # moderate heuristic signal
    LOW = "low"                   # weak signal, needs human review


class EcosystemType(enum.Enum):
    NPM = "npm"
    PYTHON = "python"
    GO = "go"
    CARGO = "cargo"
    RUBY = "ruby"
    NUGET = "nuget"
    MAVEN = "maven"
    GRADLE = "gradle"
    DOCKER = "docker"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    UNKNOWN = "unknown"


class ScanType(enum.Enum):
    REPO = "repo"
    HOST = "host"
    CI_GUARD = "ci_guard"


@dataclass
class Evidence:
    source: str          # e.g. "package-lock.json", "~/.npm/_cacache"
    detail: str          # what was found
    raw: str = ""        # raw line/content if applicable


@dataclass
class Finding:
    severity: Severity
    category: FindingCategory
    exposure_level: ExposureLevel
    package_name: str
    version: str
    description: str
    evidence: list[Evidence]
    confidence: Confidence
    remediation: str
    ecosystem: EcosystemType = EcosystemType.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.name,
            "category": self.category.value,
            "exposure_level": self.exposure_level.value,
            "ecosystem": self.ecosystem.value,
            "package_name": self.package_name,
            "version": self.version,
            "description": self.description,
            "evidence": [{"source": e.source, "detail": e.detail, "raw": e.raw} for e in self.evidence],
            "confidence": self.confidence.value,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    scan_type: ScanType
    target: str
    findings: list[Finding] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    platform: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def exit_code(self) -> int:
        ms = self.max_severity
        if ms is None:
            return 0
        if ms >= Severity.HIGH:
            return 2
        if ms >= Severity.LOW:
            return 1
        return 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def ecosystems_scanned(self) -> list[str]:
        return sorted({f.ecosystem.value for f in self.findings if f.ecosystem != EcosystemType.UNKNOWN})

    def to_dict(self) -> dict[str, Any]:
        by_eco: dict[str, int] = {}
        for f in self.findings:
            by_eco[f.ecosystem.value] = by_eco.get(f.ecosystem.value, 0) + 1
        return {
            "scan_type": self.scan_type.value,
            "target": self.target,
            "timestamp": self.timestamp,
            "platform": self.platform,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "by_ecosystem": by_eco,
                "exit_code": self.exit_code,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# Exit code constants
EXIT_CLEAN = 0
EXIT_WARNINGS = 1
EXIT_COMPROMISED = 2
EXIT_ERROR = 3
