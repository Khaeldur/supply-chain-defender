"""Scan GitLab CI configuration for supply chain risks.

Detects:
- Untrusted/unpinned CI images
- Script injection patterns
- Secret exposure risks
- Suspicious include sources
- Dangerous before_script/after_script patterns
"""
from __future__ import annotations

import re
from pathlib import Path

from scd.iocs.known_bad import IOCDatabase
from scd.models import (
    Confidence, EcosystemType, Evidence, ExposureLevel,
    Finding, FindingCategory, Severity,
)
from scd.policies.loader import Policy

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"curl[^|]*\|\s*(ba)?sh", "curl-pipe-bash"),
    (r"wget[^|]*\|\s*(ba)?sh", "wget-pipe-bash"),
    (r"eval\s+\$\(", "eval with command substitution"),
    (r"base64\s+--decode.*\|\s*(ba)?sh", "base64-decode-pipe-shell"),
    (r"python[23]?\s+-c\s+['\"]import\s+(os|subprocess|socket)", "Inline Python shell/socket code"),
    (r"--no-check-certificate", "Disabled SSL certificate verification"),
    (r"npm\s+config\s+set\s+registry\s+http://", "Insecure npm registry override"),
]

CREDENTIAL_EXPOSURE_PATTERNS = [
    (r"echo\s+\$[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|PASSWD)", "Echoing secret variable"),
    (r"printenv\s*(?:\||$)", "printenv may dump all secrets"),
    (r"env\s*(?:\||$)", "env may dump all secrets"),
    (r"set\s*-x", "set -x will trace all commands including secrets"),
]


class GitLabCIScanner:
    """Scan .gitlab-ci.yml for supply chain and secrets risks."""

    CI_FILES = {".gitlab-ci.yml", ".gitlab-ci.yaml"}

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        if not HAS_YAML:
            return []
        findings: list[Finding] = []
        for ci_file in self._find_ci_files():
            findings.extend(self._scan_ci_file(ci_file))
        return findings

    def _find_ci_files(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target] if self.target.name in self.CI_FILES else []
        for name in self.CI_FILES:
            p = self.target / name
            if p.exists():
                results.append(p)
        return results

    def _scan_ci_file(self, path: Path) -> list[Finding]:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            content = path.read_text(errors="replace")
        except Exception:
            return []

        if not isinstance(data, dict):
            return []

        findings = []
        findings.extend(self._check_image(data, path))
        findings.extend(self._check_includes(data, path))
        findings.extend(self._check_scripts(data, content, path))
        findings.extend(self._check_ioc_domains(content, path))
        return findings

    def _check_image(self, data: dict, source: Path) -> list[Finding]:
        findings = []
        # Global image
        global_image = data.get("image")
        if global_image:
            findings.extend(self._eval_image(global_image, source, "global"))
        # Per-job images
        for job_name, job in data.items():
            if not isinstance(job, dict):
                continue
            job_image = job.get("image")
            if job_image:
                findings.extend(self._eval_image(job_image, source, job_name))
        return findings

    def _eval_image(self, image, source: Path, context: str) -> list[Finding]:
        findings = []
        if isinstance(image, dict):
            image = image.get("name", "")
        if not isinstance(image, str) or not image:
            return findings

        tag = image.split(":")[-1] if ":" in image else "latest"

        if tag == "latest":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=image,
                version="latest",
                description=f"GitLab CI job '{context}' uses ':latest' tag: {image}",
                evidence=[Evidence(source=str(source), detail=f"image: {image}")],
                confidence=Confidence.CONFIRMED,
                remediation="Pin CI image to a specific version or digest",
                ecosystem=EcosystemType.GITLAB_CI,
            ))

        if "@sha256:" not in image and tag != "latest":
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=image,
                version=tag,
                description=f"GitLab CI image not digest-pinned in job '{context}': {image}",
                evidence=[Evidence(source=str(source), detail=f"image: {image}")],
                confidence=Confidence.CONFIRMED,
                remediation="Pin with @sha256:<hash> for reproducible builds",
                ecosystem=EcosystemType.GITLAB_CI,
            ))

        for ioc in self.ioc_db.all_network_iocs:
            if ioc.value.lower() in image.lower():
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.KNOWN_MALICIOUS,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name=image,
                    version=tag,
                    description=f"CI image from malicious domain: {image}",
                    evidence=[Evidence(source=str(source), detail=f"image: {image}")],
                    confidence=Confidence.CONFIRMED,
                    remediation="Do not use this image.",
                    ecosystem=EcosystemType.GITLAB_CI,
                ))
        return findings

    def _check_includes(self, data: dict, source: Path) -> list[Finding]:
        findings = []
        includes = data.get("include", [])
        if isinstance(includes, str):
            includes = [includes]
        if isinstance(includes, dict):
            includes = [includes]
        for inc in includes:
            if isinstance(inc, str):
                ref = inc
            elif isinstance(inc, dict):
                ref = inc.get("remote") or inc.get("project") or ""
            else:
                ref = ""
            if ref and ref.startswith("http://"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.SUSPICIOUS_PATTERN,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"GitLab CI includes from HTTP (not HTTPS): {ref}",
                    evidence=[Evidence(source=str(source), detail=f"include: {ref}")],
                    confidence=Confidence.CONFIRMED,
                    remediation="Use HTTPS for all remote includes",
                    ecosystem=EcosystemType.GITLAB_CI,
                ))
            for ioc in self.ioc_db.all_network_iocs:
                if ref and ioc.value in ref:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category=FindingCategory.KNOWN_MALICIOUS,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name="",
                        version="",
                        description=f"CI includes from malicious domain: {ref}",
                        evidence=[Evidence(source=str(source), detail=f"include: {ref}")],
                        confidence=Confidence.CONFIRMED,
                        remediation="Remove this include immediately.",
                        ecosystem=EcosystemType.GITLAB_CI,
                    ))
        return findings

    def _check_scripts(self, data: dict, content: str, source: Path) -> list[Finding]:
        findings = []
        all_scripts = []
        for key in ("before_script", "after_script", "script"):
            val = data.get(key, [])
            if isinstance(val, list):
                all_scripts.extend(val)
        for job_name, job in data.items():
            if not isinstance(job, dict):
                continue
            for key in ("before_script", "after_script", "script"):
                val = job.get(key, [])
                if isinstance(val, list):
                    all_scripts.extend(val)

        for script_line in all_scripts:
            if not isinstance(script_line, str):
                continue
            for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, script_line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.SUSPICIOUS_PATTERN,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name="",
                        version="",
                        description=f"Dangerous CI script pattern: {desc}",
                        evidence=[Evidence(source=str(source), detail=script_line[:200])],
                        confidence=Confidence.HIGH,
                        remediation="Avoid dynamic script execution from remote sources in CI",
                        ecosystem=EcosystemType.GITLAB_CI,
                    ))
            for pattern, desc in CREDENTIAL_EXPOSURE_PATTERNS:
                if re.search(pattern, script_line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.CREDENTIAL_RISK,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name="",
                        version="",
                        description=f"Potential secret exposure in CI script: {desc}",
                        evidence=[Evidence(source=str(source), detail=script_line[:200])],
                        confidence=Confidence.MEDIUM,
                        remediation="Remove commands that print secrets. Use masked variables.",
                        ecosystem=EcosystemType.GITLAB_CI,
                    ))
        return findings

    def _check_ioc_domains(self, content: str, source: Path) -> list[Finding]:
        findings = []
        for ioc in self.ioc_db.all_network_iocs:
            if ioc.value in content:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.KNOWN_MALICIOUS,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Malicious IOC domain in CI config: {ioc.value}. {ioc.context}",
                    evidence=[Evidence(source=str(source), detail=f"Contains: {ioc.value}")],
                    confidence=Confidence.HIGH,
                    remediation="Investigate and remove all references to this domain.",
                    ecosystem=EcosystemType.GITLAB_CI,
                ))
        return findings
