"""Scan Dockerfiles and docker-compose files for supply chain risks.

Detects:
- Suspicious base images (no digest pinning, latest tag, unknown registries)
- RUN commands installing known-bad packages
- Secrets baked into image layers
- Unsafe curl-pipe-bash patterns
- Missing USER instruction (runs as root)
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

# Trusted base image registries/namespaces
TRUSTED_REGISTRIES = {
    "docker.io", "registry.hub.docker.com", "gcr.io", "ghcr.io",
    "mcr.microsoft.com", "public.ecr.aws", "registry.k8s.io",
}

TRUSTED_BASE_IMAGES = {
    "alpine", "ubuntu", "debian", "centos", "fedora", "node", "python",
    "golang", "rust", "openjdk", "eclipse-temurin", "nginx", "redis",
    "postgres", "mysql", "mongo", "elasticsearch", "httpd",
}

# Patterns that suggest credential exposure in Dockerfiles
SECRET_PATTERNS = [
    (r"(?i)(password|passwd|secret|api_key|apikey|token|private_key)\s*=\s*\S+", "Hardcoded secret in ENV/ARG"),
    (r"ENV\s+\w*(KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*\s*=?\s*\S+", "Secret in ENV instruction"),
    (r"ARG\s+\w*(KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*", "Secret as build ARG (may appear in history)"),
]

DANGEROUS_PATTERNS = [
    (r"curl[^|]*\|\s*(ba)?sh", "curl-pipe-bash: arbitrary remote code execution"),
    (r"wget[^|]*\|\s*(ba)?sh", "wget-pipe-bash: arbitrary remote code execution"),
    (r"curl[^>]*>\s*/usr/(local/)?bin/", "curl downloading to system bin"),
    (r"chmod\s+[0-7]*7[0-7]*\s+\S+\s*&&.*exec", "chmod+exec pattern"),
    (r"--no-check-certificate", "Disabled SSL verification"),
    (r"pip install[^;]*(--extra-index-url|--index-url)[^;]*http://", "Insecure pip index URL (HTTP)"),
    (r"npm install[^;]*--registry[^;]*http://", "Insecure npm registry (HTTP)"),
]


class DockerScanner:
    """Scan Dockerfiles for supply chain risks."""

    def __init__(self, target: Path, ioc_db: IOCDatabase, policy: Policy) -> None:
        self.target = target
        self.ioc_db = ioc_db
        self.policy = policy

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for dockerfile in self._find_dockerfiles():
            findings.extend(self._scan_dockerfile(dockerfile))
        return findings

    def _find_dockerfiles(self) -> list[Path]:
        results = []
        if self.target.is_file():
            return [self.target]
        for f in self.target.rglob("Dockerfile*"):
            results.append(f)
        for f in self.target.rglob("*.dockerfile"):
            results.append(f)
        for f in self.target.rglob("docker-compose*.yml"):
            results.append(f)
        for f in self.target.rglob("docker-compose*.yaml"):
            results.append(f)
        return sorted(set(results))

    def _scan_dockerfile(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []
        findings = []
        lines = content.splitlines()
        has_user_instruction = False
        from_images = []

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            upper = stripped.upper()

            # FROM instruction
            if upper.startswith("FROM "):
                image = stripped[5:].split()[0]  # FROM image [AS name]
                if image.upper() != "SCRATCH":
                    from_images.append((image, lineno))
                    findings.extend(self._check_base_image(image, path, lineno))

            # USER instruction
            if upper.startswith("USER "):
                has_user_instruction = True

            # RUN instruction — check for known-bad package installs
            if upper.startswith("RUN "):
                run_content = stripped[4:]
                findings.extend(self._check_run_command(run_content, path, lineno))

            # ENV/ARG — check for secret patterns
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, stripped):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.CREDENTIAL_RISK,
                        exposure_level=ExposureLevel.UNKNOWN,
                        package_name="",
                        version="",
                        description=f"Potential secret in Dockerfile: {desc} (line {lineno})",
                        evidence=[Evidence(source=str(path), detail=stripped[:120], raw=f"line {lineno}")],
                        confidence=Confidence.MEDIUM,
                        remediation="Use build secrets (--secret flag) or runtime environment variables instead",
                        ecosystem=EcosystemType.DOCKER,
                    ))

        # Warn if running as root throughout
        if from_images and not has_user_instruction:
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name="",
                version="",
                description="Dockerfile runs as root (no USER instruction). Supply chain attacks have higher impact.",
                evidence=[Evidence(source=str(path), detail="No USER instruction found")],
                confidence=Confidence.CONFIRMED,
                remediation="Add 'USER nonroot' or create and use a non-root user",
                ecosystem=EcosystemType.DOCKER,
            ))

        return findings

    def _check_base_image(self, image: str, source: Path, lineno: int) -> list[Finding]:
        findings = []

        # Strip registry prefix
        parts = image.split("/")
        base = parts[-1].split(":")[0].split("@")[0]
        tag = image.split(":")[-1] if ":" in image else "latest"

        # Check for digest pinning
        if "@sha256:" not in image:
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=image,
                version=tag,
                description=f"Base image not pinned by digest: {image}. Tag '{tag}' can be overwritten.",
                evidence=[Evidence(source=str(source), detail=f"FROM {image}", raw=f"line {lineno}")],
                confidence=Confidence.CONFIRMED,
                remediation=f"Pin with digest: FROM {image.split(':')[0]}@sha256:<hash>",
                ecosystem=EcosystemType.DOCKER,
            ))

        # Warn on :latest
        if tag == "latest":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_PATTERN,
                exposure_level=ExposureLevel.UNKNOWN,
                package_name=image,
                version="latest",
                description=f"Using ':latest' tag for base image {image}. Unpredictable and mutable.",
                evidence=[Evidence(source=str(source), detail=f"FROM {image}", raw=f"line {lineno}")],
                confidence=Confidence.CONFIRMED,
                remediation="Pin to a specific version tag + digest",
                ecosystem=EcosystemType.DOCKER,
            ))

        # Check IOC network domains in image name
        for ioc in self.ioc_db.all_network_iocs:
            if ioc.value.lower() in image.lower():
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.KNOWN_MALICIOUS,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name=image,
                    version=tag,
                    description=f"Base image from malicious registry: {image}. {ioc.context}",
                    evidence=[Evidence(source=str(source), detail=f"FROM {image}", raw=f"line {lineno}")],
                    confidence=Confidence.CONFIRMED,
                    remediation="Do not use this image. Investigate source.",
                    ecosystem=EcosystemType.DOCKER,
                ))

        return findings

    def _check_run_command(self, run_cmd: str, source: Path, lineno: int) -> list[Finding]:
        findings = []

        # Dangerous shell patterns
        for pattern, desc in DANGEROUS_PATTERNS:
            if re.search(pattern, run_cmd, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.SUSPICIOUS_PATTERN,
                    exposure_level=ExposureLevel.UNKNOWN,
                    package_name="",
                    version="",
                    description=f"Dangerous pattern in RUN: {desc} (line {lineno})",
                    evidence=[Evidence(source=str(source), detail=run_cmd[:200], raw=f"line {lineno}")],
                    confidence=Confidence.HIGH,
                    remediation="Replace with verified package installs. Avoid piping to shell.",
                    ecosystem=EcosystemType.DOCKER,
                ))

        # Check for known-bad package names in npm/pip install commands
        npm_match = re.findall(r"npm\s+(?:install|i)\s+([^;&|]+)", run_cmd)
        for install_args in npm_match:
            for pkg_spec in install_args.split():
                if pkg_spec.startswith("-"):
                    continue
                name = pkg_spec.split("@")[0]
                version = pkg_spec.split("@")[1] if "@" in pkg_spec else ""
                bad = self.ioc_db.is_known_bad(name, version) if version else self.ioc_db.is_known_bad_name(name)
                if bad:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category=FindingCategory.KNOWN_MALICIOUS,
                        exposure_level=ExposureLevel.INSTALLED,
                        package_name=name,
                        version=version,
                        description=f"Known malicious npm package in Dockerfile RUN: {name}",
                        evidence=[Evidence(source=str(source), detail=run_cmd[:200], raw=f"line {lineno}")],
                        confidence=Confidence.CONFIRMED,
                        remediation=f"Remove {name} from Dockerfile",
                        ecosystem=EcosystemType.DOCKER,
                    ))

        pip_match = re.findall(r"pip[23]?\s+install\s+([^;&|]+)", run_cmd)
        for install_args in pip_match:
            for pkg_spec in install_args.split():
                if pkg_spec.startswith("-") or not pkg_spec[0].isalpha():
                    continue
                name = re.split(r"[=><!~^]", pkg_spec)[0]
                bad = self.ioc_db.is_known_bad_name(name)
                if bad and not bad.versions:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category=FindingCategory.KNOWN_MALICIOUS,
                        exposure_level=ExposureLevel.INSTALLED,
                        package_name=name,
                        version="",
                        description=f"Known malicious Python package in Dockerfile RUN: {name}",
                        evidence=[Evidence(source=str(source), detail=run_cmd[:200], raw=f"line {lineno}")],
                        confidence=Confidence.CONFIRMED,
                        remediation=f"Remove {name} from Dockerfile",
                        ecosystem=EcosystemType.DOCKER,
                    ))

        return findings
