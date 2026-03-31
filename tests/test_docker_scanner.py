"""Tests for Docker scanner."""
import tempfile
from pathlib import Path

import pytest

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import EcosystemType, FindingCategory, Severity
from scd.policies.loader import load_policy
from scd.scanners.docker_scanner import DockerScanner


@pytest.fixture
def ioc_db():
    return get_default_ioc_db()

@pytest.fixture
def policy():
    return load_policy()


class TestDockerScanner:
    def test_clean_dockerfile(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text(
                "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nUSER node\nCMD [\"node\", \"server.js\"]\n"
            )
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            # May have digest pinning warning but no CRITICAL/HIGH
            assert not any(f.severity >= Severity.HIGH for f in findings)

    def test_detect_latest_tag(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text("FROM node:latest\nRUN npm install\nCMD [\"node\", \"app.js\"]\n")
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert any(
                f.category == FindingCategory.SUSPICIOUS_PATTERN and "latest" in f.description
                for f in findings
            )

    def test_detect_curl_pipe_bash(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text(
                "FROM ubuntu:22.04\nRUN curl https://example.com/install.sh | bash\nCMD [\"/bin/bash\"]\n"
            )
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity >= Severity.HIGH for f in findings)

    def test_detect_no_user_instruction(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text("FROM alpine:3.18\nRUN apk add curl\nCMD [\"/bin/sh\"]\n")
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert any("root" in f.description.lower() or "USER" in f.description for f in findings)

    def test_detect_malicious_npm_in_run(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text(
                "FROM node:20\nRUN npm install axios@1.14.1\nUSER node\nCMD [\"node\", \"app.js\"]\n"
            )
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detect_secret_in_env(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Dockerfile"
            p.write_text(
                "FROM node:20\nENV API_KEY=abc123secret\nUSER node\nCMD [\"node\", \"app.js\"]\n"
            )
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert any(f.category == FindingCategory.CREDENTIAL_RISK for f in findings)

    def test_no_dockerfiles(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            findings = DockerScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0
