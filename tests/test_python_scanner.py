"""Tests for Python scanner."""
import tempfile
from pathlib import Path

import pytest

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import EcosystemType, FindingCategory, Severity
from scd.policies.loader import load_policy
from scd.scanners.python_scanner import PythonScanner


@pytest.fixture
def ioc_db():
    return get_default_ioc_db()

@pytest.fixture
def policy():
    return load_policy()


class TestPythonScanner:
    def test_clean_requirements(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "requirements.txt"
            p.write_text("requests==2.28.0\nflask==2.3.0\n")
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_detect_malicious_pypi_package(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "requirements.txt"
            p.write_text("ctx==0.1.2\n")
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)
            assert any(f.ecosystem == EcosystemType.PYTHON for f in findings)

    def test_detect_entirely_malicious_package(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "requirements.txt"
            p.write_text("request==1.0.0\n")  # typosquat of requests
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_pipfile_lock(self, ioc_db, policy):
        import json
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Pipfile.lock"
            data = {
                "default": {"ctx": {"version": "==0.1.2"}},
                "develop": {},
            }
            p.write_text(json.dumps(data))
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_poetry_lock(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "poetry.lock"
            p.write_text('[[package]]\nname = "ctx"\nversion = "0.1.2"\n\n')
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_skip_venv(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / ".venv" / "lib" / "site-packages").mkdir(parents=True)
            p = d / ".venv" / "lib" / "site-packages" / "requirements.txt"
            p.write_text("ctx==0.1.2\n")
            findings = PythonScanner(d, ioc_db, policy).scan()
            assert len(findings) == 0

    def test_suspicious_discord_pattern(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "requirements.txt"
            p.write_text("discord-selfbot-v14==1.0.0\n")
            findings = PythonScanner(Path(d), ioc_db, policy).scan()
            assert any(f.severity >= Severity.HIGH for f in findings)
