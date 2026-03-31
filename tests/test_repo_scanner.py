"""Tests for repo scanner."""
import json
import tempfile
from pathlib import Path

import pytest

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import FindingCategory, Severity
from scd.policies.loader import load_policy
from scd.scanners.repo_scanner import RepoScanner


@pytest.fixture
def ioc_db():
    return get_default_ioc_db()


@pytest.fixture
def policy():
    return load_policy()


def _write_package_json(tmpdir: Path, data: dict) -> Path:
    pkg = tmpdir / "package.json"
    pkg.write_text(json.dumps(data))
    return pkg


class TestRepoScanner:
    def test_clean_project(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "axios": "1.13.0",
                    "express": "4.18.0",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) == 0

    def test_detect_malicious_exact_version(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "axios": "1.14.1",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) >= 1
            critical = [f for f in findings if f.severity == Severity.CRITICAL]
            assert len(critical) >= 1
            assert critical[0].package_name == "axios"
            assert critical[0].category == FindingCategory.KNOWN_MALICIOUS

    def test_detect_malicious_dependency(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "plain-crypto-js": "4.2.1",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) >= 1
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detect_second_bad_version(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "axios": "0.30.4",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detect_suspicious_pattern(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "plain-crypto-utils": "1.0.0",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            sus = [f for f in findings if f.category == FindingCategory.SUSPICIOUS_PATTERN]
            assert len(sus) >= 1

    def test_caret_range_detection(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "axios": "^1.14.0",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            # Should detect that ^1.14.0 could resolve to 1.14.1
            assert len(findings) >= 1

    def test_policy_blocklist(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "dependencies": {
                    "event-stream": "4.0.0",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            policy_findings = [f for f in findings if f.category == FindingCategory.POLICY_VIOLATION]
            assert len(policy_findings) >= 1

    def test_dev_dependencies_scanned(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {
                "name": "test-project",
                "devDependencies": {
                    "axios": "1.14.1",
                }
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_skip_node_modules(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_package_json(tmpdir, {"name": "root", "dependencies": {}})
            nm = tmpdir / "node_modules" / "axios"
            nm.mkdir(parents=True)
            _write_package_json(nm, {
                "name": "axios",
                "version": "1.14.1",
                "dependencies": {"plain-crypto-js": "4.2.1"},
            })
            scanner = RepoScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            # Should only scan root package.json, not node_modules
            assert len(findings) == 0

    def test_empty_project(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = RepoScanner(Path(tmpdir), ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) == 0
