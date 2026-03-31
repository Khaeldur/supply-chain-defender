"""Tests for lockfile scanner."""
import json
import tempfile
from pathlib import Path

import pytest

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import FindingCategory, Severity
from scd.policies.loader import load_policy
from scd.scanners.lockfile_scanner import LockfileScanner


@pytest.fixture
def ioc_db():
    return get_default_ioc_db()


@pytest.fixture
def policy():
    return load_policy()


def _write_npm_lockfile(tmpdir: Path, packages: dict) -> Path:
    lockfile = tmpdir / "package-lock.json"
    data = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {"": {"name": "test-project", "version": "1.0.0"}},
    }
    data["packages"].update(packages)
    lockfile.write_text(json.dumps(data))
    return lockfile


class TestLockfileScanner:
    def test_clean_lockfile(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_npm_lockfile(tmpdir, {
                "node_modules/axios": {"version": "1.13.0"},
                "node_modules/express": {"version": "4.18.0"},
            })
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) == 0

    def test_detect_malicious_resolved_version(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_npm_lockfile(tmpdir, {
                "node_modules/axios": {
                    "version": "1.14.1",
                    "integrity": "sha512-fake",
                },
            })
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            critical = [f for f in findings if f.severity == Severity.CRITICAL]
            assert len(critical) >= 1
            assert critical[0].package_name == "axios"
            assert critical[0].version == "1.14.1"

    def test_detect_malicious_transitive_dep(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_npm_lockfile(tmpdir, {
                "node_modules/axios": {"version": "1.14.1"},
                "node_modules/plain-crypto-js": {"version": "4.2.1"},
            })
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            # Should find both axios and plain-crypto-js
            bad_names = {f.package_name for f in findings if f.severity == Severity.CRITICAL}
            assert "axios" in bad_names
            assert "plain-crypto-js" in bad_names

    def test_detect_second_bad_version(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_npm_lockfile(tmpdir, {
                "node_modules/axios": {"version": "0.30.4"},
            })
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_yarn_lock_parsing(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            yarn_lock = tmpdir / "yarn.lock"
            yarn_lock.write_text('''# yarn lockfile v1

axios@^1.14.0:
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz#abc123"
  integrity sha512-fake

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#def456"
  integrity sha512-clean
''')
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert any(
                f.package_name == "axios" and f.severity == Severity.CRITICAL
                for f in findings
            )

    def test_no_lockfile(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = LockfileScanner(Path(tmpdir), ioc_db, policy)
            findings = scanner.scan()
            assert len(findings) == 0

    def test_suspicious_pattern_in_lockfile(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_npm_lockfile(tmpdir, {
                "node_modules/plain-crypto-utils": {"version": "1.0.0"},
            })
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            sus = [f for f in findings if f.category == FindingCategory.SUSPICIOUS_PATTERN]
            assert len(sus) >= 1

    def test_v1_lockfile_format(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            lockfile = tmpdir / "package-lock.json"
            data = {
                "name": "test",
                "version": "1.0.0",
                "lockfileVersion": 1,
                "dependencies": {
                    "axios": {
                        "version": "1.14.1",
                        "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
                        "integrity": "sha512-fake",
                    }
                },
            }
            lockfile.write_text(json.dumps(data))
            scanner = LockfileScanner(tmpdir, ioc_db, policy)
            findings = scanner.scan()
            assert any(f.severity == Severity.CRITICAL for f in findings)
