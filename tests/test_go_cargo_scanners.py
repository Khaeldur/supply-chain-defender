"""Tests for Go and Cargo scanners."""
import tempfile
from pathlib import Path

import pytest

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import EcosystemType, Severity
from scd.policies.loader import load_policy
from scd.scanners.cargo_scanner import CargoScanner
from scd.scanners.go_scanner import GoScanner


@pytest.fixture
def ioc_db():
    return get_default_ioc_db()

@pytest.fixture
def policy():
    return load_policy()


class TestGoScanner:
    def test_clean_go_mod(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "go.mod"
            p.write_text("module example.com/myapp\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n")
            findings = GoScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_no_go_mod(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            findings = GoScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_go_sum_parsing(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "go.mod"
            p.write_text("module example.com/test\n\ngo 1.21\n")
            s = Path(d) / "go.sum"
            s.write_text("github.com/gin-gonic/gin v1.9.1 h1:abc123=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:def456=\n")
            findings = GoScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_skip_vendor(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "vendor").mkdir()
            p = d / "vendor" / "go.mod"
            p.write_text("module evil\n")
            findings = GoScanner(d, ioc_db, policy).scan()
            assert len(findings) == 0


class TestCargoScanner:
    def test_clean_cargo_toml(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Cargo.toml"
            p.write_text('[package]\nname = "myapp"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\ntokio = { version = "1.0", features = ["full"] }\n')
            findings = CargoScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_cargo_lock_parsing(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Cargo.lock"
            p.write_text('[[package]]\nname = "serde"\nversion = "1.0.193"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\n')
            findings = CargoScanner(Path(d), ioc_db, policy).scan()
            assert len(findings) == 0

    def test_skip_build_target(self, ioc_db, policy):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "target" / "debug").mkdir(parents=True)
            p = d / "target" / "debug" / "Cargo.toml"
            p.write_text("[package]\nname = \"evil\"\n")
            findings = CargoScanner(d, ioc_db, policy).scan()
            assert len(findings) == 0
