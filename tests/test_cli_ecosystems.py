"""Integration tests for CLI ecosystem auto-detection and multi-ecosystem scanning."""
import json
import subprocess
import tempfile
from pathlib import Path
import sys

import pytest


def _run(args: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    result = subprocess.run(
        [sys.executable, "-m", "scd.cli"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestEcosystemDetection:
    def test_auto_detect_npm(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"name":"test","dependencies":{"axios":"1.13.0"}}')
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 0  # clean

    def test_detect_malicious_npm_auto(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"name":"test","dependencies":{"axios":"1.14.1"}}')
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 2

    def test_auto_detect_python(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 0

    def test_malicious_python_auto(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("ctx==0.1.2\n")
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 2

    def test_multi_ecosystem_project(self, tmp_path):
        # Project with both npm and python files
        (tmp_path / "package.json").write_text('{"name":"test","dependencies":{"lodash":"4.17.21"}}')
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 0

    def test_json_format_output(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name":"test","dependencies":{"axios":"1.14.1"}}')
        code, out, err = _run(["scan-repo", str(tmp_path), "--format", "json"])
        assert code == 2
        data = json.loads(out)
        assert data["summary"]["critical"] >= 1
        assert "by_ecosystem" in data["summary"]

    def test_ecosystem_filter(self, tmp_path):
        # Has both npm (malicious) and python (clean) — only scan python
        (tmp_path / "package.json").write_text('{"name":"test","dependencies":{"axios":"1.14.1"}}')
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        code, out, err = _run(["scan-repo", str(tmp_path), "--ecosystem", "python"])
        assert code == 0  # npm not scanned

    def test_sbom_command(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name":"test","dependencies":{"lodash":"4.17.21"}}')
        code, out, err = _run(["sbom", str(tmp_path)])
        assert code == 0
        data = json.loads(out)
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"

    def test_ci_guard_strict(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name":"test","dependencies":{"lodash":"4.17.21"}}')
        code, out, err = _run(["ci-guard", str(tmp_path), "--strict"])
        assert code == 0

    def test_no_ecosystem_files(self, tmp_path):
        code, out, err = _run(["scan-repo", str(tmp_path)])
        assert code == 0

    def test_docker_malicious_in_run(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM node:20\nRUN npm install axios@1.14.1\nUSER node\nCMD [\"node\",\"app.js\"]\n"
        )
        code, out, err = _run(["scan-repo", str(tmp_path), "--ecosystem", "docker"])
        assert code == 2
