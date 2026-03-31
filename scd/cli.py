"""CLI entrypoint for Supply Chain Defender."""
from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

from scd.iocs.known_bad import get_default_ioc_db
from scd.models import (
    EXIT_CLEAN, EXIT_COMPROMISED, EXIT_ERROR, EXIT_WARNINGS,
    EcosystemType, ScanResult, ScanType, Severity,
)
from scd.policies.loader import load_policy
from scd.reporters.json_reporter import JSONReporter
from scd.reporters.terminal_reporter import TerminalReporter

# ──────────────────────────────────────────────
# Ecosystem detection
# ──────────────────────────────────────────────

ECOSYSTEM_INDICATORS: dict[EcosystemType, list[str]] = {
    EcosystemType.NPM: [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    ],
    EcosystemType.PYTHON: [
        "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
        "setup.py", "setup.cfg", "poetry.lock",
    ],
    EcosystemType.GO: ["go.mod", "go.sum"],
    EcosystemType.CARGO: ["Cargo.toml", "Cargo.lock"],
    EcosystemType.RUBY: ["Gemfile", "Gemfile.lock"],
    EcosystemType.NUGET: ["packages.config", "packages.lock.json"],
    EcosystemType.MAVEN: ["pom.xml"],
    EcosystemType.GRADLE: ["build.gradle", "build.gradle.kts", "settings.gradle"],
    EcosystemType.DOCKER: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    EcosystemType.GITLAB_CI: [".gitlab-ci.yml", ".gitlab-ci.yaml"],
    EcosystemType.JENKINS: ["Jenkinsfile"],
}


def detect_ecosystems(target: Path) -> list[EcosystemType]:
    """Detect which ecosystems are present in the target directory."""
    found = []
    for eco, indicators in ECOSYSTEM_INDICATORS.items():
        for indicator in indicators:
            # Check direct file or glob
            if (target / indicator).exists():
                found.append(eco)
                break
            # Check one level deep for monorepos
            if eco in (EcosystemType.NPM, EcosystemType.PYTHON) and list(target.glob(f"*/{indicator}")):
                found.append(eco)
                break
            # Check for extension patterns (NuGet)
            if eco == EcosystemType.NUGET and list(target.glob("**/*.csproj")):
                found.append(eco)
                break
    return found


def _get_scanners(
    target: Path,
    ecosystems: list[EcosystemType],
    ioc_db,
    policy,
    include_registry_api: bool = False,
    include_git_history: bool = False,
):
    """Return scanner instances for the detected ecosystems."""
    scanners = []

    if EcosystemType.NPM in ecosystems:
        from scd.scanners.repo_scanner import RepoScanner
        from scd.scanners.lockfile_scanner import LockfileScanner
        from scd.scanners.node_modules_scanner import NodeModulesScanner
        scanners.append(RepoScanner(target, ioc_db, policy))
        scanners.append(LockfileScanner(target, ioc_db, policy))
        if policy.scan_options.scan_node_modules and (target / "node_modules").exists():
            scanners.append(NodeModulesScanner(target, ioc_db, policy))

    if EcosystemType.PYTHON in ecosystems:
        from scd.scanners.python_scanner import PythonScanner
        scanners.append(PythonScanner(target, ioc_db, policy))

    if EcosystemType.GO in ecosystems:
        from scd.scanners.go_scanner import GoScanner
        scanners.append(GoScanner(target, ioc_db, policy))

    if EcosystemType.CARGO in ecosystems:
        from scd.scanners.cargo_scanner import CargoScanner
        scanners.append(CargoScanner(target, ioc_db, policy))

    if EcosystemType.RUBY in ecosystems:
        from scd.scanners.ruby_scanner import RubyScanner
        scanners.append(RubyScanner(target, ioc_db, policy))

    if EcosystemType.NUGET in ecosystems:
        from scd.scanners.nuget_scanner import NuGetScanner
        scanners.append(NuGetScanner(target, ioc_db, policy))

    if EcosystemType.MAVEN in ecosystems or EcosystemType.GRADLE in ecosystems:
        from scd.scanners.maven_scanner import MavenScanner
        scanners.append(MavenScanner(target, ioc_db, policy))

    if EcosystemType.DOCKER in ecosystems:
        from scd.scanners.docker_scanner import DockerScanner
        scanners.append(DockerScanner(target, ioc_db, policy))

    if EcosystemType.GITLAB_CI in ecosystems:
        from scd.scanners.gitlab_ci_scanner import GitLabCIScanner
        scanners.append(GitLabCIScanner(target, ioc_db, policy))

    if EcosystemType.JENKINS in ecosystems:
        from scd.scanners.jenkins_scanner import JenkinsScanner
        scanners.append(JenkinsScanner(target, ioc_db, policy))

    if include_git_history:
        from scd.scanners.git_history_scanner import GitHistoryScanner
        scanners.append(GitHistoryScanner(target, ioc_db, policy))

    if include_registry_api:
        from scd.scanners.registry_api_scanner import RegistryAPIScanner
        check_npm = EcosystemType.NPM in ecosystems
        check_pypi = EcosystemType.PYTHON in ecosystems
        if check_npm or check_pypi:
            scanners.append(RegistryAPIScanner(target, ioc_db, policy,
                                                check_npm=check_npm, check_pypi=check_pypi))
    return scanners


# ──────────────────────────────────────────────
# CLI definition
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scd",
        description="Supply Chain Defender — multi-ecosystem supply-chain attack detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported ecosystems: npm, python, go, cargo, ruby, nuget, maven, gradle, docker, gitlab-ci, jenkins

Examples:
  scd scan-repo .                         # Auto-detect all ecosystems
  scd scan-repo . --ecosystem npm python  # Scan only npm and python
  scd scan-repo . --format json           # JSON output
  scd scan-host                           # Host IOC scan
  scd ci-guard . --strict                 # CI mode, fail on any finding
  scd sbom . --output sbom.json           # Generate CycloneDX SBOM
""",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    sub = parser.add_subparsers(dest="command", metavar="command")
    _add_scan_repo(sub)
    _add_scan_host(sub)
    _add_ci_guard(sub)
    _add_sbom(sub)
    return parser


def _common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", type=Path, help="Custom policy JSON file")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--output", type=Path, help="Write JSON report to file")
    p.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    default="HIGH", dest="fail_on")


def _add_scan_repo(sub) -> None:
    p = sub.add_parser("scan-repo", help="Scan a project repository (all ecosystems)")
    p.add_argument("path", nargs="?", default=".", help="Project root (default: .)")
    p.add_argument(
        "--ecosystem", nargs="+",
        choices=["npm", "python", "go", "cargo", "ruby", "nuget", "maven",
                 "gradle", "docker", "gitlab-ci", "jenkins"],
        metavar="ECO", help="Limit to specific ecosystems",
    )
    p.add_argument("--registry-api", action="store_true",
                    help="Query npm/PyPI registry APIs for anomaly detection (requires internet)")
    p.add_argument("--git-history", action="store_true",
                    help="Scan git history for past exposures")
    _common_args(p)


def _add_scan_host(sub) -> None:
    p = sub.add_parser("scan-host", help="Scan this host for supply-chain attack IOCs")
    _common_args(p)


def _add_ci_guard(sub) -> None:
    p = sub.add_parser("ci-guard", help="CI/CD mode — strict scanning")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--strict", action="store_true", help="Fail on ANY finding")
    p.add_argument(
        "--ecosystem", nargs="+",
        choices=["npm", "python", "go", "cargo", "ruby", "nuget", "maven",
                 "gradle", "docker", "gitlab-ci", "jenkins"],
        metavar="ECO",
    )
    _common_args(p)


def _add_sbom(sub) -> None:
    p = sub.add_parser("sbom", help="Generate CycloneDX SBOM from scan results")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--output", type=Path, required=False, help="Output file (default: stdout)")
    p.add_argument(
        "--ecosystem", nargs="+",
        choices=["npm", "python", "go", "cargo", "ruby", "nuget", "maven",
                 "gradle", "docker", "gitlab-ci", "jenkins"],
        metavar="ECO",
    )
    p.add_argument("--policy", type=Path)


# ──────────────────────────────────────────────
# Command handlers
# ──────────────────────────────────────────────

def cmd_scan_repo(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        sys.stderr.write(f"Error: path does not exist: {target}\n")
        return EXIT_ERROR

    ioc_db = get_default_ioc_db()
    policy = load_policy(getattr(args, "policy", None))

    ecosystems = _resolve_ecosystems(target, getattr(args, "ecosystem", None))
    if not ecosystems:
        sys.stderr.write("No supported ecosystem files found in target directory.\n")
        return EXIT_CLEAN

    result = ScanResult(scan_type=ScanType.REPO, target=str(target), platform=platform.system())
    scanners = _get_scanners(
        target, ecosystems, ioc_db, policy,
        include_registry_api=getattr(args, "registry_api", False),
        include_git_history=getattr(args, "git_history", False),
    )

    _run_scanners(scanners, result)
    result.findings = _dedup(result.findings)
    _output(result, args.format, getattr(args, "output", None))
    return _exit_code(result, Severity[args.fail_on])


def cmd_scan_host(args: argparse.Namespace) -> int:
    ioc_db = get_default_ioc_db()
    result = ScanResult(scan_type=ScanType.HOST, target="localhost", platform=platform.system())

    from scd.scanners.host_scanner import HostScanner
    from scd.scanners.ioc_scanner import IOCScanner
    _run_scanners([HostScanner(ioc_db), IOCScanner(ioc_db)], result)
    result.findings = _dedup(result.findings)
    _output(result, args.format, getattr(args, "output", None))
    return result.exit_code


def cmd_ci_guard(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        sys.stderr.write(f"Error: path does not exist: {target}\n")
        return EXIT_ERROR

    ioc_db = get_default_ioc_db()
    policy = load_policy(getattr(args, "policy", None))
    ecosystems = _resolve_ecosystems(target, getattr(args, "ecosystem", None))

    result = ScanResult(scan_type=ScanType.CI_GUARD, target=str(target), platform=platform.system())
    scanners = _get_scanners(target, ecosystems, ioc_db, policy)
    _run_scanners(scanners, result)
    result.findings = _dedup(result.findings)
    _output(result, args.format, getattr(args, "output", None))

    if getattr(args, "strict", False) and result.findings:
        return EXIT_COMPROMISED

    threshold = Severity[policy.ci_options.fail_on_severity]
    return _exit_code(result, threshold)


def cmd_sbom(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        sys.stderr.write(f"Error: path does not exist: {target}\n")
        return EXIT_ERROR

    ioc_db = get_default_ioc_db()
    policy = load_policy(getattr(args, "policy", None))
    ecosystems = _resolve_ecosystems(target, getattr(args, "ecosystem", None))

    result = ScanResult(scan_type=ScanType.REPO, target=str(target), platform=platform.system())
    scanners = _get_scanners(target, ecosystems, ioc_db, policy)
    _run_scanners(scanners, result)
    result.findings = _dedup(result.findings)

    from scd.reporters.sbom_reporter import SBOMReporter
    SBOMReporter(getattr(args, "output", None)).report(result)
    return EXIT_CLEAN


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _resolve_ecosystems(
    target: Path,
    requested: list[str] | None,
) -> list[EcosystemType]:
    if requested:
        mapping = {
            "npm": EcosystemType.NPM,
            "python": EcosystemType.PYTHON,
            "go": EcosystemType.GO,
            "cargo": EcosystemType.CARGO,
            "ruby": EcosystemType.RUBY,
            "nuget": EcosystemType.NUGET,
            "maven": EcosystemType.MAVEN,
            "gradle": EcosystemType.GRADLE,
            "docker": EcosystemType.DOCKER,
            "gitlab-ci": EcosystemType.GITLAB_CI,
            "jenkins": EcosystemType.JENKINS,
        }
        return [mapping[e] for e in requested if e in mapping]
    return detect_ecosystems(target)


def _run_scanners(scanners: list, result: ScanResult) -> None:
    for scanner in scanners:
        try:
            result.findings.extend(scanner.scan())
        except Exception as e:
            result.errors.append(f"{scanner.__class__.__name__}: {e}")


def _output(result: ScanResult, fmt: str, output_path: Path | None) -> None:
    if fmt == "json":
        JSONReporter(output_path).report(result)
    else:
        TerminalReporter().report(result)
        if output_path:
            JSONReporter(output_path).report(result)


def _dedup(findings: list) -> list:
    seen: set = set()
    unique = []
    for f in findings:
        key = (f.package_name, f.version, f.category, f.severity, f.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _exit_code(result: ScanResult, threshold: Severity) -> int:
    if any(f.severity >= threshold for f in result.findings):
        return EXIT_COMPROMISED
    if result.findings:
        return EXIT_WARNINGS
    return EXIT_CLEAN


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan-repo": cmd_scan_repo,
        "scan-host": cmd_scan_host,
        "ci-guard": cmd_ci_guard,
        "sbom": cmd_sbom,
    }

    handler = handlers.get(args.command)
    if handler:
        try:
            code = handler(args)
        except Exception as e:
            sys.stderr.write(f"Fatal: {e}\n")
            code = EXIT_ERROR
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
