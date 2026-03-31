"""Rich terminal output without external dependencies."""
from __future__ import annotations

import sys
from scd.models import Finding, ScanResult, Severity


# ANSI color codes
_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "white": "\033[97m",
    "bg_red": "\033[41m",
    "bg_yellow": "\033[43m",
    "bg_green": "\033[42m",
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: ("bg_red", "white", "bold"),
    Severity.HIGH: ("red", "bold"),
    Severity.MEDIUM: ("yellow",),
    Severity.LOW: ("dim",),
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "!!!",
    Severity.HIGH: " !! ",
    Severity.MEDIUM: " !  ",
    Severity.LOW: " .  ",
}


def _use_color() -> bool:
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def _style(text: str, *styles: str) -> str:
    if not _use_color():
        return text
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}"


def _severity_badge(sev: Severity) -> str:
    styles = _SEVERITY_STYLE.get(sev, ())
    icon = _SEVERITY_ICON.get(sev, "?")
    label = f"[{icon} {sev.name}]"
    return _style(label, *styles)


class TerminalReporter:
    """Human-readable terminal output."""

    def report(self, result: ScanResult) -> None:
        w = sys.stderr.write

        # Header
        w("\n")
        w(_style("=" * 70, "bold") + "\n")
        w(_style("  SUPPLY CHAIN DEFENDER — Scan Report", "bold", "cyan") + "\n")
        w(_style("=" * 70, "bold") + "\n")
        ecosystems = result.ecosystems_scanned
        w(f"  Scan type  : {result.scan_type.value}\n")
        w(f"  Target     : {result.target}\n")
        w(f"  Platform   : {result.platform or 'unknown'}\n")
        w(f"  Ecosystems : {', '.join(ecosystems) if ecosystems else 'auto-detected'}\n")
        w(f"  Findings   : {len(result.findings)}\n")

        if result.errors:
            w(_style(f"  Errors    : {len(result.errors)}", "yellow") + "\n")

        w(_style("-" * 70, "dim") + "\n\n")

        if not result.findings:
            w(_style("  No findings. Clean scan.", "green", "bold") + "\n\n")
        else:
            # Sort by severity (highest first)
            sorted_findings = sorted(result.findings, key=lambda f: f.severity, reverse=True)
            for i, finding in enumerate(sorted_findings, 1):
                self._print_finding(w, i, finding)

        # Summary bar
        w(_style("=" * 70, "bold") + "\n")
        self._print_summary(w, result)
        w(_style("=" * 70, "bold") + "\n\n")

    def _print_finding(self, w, index: int, finding: Finding) -> None:
        badge = _severity_badge(finding.severity)
        w(f"  {badge} #{index}\n")
        w(f"    {_style(finding.description, 'bold')}\n")

        if finding.package_name:
            w(f"    Package  : {finding.package_name}@{finding.version}\n")
        w(f"    Category : {finding.category.value}\n")
        w(f"    Exposure : {finding.exposure_level.value}\n")
        w(f"    Confidence: {finding.confidence.value}\n")

        if finding.evidence:
            w(f"    Evidence:\n")
            for ev in finding.evidence[:3]:
                w(f"      - {ev.source}: {ev.detail}\n")

        if finding.remediation:
            w(f"    {_style('Remediation:', 'yellow')}\n")
            for line in finding.remediation.splitlines():
                w(f"      {line}\n")

        w("\n")

    def _print_summary(self, w, result: ScanResult) -> None:
        total = len(result.findings)
        crit = result.critical_count
        high = result.high_count
        med = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in result.findings if f.severity == Severity.LOW)

        w(f"  SUMMARY: {total} findings")
        if crit:
            w(f" | {_style(f'{crit} CRITICAL', 'red', 'bold')}")
        if high:
            w(f" | {_style(f'{high} HIGH', 'red')}")
        if med:
            w(f" | {_style(f'{med} MEDIUM', 'yellow')}")
        if low:
            w(f" | {low} LOW")
        w("\n")

        ec = result.exit_code
        if ec == 0:
            w(f"  EXIT CODE: {_style('0 — CLEAN', 'green', 'bold')}\n")
        elif ec == 1:
            w(f"  EXIT CODE: {_style('1 — WARNINGS', 'yellow', 'bold')}\n")
        elif ec == 2:
            w(f"  EXIT CODE: {_style('2 — COMPROMISED', 'red', 'bold')}\n")
        else:
            w(f"  EXIT CODE: {_style(f'{ec} — ERROR', 'red')}\n")
