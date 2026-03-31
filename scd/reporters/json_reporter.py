"""JSON report output."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from scd.models import ScanResult


class JSONReporter:
    """Output scan results as JSON."""

    def __init__(self, output: Path | None = None) -> None:
        self.output = output

    def report(self, result: ScanResult) -> str:
        data = result.to_dict()
        formatted = json.dumps(data, indent=2, default=str)

        if self.output:
            self.output.write_text(formatted)
        else:
            sys.stdout.write(formatted + "\n")

        return formatted
