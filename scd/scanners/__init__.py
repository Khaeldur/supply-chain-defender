"""Scanner modules for Supply Chain Defender."""
from __future__ import annotations

from typing import Protocol

from scd.models import Finding


class Scanner(Protocol):
    """Protocol for all scanner implementations."""
    def scan(self) -> list[Finding]: ...
