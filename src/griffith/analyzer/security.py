"""Security scanning for plugins"""

from dataclasses import dataclass
from typing import List


@dataclass
class SecurityFinding:
    """A security concern found in a plugin"""

    severity: str  # critical, high, medium, low, info
    file: str
    line: int
    pattern: str
    message: str


class SecurityScanner:
    """Scan plugins for security concerns"""

    def scan(self, path) -> List[SecurityFinding]:
        """Scan a plugin for security patterns"""
        # TODO: Implement using rules/security_patterns.yaml
        raise NotImplementedError("See docs/design.md Phase 1")
