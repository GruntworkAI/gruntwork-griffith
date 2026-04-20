"""SecurityFinding — the shared finding type produced by every security rule.

Lives in its own module so both `security.py` (regex scanner + orchestrator)
and `ast_rules.py` (AST rule registrations) can import it without creating
an import cycle. Pure dataclass; no dependencies on scanner state.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecurityFinding:
    """A single security concern raised against one file.

    `message` is the rule's human-readable description — safe for embedding.
    The matched bytes are never included to prevent secret leakage.
    """

    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    # Deprecated field kept for backwards-compat with the original stub.
    # Carries the rule's regex pattern source for debugging; NOT the matched
    # bytes. Not embedded in the JSON report.
    pattern: str = ""
