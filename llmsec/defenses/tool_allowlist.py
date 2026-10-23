"""Tool allowlist and per-tool authorization policy.

Models should never decide for themselves which tools exist. The policy owns
the list of callable tools, which arguments are allowed, which fields of a
result are returned, and which tools require an explicit human confirmation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolDecision:
    """Result of :meth:`ToolPolicy.authorize`."""

    allowed: bool
    reason: str
    needs_confirmation: bool = False


@dataclass
class ToolPolicy:
    """Declarative policy: allowlist + confirmation set + argument validators."""

    allowed: frozenset[str] = frozenset({"lookup_customer", "issue_refund"})
    requires_confirmation: frozenset[str] = frozenset({"issue_refund"})
    redacted_fields: frozenset[str] = frozenset({"card_number", "date_of_birth", "address", "notes"})
    max_refund: float = 100.0
    validators: dict[str, Any] = field(default_factory=dict)

    def authorize(self, tool: str, args: dict[str, Any], confirmed: bool = False) -> ToolDecision:
        """Decide whether ``tool(**args)`` may run."""
        if tool not in self.allowed:
            return ToolDecision(False, f"tool '{tool}' is not on the allowlist")
        if tool == "lookup_customer":
            if not re.fullmatch(r"\d{4}", str(args.get("customer_id", ""))):
                return ToolDecision(False, "customer_id must be a 4-digit identifier")
        if tool == "issue_refund":
            try:
                amount = float(args.get("amount", 0))
            except (TypeError, ValueError):
                return ToolDecision(False, "amount must be numeric")
            if amount <= 0 or amount > self.max_refund:
                return ToolDecision(False, f"amount must be between 0 and {self.max_refund:.0f}")
        if tool in self.requires_confirmation and not confirmed:
            return ToolDecision(False, f"tool '{tool}' requires explicit human confirmation", needs_confirmation=True)
        return ToolDecision(True, "allowed")

    def redact(self, record: dict[str, Any]) -> dict[str, Any]:
        """Drop fields the task does not need before they reach the model/user."""
        return {k: v for k, v in record.items() if k not in self.redacted_fields}
