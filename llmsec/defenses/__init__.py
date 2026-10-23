"""Reference mitigations used by :class:`llmsec.targets.MockHardenedApp`.

Each module is a small, testable control that maps to one or more OWASP LLM
Top 10 items. They are heuristics - good enough to show a before/after
attack-success-rate and to document the *shape* of a defence, not a
substitute for a production safety stack.
"""

from llmsec.defenses.canary import contains_secret, redact_secrets
from llmsec.defenses.grounding import GROUNDED_REFUSAL, is_ungrounded_query
from llmsec.defenses.input_classifier import ClassifierResult, classify_input, normalize_text
from llmsec.defenses.instruction_hierarchy import quarantine_document
from llmsec.defenses.output_filter import sanitize_output
from llmsec.defenses.tool_allowlist import ToolDecision, ToolPolicy

__all__ = [
    "ClassifierResult",
    "GROUNDED_REFUSAL",
    "ToolDecision",
    "ToolPolicy",
    "classify_input",
    "contains_secret",
    "is_ungrounded_query",
    "normalize_text",
    "quarantine_document",
    "redact_secrets",
    "sanitize_output",
]
