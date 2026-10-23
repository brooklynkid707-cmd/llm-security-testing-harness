"""MockHardenedApp - the same assistant with the reference defences wired in.

It wraps a :class:`MockVulnerableApp` so the before/after comparison is honest:
identical business logic, with the controls from :mod:`llmsec.defenses` applied
to inbound text, retrieved documents, tool calls and outbound text.
"""

from __future__ import annotations

from llmsec.defenses import (
    GROUNDED_REFUSAL,
    classify_input,
    contains_secret,
    is_ungrounded_query,
    quarantine_document,
    redact_secrets,
    sanitize_output,
)
from llmsec.defenses.tool_allowlist import ToolPolicy
from llmsec.models import Document, TargetResponse, ToolCall
from llmsec.targets import mock_world as W
from llmsec.targets.base import Target
from llmsec.targets.mock_vulnerable import MockVulnerableApp, VulnConfig

REFUSAL = (
    "I can't help with that. I can only assist with Example Corp orders, shipping "
    "and products. Is there something about your order I can help with?"
)


class MockHardenedApp(Target):
    """Defended target used to demonstrate control effectiveness."""

    name = "mock-hardened"

    def __init__(self, policy: ToolPolicy | None = None) -> None:
        super().__init__()
        self.secrets = {"canary": W.CANARY, "api_key": W.FAKE_API_KEY}
        self.policy = policy or ToolPolicy()
        # The engine keeps the same grounded answers; weaknesses stay on so we can
        # prove the *wrapper* is what stops them, not a neutered backend.
        self._engine = MockVulnerableApp(VulnConfig())

    def start_case(self, documents: tuple[Document, ...] = ()) -> None:
        super().start_case(documents)
        fired: list[str] = []
        safe_docs: list[Document] = []
        for doc in documents:
            safe_text, removed = quarantine_document(doc)
            if removed:
                fired.append("doc-quarantine")
            safe_docs.append(Document(doc.title, safe_text))
        self._doc_defenses = fired
        self._engine.start_case(tuple(safe_docs))

    def send(self, user_text: str) -> TargetResponse:
        fired = list(getattr(self, "_doc_defenses", []))
        self._doc_defenses = []  # only report once, on the turn that consumes docs

        # 1. input classifier - refuse obvious injection/jailbreak before the backend.
        verdict = classify_input(user_text)
        if verdict.flagged:
            fired.append(f"input-classifier:{'+'.join(dict.fromkeys(verdict.labels))}")
            return self._blocked(user_text, fired)

        # 2. grounding guard (LLM09): decline questions with no verified answer.
        if is_ungrounded_query(user_text):
            fired.append("grounding-guard")
            return self._blocked_text(user_text, GROUNDED_REFUSAL, fired)

        # 3. run the backend engine on the (clean) turn.
        resp = self._engine.send(user_text)
        text = resp.text

        # 3. tool allowlist / confirmation / field redaction.
        safe_calls: list[ToolCall] = []
        for call in resp.tool_calls:
            decision = self.policy.authorize(call.name, call.arguments, confirmed=False)
            if not decision.allowed:
                fired.append(f"tool-blocked:{call.name}")
                text = (
                    f"That action needs a human to confirm it, so I can't do it automatically ({decision.reason})."
                    if decision.needs_confirmation
                    else REFUSAL
                )
                continue
            if call.name == "lookup_customer":
                record = self.policy.redact(W.CUSTOMERS.get(call.arguments.get("customer_id", ""), {}))
                fired.append("field-redaction")
                safe = ToolCall(call.name, call.arguments, result="redacted record returned")
                safe_calls.append(safe)
                text = f"I found the account. For your privacy I can share the name and last order only: " + (
                    f"{record.get('name', 'n/a')}, last order {record.get('last_order', 'n/a')}."
                )
            else:
                safe_calls.append(call)

        # 4. output DLP - canary / secret / key-shaped strings never leave.
        leaked = contains_secret(text, [W.CANARY, W.FAKE_API_KEY])
        if leaked:
            text, _ = redact_secrets(text, [W.CANARY, W.FAKE_API_KEY])
            fired.append("output-dlp")
            if "[REDACTED]" in text and ("configuration" in text.lower() or "credential" in text.lower()):
                text = REFUSAL

        # 5. insecure-output sanitisation.
        text, out_fired = sanitize_output(text)
        fired.extend(out_fired)

        self._record(user_text, text)
        out = TargetResponse(text=text, tool_calls=safe_calls, defenses_fired=fired)
        out.raw = {"tag": "hardened"}
        return out

    def _blocked(self, user_text: str, fired: list[str]) -> TargetResponse:
        return self._blocked_text(user_text, REFUSAL, fired)

    def _blocked_text(self, user_text: str, message: str, fired: list[str]) -> TargetResponse:
        self._record(user_text, message)
        resp = TargetResponse(text=message, blocked=True, defenses_fired=fired)
        resp.raw = {"tag": "blocked"}
        return resp
