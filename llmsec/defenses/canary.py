"""Canary tokens and secret-pattern detection for model output.

A canary is an unguessable string planted in the system prompt. If it ever
appears in output, the prompt leaked - regardless of how the attacker phrased
the request. The same check doubles as output DLP for key-shaped strings.
"""

from __future__ import annotations

import re
import secrets as _secrets
from typing import Iterable

KEY_SHAPED = re.compile(r"\b(?:sk|ak|key|tok)[-_][A-Za-z0-9_-]{12,}\b|\b[A-Z]{3,}-FAKE-KEY-[A-Z0-9-]{8,}\b", re.IGNORECASE)


def make_canary(prefix: str = "CANARY") -> str:
    """Generate a fresh canary token (``CANARY-<16 hex>``)."""
    return f"{prefix}-{_secrets.token_hex(8)}"


def _spaced_variants(secret: str) -> list[str]:
    """Secrets are sometimes leaked with separators inserted; match the alnum core too."""
    core = re.sub(r"[^A-Za-z0-9]", "", secret)
    return [secret, core] if len(core) >= 12 else [secret]


def contains_secret(text: str, secrets_: Iterable[str]) -> list[str]:
    """Return the secrets (or 'key-shaped') found in ``text``, tolerant to separators."""
    squashed = re.sub(r"[^A-Za-z0-9]", "", text)
    found: list[str] = []
    for s in secrets_:
        if not s:
            continue
        if s in text or any(v in squashed for v in _spaced_variants(s) if v != s):
            found.append(s)
    if KEY_SHAPED.search(text):
        found.append("key-shaped")
    return found


def redact_secrets(text: str, secrets_: Iterable[str]) -> tuple[str, bool]:
    """Replace known secrets and key-shaped strings with ``[REDACTED]``."""
    fired = False
    for s in secrets_:
        if s and s in text:
            text = text.replace(s, "[REDACTED]")
            fired = True
    text, n = KEY_SHAPED.subn("[REDACTED]", text)
    return text, fired or n > 0
