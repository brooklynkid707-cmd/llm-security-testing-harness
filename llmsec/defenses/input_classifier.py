"""Heuristic prompt-injection / jailbreak classifier for inbound user text.

The classifier first *normalises* the text (decodes base64 blobs, folds
leetspeak, collapses whitespace) so cheap obfuscation does not slip past the
pattern list, then scores weighted regex hits. Anything at or above
``THRESHOLD`` is treated as an injection attempt.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

THRESHOLD = 3

LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l"})
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")

# (pattern, weight, label) - weights are additive; see THRESHOLD.
PATTERNS: tuple[tuple[str, int, str], ...] = (
    (r"\bignore\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?)", 3, "override"),
    (r"\bdisregard\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier)?\s*(instructions?|prompts?|rules?|guidelines?)", 3, "override"),
    (r"\bforget\s+(all\s+)?(your|the|previous)\s+(instructions?|rules?|training)", 3, "override"),
    (r"\b(new|updated|real|true)\s+(instructions?|system\s+prompt)\s*:", 3, "override"),
    (r"\bfrom\s+now\s+on\b", 2, "persistence"),
    (r"\bfor\s+the\s+rest\s+of\s+(this|the)\s+(conversation|chat|session)", 2, "persistence"),
    (r"\b(system|initial|original|hidden|secret|developer|configuration)\s+(prompt|instructions?|message|rules?)", 3, "prompt-extraction"),
    (r"\b(repeat|print|show|reveal|output|display|echo|recite|summari[sz]e|translate)\b[^.?!\n]{0,60}\b(instructions?|prompt|configuration|rules|above|everything\s+before)", 2, "prompt-extraction"),
    (r"\b(text|everything|words?)\s+(above|before)\s+(this|the)\s+(line|message|conversation)", 3, "prompt-extraction"),
    (r"\b(api|access|secret)\s*[-_ ]?(key|token)s?\b", 2, "secret-extraction"),
    (r"\bcredentials?\b", 1, "secret-extraction"),
    (r"\bcanary\b", 3, "secret-extraction"),
    (r"\byou\s+are\s+(now|no\s+longer)\b", 2, "role-play"),
    (r"\b(pretend|act|behave|roleplay|role-play)\s+(to\s+be|as|like|that\s+you)\b", 2, "role-play"),
    (r"\b(developer|debug|maintenance|god|admin|unrestricted|jailbreak)\s+mode\b", 3, "role-play"),
    (r"\bDAN\b|\bdo\s+anything\s+now\b", 3, "role-play"),
    (r"\bno\s+(rules|restrictions|limitations|filters)\b", 2, "role-play"),
    (r"\bpwned\b", 3, "known-token"),
    (r"<\s*/?\s*(system|assistant|instructions?|admin)\s*>", 3, "delimiter"),
    (r"\[(system|inst|admin)\]|###\s*(system|instruction)", 3, "delimiter"),
    (r"\b(delete|drop|wipe|purge)\s+(the\s+)?(account|table|database|records?)\b", 2, "destructive"),
    (r"\b(select|union|drop|insert)\b[^\n]{0,40}\b(from|table|into)\b", 2, "sql"),
    (r"169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1", 3, "ssrf"),
    (r"<\s*script|onerror\s*=|onload\s*=|javascript\s*:", 3, "active-content"),
    (r"!\[[^\]]*\]\(\s*https?://", 2, "markdown-exfil"),
    (r"\b(issue|process|give|send)\s+(me\s+)?(a\s+)?refund\b", 1, "financial"),
)
_COMPILED = [(re.compile(p, re.IGNORECASE), w, label) for p, w, label in PATTERNS]


@dataclass
class ClassifierResult:
    """Score plus the labels of every pattern that fired."""

    score: int = 0
    labels: list[str] = field(default_factory=list)
    decoded_base64: bool = False

    @property
    def flagged(self) -> bool:
        return self.score >= THRESHOLD


def decode_base64_blobs(text: str) -> tuple[str, bool]:
    """Replace any base64 blob that decodes to printable text with its plaintext."""
    changed = False

    def _sub(m: re.Match[str]) -> str:
        nonlocal changed
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return blob
        if decoded and all(ch.isprintable() or ch in "\n\t" for ch in decoded) and any(ch.isalpha() for ch in decoded):
            changed = True
            return decoded
        return blob

    return _B64_BLOB.sub(_sub, text), changed


def fold_leetspeak(text: str) -> str:
    """Map common leetspeak substitutions back to letters, only inside words that contain letters."""

    def _fold(m: re.Match[str]) -> str:
        word = m.group(0)
        if any(c.isalpha() for c in word) and any(c in "01345@$|7" for c in word):
            return word.translate(LEET_MAP)
        return word

    return re.sub(r"[A-Za-z0-9@$|]+", _fold, text)


def normalize_text(text: str) -> tuple[str, bool]:
    """Full normalisation pipeline. Returns ``(normalised, base64_was_decoded)``."""
    decoded, changed = decode_base64_blobs(text)
    folded = fold_leetspeak(decoded)
    folded = re.sub(r"[​‌‍﻿]", "", folded)  # zero-width characters
    collapsed = re.sub(r"\s+", " ", folded)
    # Collapse "i g n o r e"-style letter spacing for short runs.
    collapsed = re.sub(r"\b(?:[A-Za-z] ){3,}[A-Za-z]\b", lambda m: m.group(0).replace(" ", ""), collapsed)
    return collapsed, changed


def classify_input(text: str) -> ClassifierResult:
    """Score ``text`` for injection/jailbreak intent."""
    normalized, decoded = normalize_text(text)
    result = ClassifierResult(decoded_base64=decoded)
    for rx, weight, label in _COMPILED:
        if rx.search(normalized):
            result.score += weight
            result.labels.append(label)
    if decoded:
        result.score += 1
        result.labels.append("encoded-payload")
    return result
