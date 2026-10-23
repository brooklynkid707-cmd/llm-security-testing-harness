"""Instruction hierarchy: retrieved documents are data, never instructions.

``quarantine_document`` wraps a document in explicit delimiters, tags it as
untrusted and strips lines that read like instructions to the assistant. The
hardened mock only ever *summarises* the remaining text; it never executes it.
"""

from __future__ import annotations

import re

from llmsec.defenses.input_classifier import classify_input
from llmsec.models import Document

_ADDRESSED_TO_AI = re.compile(
    r"^\s*(?:\[?\s*(?:ai|assistant|system|note\s+to\s+(?:the\s+)?(?:ai|assistant|model)|important|instruction)s?\s*\]?\s*[:\-]|"
    r"(?:ai|assistant|chatbot|model)\s*,?\s+(?:please|you\s+must|ignore|stop|now))",
    re.IGNORECASE,
)


def quarantine_document(doc: Document) -> tuple[str, list[str]]:
    """Return ``(safe_text, removed_lines)`` for one document."""
    kept: list[str] = []
    removed: list[str] = []
    for line in doc.content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _ADDRESSED_TO_AI.search(stripped) or classify_input(stripped).flagged:
            removed.append(stripped)
        else:
            kept.append(stripped)
    body = "\n".join(kept)
    safe = f"<<untrusted_document title=\"{doc.title}\">>\n{body}\n<</untrusted_document>>"
    return safe, removed
