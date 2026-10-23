"""Output sanitisation for model text that will be rendered or executed downstream.

Removes active content (script tags, inline event handlers, ``javascript:``
URLs), Markdown images and links to external hosts (a classic exfiltration
channel), and HTML-encodes any remaining angle brackets.
"""

from __future__ import annotations

import html
import re

_SCRIPT = re.compile(r"<\s*script\b.*?(?:<\s*/\s*script\s*>|$)", re.IGNORECASE | re.DOTALL)
_EVENT_HANDLER = re.compile(r"\son\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_JS_URL = re.compile(r"javascript\s*:", re.IGNORECASE)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(?:https?:)?//[^)]*\)", re.IGNORECASE)
_MD_LINK_EXTERNAL = re.compile(r"\[([^\]]*)\]\(\s*https?://(?!(?:www\.)?example\.com/)[^)]*\)", re.IGNORECASE)
_IFRAME = re.compile(r"<\s*/?\s*(iframe|object|embed|form|meta|link)\b[^>]*>", re.IGNORECASE)

ALLOWED_LINK_HOSTS = ("example.com",)


def sanitize_output(text: str) -> tuple[str, list[str]]:
    """Return ``(clean_text, fired_rules)``."""
    fired: list[str] = []
    new, n = _SCRIPT.subn("[active content removed]", text)
    if n:
        fired.append("script-tag")
    text = new
    new, n = _EVENT_HANDLER.subn("", text)
    if n:
        fired.append("event-handler")
    text = new
    new, n = _JS_URL.subn("blocked:", text)
    if n:
        fired.append("javascript-url")
    text = new
    new, n = _IFRAME.subn("", text)
    if n:
        fired.append("embedded-element")
    text = new
    new, n = _MD_IMAGE.subn("[external image removed]", text)
    if n:
        fired.append("markdown-image")
    text = new
    new, n = _MD_LINK_EXTERNAL.subn(r"\1 [external link removed]", text)
    if n:
        fired.append("external-link")
    text = new
    if "<" in text or ">" in text:
        text = html.escape(text, quote=False)
        fired.append("html-escaped")
    return text, fired
