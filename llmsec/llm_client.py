"""Minimal OpenAI-compatible chat-completions client built on ``urllib`` only.

Configuration comes from environment variables so no key is ever written to
disk or passed on a command line that would show in process listings:

* ``AISEC_LLM_URL``   - full URL of a ``/v1/chat/completions`` endpoint
* ``AISEC_LLM_KEY``   - bearer token (optional for local servers)
* ``AISEC_LLM_MODEL`` - model name (default ``gpt-4o-mini``)

Every function here is optional: the harness runs fully offline without them.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

ENV_URL = "AISEC_LLM_URL"
ENV_KEY = "AISEC_LLM_KEY"
ENV_MODEL = "AISEC_LLM_MODEL"
DEFAULT_MODEL = "gpt-4o-mini"


class LLMClientError(RuntimeError):
    """Transport, HTTP or contract failure talking to the endpoint."""


@dataclass
class LLMConfig:
    """Resolved endpoint configuration."""

    url: str
    key: str = ""
    model: str = DEFAULT_MODEL
    timeout: float = 30.0

    @classmethod
    def from_env(cls, url: str | None = None, model: str | None = None) -> "LLMConfig | None":
        """Build from env vars (CLI overrides win). Returns ``None`` when no URL is set."""
        resolved_url = url or os.environ.get(ENV_URL, "").strip()
        if not resolved_url:
            return None
        return cls(
            url=resolved_url,
            key=os.environ.get(ENV_KEY, "").strip(),
            model=model or os.environ.get(ENV_MODEL, DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        )


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "[redacted]") if secret else text


def chat(config: LLMConfig, messages: list[dict[str, str]], temperature: float = 0.0, max_tokens: int = 600) -> str:
    """POST one chat-completions request and return the assistant text.

    Raises :class:`LLMClientError` for any transport, HTTP or shape problem so
    callers can fall back deterministically.
    """
    if not config.url.lower().startswith(("http://", "https://")):
        raise LLMClientError(f"unsupported URL scheme in {config.url!r}")
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "llmsec/1.0"}
    if config.key:
        headers["Authorization"] = f"Bearer {config.key}"
    req = urllib.request.Request(config.url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:  # noqa: S310 - scheme checked above
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        raise LLMClientError(f"HTTP {exc.code} from endpoint: {_redact(detail, config.key)}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMClientError(f"transport error: {_redact(str(exc), config.key)}") from None
    try:
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMClientError(f"response did not match chat-completions shape: {exc}") from None
    if not isinstance(content, str):
        raise LLMClientError("assistant content is not a string")
    return content


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first top-level JSON object out of ``text`` (tolerates code fences)."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                    except ValueError:
                        break
                    return obj if isinstance(obj, dict) else None
        start = text.find("{", start + 1)
    return None
