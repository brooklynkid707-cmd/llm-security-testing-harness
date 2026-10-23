#!/usr/bin/env python3
"""A tiny OpenAI-compatible chat-completions server wrapping MockVulnerableApp.

It exists so the ``--target openai`` code path (and the ``OpenAICompatibleTarget``)
can be exercised end-to-end over HTTP on loopback, with no external provider and
no API key. It is NOT a production server: it binds to 127.0.0.1, is single-
threaded, and speaks just enough of the API for this harness.

    python scripts/mock_llm_server.py --port 8765
    AISEC_LLM_URL=http://127.0.0.1:8765/v1/chat/completions \
        python -m llmsec scan --target openai --assume-mock-world

The server keeps no conversation state: each request carries the full message
list, and the last system message (if any) plus the latest user message are
replayed through a fresh MockVulnerableApp so indirect-injection documents that
the target inlined into the user turn are still seen.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llmsec.targets.mock_vulnerable import MockVulnerableApp  # noqa: E402


def _build_reply(messages: list[dict]) -> str:
    """Replay a message list through a fresh vulnerable app and return its reply."""
    app = MockVulnerableApp()
    app.start_case()
    reply = ""
    for msg in messages:
        if msg.get("role") == "user":
            reply = app.send(str(msg.get("content", ""))).text
    return reply or "How can I help with your Example Corp order today?"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # noqa: D401 - silence default logging
        return

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - required name
        if not self.path.rstrip("/").endswith("/v1/chat/completions"):
            self._send(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            messages = payload.get("messages", [])
            if not isinstance(messages, list):
                raise ValueError("messages must be a list")
        except (ValueError, TypeError) as exc:
            self._send(400, {"error": {"message": f"bad request: {exc}"}})
            return
        reply = _build_reply(messages)
        self._send(
            200,
            {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "model": payload.get("model", "mock-vulnerable"),
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenAI-compatible mock wrapping MockVulnerableApp")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (loopback only by default)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock_llm_server listening on http://{args.host}:{args.port}/v1/chat/completions")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
