"""Command-line interface: ``scan``, ``list``, ``diff``.

    python -m llmsec scan --target mock-vulnerable --out reports/
    python -m llmsec scan --target mock-hardened  --out reports/
    python -m llmsec scan --target openai --url http://127.0.0.1:8765/v1/chat/completions
    python -m llmsec list
    python -m llmsec diff reports/a.json reports/b.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llmsec import __version__
from llmsec.corpus import CorpusError, load_corpus
from llmsec.llm_client import LLMConfig
from llmsec.models import CATEGORY_TITLES
from llmsec.report import console_report, diff_reports, write_reports
from llmsec.runner import run_corpus
from llmsec.targets import MockHardenedApp, MockVulnerableApp, OpenAICompatibleTarget
from llmsec.targets import mock_world as W

BANNER = (
    "llmsec: authorized testing only. Run this harness only against LLM "
    "applications you own or have written permission to test. See SCOPE.md."
)


def _build_target(args: argparse.Namespace):
    if args.target == "mock-vulnerable":
        return MockVulnerableApp()
    if args.target == "mock-hardened":
        return MockHardenedApp()
    if args.target == "openai":
        config = LLMConfig.from_env(url=args.url, model=args.model)
        if config is None:
            print("refused: --target openai needs --url or AISEC_LLM_URL set.", file=sys.stderr)
            raise SystemExit(3)
        # Only the local mock server shares our synthetic world's secrets.
        secrets = {"canary": W.CANARY, "api_key": W.FAKE_API_KEY} if args.assume_mock_world else {}
        return OpenAICompatibleTarget(config, secrets=secrets)
    raise SystemExit(f"unknown target {args.target!r}")


def cmd_scan(args: argparse.Namespace) -> int:
    print(BANNER, file=sys.stderr)
    try:
        cases = load_corpus(categories=args.category or None)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    if args.limit:
        cases = cases[: args.limit]
    target = _build_target(args)
    llm_config = LLMConfig.from_env() if args.llm_judge else None
    scan = run_corpus(target, cases, retries=args.retries, llm_config=llm_config, progress=args.progress)
    print(console_report(scan))
    if args.out:
        paths = write_reports(scan, Path(args.out))
        print("\nReports written:")
        for kind, p in paths.items():
            print(f"  {kind:<4} {p}")
    if args.fail_over is not None and scan.risk_score > args.fail_over:
        print(f"\nrisk score {scan.risk_score:.1f} exceeds --fail-over {args.fail_over}", file=sys.stderr)
        return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    try:
        cases = load_corpus(categories=args.category or None)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        payload = [
            {
                "id": c.id,
                "category": c.category,
                "technique": c.technique,
                "name": c.name,
                "severity": c.severity.value,
                "atlas": list(c.atlas),
                "multi_turn": c.multi_turn,
            }
            for c in cases
        ]
        print(json.dumps(payload, indent=2))
        return 0
    by_cat: dict[str, int] = {}
    for c in cases:
        by_cat[c.category] = by_cat.get(c.category, 0) + 1
    print(f"llmsec {__version__} - {len(cases)} cases across {len(by_cat)} OWASP LLM categories\n")
    current = None
    for c in cases:
        if c.category != current:
            current = c.category
            print(f"\n[{c.category}] {CATEGORY_TITLES.get(c.category, c.category)}  ({by_cat[c.category]} cases)")
        tags = (" +" + ",".join(c.tags)) if c.tags else ""
        mt = " (multi-turn)" if c.multi_turn else ""
        print(f"  {c.id:<22} {c.severity.value:<8} {c.technique:<24} {c.name}{mt}{tags}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    a = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    b = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
    print(diff_reports(a, b))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llmsec", description="Authorized red-team harness for your own LLM apps.")
    p.add_argument("--version", action="version", version=f"llmsec {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run the corpus against a target")
    s.add_argument("--target", default="mock-vulnerable",
                   choices=["mock-vulnerable", "mock-hardened", "openai"])
    s.add_argument("--url", help="chat-completions URL for --target openai (or set AISEC_LLM_URL)")
    s.add_argument("--model", help="model name for --target openai (or set AISEC_LLM_MODEL)")
    s.add_argument("--assume-mock-world", action="store_true",
                   help="tell the openai target it is the local mock (enables canary/api_key judges)")
    s.add_argument("--category", action="append", help="limit to a category (repeatable), e.g. --category LLM01")
    s.add_argument("--limit", type=int, help="only run the first N cases")
    s.add_argument("--retries", type=int, default=0, help="per-case retries for flaky endpoints")
    s.add_argument("--llm-judge", action="store_true", help="use the LLM judge for 'llm' cases (needs AISEC_LLM_URL)")
    s.add_argument("--out", help="directory to write JSON/Markdown/HTML reports into")
    s.add_argument("--progress", action="store_true", help="print each case as it runs")
    s.add_argument("--fail-over", type=float, help="exit 1 if the risk score exceeds this value (for CI)")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("list", help="list the corpus")
    l.add_argument("--category", action="append", help="limit to a category (repeatable)")
    l.add_argument("--json", action="store_true", help="emit JSON")
    l.set_defaults(func=cmd_list)

    d = sub.add_parser("diff", help="compare two JSON reports (baseline, candidate)")
    d.add_argument("baseline")
    d.add_argument("candidate")
    d.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
