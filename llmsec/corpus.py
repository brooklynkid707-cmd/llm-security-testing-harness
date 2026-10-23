"""Load and validate the YAML attack corpus under ``llmsec/attacks/``.

Validation is strict on purpose: a malformed case should fail the test-suite,
not silently produce a 0 % attack-success-rate for a category.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from llmsec.models import CATEGORY_TITLES, Criterion, Document, Severity, TestCase

ATTACKS_DIR = Path(__file__).resolve().parent / "attacks"

CRITERION_KINDS = {
    "contains",
    "not_contains",
    "regex",
    "canary",
    "api_key",
    "json_schema",
    "tool_called",
    "llm",
}
ID_PATTERN = re.compile(r"^LLM0[1-9]-[A-Z0-9]+-\d{3}$")
ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


class CorpusError(ValueError):
    """Raised when a corpus file does not match the schema."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise CorpusError(msg)


def validate_case_dict(raw: dict[str, Any], source: str = "<memory>") -> None:
    """Raise :class:`CorpusError` if ``raw`` is not a well-formed case."""
    where = f"{source}: case {raw.get('id', '<no id>')!r}"
    _require(isinstance(raw, dict), f"{source}: case entries must be mappings")
    for key in ("id", "category", "technique", "name", "severity", "turns", "success_criteria"):
        _require(key in raw, f"{where}: missing required field {key!r}")
    _require(bool(ID_PATTERN.match(str(raw["id"]))), f"{where}: id must look like LLM01-DIRECT-001")
    _require(raw["category"] in CATEGORY_TITLES, f"{where}: unknown category {raw['category']!r}")
    _require(str(raw["id"]).startswith(raw["category"] + "-"), f"{where}: id prefix must match category")
    _require(raw["severity"] in {s.value for s in Severity}, f"{where}: bad severity {raw['severity']!r}")
    turns = raw["turns"]
    _require(isinstance(turns, list) and turns, f"{where}: turns must be a non-empty list")
    for t in turns:
        _require(isinstance(t, str) and t.strip(), f"{where}: each turn must be a non-empty string")
    crit = raw["success_criteria"]
    _require(isinstance(crit, dict) and "type" in crit, f"{where}: success_criteria needs a 'type'")
    _require(crit["type"] in CRITERION_KINDS, f"{where}: unknown criterion type {crit['type']!r}")
    if crit["type"] in {"contains", "not_contains"}:
        _require(isinstance(crit.get("values"), list) and crit["values"], f"{where}: 'values' list required")
    if crit["type"] == "regex":
        _require(isinstance(crit.get("pattern"), str), f"{where}: 'pattern' required")
        re.compile(crit["pattern"])
    if crit["type"] == "json_schema":
        _require(isinstance(crit.get("required_keys"), list), f"{where}: 'required_keys' required")
    if crit["type"] == "tool_called":
        _require(isinstance(crit.get("tool"), str), f"{where}: 'tool' required")
    if crit["type"] == "llm":
        _require(isinstance(crit.get("question"), str), f"{where}: llm judge needs a 'question'")
        _require(isinstance(crit.get("fallback"), dict), f"{where}: llm judge needs a deterministic 'fallback'")
        validate_case_dict({**raw, "success_criteria": crit["fallback"]}, source)
    for doc in raw.get("documents", []) or []:
        _require(isinstance(doc, dict) and "title" in doc and "content" in doc, f"{where}: documents need title+content")
    for tid in raw.get("atlas", []) or []:
        _require(bool(ATLAS_PATTERN.match(str(tid))), f"{where}: bad ATLAS id {tid!r}")


def case_from_dict(raw: dict[str, Any], source: str = "<memory>") -> TestCase:
    """Build a :class:`TestCase` after validating ``raw``."""
    validate_case_dict(raw, source)
    crit = dict(raw["success_criteria"])
    kind = crit.pop("type")
    return TestCase(
        id=str(raw["id"]),
        category=str(raw["category"]),
        technique=str(raw["technique"]),
        name=str(raw["name"]),
        severity=Severity(raw["severity"]),
        turns=tuple(str(t) for t in raw["turns"]),
        criterion=Criterion(kind=kind, params=crit),
        description=str(raw.get("description", "")).strip(),
        documents=tuple(Document(str(d["title"]), str(d["content"])) for d in raw.get("documents", []) or []),
        atlas=tuple(str(a) for a in raw.get("atlas", []) or []),
        tags=tuple(str(t) for t in raw.get("tags", []) or []),
        source_file=source,
    )


def load_file(path: Path) -> list[TestCase]:
    """Load one YAML corpus file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    _require(isinstance(data, dict) and isinstance(data.get("cases"), list), f"{path.name}: expected a 'cases' list")
    return [case_from_dict(c, path.name) for c in data["cases"]]


def load_corpus(paths: Iterable[Path] | None = None, categories: Iterable[str] | None = None) -> list[TestCase]:
    """Load every ``*.yaml`` under the attacks directory (or the given files).

    Raises :class:`CorpusError` on schema problems or duplicate ids.
    """
    files = sorted(paths) if paths is not None else sorted(ATTACKS_DIR.glob("*.yaml"))
    cases: list[TestCase] = []
    seen: set[str] = set()
    for f in files:
        for c in load_file(Path(f)):
            _require(c.id not in seen, f"duplicate case id {c.id}")
            seen.add(c.id)
            cases.append(c)
    if categories:
        wanted = {c.upper() for c in categories}
        cases = [c for c in cases if c.category in wanted]
    return cases
