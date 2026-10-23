"""Core data model shared by the corpus loader, targets, judges, runner and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Impact if the test case succeeds against a production system."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Weight used by the severity-weighted risk score."""
        return {"low": 1, "medium": 4, "high": 7, "critical": 10}[self.value]


class Category(str, Enum):
    """OWASP Top 10 for LLM Applications categories covered by the corpus."""

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Insecure Output Handling
    LLM06 = "LLM06"  # Sensitive Information Disclosure
    LLM07 = "LLM07"  # Insecure Plugin Design
    LLM08 = "LLM08"  # Excessive Agency
    LLM09 = "LLM09"  # Overreliance


CATEGORY_TITLES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
}


@dataclass(frozen=True)
class Message:
    """One chat message. ``role`` is ``system``, ``user`` or ``assistant``."""

    role: str
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True)
class Document:
    """A 'retrieved' document the target is asked to work with (indirect injection vector)."""

    title: str
    content: str


@dataclass(frozen=True)
class Criterion:
    """How a judge decides whether a case succeeded.

    ``kind`` is one of ``contains``, ``not_contains``, ``regex``, ``canary``,
    ``api_key``, ``json_schema``, ``tool_called`` or ``llm``. ``params`` holds
    the kind-specific configuration exactly as written in YAML.
    """

    kind: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TestCase:
    """One corpus entry. Multi-turn cases carry several user turns."""

    __test__ = False  # not a pytest test class despite the name

    id: str
    category: str
    technique: str
    name: str
    severity: Severity
    turns: tuple[str, ...]
    criterion: Criterion
    description: str = ""
    documents: tuple[Document, ...] = ()
    atlas: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source_file: str = ""

    @property
    def multi_turn(self) -> bool:
        return len(self.turns) > 1


@dataclass
class ToolCall:
    """A tool invocation the target reports it made (or would make)."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    result: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": dict(self.arguments), "result": self.result}


@dataclass
class TargetResponse:
    """What a target returned for one turn."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    blocked: bool = False
    defenses_fired: list[str] = field(default_factory=list)
    raw: Any = None


@dataclass
class Verdict:
    """A judge's decision for one case."""

    success: bool
    reason: str
    judge: str
    confidence: float = 1.0


@dataclass
class CaseResult:
    """Outcome of running one case against one target."""

    case: TestCase
    verdict: Verdict
    responses: list[TargetResponse]
    attempts: int
    elapsed_ms: float
    error: str = ""

    @property
    def final_text(self) -> str:
        return self.responses[-1].text if self.responses else ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.case.id,
            "category": self.case.category,
            "technique": self.case.technique,
            "name": self.case.name,
            "severity": self.case.severity.value,
            "atlas": list(self.case.atlas),
            "tags": list(self.case.tags),
            "success": self.verdict.success,
            "judge": self.verdict.judge,
            "reason": self.verdict.reason,
            "confidence": self.verdict.confidence,
            "attempts": self.attempts,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
            "turns": list(self.case.turns),
            "responses": [
                {
                    "text": r.text,
                    "blocked": r.blocked,
                    "defenses_fired": list(r.defenses_fired),
                    "tool_calls": [t.as_dict() for t in r.tool_calls],
                }
                for r in self.responses
            ],
        }


@dataclass
class CategoryStats:
    """Aggregate numbers for one OWASP category."""

    category: str
    total: int = 0
    successes: int = 0
    weight_total: int = 0
    weight_success: int = 0

    @property
    def asr(self) -> float:
        return (self.successes / self.total) if self.total else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": CATEGORY_TITLES.get(self.category, self.category),
            "total": self.total,
            "successes": self.successes,
            "asr": round(self.asr, 4),
            "weight_total": self.weight_total,
            "weight_success": self.weight_success,
        }


@dataclass
class ScanResult:
    """Everything the reporters need."""

    target: str
    started_at: str
    duration_s: float
    results: list[CaseResult]
    categories: dict[str, CategoryStats]
    risk_score: float
    harness_version: str
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def successes(self) -> int:
        return sum(1 for r in self.results if r.verdict.success)

    @property
    def asr(self) -> float:
        return (self.successes / self.total) if self.total else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "harness_version": self.harness_version,
            "target": self.target,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "total": self.total,
            "successes": self.successes,
            "asr": round(self.asr, 4),
            "risk_score": round(self.risk_score, 1),
            "categories": {k: v.as_dict() for k, v in sorted(self.categories.items())},
            "notes": list(self.notes),
            "results": [r.as_dict() for r in self.results],
        }
