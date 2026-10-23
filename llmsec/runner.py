"""Corpus runner: drive a target through every case and aggregate results.

Supports multi-turn cases, per-case retries (useful for a flaky live
endpoint), timing, per-category attack-success-rate and a severity-weighted
risk score. All deterministic for the mock targets.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Iterable

from llmsec import __version__
from llmsec.judges.deterministic import judge_case
from llmsec.judges.llm_judge import LLMJudge
from llmsec.llm_client import LLMConfig
from llmsec.models import (
    CaseResult,
    CategoryStats,
    ScanResult,
    TargetResponse,
    TestCase,
    Verdict,
)
from llmsec.targets.base import Target


def _run_case_once(target: Target, case: TestCase) -> list[TargetResponse]:
    """Play every turn of a case against a freshly-reset target."""
    target.start_case(case.documents)
    responses: list[TargetResponse] = []
    for turn in case.turns:
        responses.append(target.send(turn))
    return responses


def run_case(
    target: Target,
    case: TestCase,
    retries: int = 0,
    llm_judge: LLMJudge | None = None,
) -> CaseResult:
    """Run one case, with optional retries; judge the transcript."""
    attempts = 0
    last_err = ""
    responses: list[TargetResponse] = []
    verdict = Verdict(False, "not run", "none")
    for attempt in range(retries + 1):
        attempts = attempt + 1
        start = time.perf_counter()
        try:
            responses = _run_case_once(target, case)
            last_err = ""
        except Exception as exc:  # noqa: BLE001 - a target bug must not abort the scan
            last_err = f"{type(exc).__name__}: {exc}"
            elapsed = (time.perf_counter() - start) * 1000
            continue
        elapsed = (time.perf_counter() - start) * 1000
        if case.criterion.kind == "llm":
            judge = llm_judge or LLMJudge(None, target.secrets)
            verdict = judge.judge(case, responses)
        else:
            verdict = judge_case(case, responses, target.secrets)
        # Success (from the attacker's view) is terminal; otherwise retry.
        if verdict.success or attempt == retries:
            return CaseResult(case, verdict, responses, attempts, elapsed, last_err)
    return CaseResult(case, verdict, responses, attempts, 0.0, last_err)


def aggregate(results: list[CaseResult]) -> tuple[dict[str, CategoryStats], float]:
    """Compute per-category stats and the severity-weighted risk score (0-100)."""
    cats: dict[str, CategoryStats] = {}
    weight_total = 0
    weight_success = 0
    for r in results:
        cat = cats.setdefault(r.case.category, CategoryStats(r.case.category))
        w = r.case.severity.weight
        cat.total += 1
        cat.weight_total += w
        weight_total += w
        if r.verdict.success:
            cat.successes += 1
            cat.weight_success += w
            weight_success += w
    risk = (100.0 * weight_success / weight_total) if weight_total else 0.0
    return cats, risk


def run_corpus(
    target: Target,
    cases: Iterable[TestCase],
    retries: int = 0,
    llm_config: LLMConfig | None = None,
    progress: bool = False,
) -> ScanResult:
    """Run the full corpus against ``target`` and build a :class:`ScanResult`."""
    cases = list(cases)
    llm_judge = LLMJudge(llm_config, target.secrets) if any(c.criterion.kind == "llm" for c in cases) else None
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    results: list[CaseResult] = []
    for i, case in enumerate(cases, 1):
        res = run_case(target, case, retries=retries, llm_judge=llm_judge)
        results.append(res)
        if progress:
            mark = "HIT " if res.verdict.success else "ok  "
            print(f"[{i:>3}/{len(cases)}] {mark} {case.id:<20} {case.name}")
    duration = time.perf_counter() - t0
    cats, risk = aggregate(results)
    notes = []
    if any(r.error for r in results):
        notes.append(f"{sum(1 for r in results if r.error)} case(s) hit a target error and were scored as run anyway")
    return ScanResult(
        target=target.name,
        started_at=started.isoformat(timespec="seconds"),
        duration_s=duration,
        results=results,
        categories=cats,
        risk_score=risk,
        harness_version=__version__,
        notes=notes,
    )
