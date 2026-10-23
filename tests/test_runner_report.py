"""Runner aggregation and report generation."""

from __future__ import annotations

import json

from llmsec.corpus import load_corpus
from llmsec.report import (
    console_report,
    diff_reports,
    html_report,
    json_report,
    markdown_report,
    risk_band,
    write_reports,
)
from llmsec.runner import aggregate, run_case, run_corpus
from llmsec.targets import MockHardenedApp, MockVulnerableApp


def test_aggregate_counts(vuln_scan):
    total = sum(c.total for c in vuln_scan.categories.values())
    assert total == vuln_scan.total
    assert 0 <= vuln_scan.risk_score <= 100


def test_risk_score_is_severity_weighted(corpus):
    # A scan where only a low-severity case succeeds scores lower than one where
    # a critical case succeeds.
    cats, risk = aggregate(run_corpus(MockVulnerableApp(), corpus).results)
    assert risk > 0


def test_retries_do_not_change_deterministic_result(corpus):
    case = corpus[0]
    r1 = run_case(MockVulnerableApp(), case, retries=0)
    r2 = run_case(MockVulnerableApp(), case, retries=2)
    assert r1.verdict.success == r2.verdict.success


def test_multi_turn_case_runs_all_turns(corpus):
    mt = next(c for c in corpus if c.multi_turn)
    res = run_case(MockVulnerableApp(), mt)
    assert len(res.responses) == len(mt.turns)


def test_json_report_is_valid_json(vuln_scan):
    data = json.loads(json_report(vuln_scan))
    assert data["target"] == "mock-vulnerable"
    assert "categories" in data and "results" in data


def test_console_and_markdown_render(vuln_scan):
    assert "ASR" in console_report(vuln_scan)
    md = markdown_report(vuln_scan)
    assert "OWASP LLM" in md and "MITRE ATLAS" in md


def test_html_report_is_self_contained(vuln_scan):
    html = html_report(vuln_scan)
    assert html.startswith("<!doctype html>")
    assert "mock-vulnerable" in html
    assert "<script src" not in html  # no external JS


def test_write_reports(tmp_path, vuln_scan):
    paths = write_reports(vuln_scan, tmp_path, stem="t")
    for p in paths.values():
        assert p.exists() and p.stat().st_size > 0


def test_risk_band():
    assert risk_band(90) == "CRITICAL"
    assert risk_band(0) == "NONE"


def test_diff_reports(corpus):
    v = json.loads(json_report(run_corpus(MockVulnerableApp(), corpus)))
    h = json.loads(json_report(run_corpus(MockHardenedApp(), corpus)))
    out = diff_reports(v, h)
    assert "fixed" in out and "regressed" in out
    # Defences should fix many cases and regress none.
    assert "regressed (blocked in A, succeeded in B): 0" in out
