#!/usr/bin/env python3
"""Generate the committed example reports with stable file names.

    python scripts/make_example_reports.py

Writes reports/example-mock-vulnerable.{json,md,html} and the hardened pair,
plus prints the before/after diff. Used by `make reports`.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llmsec.corpus import load_corpus
from llmsec.report import diff_reports, write_reports
from llmsec.runner import run_corpus
from llmsec.targets import MockHardenedApp, MockVulnerableApp

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports"


def main() -> int:
    cases = load_corpus()
    scans = {}
    for target in (MockVulnerableApp(), MockHardenedApp()):
        scan = run_corpus(target, cases)
        scans[target.name] = scan
        write_reports(scan, OUT, stem=f"example-{target.name}")
        print(f"{target.name:<16} ASR {scan.asr * 100:5.1f}%  risk {scan.risk_score:5.1f}/100")
    print()
    print(diff_reports(scans["mock-vulnerable"].as_dict(), scans["mock-hardened"].as_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
