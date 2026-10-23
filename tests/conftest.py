"""Shared fixtures: load the corpus once and run each mock target once."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llmsec.corpus import load_corpus
from llmsec.runner import run_corpus
from llmsec.targets import MockHardenedApp, MockVulnerableApp


@pytest.fixture(scope="session")
def corpus():
    return load_corpus()


@pytest.fixture(scope="session")
def vuln_scan(corpus):
    return run_corpus(MockVulnerableApp(), corpus)


@pytest.fixture(scope="session")
def hardened_scan(corpus):
    return run_corpus(MockHardenedApp(), corpus)
