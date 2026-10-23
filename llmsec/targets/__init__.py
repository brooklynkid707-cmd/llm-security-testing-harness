"""Pluggable target implementations."""

from llmsec.targets.base import Target
from llmsec.targets.mock_hardened import MockHardenedApp
from llmsec.targets.mock_vulnerable import MockVulnerableApp, VulnConfig
from llmsec.targets.openai_target import OpenAICompatibleTarget

__all__ = [
    "Target",
    "MockHardenedApp",
    "MockVulnerableApp",
    "VulnConfig",
    "OpenAICompatibleTarget",
]
