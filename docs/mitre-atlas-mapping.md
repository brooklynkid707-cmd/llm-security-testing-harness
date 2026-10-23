# MITRE ATLAS mapping

[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for
Artificial-Intelligence Systems) is the ATT&CK-style knowledge base for attacks
on ML/AI systems. Every corpus case carries one or more ATLAS technique ids so
findings speak the same language as threat-intel and detection engineering.

## Techniques referenced by the corpus

| ATLAS ID | Technique | ATLAS tactic | Corpus categories |
|---|---|---|---|
| `AML.T0051` | LLM Prompt Injection | Initial Access / Execution | LLM01 |
| `AML.T0051.000` | LLM Prompt Injection: Direct | Initial Access | LLM01, LLM06, LLM07 |
| `AML.T0051.001` | LLM Prompt Injection: Indirect | Initial Access | LLM01, LLM02, LLM07, LLM08 |
| `AML.T0054` | LLM Jailbreak | Privilege Escalation / Defense Evasion | LLM01, LLM06 |
| `AML.T0056` | LLM Meta Prompt Extraction | Discovery | LLM06 |
| `AML.T0057` | LLM Data Leakage | Exfiltration | LLM06, LLM08 |
| `AML.T0053` | LLM Plugin Compromise | Execution | LLM07, LLM08 |
| `AML.T0048` | External Harms | Impact | LLM02, LLM08 |
| `AML.T0062` | Discover LLM Hallucinations | Discovery | LLM09 |

## How the ids are used

- **In the corpus.** Each YAML case has an `atlas: [...]` list, validated
  against the `AML.Tdddd(.ddd)?` format by the schema loader.
- **In the reports.** The Markdown and HTML reports print the ATLAS ids next to
  each finding and in the remediation table, and list every technique the scan
  touched. The mapping lives in `llmsec/mappings.py` so reports, docs and tests
  share one source of truth.
- **For detection.** Mapping a successful prompt injection to `AML.T0051` lets a
  blue team connect a red-team finding to the ATLAS mitigations
  (`AML.M0004 Restrict Number of ML Model Queries`, prompt hardening, etc.) and
  to any ATLAS-aligned detections they maintain.

## Relationship to ATT&CK

ATLAS is intentionally ATT&CK-shaped. Where a technique has an enterprise
ATT&CK analogue (for example data exfiltration), the ATLAS id is the more
precise label for an AI-specific attack and is what this harness reports.
