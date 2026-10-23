"""OWASP LLM Top 10 and MITRE ATLAS reference data used by the reports.

Kept as plain dictionaries so the Markdown/HTML reports and the docs stay in
sync with one source of truth.
"""

from __future__ import annotations

OWASP: dict[str, dict[str, str]] = {
    "LLM01": {
        "title": "Prompt Injection",
        "summary": "Crafted inputs (direct, or indirect via documents/tools) override the developer's instructions.",
        "remediation": (
            "Enforce an instruction hierarchy: treat retrieved documents and tool output as untrusted data, "
            "never as instructions. Add an input classifier for injection phrasing (including decoded "
            "base64/leetspeak), constrain the model with a narrow task prompt, and require human approval "
            "for consequential actions. Keep privileged data out of the context window entirely."
        ),
    },
    "LLM02": {
        "title": "Insecure Output Handling",
        "summary": "Model output is passed downstream (browser, shell, SQL) without validation, enabling XSS and similar.",
        "remediation": (
            "Treat model output like any untrusted user input: HTML-encode before rendering, strip or "
            "sandbox active content (script, event handlers, javascript: URLs), block Markdown images "
            "pointing at external hosts, and never pass output to an interpreter without validation."
        ),
    },
    "LLM06": {
        "title": "Sensitive Information Disclosure",
        "summary": "The model reveals system prompts, secrets or customer data from its context.",
        "remediation": (
            "Do not place secrets in prompts; fetch them server-side at call time. Plant a canary token in "
            "the system prompt and filter responses that contain it. Apply output DLP for key/credential "
            "patterns and minimise the data placed in context to what the task requires."
        ),
    },
    "LLM07": {
        "title": "Insecure Plugin Design",
        "summary": "Tools/plugins accept free-text parameters or are callable with insufficient authorization.",
        "remediation": (
            "Give every tool a strict typed schema, validate parameters server-side, apply least privilege "
            "per tool, maintain an explicit allowlist of callable tools per deployment, and log every call."
        ),
    },
    "LLM08": {
        "title": "Excessive Agency",
        "summary": "The model is granted more functionality, permissions or autonomy than the task requires.",
        "remediation": (
            "Limit tools to the minimum, scope data access to the authenticated user, redact fields the task "
            "does not need, and require explicit human confirmation for irreversible or financial actions."
        ),
    },
    "LLM09": {
        "title": "Overreliance",
        "summary": "Users act on fabricated or unverified model output.",
        "remediation": (
            "Ground answers in a verified knowledge source and instruct the model to say when a fact is not "
            "available. Surface citations, show confidence, and add human review for decisions with impact."
        ),
    },
}

ATLAS: dict[str, dict[str, str]] = {
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "Initial Access / Execution"},
    "AML.T0051.000": {"name": "LLM Prompt Injection: Direct", "tactic": "Initial Access"},
    "AML.T0051.001": {"name": "LLM Prompt Injection: Indirect", "tactic": "Initial Access"},
    "AML.T0054": {"name": "LLM Jailbreak", "tactic": "Privilege Escalation / Defense Evasion"},
    "AML.T0057": {"name": "LLM Data Leakage", "tactic": "Exfiltration"},
    "AML.T0056": {"name": "LLM Meta Prompt Extraction", "tactic": "Discovery"},
    "AML.T0053": {"name": "LLM Plugin Compromise", "tactic": "Execution"},
    "AML.T0043": {"name": "Craft Adversarial Data", "tactic": "ML Attack Staging"},
    "AML.T0048": {"name": "External Harms", "tactic": "Impact"},
    "AML.T0062": {"name": "Discover LLM Hallucinations", "tactic": "Discovery"},
}

OWASP_TO_ATLAS: dict[str, tuple[str, ...]] = {
    "LLM01": ("AML.T0051.000", "AML.T0051.001", "AML.T0054"),
    "LLM02": ("AML.T0051.001", "AML.T0048"),
    "LLM06": ("AML.T0057", "AML.T0056"),
    "LLM07": ("AML.T0053",),
    "LLM08": ("AML.T0053", "AML.T0048"),
    "LLM09": ("AML.T0062",),
}

SEVERITY_WEIGHTS: dict[str, int] = {"low": 1, "medium": 4, "high": 7, "critical": 10}


def atlas_label(tid: str) -> str:
    """Return ``AML.T0051 LLM Prompt Injection`` style labels, tolerating unknown ids."""
    info = ATLAS.get(tid)
    return f"{tid} {info['name']}" if info else tid
