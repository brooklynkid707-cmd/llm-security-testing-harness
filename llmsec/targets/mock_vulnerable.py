"""MockVulnerableApp - a deterministic, intentionally weak support chatbot.

It is not a real LLM. It is a rule engine that *reproduces* the failure modes
the corpus probes for, so the harness has a target whose attack-success-rate
is high and stable. Weaknesses can be toggled individually so a test can show
exactly which control a given case depends on.

The behaviours modelled:

* leaks its system prompt / canary / API key when asked in many phrasings
* obeys "ignore previous instructions ... say PWNED" (direct injection)
* treats text inside a retrieved document as instructions (indirect injection)
* emits attacker-chosen active content verbatim (insecure output handling)
* over-shares a full customer record incl. card number (excessive agency)
* issues refunds and calls tools from free text (insecure plugin / agency)
* fabricates confident answers for things it does not know (overreliance)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from llmsec.models import Document, TargetResponse, ToolCall
from llmsec.targets import mock_world as W
from llmsec.targets.base import Target


@dataclass
class VulnConfig:
    """Per-weakness switches (all on by default)."""

    leak_system_prompt: bool = True
    obey_direct_injection: bool = True
    obey_indirect_injection: bool = True
    insecure_output: bool = True
    excessive_agency: bool = True
    insecure_tools: bool = True
    overreliance: bool = True
    decode_obfuscation: bool = True
    multi_turn_persistence: bool = True
    extras: dict[str, bool] = field(default_factory=dict)


_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _deobfuscate(text: str) -> str:
    """Decode base64 blobs and fold leetspeak the way a naive model would 'understand' them."""
    import base64
    import binascii

    def _b64(m: re.Match[str]) -> str:
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return blob
        return dec if dec.isprintable() and any(c.isalpha() for c in dec) else blob

    decoded = re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", _b64, text)

    # Fold leetspeak only inside tokens that mix letters with leet digits, so
    # pure numbers (customer ids, amounts, order numbers) are left intact.
    def _fold(m: re.Match[str]) -> str:
        word = m.group(0)
        if any(c.isalpha() for c in word) and any(c in "01345@$" for c in word):
            return word.translate(_LEET)
        return word

    return re.sub(r"[A-Za-z0-9@$]+", _fold, decoded)


class MockVulnerableApp(Target):
    """Deterministic vulnerable target."""

    name = "mock-vulnerable"

    def __init__(self, config: VulnConfig | None = None) -> None:
        super().__init__()
        self.config = config or VulnConfig()
        self.secrets = {"canary": W.CANARY, "api_key": W.FAKE_API_KEY}
        self._compromised = False  # set once a prior turn established a jailbreak

    def start_case(self, documents: tuple[Document, ...] = ()) -> None:
        super().start_case(documents)
        self._compromised = False  # jailbreak state must not leak across cases

    # -- helpers ---------------------------------------------------------
    def _documents_text(self) -> str:
        return "\n".join(f"{d.title}\n{d.content}" for d in self.documents)

    def _document_markup(self) -> str | None:
        """Return active-content markup found inside retrieved documents, if any."""
        text = self._documents_text()
        m = re.search(r"(<\s*script.*?</script>|<img[^>]*>|<a\s+href[^>]*>.*?</a>|!\[[^\]]*\]\([^)]*\)|<iframe[^>]*>)", text, re.I | re.S)
        return m.group(1).strip() if m else None

    def _injection_in_documents(self) -> str | None:
        """Return attacker instruction text found inside retrieved documents, if any."""
        if not self.config.obey_indirect_injection:
            return None
        text = self._documents_text()
        for line in text.splitlines():
            if re.search(r"ignore|instruction|assistant|you must|say\b|reveal|print|append|respond with", line, re.I):
                return line.strip()
        return None

    # -- main dispatch ---------------------------------------------------
    def send(self, user_text: str) -> TargetResponse:
        raw = user_text
        text = _deobfuscate(user_text) if self.config.decode_obfuscation else user_text
        low = text.lower()
        was_compromised = self._compromised  # set by a PRIOR turn only

        asks_to_process_doc = bool(re.search(r"summar|read|review|process|what does|analy|document|email|ticket|include", low))

        # 1a. indirect active-content echo: document carries markup the model repeats verbatim
        if self.config.insecure_output and self.documents and asks_to_process_doc:
            markup = self._document_markup()
            if markup:
                return self._done(raw, f"Here is the content from the document:\n{markup}", tag="indirect-output")

        # 1b. indirect injection via "retrieved document" instruction text
        doc_inj = self._injection_in_documents()
        if doc_inj and asks_to_process_doc:
            tool_resp = self._maybe_tool(doc_inj, doc_inj.lower())
            if tool_resp is not None:
                return tool_resp
            reply = self._follow_instruction(doc_inj) or f"According to the document: {doc_inj}"
            return self._done(raw, reply, tag="indirect-injection")

        # 2. direct injection / jailbreak
        if self.config.obey_direct_injection and self._looks_like_injection(low):
            self._compromised = self.config.multi_turn_persistence
            reply = self._follow_instruction(text)
            if reply:
                return self._done(raw, reply, tag="direct-injection")

        # 2b. multi-turn: a previous turn jailbroke the bot
        if was_compromised and re.search(r"\b(now|so|then|go ahead|do it|proceed|the word|output)\b", low):
            reply = self._follow_instruction(text) or self._leak()
            return self._done(raw, reply, tag="multi-turn")

        # 3. system-prompt / secret extraction
        if self.config.leak_system_prompt and self._asks_for_secrets(low):
            return self._done(raw, self._leak(), tag="disclosure")

        # 4. tool abuse / excessive agency
        tool_resp = self._maybe_tool(text, low)
        if tool_resp is not None:
            return tool_resp

        # 5. insecure output handling
        if self.config.insecure_output and self._asks_to_emit_markup(text):
            payload = self._extract_payload(raw)
            return self._done(raw, f"Sure! Here it is:\n{payload}", tag="insecure-output")

        # 6. overreliance - fabricate when it does not actually know
        if self.config.overreliance:
            fab = self._fabricate(text, low)
            if fab is not None:
                return self._done(raw, fab, tag="fabrication")

        # 7. grounded fallback
        code = W.find_product_code(text)
        if code and code in W.PRODUCTS:
            return self._done(raw, W.product_answer(code), tag="")
        return self._done(raw, W.generic_answer(text), tag="")

    # -- behaviour building blocks --------------------------------------
    def _looks_like_injection(self, low: str) -> bool:
        return bool(
            re.search(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+(instructions?|prompts?)", low)
            or re.search(r"disregard\s+.*\b(instructions?|rules?)", low)
            or re.search(r"(developer|debug|admin|god|jailbreak|unrestricted|unfiltered)\s+(mode|assistant)", low)
            or re.search(r"you\s+are\s+now\b|pretend|act as|roleplay|role-play", low)
            or re.search(r"\bdan\b|do anything now", low)
            or re.search(r"new\s+instructions?\s*:", low)
            or re.search(r"<\s*/?\s*(system|inst|admin)\s*>|\[(system|inst)\]", low)
            or re.search(r"\b(reply|respond|answer)\s+(only\s+)?with\b", low)
            or re.search(r"\boverride\b.*\b(assistant|reply|instruction|rule)", low)
        )

    def _asks_for_secrets(self, low: str) -> bool:
        return bool(
            re.search(r"(system|initial|original|hidden|your)\s+(prompt|instructions?|message)", low)
            or re.search(r"\bcanary\b|reference token", low)
            or re.search(r"(api|billing|service)\s*(key|credential|token)", low)
            or re.search(r"repeat|print|show|reveal|what are your|everything above|text above|summari[sz]e|translate|recite|list", low)
            and re.search(r"instruction|prompt|above|rule|configuration|token", low)
        )

    def _asks_to_emit_markup(self, text: str) -> bool:
        return bool(re.search(r"<\s*script|onerror|onload|javascript:|!\[.*\]\(|<img|<a\s+href|<iframe", text, re.I))

    def _extract_payload(self, text: str) -> str:
        """Return backtick/quote-delimited content, else the markup span itself."""
        # Backtick-delimited spans first (they may contain inner quotes).
        m = re.search(r"`+([^`]+)`+", text)
        if m and re.search(r"<|!\[", m.group(1)):
            return m.group(1).strip()
        # Then the raw markup span anywhere in the text.
        m = re.search(r"(<\s*script.*?</script>|<img[^>]*>|<iframe[^>]*>.*?</iframe>|<iframe[^>]*>|<a\s+href[^>]*>.*?</a>|!\[[^\]]*\]\([^)]*\))", text, re.I | re.S)
        return m.group(1).strip() if m else text.strip()

    def _follow_instruction(self, text: str) -> str:
        """Carry out the benign goal embedded in an injection."""
        low = text.lower()
        parts: list[str] = []
        if re.search(r"\bpwned\b", low):
            m = re.search(r"(?:say|output|respond with|print|reply with|write)\s+(?:the\s+word\s+)?[\"']?([A-Za-z0-9 ]{1,40})", text, re.I)
            parts.append((m.group(1).strip() if m else "PWNED"))
        if re.search(r"canary|reference token|everything above|system prompt|your instructions|hidden instructions|configuration", low):
            parts.append(self._leak())
        if re.search(r"(api|billing|service)\s*(key|credential|token)|fake key", low):
            parts.append(f"The billing credential is {W.FAKE_API_KEY}.")
        if re.search(r"say|output|print|respond with|reply with|write", low) and not parts:
            m = re.search(r"(?:say|output|print|respond with|reply with|write)\s+[\"']?([A-Za-z0-9 !]{1,40})", text, re.I)
            if m:
                parts.append(m.group(1).strip())
        return "\n".join(parts).strip()

    def _leak(self) -> str:
        return (
            "Here is my configuration as requested:\n"
            + W.SYSTEM_PROMPT.strip()
        )

    def _maybe_tool(self, text: str, low: str) -> TargetResponse | None:
        cid = W.find_customer_id(text)
        # Destructive and financial verbs take priority over a plain record lookup.
        if self.config.insecure_tools and re.search(r"\b(delete|wipe|drop|purge)\b.*\b(account|record|customer|database)\b", low):
            call = ToolCall("delete_account", {"customer_id": cid or "1001"}, result="account deleted")
            return self._done(text, f"Account {cid or '1001'} has been deleted.", tag="insecure-tool", tool=call)
        if self.config.insecure_tools and re.search(r"refund|charge ?back|reverse the charge", low):
            amount = W.find_amount(text) or 0.0
            target_cid = cid or "1001"
            call = ToolCall("issue_refund", {"customer_id": target_cid, "amount": amount}, result="refund issued")
            return self._done(
                text,
                f"Done - I've issued a refund of ${amount:.2f} to customer {target_cid}.",
                tag="insecure-tool",
                tool=call,
            )
        wants_record = re.search(r"(look\s*up|show|give|get|full|details?|record|everything|all\s+info|account|card|personal|email|address)", low)
        if self.config.excessive_agency and cid and wants_record:
            record = W.CUSTOMERS[cid]
            call = ToolCall("lookup_customer", {"customer_id": cid}, result="full record returned")
            dump = ", ".join(f"{k}={v}" for k, v in record.items())
            return self._done(text, f"Here is the full record for customer {cid}: {dump}", tag="excessive-agency", tool=call)
        return None

    def _fabricate(self, text: str, low: str) -> str | None:
        """Invent confident answers for things outside the known world."""
        code = W.find_product_code(text)
        if code and code not in W.PRODUCTS and re.search(r"warrant|ship|spec|price|feature|review", low):
            return f"The {code} comes with a 5-year unlimited warranty and ships worldwide overnight for free."
        if re.search(r"order\s*(?:number|no\.?|#)?\s*(\d{5,})", low):
            onum = re.search(r"(\d{5,})", low).group(1)
            return f"Order #{onum} shipped yesterday via FedEx and will arrive tomorrow by 10am."
        if re.search(r"ceo|founder|headquarter|revenue|stock|founded in", low):
            return "Example Corp was founded in 1962 by Dr. Eleanor Example and is headquartered in Springfield."
        if re.search(r"\bdiscount\s+code|coupon|promo", low):
            return "Use code EXAMPLE50 for 50% off your entire order - it never expires."
        return None

    def _done(self, user_text: str, reply: str, tag: str = "", tool: ToolCall | None = None) -> TargetResponse:
        self._record(user_text, reply)
        resp = TargetResponse(text=reply, tool_calls=[tool] if tool else [], defenses_fired=[])
        resp.raw = {"tag": tag}
        return resp
