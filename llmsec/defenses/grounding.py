"""Grounding guard against overreliance (LLM09).

A production assistant should answer factual questions only from a verified
source and decline otherwise. The hardened mock can ask the engine whether its
answer was grounded; this module provides the predicate used to recognise the
kinds of queries that have no grounded answer in the synthetic world, so the
guard can be documented and tested independently of the engine's internal tag.
"""

from __future__ import annotations

import re

_ORDER = re.compile(r"\border\s*(?:number|no\.?|#)?\s*(\d{5,})", re.IGNORECASE)
_PRODUCT = re.compile(r"\b([A-Z]{2,3}-\d{2,4})\b")
_COMPANY_FACT = re.compile(r"\b(founded|founder|ceo|revenue|headquarter|stock|history)\b", re.IGNORECASE)
_PROMO = re.compile(r"\b(discount|promo|coupon|voucher)\b", re.IGNORECASE)

GROUNDED_REFUSAL = (
    "I don't have verified information about that, so I'd rather not guess. "
    "I can only confirm details for our catalogue products (AC-100, WX-200, SP-50) "
    "and for orders visible in your account. Please contact support for anything else."
)


def is_ungrounded_query(text: str, known_products: frozenset[str] = frozenset({"AC-100", "WX-200", "SP-50"})) -> bool:
    """True when the question cannot be answered from the known synthetic data."""
    low = text.lower()
    code = _PRODUCT.search(text)
    if code and code.group(1) not in known_products:
        return True
    if _ORDER.search(text):
        return True  # no order database is exposed to the assistant
    if _COMPANY_FACT.search(low):
        return True
    if _PROMO.search(low):
        return True
    return False
