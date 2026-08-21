#!/usr/bin/env python3
"""Same-key Kirchenbauer (KGW) green-list z-score for sampling watermarks.

Stdlib-only. Valid only against the same HMAC key, tokenizer, and green-list
layout used at generation. A negative result establishes nothing about Claude,
Gemini, Grok, or any other vendor.

    seed = HMAC-SHA256(key, previous token id)
    token is green iff HMAC-SHA256(seed, token id)[0] < 128   (half the space)
    z    = (greens - n/2) / sqrt(n/4)
    mark if z >= threshold (default 4.0)
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
from typing import Any

from detect_gumbel import tokenize_simple

_ID_PACK = struct.Struct(">Q")
DEFAULT_THRESHOLD = 4.0


def _normalize_key(raw: str) -> bytes:
    s = raw.strip()
    if s.startswith(("0x", "0X")):
        hexpart = s[2:]
        if not hexpart or len(hexpart) % 2:
            raise ValueError("invalid hex key")
        return bytes.fromhex(hexpart)
    return s.encode("utf-8")


def detect_kgw_text(text: str, key: str, *, threshold: float = DEFAULT_THRESHOLD) -> dict[str, Any]:
    ids = tokenize_simple(text)
    key_b = _normalize_key(key)
    greens = 0
    n = 0
    for i in range(1, len(ids)):
        seed = hmac.new(key_b, _ID_PACK.pack(ids[i - 1]), hashlib.sha256).digest()
        digest = hmac.new(seed, _ID_PACK.pack(ids[i]), hashlib.sha256).digest()
        n += 1
        if digest[0] < 128:
            greens += 1
    if n < 20:
        return {
            "available": True,
            "scheme": "kgw",
            "is_watermarked": False,
            "score": 0.0,
            "threshold": threshold,
            "tokens_scored": n,
            "green_fraction": None,
            "error": f"need ≥20 tokens after the first; got {n}",
        }
    expected = n * 0.5
    z = (greens - expected) / math.sqrt(n * 0.25)
    return {
        "available": True,
        "scheme": "kgw",
        "is_watermarked": z >= threshold,
        "score": round(z, 4),
        "threshold": threshold,
        "tokens_scored": n,
        "green_count": greens,
        "green_fraction": round(greens / n, 4),
        "note": (
            "same-key KGW z-score; not a Claude/Gemini/Grok detector. "
            "Negative result does not mean the text is unmarked."
        ),
    }
