# SPDX-License-Identifier: Apache-2.0
"""Canonical action digest — byte-compatible with @emilia-protocol/verify.

The digest is the executor-side binding: it is computed from the ACTUAL tool
arguments at execution time (never from what the model said it would do), so
an approval for action A can never authorize a different action B.

`canonicalize` mirrors the JS `canonicalize()` in packages/verify exactly
(recursive depth-first key sort, JSON.stringify scalar semantics) and the
Python port in packages/python-verify — proven byte-identical by the pinned
cross-language vectors in tests/test_digest.py.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize(value: Any) -> str:
    """Recursive canonical JSON — depth-first key sort at every level."""
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(value[k])
            for k in sorted(value.keys())
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def action_digest(tool: str, args: Any) -> str:
    """SHA-256 over the canonicalized {args, tool} envelope (hex)."""
    return hashlib.sha256(
        canonicalize({"tool": tool, "args": args}).encode("utf-8")
    ).hexdigest()
