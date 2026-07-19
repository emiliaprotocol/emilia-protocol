# SPDX-License-Identifier: Apache-2.0
"""langchain-emilia — the EMILIA Protocol guard for LangChain tools.

Before an agent does anything irreversible, a named human approves that exact
action on their own device. Wrapped tools fail closed; every approval mints an
offline-verifiable Trust Receipt.
"""
from .client import (
    ACTION_TYPES,
    EmiliaGateClient,
    EmiliaConfigError,
    EmiliaError,
    EmiliaUnreachable,
    GateResult,
)
from .digest import action_digest, canonicalize
from .guard import (
    DEFAULT_MATCH,
    EmiliaApprovalPending,
    EmiliaDenied,
    EmiliaGuard,
    GuardedTool,
    guard_tools,
    wrap_tool,
)

__version__ = "0.1.1"

__all__ = [
    "ACTION_TYPES",
    "DEFAULT_MATCH",
    "EmiliaApprovalPending",
    "EmiliaGateClient",
    "EmiliaConfigError",
    "EmiliaDenied",
    "EmiliaError",
    "EmiliaGuard",
    "EmiliaUnreachable",
    "GateResult",
    "GuardedTool",
    "action_digest",
    "canonicalize",
    "guard_tools",
    "wrap_tool",
    "__version__",
]
