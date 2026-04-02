# DEPRECATED / LEGACY — this package (emilia_protocol) is no longer the
# primary distribution.  The canonical, actively-maintained SDK lives in the
# `ep` package (src/ep/), which is what gets installed when you run
# `pip install emilia-protocol`.  Please update your imports to use `ep`:
#
#     from ep import EPClient, EPError
#
# This module is kept for backwards compatibility only and may be removed in a
# future major release.
"""EMILIA Protocol Python SDK."""
from .client import EPClient
from .types import (
    EntityType, AgentBehavior, TransactionType, TrustPolicy,
    TrustDecision, DisputeReason, ReportType, TrustDomain,
    EPError,
)

__version__ = "1.1.0"
__all__ = [
    "EPClient",
    "EntityType", "AgentBehavior", "TransactionType", "TrustPolicy",
    "TrustDecision", "DisputeReason", "ReportType", "TrustDomain",
    "EPError",
]
