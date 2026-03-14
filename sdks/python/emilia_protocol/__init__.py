"""
EMILIA Protocol Python SDK

Portable trust evaluation and appeals for counterparties, software, and machine actors.

This SDK provides:
- trust profile retrieval
- policy-based trust evaluation
- install preflight checks
- dispute and appeal workflows
- compatibility score access for legacy use cases
"""

from .client import EmiliaClient

__all__ = ["EmiliaClient"]
__version__ = "0.1.0"
