# SPDX-License-Identifier: Apache-2.0
"""ep-verify: thin CLI alias over emilia_verify (same verifier, one verb)."""
from emilia_verify import verify_receipt  # re-export the real verifier

__all__ = ["verify_receipt"]
