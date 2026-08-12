#!/usr/bin/env python3
"""Print the executable surface of the installed ccs-verifier package."""

from __future__ import annotations

import importlib.metadata
import json

import ccs_verifier
from ccs_verifier.protocol import VerificationResult


def main() -> None:
    try:
        import ccs_verifier_l1  # type: ignore  # noqa: F401
        l1_importable = True
        l1_error = None
    except Exception as exc:  # The exact missing-module state is the audit result.
        l1_importable = False
        l1_error = f"{type(exc).__name__}: {exc}"

    result = {
        "distribution": "ccs-verifier",
        "distribution_version": importlib.metadata.version("ccs-verifier"),
        "runtime_version": getattr(ccs_verifier, "__version__", None),
        "verification_result_fields": list(VerificationResult.__dataclass_fields__),
        "l1_module_importable": l1_importable,
        "l1_import_error": l1_error,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
