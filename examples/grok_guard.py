# SPDX-License-Identifier: Apache-2.0
"""Deprecated compatibility import for the former xAI-branded module name.

The reusable executor gate is vendor-neutral and now lives in
``examples.executor_approval_gate``. Existing integrations may keep importing
this module while they migrate; new code should import the neutral module.
"""

try:
    from examples.executor_approval_gate import *  # noqa: F401,F403
except ModuleNotFoundError:  # direct import with examples/ on sys.path
    from executor_approval_gate import *  # type: ignore # noqa: F401,F403
