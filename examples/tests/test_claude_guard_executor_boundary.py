# SPDX-License-Identifier: Apache-2.0
"""The Claude-facing loop may propose, but it must not expose execution."""

from examples import claude_guard


def test_registered_model_tools_expose_proposal_only():
    names = [tool["name"] for tool in claude_guard.REGISTERED_AGENT_TOOLS]
    assert names == ["propose_irreversible_action"]
    assert "release_payment" not in names


def test_no_legacy_release_tool_is_exported():
    assert not hasattr(claude_guard, "RELEASE_PAYMENT_TOOL")
