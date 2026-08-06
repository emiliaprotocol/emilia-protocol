# SPDX-License-Identifier: Apache-2.0
"""EMILIA Protocol API client — stdlib-only, fail-closed.

Mirrors the proven flow in integrations/claude-agent-sdk/guard_hook.py:
mint a trust receipt → policy decides (allow / deny / require_signoff) →
on require_signoff, request a signoff and poll until a named human approves
on their own device (Face ID / passkey) or the window times out.

Deliberately zero third-party dependencies: http.client with an explicit
HTTPS connection is structurally incapable of file:// or other schemes,
unlike scheme-dispatching openers.
"""
from __future__ import annotations

import http.client
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_BASE_URL = "https://www.emiliaprotocol.ai"
_SAFE_ID = re.compile(r"^[A-Za-z0-9_:.-]{1,128}$")
_ACTION_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")

# Production action_type enum (server-validated; learned from the live API).
ACTION_TYPES = (
    "benefit_bank_account_change",
    "benefit_address_change",
    "caseworker_override",
    "vendor_bank_account_change",
    "beneficiary_creation",
    "large_payment_release",
    "ai_agent_payment_action",
)


class EmiliaError(Exception):
    """Base class for EMILIA client errors."""


class EmiliaConfigError(EmiliaError):
    """Missing or invalid configuration (API key / org id)."""


class EmiliaUnreachable(EmiliaError):
    """Network or server failure talking to EMILIA. Callers fail closed."""


@dataclass
class GateResult:
    """Outcome of one gate evaluation.

    decision: 'allow' | 'deny' | 'pending'
      allow   — execute; `receipt_id` is the offline-verifiable evidence
      deny    — blocked by policy or rejected by the human; do not execute
      pending — a human signoff is required and not yet given; do not execute
    """
    decision: str
    receipt_id: Optional[str] = None
    signoff_id: Optional[str] = None
    signoff_url: Optional[str] = None
    approved_by_human: bool = False
    reasons: list[str] = field(default_factory=list)
    action_hash: Optional[str] = None
    canonical_action: Optional[dict] = None
    execution_reference_id: Optional[str] = None
    consumed: bool = False


def _safe_base_url(url: str) -> str:
    url = (url or DEFAULT_BASE_URL).rstrip("/")
    if url.startswith("https://") or url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        return url
    return DEFAULT_BASE_URL


class EmiliaGateClient:
    """Thin, blocking client for the EP gate flow. Thread-safe per call."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        org_id: Optional[str] = None,
        base_url: Optional[str] = None,
        signoff_timeout_s: float = 280.0,
        poll_interval_s: float = 3.0,
        request_timeout_s: float = 15.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("EP_API_KEY", "")
        self.org_id = org_id if org_id is not None else os.environ.get("EP_ORG_ID", "")
        self.base_url = _safe_base_url(base_url or os.environ.get("EP_BASE_URL", DEFAULT_BASE_URL))
        self.signoff_timeout_s = min(float(signoff_timeout_s), 590.0)
        self.poll_interval_s = float(poll_interval_s)
        self.request_timeout_s = float(request_timeout_s)

    # -- low-level ------------------------------------------------------------

    def require_creds(self) -> None:
        if not (self.api_key and self.org_id):
            raise EmiliaConfigError(
                "EMILIA enforce mode needs credentials: set EP_API_KEY and EP_ORG_ID "
                "(or pass api_key/org_id to EmiliaGateClient). Use mode='observe' for a "
                "zero-setup local dry run."
            )

    def _request(self, path: str, body: Optional[dict] = None) -> dict:
        scheme, _, rest = self.base_url.partition("://")
        hostport = rest.split("/", 1)[0]
        host, _, port = hostport.partition(":")
        conn_cls = http.client.HTTPConnection if scheme == "http" else http.client.HTTPSConnection
        conn = conn_cls(host, int(port) if port else None, timeout=self.request_timeout_s)
        try:
            conn.request(
                "POST" if body is not None else "GET",
                path,
                body=json.dumps(body) if body is not None else None,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            )
            resp = conn.getresponse()
            data = json.loads(resp.read() or b"{}")
            if resp.status >= 400:
                raise EmiliaUnreachable(data.get("detail") or data.get("title") or f"HTTP {resp.status}")
            return data
        except EmiliaUnreachable:
            raise
        except Exception as err:  # noqa: BLE001 — every transport failure fails closed upstream
            raise EmiliaUnreachable(str(err)) from err
        finally:
            conn.close()

    # -- gate flow ------------------------------------------------------------

    @staticmethod
    def _execution_reference(target: str) -> str:
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
        return f"langchain-emilia:sha256:{digest}"

    def _consume_allowed(
        self,
        mint: dict,
        receipt_id: str,
        target: str,
        signoff_id: Optional[str] = None,
        signoff_url: Optional[str] = None,
        approved_by_human: bool = False,
    ) -> GateResult:
        action_hash = mint.get("action_hash")
        canonical_action = mint.get("canonical_action")
        if not isinstance(action_hash, str) or not _ACTION_HASH.fullmatch(action_hash):
            return GateResult("deny", receipt_id or None, reasons=["receipt action hash is missing or malformed"])
        if not isinstance(canonical_action, dict):
            return GateResult("deny", receipt_id or None, reasons=["canonical action is missing; refusing consume"])
        execution_reference_id = self._execution_reference(target)
        consumed = self._request(
            f"/api/v1/trust-receipts/{receipt_id}/consume",
            {
                "action_hash": action_hash,
                "executing_system": "langchain-emilia",
                "execution_reference_id": execution_reference_id,
            },
        )
        if consumed.get("status") != "consumed" or consumed.get("receipt_id") != receipt_id:
            return GateResult("deny", receipt_id, reasons=["receipt consumption was not confirmed"])
        return GateResult(
            "allow",
            receipt_id,
            signoff_id,
            signoff_url,
            approved_by_human=approved_by_human,
            action_hash=action_hash,
            canonical_action=canonical_action,
            execution_reference_id=execution_reference_id,
            consumed=True,
        )

    def attest_execution(self, result: GateResult, observed_action: dict) -> dict:
        """Record the exact action after the wrapped tool returns.

        This is deliberately separate from consume: consume must happen before
        tool entry, while execution evidence can exist only after the call. The
        caller must supply executor-observed fields; the approved plan is not an
        observation of its own execution.
        """
        if not result.consumed or not result.receipt_id:
            raise EmiliaUnreachable("execution attestation requires a consumed receipt")
        if not isinstance(result.canonical_action, dict):
            raise EmiliaUnreachable("execution attestation lacks the canonical action")
        if not isinstance(observed_action, dict):
            raise EmiliaUnreachable("execution attestation lacks executor-observed action fields")
        body = {
            "executed_action": result.canonical_action,
            "observed_action": observed_action,
            "executing_system": "langchain-emilia",
            "execution_id": result.execution_reference_id,
        }
        attestation = self._request(
            f"/api/v1/trust-receipts/{result.receipt_id}/execution",
            body,
        )
        if attestation.get("status") != "executed" or attestation.get("binding_status") != "match":
            raise EmiliaUnreachable("execution attestation was not confirmed as an exact match")
        return attestation

    def gate(
        self,
        action_type: str,
        target: str,
        amount: Optional[float] = None,
        comment: str = "",
        wait_for_approval: bool = True,
    ) -> GateResult:
        """Run the full gate flow for one action. Blocking; fail-closed.

        Never returns 'allow' unless policy allowed it or a named human
        approved it. Raises EmiliaUnreachable on transport failure (callers
        treat that as deny/hold), EmiliaConfigError on missing credentials.
        """
        self.require_creds()

        mint = self._request("/api/v1/trust-receipts", {
            "organization_id": self.org_id,
            "action_type": action_type,
            "target_resource_id": target[:200],
            "amount": amount,
            "currency": "USD",
            "risk_flags": ["langchain_tool_call"],
        })

        receipt_id = str(mint.get("receipt_id", ""))
        if mint.get("decision") == "deny":
            return GateResult("deny", receipt_id or None, reasons=list(mint.get("reasons") or ["denied by policy"]))
        if not mint.get("signoff_required"):
            if not _SAFE_ID.match(receipt_id):
                return GateResult("deny", reasons=["malformed receipt id from server; failing closed"])
            return self._consume_allowed(mint, receipt_id, target)
        if not _SAFE_ID.match(receipt_id):
            return GateResult("deny", reasons=["malformed receipt id from server; failing closed"])

        sig = self._request("/api/v1/signoffs/request", {"receipt_id": receipt_id, "comment": comment[:500]})
        signoff_id = str(sig.get("signoff_id", ""))
        if not _SAFE_ID.match(signoff_id):
            return GateResult("deny", receipt_id, reasons=["malformed signoff id from server; failing closed"])
        signoff_url = f"{self.base_url}/signoff/{signoff_id}"

        if not wait_for_approval:
            return GateResult("pending", receipt_id, signoff_id or None, signoff_url)

        deadline = time.monotonic() + self.signoff_timeout_s
        while time.monotonic() < deadline:
            time.sleep(self.poll_interval_s)
            rec = self._request(f"/api/v1/trust-receipts/{receipt_id}")
            status = rec.get("receipt_status") or rec.get("status", "pending")
            if status in ("approved_pending_consume", "approved"):
                return self._consume_allowed(
                    mint,
                    receipt_id,
                    target,
                    signoff_id,
                    signoff_url,
                    approved_by_human=True,
                )
            if status in ("consumed", "fulfilled"):
                return GateResult("deny", receipt_id, signoff_id, signoff_url,
                                  reasons=["receipt was already consumed by another executor"])
            if status in ("denied", "rejected", "revoked", "expired"):
                return GateResult("deny", receipt_id, signoff_id or None, signoff_url,
                                  reasons=["rejected by the named approver"])
        return GateResult("pending", receipt_id, signoff_id or None, signoff_url,
                          reasons=[f"signoff window timed out after {int(self.signoff_timeout_s)}s"])
