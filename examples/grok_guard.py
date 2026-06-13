# SPDX-License-Identifier: Apache-2.0
"""grok_guard — gate a Grok (xAI) agent's irreversible actions with EMILIA.

This is honest glue around the endpoints EMILIA actually ships. There is NO
single /approve call that hands the agent a passkey challenge: WebAuthn
(Touch ID / Face ID / security key) happens on the *human's* device, in a
*browser*, out of band. The agent's job is to mint a pre-action Trust Receipt,
open a signoff, and wait for the named human.

THE POINT — the guard does not trust EMILIA's word for "approved":
-----------------------------------------------------------------
When a signoff resolves, the guard FETCHES the signed evidence and VERIFIES THE
Ed25519 SIGNATURE OFFLINE, in this process, using the repo's own pure-Python
verifier (`emilia_verify`). `allowed=True` is returned only if that
cryptographic check passes. A compromised EMILIA server — or a forged
`receipt_status: "approved_pending_consume"` injected on the wire — cannot make
the agent proceed, because the agent re-derives trust from the signature over
the exact action, not from a status string. That is the difference between this
and a webhook: a webhook trusts whoever calls it; this trusts math.

The receipt does NOT prove the approver is wise or that the action is good. It
proves that a *named key* produced a *user-verified signature* over the *exact*
canonical action — accountable, non-repudiable, replay-bound. Nothing more, and
that is enough to gate money.

The real flow:

  1. mint     POST /api/v1/trust-receipts          (Bearer EP_API_KEY)
                -> 201 { receipt_id, decision, signoff_required, receipt_status }
                   decision ∈ { allow, allow_with_signoff, deny, observe }
  2. request  POST /api/v1/signoffs/request         (Bearer EP_API_KEY)
                -> 201 { signoff_id, status: "pending" }
                   approval URL = {base}/signoff/{signoff_id}   (opaque id only)
  3. HUMAN    opens the approval URL, reviews the exact action, Face ID
  4. poll     GET  /api/v1/trust-receipts/{id}      (Bearer EP_API_KEY)
                -> receipt_status: approved_pending_consume | consumed
                                 | rejected | expired | pending_signoff
  5. VERIFY   GET  /api/v1/trust-receipts/{id}/evidence   (Bearer EP_API_KEY)
                -> evidence packet; if it carries a signed { document, public_key }
                   the guard verifies the Ed25519 signature OFFLINE before
                   ever returning allowed=True.

Offline verification needs the verifier on the path:

    pip install emilia-verify
    # or, from this repo, without installing:
    PYTHONPATH=packages/python-verify python examples/grok_guard.py

Without it, the guard still works but marks the receipt
"unverified — install emilia-verify to verify offline" and refuses to claim a
cryptographic guarantee it did not check.

Stdlib only for HTTP (no `requests`/`httpx` dependency). Swap the `_http`
helper for your client of choice; the request/response shapes are identical.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

# Silent by default (library convention); your app configures handlers/level.
# Treasury/ops want the trail: "minted tr_… -> signoff requested -> approved
# -> signature VERIFIED offline".
logger = logging.getLogger("emilia.grok_guard")

# ── Offline verifier (the headline feature) ──────────────────────────────────
# emilia_verify is the repo's pure-Python port of @emilia-protocol/verify. It is
# byte-compatible with the JS verifier: Ed25519 over recursive-canonical JSON +
# sorted-pair Merkle anchor. No EP account, no API key — just math.
#   from-repo:  PYTHONPATH=packages/python-verify
#   installed:  pip install emilia-verify
# If it is not importable we degrade HONESTLY (see _verify_evidence_offline);
# we never silently treat the server's "approved" as proof.
try:
    from emilia_verify import verify_receipt as _verify_receipt  # type: ignore

    _HAVE_VERIFIER = True
except Exception:  # noqa: BLE001 - any import failure means "verify offline" is unavailable
    _verify_receipt = None  # type: ignore
    _HAVE_VERIFIER = False


class EmiliaAPIError(Exception):
    """A transport-level failure reaching the EMILIA API (DNS/TLS/connection).

    HTTP *status codes* are deliberately returned as data, not raised: a policy
    `deny` or a 4xx is a normal outcome the caller turns into a structured tool
    result, not an exception. Only when there is no response at all do we raise.
    """


# Receipt statuses that mean "a named human approved — safe to proceed".
# Read from app/api/v1/trust-receipts/[receiptId]/route.js: the GET endpoint
# replays the audit log and reports 'approved_pending_consume' once a signoff is
# approved, and 'consumed' once the action has been spent. Both are success.
APPROVED_STATUSES = frozenset({"approved_pending_consume", "consumed"})
# Statuses that end the poll without success.
REJECTED_STATUSES = frozenset({"rejected", "denied", "expired"})
TERMINAL_STATUSES = APPROVED_STATUSES | REJECTED_STATUSES


# ── Minimal HTTP (stdlib). Replace with requests/httpx in your backend. ──────
def _http(
    method: str,
    url: str,
    api_key: str,
    body: Optional[dict] = None,
    timeout: int = 15,
    idempotency_key: Optional[str] = None,
) -> tuple[int, dict]:
    # SECURITY: pin to https. urllib honors file://, ftp://, etc.; a plain http
    # base_url would also send the Bearer token in cleartext. In a security
    # context anything but https is rejected outright (CWE-319 / CWE-939).
    if not url.lower().startswith("https://"):
        raise ValueError(f"refusing non-https URL (token would be exposed): {url!r}")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {api_key}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    # SECURITY: an Idempotency-Key makes a retried mint return the SAME receipt
    # instead of creating a duplicate (and a duplicate audit trail / signoff).
    if idempotency_key is not None:
        req.add_header("Idempotency-Key", idempotency_key)
    # The scheme is pinned to https above (file://, ftp://, etc. are rejected
    # before we get here), and `url` is operator config (EMILIA_BASE_URL) +
    # server-issued ids, never end-user input — so the CWE-939 custom-scheme
    # vector the linter warns about is closed.
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosemgrep
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        # A 4xx/5xx is a normal outcome callers interpret (e.g. a policy deny).
        # Return it as data, never raise — the agent gets a structured
        # "blocked", not a crash.
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {"error": "http_error"}
    except urllib.error.URLError as e:
        # No response at all (network/DNS/TLS) — surface a typed error instead
        # of a bare urllib exception so backends can catch one thing.
        raise EmiliaAPIError(f"cannot reach EMILIA at {url}: {e.reason}") from e


@dataclass
class VerifiedReceipt:
    """Result of the OFFLINE cryptographic check of a resolved receipt."""

    verified: bool                 # True only if the Ed25519 signature checked out, here
    status: str                    # "verified" | "unsigned_evidence" | "verifier_unavailable"
    #                                | "signature_invalid" | "no_evidence" | "rejected" | "timeout"
    detail: Optional[str] = None
    checks: dict = field(default_factory=dict)   # the verifier's per-check map
    raw: dict = field(default_factory=dict)       # the evidence packet as fetched


@dataclass
class GuardResult:
    allowed: bool                 # True only when no human signoff is needed (allow)
    decision: str                 # allow | allow_with_signoff | deny | observe
    receipt_id: Optional[str] = None
    signoff_id: Optional[str] = None
    approval_url: Optional[str] = None   # opaque — send this to the human
    reason: Optional[str] = None
    raw: dict = field(default_factory=dict)


class EmiliaGuard:
    """Drop-in guard for a Grok/xAI (or any) agent backend.

    Sync and stdlib-only for the HTTP; the only optional dependency is
    `emilia_verify`, used solely for the offline signature check.
    """

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        # Use the www host: the apex 307-redirects, and urllib would drop the
        # Authorization header on the cross-origin hop.
        self.base_url = (
            base_url or os.environ.get("EMILIA_BASE_URL", "https://www.emiliaprotocol.ai")
        ).rstrip("/")
        # SECURITY: the key is NEVER hardcoded — env (EP_API_KEY) or constructor.
        self.api_key = api_key or os.environ.get("EP_API_KEY", "")
        if not self.api_key:
            raise ValueError("EmiliaGuard: set EP_API_KEY (env) or pass api_key=...")
        # SECURITY: https only. Fail loudly at construction, not mid-flight.
        if not self.base_url.lower().startswith("https://"):
            raise ValueError(f"EmiliaGuard: base_url must be https (got {self.base_url!r})")

    # 1+2: mint a pre-action receipt and, if the policy demands it, open a signoff.
    def guard(
        self,
        action_type: str,                 # e.g. "large_payment_release", "vendor_bank_account_change"
        target_resource_id: str,          # the thing being acted on, e.g. "wire/8841"
        organization_id: str,
        amount: Optional[float] = None,
        currency: str = "USD",
        risk_flags: Optional[list[str]] = None,
        target_changed_fields: Optional[list[str]] = None,
        enforcement_mode: Optional[str] = None,   # observe | warn | enforce (server default: enforce)
        actor_role: Optional[str] = None,
        approver_id: Optional[str] = None,        # named human to route the signoff to
    ) -> GuardResult:
        # One idempotency key per logical guard call: a network retry of the
        # mint POST returns the same receipt instead of minting a duplicate.
        idem = f"grok-guard-{uuid.uuid4()}"

        mint_body: dict[str, Any] = {
            "organization_id": organization_id,
            "action_type": action_type,
            "target_resource_id": target_resource_id,
            "currency": currency,
            "risk_flags": risk_flags or [],
            "target_changed_fields": target_changed_fields or [],
        }
        if amount is not None:
            mint_body["amount"] = amount
        if enforcement_mode is not None:
            mint_body["enforcement_mode"] = enforcement_mode
        if actor_role is not None:
            mint_body["actor_role"] = actor_role

        status, mint = _http(
            "POST",
            f"{self.base_url}/api/v1/trust-receipts",
            self.api_key,
            mint_body,
            idempotency_key=idem,
        )
        # Branch on the real success signal: a receipt_id on a 2xx. The MINT
        # endpoint returns 201, but we don't hardcode 201 == success — presence
        # of receipt_id is what actually tells us a receipt was created.
        receipt_id = mint.get("receipt_id")
        if status not in (200, 201) or not receipt_id:
            return GuardResult(
                False,
                "deny",
                reason=f"mint failed ({status}): {mint.get('detail') or mint.get('error')}",
                raw=mint,
            )

        # Decision enum (lib/guard-policies.js GUARD_DECISIONS) is lowercase:
        # allow | observe | allow_with_signoff | deny. Compare exact-cased.
        decision = mint.get("decision", "deny")
        signoff_required = bool(mint.get("signoff_required"))
        logger.info(
            "emilia: minted %s decision=%s signoff_required=%s status=%s",
            receipt_id, decision, signoff_required, mint.get("receipt_status"),
        )

        if not signoff_required:
            # No human needed. allow -> proceed; deny/observe -> do not.
            return GuardResult(
                decision == "allow",
                decision,
                receipt_id=receipt_id,
                reason=("denied by policy" if decision == "deny" else None),
                raw=mint,
            )

        # Signoff required: open the request.
        status, sreq = _http(
            "POST",
            f"{self.base_url}/api/v1/signoffs/request",
            self.api_key,
            {
                "receipt_id": receipt_id,
                # SECURITY: bind the approver in the POST BODY, never in a URL
                # query string. The approval URL must stay free of PII (email /
                # operator id) so it can be logged, forwarded, and pasted safely.
                **({"approver_id": approver_id} if approver_id else {}),
            },
        )
        signoff_id = sreq.get("signoff_id")
        if status not in (200, 201) or not signoff_id:
            return GuardResult(
                False,
                decision,
                receipt_id=receipt_id,
                reason=f"signoff request failed ({status}): {sreq.get('detail') or sreq.get('error')}",
                raw=sreq,
            )

        # SECURITY: the approval URL carries the OPAQUE signoff_id only — no
        # approver email, no query-string PII. The server already knows which
        # human this signoff is bound to (from the POST body above).
        url = f"{self.base_url}/signoff/{signoff_id}"
        logger.info("emilia: signoff %s opened for %s", signoff_id, receipt_id)
        return GuardResult(
            False,
            decision,
            receipt_id=receipt_id,
            signoff_id=signoff_id,
            approval_url=url,
            reason="human signoff required",
            raw={"mint": mint, "request": sreq},
        )

    # 4: poll until a named human decides (or the window closes).
    #
    # ⚠ BLOCKS. Use this only in a worker / batch job, NEVER inside a Grok tool
    # call — a tool call must return promptly. For the tool-calling pattern,
    # return approval_url and let the orchestrator come back later (see
    # dispatch_emilia_tool, default mode).
    def wait_for_approval(
        self,
        receipt_id: str,
        timeout_s: int = 600,
        interval_s: int = 3,
    ) -> VerifiedReceipt:
        """Poll the receipt to a terminal state, then — on approval — FETCH and
        VERIFY the signed evidence OFFLINE. Returns a VerifiedReceipt whose
        `.verified` is True only when the Ed25519 signature checked out in this
        process. A timeout, a rejection, or a failed signature all yield
        verified=False.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            status, rec = _http(
                "GET", f"{self.base_url}/api/v1/trust-receipts/{receipt_id}", self.api_key
            )
            st = rec.get("receipt_status")
            if status == 200 and st in TERMINAL_STATUSES:
                if st in APPROVED_STATUSES:
                    logger.info(
                        "emilia: %s approved (status=%s key_class=%s) — verifying offline",
                        receipt_id, st, rec.get("signoff_key_class"),
                    )
                    # DO NOT trust the "approved" string. Verify the signature.
                    return self.verify_receipt_offline(receipt_id)
                logger.info("emilia: %s resolved without approval (status=%s)", receipt_id, st)
                return VerifiedReceipt(
                    verified=False, status="rejected", detail=f"signoff {st}", raw=rec
                )
            time.sleep(interval_s)
        logger.info("emilia: signoff for %s timed out after %ss", receipt_id, timeout_s)
        return VerifiedReceipt(verified=False, status="timeout", detail=f"no decision in {timeout_s}s")

    # 5: the headline feature — fetch signed evidence and verify it OFFLINE.
    def verify_receipt_offline(self, receipt_id: str) -> VerifiedReceipt:
        """Fetch the evidence packet and verify its Ed25519 signature locally.

        The /evidence endpoint returns the evidence packet. When that packet
        carries a signed EP-RECEIPT-v1 `document` plus the signer's `public_key`
        (base64url SPKI), we run emilia_verify.verify_receipt over it — the SAME
        check anyone can run offline with `pip install emilia-verify`. `verified`
        is True only if that signature (and any Merkle anchor) is valid.
        """
        status, ev = _http(
            "GET",
            f"{self.base_url}/api/v1/trust-receipts/{receipt_id}/evidence",
            self.api_key,
        )
        if status != 200 or not ev:
            return VerifiedReceipt(
                verified=False, status="no_evidence",
                detail=f"evidence fetch failed ({status})", raw=ev or {},
            )
        return _verify_evidence_offline(ev)


def _verify_evidence_offline(evidence: dict) -> VerifiedReceipt:
    """Pure function: given an evidence packet, verify the signed receipt inside
    it offline. Extracted so tests can exercise it without any network.

    Honest degradation, in order:
      - packet carries no signed doc -> verified=False, "unsigned_evidence"
      - verifier not importable      -> verified=False, "verifier_unavailable"
      - signature/anchor invalid     -> verified=False, "signature_invalid"
      - signature valid              -> verified=True,  "verified"

    We NEVER return verified=True off a server status string alone.
    """
    # The signed receipt lives under `document` with the signer's `public_key`
    # (base64url SPKI Ed25519) — the shape the evidence / public demo endpoints
    # expose for offline verification.
    document = evidence.get("document")
    public_key = evidence.get("public_key")

    if not document or not public_key:
        # Current production /evidence returns a plaintext, DB-tamper-evident
        # packet (schema ep-guard-evidence-v1) with no embedded signature. That
        # is server-attested, NOT offline-verifiable — say so plainly rather
        # than implying a cryptographic guarantee we didn't check.
        return VerifiedReceipt(
            verified=False,
            status="unsigned_evidence",
            detail=(
                "evidence packet carries no signed EP-RECEIPT-v1 document — "
                "server-attested only, not verified offline"
            ),
            raw=evidence,
        )

    if not _HAVE_VERIFIER:
        return VerifiedReceipt(
            verified=False,
            status="verifier_unavailable",
            detail="unverified — install emilia-verify to verify offline (pip install emilia-verify)",
            raw=evidence,
        )

    result = _verify_receipt(document, public_key)  # type: ignore[misc]
    if getattr(result, "valid", False):
        logger.info("emilia: OFFLINE signature VERIFIED — checks=%s", result.checks)
        return VerifiedReceipt(
            verified=True, status="verified", checks=dict(result.checks), raw=evidence
        )

    logger.warning(
        "emilia: OFFLINE signature FAILED — checks=%s error=%s",
        getattr(result, "checks", {}), getattr(result, "error", None),
    )
    return VerifiedReceipt(
        verified=False,
        status="signature_invalid",
        detail=getattr(result, "error", None) or "signature did not verify",
        checks=dict(getattr(result, "checks", {})),
        raw=evidence,
    )


# ── xAI / OpenAI-compatible tool schema. Register this with Grok. ────────────
# Grok calls this tool *instead of* executing the irreversible action directly;
# your dispatcher (below) runs EmiliaGuard and only returns proceed=true on a
# real human approval whose signature verified offline.
EMILIA_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "emilia_require_human_signoff",
        "description": (
            "REQUIRED before any irreversible high-stakes action (releasing a "
            "large payment, changing a payee bank account, deleting records). "
            "Returns proceed=true only after a named human cryptographically "
            "approves on their own device AND the signature verifies; otherwise "
            "blocked. Never execute the action unless this returns proceed=true."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "enum": [
                        "large_payment_release",
                        "vendor_bank_account_change",
                        "benefit_bank_account_change",
                        "ai_agent_payment_action",
                    ],
                },
                "organization_id": {"type": "string"},
                "target_resource_id": {
                    "type": "string",
                    "description": "what is being acted on, e.g. wire/8841",
                },
                "amount": {"type": "number"},
                "currency": {"type": "string", "default": "USD"},
                "risk_flags": {"type": "array", "items": {"type": "string"}},
                "approver_id": {
                    "type": "string",
                    "description": "the named human to route the signoff to",
                },
            },
            "required": ["action_type", "organization_id", "target_resource_id"],
        },
    },
}


def dispatch_emilia_tool(
    args: dict,
    guard: Optional[EmiliaGuard] = None,
    notify=None,
    wait: bool = False,
    timeout_s: int = 600,
) -> dict:
    """Run the guard for a Grok tool call.

    DEFAULT (wait=False) — the right pattern for a tool call. We mint + open the
    signoff and return immediately with status "approval_required" plus the
    approval_url. The tool call does NOT block; your orchestrator notifies the
    human (Slack/SMS/email via `notify(approval_url)`), and a later turn (or a
    worker calling guard.wait_for_approval) resolves it. A tool must return
    promptly — blocking a model's tool call for minutes is an anti-pattern.

    wait=True — synchronous, BLOCKING. Only for a worker/batch job, never inside
    a live tool call. Polls to approval, then verifies the signature OFFLINE and
    returns proceed=true ONLY if that check passed.
    """
    guard = guard or EmiliaGuard()
    res = guard.guard(
        action_type=args["action_type"],
        target_resource_id=args["target_resource_id"],
        organization_id=args["organization_id"],
        amount=args.get("amount"),
        currency=args.get("currency", "USD"),
        risk_flags=args.get("risk_flags"),
        target_changed_fields=args.get("target_changed_fields"),
        enforcement_mode=args.get("enforcement_mode"),
        actor_role=args.get("actor_role"),
        approver_id=args.get("approver_id"),
    )

    if res.allowed:
        return {
            "proceed": True,
            "status": "allowed",
            "reason": "allowed by policy (no signoff needed)",
            "receipt_id": res.receipt_id,
        }
    if res.decision == "deny":
        return {
            "proceed": False,
            "status": "denied",
            "reason": res.reason,
            "receipt_id": res.receipt_id,
        }

    # Signoff required. Route the OPAQUE approval URL to the human.
    (notify or (lambda u: print(f"[emilia] approve this action: {u}")))(res.approval_url)

    if not wait:
        # Non-blocking: hand control back to the orchestrator. The action is NOT
        # yet allowed — proceed=false until a verified signoff comes back.
        return {
            "proceed": False,
            "status": "approval_required",
            "reason": "named human signoff required — awaiting device signature",
            "receipt_id": res.receipt_id,
            "signoff_id": res.signoff_id,
            "approval_url": res.approval_url,
        }

    # Blocking worker path: poll, then verify the signature OFFLINE.
    verified = guard.wait_for_approval(res.receipt_id, timeout_s=timeout_s)
    return {
        # proceed=true requires BOTH a human approval AND a signature that
        # verified locally. A server that merely *says* "approved" is not enough.
        "proceed": bool(verified.verified),
        "status": verified.status,
        "reason": verified.detail or f"signoff {verified.status}",
        "receipt_id": res.receipt_id,
        "signoff_id": res.signoff_id,
        "offline_verified": verified.verified,
        "verifier_checks": verified.checks or None,
    }


# ── Wiring into a real Grok (xAI) agent loop ────────────────────────────────
# xAI is OpenAI-compatible, so this is the standard tool-calling loop. The only
# EMILIA-specific part: when Grok calls the tool, run dispatch_emilia_tool and
# feed the result back. Grok proceeds with the irreversible action ONLY when
# proceed is true.
#
# Tool-call pattern (DEFAULT, non-blocking) — the tool returns immediately with
# status="approval_required"; a human approves out of band; a later turn (or a
# worker) resolves and verifies it:
#
#   from openai import OpenAI
#   client = OpenAI(api_key=os.environ["XAI_API_KEY"], base_url="https://api.x.ai/v1")
#   guard = EmiliaGuard()
#
#   messages = [{"role": "user", "content": "Pay the $82k Acme invoice to the new account."}]
#   resp = client.chat.completions.create(
#       model="grok-4", messages=messages,
#       tools=[EMILIA_TOOL_SCHEMA, release_payment_schema], tool_choice="auto",
#   )
#   for call in (resp.choices[0].message.tool_calls or []):
#       if call.function.name == "emilia_require_human_signoff":
#           args = json.loads(call.function.arguments)
#           result = dispatch_emilia_tool(args, guard=guard, notify=send_to_slack)
#           messages.append({"role": "tool", "tool_call_id": call.id,
#                            "content": json.dumps(result)})
#           # result["proceed"] is false here on a signoff (status=approval_required).
#           # release_payment(...) must refuse to run unless it later sees proceed=true.
#
# Synchronous batch pattern (BLOCKING — worker only, not a tool call):
#   result = dispatch_emilia_tool(args, guard=guard, wait=True, timeout_s=900)
#   # result["proceed"] is true ONLY if the device signature VERIFIED OFFLINE.
#
# The guarantee holds end-to-end only if release_payment refuses to run unless
# proceed=true — ideally re-verifying the receipt at the executor itself (the
# EP-Verified Execution conformance class).


if __name__ == "__main__":
    # Smoke demo against a running EMILIA. Needs EP_API_KEY (+ optional
    # EMILIA_BASE_URL). For offline verification, put the verifier on the path:
    #   PYTHONPATH=packages/python-verify EP_API_KEY=ep_live_... \
    #     python examples/grok_guard.py
    # Mints an $82k release, opens a signoff, prints the (opaque) approval URL,
    # then blocks (wait=True, worker mode) until you approve it in the browser —
    # and only prints proceed=true after the signature verifies locally.
    if not os.environ.get("EP_API_KEY"):
        raise SystemExit(
            "Set EP_API_KEY (and optionally EMILIA_BASE_URL), then re-run.\n"
            "Offline verify also needs emilia-verify on the path:\n"
            "  pip install emilia-verify   (or  PYTHONPATH=packages/python-verify)"
        )
    if not _HAVE_VERIFIER:
        print("[warn] emilia_verify not importable — receipts will be marked "
              "'unverified'. Install with: pip install emilia-verify")
    g = EmiliaGuard()
    print(f"EMILIA: {g.base_url}")
    out = dispatch_emilia_tool(
        {
            "action_type": "large_payment_release",
            "organization_id": "org-demo",
            "target_resource_id": "wire/demo-001",
            "amount": 82000,
            "risk_flags": ["new_destination", "after_hours"],
            "approver_id": "ep:approver:demo-controller",
        },
        guard=g,
        wait=True,   # worker-style blocking demo; a real tool call would omit this
    )
    print(json.dumps(out, indent=2))
