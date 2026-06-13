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
verifier (`emilia_verify`). `verified=True` is returned only when EVERY one of
the following independent checks passes — any failure fails CLOSED:

  1. SIGNATURE — the Ed25519 signature over the canonical EP-RECEIPT-v1 payload
     verifies. A forged `receipt_status: "approved_pending_consume"` injected on
     the wire is worthless: the guard re-derives trust from the signature over
     the exact action, not from a status string.
  2. SIGNER PINNING — the signing key is a member of a SERVER-INDEPENDENT
     trusted set (constructor `trusted_signer_keys` and/or env
     `EP_TRUSTED_SIGNER_KEYS`). The guard does NOT trust the `public_key` that
     the same /evidence response served. A fully compromised server that signs a
     forged document with its OWN key and serves its OWN pubkey is rejected
     (`untrusted_signer`) because that key is not pinned. If NO pinned set is
     available the guard fails CLOSED — it never falls back to trusting the
     inline key.
  3. REQUEST BINDING — the signed receipt_id / amount / currency / destination /
     approver equal what THIS agent actually requested. A genuinely-signed $1
     receipt can no longer approve an $82k wire, and a real receipt for a
     different action cannot be substituted (`claim_mismatch`).
  4. REPLAY — a receipt_id is single-use within the injected `replay_store`;
     re-presenting it is rejected (`replay`). The receipt_status `consumed`
     (already spent) is treated as a non-approval (`already_consumed`).
  5. ANCHOR (optional, `require_anchor=True`) — the Merkle inclusion proof must
     be present and valid; a stripped/partial anchor is rejected
     (`anchor_required`).

The receipt does NOT prove the approver is wise or that the action is good. It
proves that a *named, pinned key* produced a signature over the *exact* canonical
action this agent requested — accountable, non-repudiable, request-bound,
single-use. Nothing more, and that is enough to gate money.

RESIDUAL / THREAT MODEL — be precise about what each defense covers:
  - With `EP_TRUSTED_SIGNER_KEYS` (or `trusted_signer_keys=`) configured, a
    FULLY compromised EMILIA server cannot make the agent proceed: it cannot
    produce a signature under a pinned key, and the agent ignores any pubkey the
    server serves.
  - The optional `/.well-known/ep-keys.json` bootstrap (off by default; the app
    does not serve that route yet — publishing it is the recommended follow-up)
    resists wire-tampering and receipt substitution, but a server that controls
    BOTH `/.well-known` and `/evidence` is OUT OF SCOPE for it — only the
    explicitly configured pinned set defends against that.

KNOWN-ISSUES (tracked, not a bypass):
  - emilia_verify.canonicalize() is NOT yet RFC 8785 / JCS-strict (it sorts
    object keys by Unicode code point rather than UTF-16 code unit and does not
    normalize number formatting). It currently fails CLOSED — Python may REJECT
    some valid JS-signed receipts, never the reverse — so it is a
    false-negative risk, not a forgery vector. A JCS migration is deferred
    because it would break byte-compatibility with already-issued receipts and
    the JS verifier; it is tracked for a future RFC 8785 pass.

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
                   the guard verifies the Ed25519 signature OFFLINE, pins the
                   signer, binds the claim to the request, enforces single-use
                   (and optionally the anchor) before ever returning
                   verified=True.

Offline verification needs the verifier on the path:

    pip install emilia-verify
    # or, from this repo, without installing:
    PYTHONPATH=packages/python-verify python examples/grok_guard.py

Without it, the guard still works but marks the receipt
"unverified — install emilia-verify to verify offline" and refuses to claim a
cryptographic guarantee it did not check.

Stdlib only for HTTP (no `requests`/`httpx` dependency) on the sync path. Swap
the `_http` helper for your client of choice; the request/response shapes are
identical.

ASYNC: `AsyncEmiliaGuard` mirrors `EmiliaGuard` exactly — same offline
verification, same signer pinning, same request binding, same replay/anchor
gates, same https-only enforcement, same Idempotency-Key, same
approver-in-body-not-URL — over `httpx`. The two paths share the SAME pure
function (`_verify_evidence_offline`) so they cannot drift. httpx is the only
part of this file that needs a third-party dependency; `import httpx` is guarded
so the sync path keeps importing with stdlib only, and `AsyncEmiliaGuard` raises
a clear ImportError if constructed without httpx installed.

For a PRODUCTION-GRADE verifier that fails closed on a missing inclusion proof
(stricter than this example's opt-in `require_anchor`), see the repo's
`@emilia-protocol/verify` `verifyTrustReceipt()` and the EP Internet-Draft
§6.3 — the EP-Verified Execution conformance class re-verifies at the executor.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

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

# ── Optional async HTTP client ───────────────────────────────────────────────
# httpx is the ONLY third-party dependency in this file, and only AsyncEmiliaGuard
# uses it. Guard the import so the whole module — and the stdlib-only sync
# EmiliaGuard that claude_guard.py depends on — still imports when httpx is
# absent. AsyncEmiliaGuard raises a clear ImportError at construction in that case.
try:
    import httpx  # type: ignore

    _HAVE_HTTPX = True
except Exception:  # noqa: BLE001 - httpx missing means only the async path is unavailable
    httpx = None  # type: ignore
    _HAVE_HTTPX = False


class EmiliaAPIError(Exception):
    """A transport-level failure reaching the EMILIA API (DNS/TLS/connection).

    HTTP *status codes* are deliberately returned as data, not raised: a policy
    `deny` or a 4xx is a normal outcome the caller turns into a structured tool
    result, not an exception. Only when there is no response at all do we raise.
    """


# Receipt statuses that mean "a named human approved — safe to verify+proceed".
# Read from app/api/v1/trust-receipts/[receiptId]/route.js: the GET endpoint
# replays the audit log and reports 'approved_pending_consume' once a signoff is
# approved, and 'consumed' once the action has ALREADY been spent.
#
# FIX 3 (replay): 'consumed' is NOT an approval to act on — it means this
# receipt was already redeemed. Treating it as success would let a replayed,
# already-spent receipt authorize a SECOND execution. We therefore approve ONLY
# 'approved_pending_consume' and route 'consumed' to a non-approval terminal
# (status 'already_consumed', verified=False) below.
APPROVED_STATUSES = frozenset({"approved_pending_consume"})
# Already-spent: a terminal state that must BLOCK, not approve (single-use).
CONSUMED_STATUSES = frozenset({"consumed"})
# Statuses that end the poll without success.
REJECTED_STATUSES = frozenset({"rejected", "denied", "expired"})
TERMINAL_STATUSES = APPROVED_STATUSES | CONSUMED_STATUSES | REJECTED_STATUSES


# ── Replay store (single-use enforcement) ────────────────────────────────────
# FIX 3 (replay): a verified receipt must be redeemable at most ONCE. Before the
# guard returns verified=True it records the receipt_id; a second presentation of
# the same id is rejected (status "replay").
#
# ⚠ PRODUCTION WARNING — READ THIS. The default InMemoryReplayStore lives in this
# Python PROCESS ONLY. It does NOT survive a restart, and it is NOT shared across
# workers/replicas/hosts. It is adequate for a single long-lived worker and for
# tests, and it is INADEQUATE as the real single-use guarantee for money
# movement. Production MUST inject a PERSISTENT, ATOMIC store backed by the same
# database that executes the action — ideally the consume step itself
# (INSERT ... ON CONFLICT / a unique constraint on receipt_id, or the EP
# `consume` endpoint's atomic state transition), so that "mark consumed" and
# "execute" commit together. Anything less has a check-then-act race.
class ReplayStore(Protocol):
    """Single-use ledger keyed by receipt_id.

    `seen(receipt_id)` MUST be atomic test-and-set: it returns True iff the id
    was ALREADY recorded (i.e. this is a replay), and otherwise records it and
    returns False. A correct production implementation performs the check and
    the insert in one atomic DB operation.
    """

    def seen(self, receipt_id: str) -> bool: ...  # noqa: D401,E704


class InMemoryReplayStore:
    """Per-process, NON-persistent ReplayStore. See the loud warning above —
    NOT suitable as the production single-use guarantee; inject a DB-backed
    atomic store there."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen(self, receipt_id: str) -> bool:
        if receipt_id in self._seen:
            return True
        self._seen.add(receipt_id)
        return False


# A module-level default so the sync and async guards share one ledger when the
# caller does not inject their own. (Still per-process — see the warning above.)
_DEFAULT_REPLAY_STORE = InMemoryReplayStore()


# ── Signer key pinning (trust root) ──────────────────────────────────────────
# FIX 2: the trust root must be SERVER-INDEPENDENT. We never accept the
# `public_key` from the same /evidence response as proof of who signed — a
# compromised server would just sign with its own key and serve its own pubkey.
# Instead the signer must match a configured pinned set: exact base64url SPKI
# key material and/or its SHA-256 fingerprint (hex). Env EP_TRUSTED_SIGNER_KEYS
# is a comma-separated list of either form.
#
# NOTE: an optional `/.well-known/ep-keys.json` bootstrap is supported by
# load_trusted_signer_keys(base_url=...), but the app does NOT serve that route
# today (only /.well-known/{security.txt,ep-protocol.json,ep-trust.json} exist).
# Publishing /.well-known/ep-keys.json is the recommended follow-up; until then
# the CONFIGURED set is the required, real defense and the guard fails closed
# without it.
def _normalize_b64url(s: str) -> str:
    """Strip '=' padding and whitespace so equal keys compare equal regardless
    of how they were padded/encoded."""
    return s.strip().rstrip("=")


def _spki_fingerprint(public_key_b64url: str) -> Optional[str]:
    """SHA-256 (hex) of the raw SPKI DER bytes of a base64url public key. None if
    the key cannot be decoded."""
    try:
        raw = base64.urlsafe_b64decode(
            public_key_b64url + "=" * (-len(public_key_b64url) % 4)
        )
    except Exception:  # noqa: BLE001 - undecodable key is simply unpinnable
        return None
    return hashlib.sha256(raw).hexdigest()


def _is_pinned(public_key_b64url: str, pinned: "frozenset[str]") -> bool:
    """True iff this key is in the pinned set, by exact base64url value OR by its
    SHA-256 SPKI fingerprint (case-insensitive hex)."""
    if not public_key_b64url or not pinned:
        return False
    if _normalize_b64url(public_key_b64url) in pinned:
        return True
    fp = _spki_fingerprint(public_key_b64url)
    return bool(fp and fp.lower() in pinned)


def load_trusted_signer_keys(
    explicit: Optional["list[str]"] = None,
    env_var: str = "EP_TRUSTED_SIGNER_KEYS",
) -> "frozenset[str]":
    """Build the pinned signer set from an explicit list and/or an env var.

    Each entry is either a base64url SPKI key (padding-insensitive) or a
    SHA-256 fingerprint (hex). Returns a normalized frozenset; empty means "no
    pinned set configured" and the guard then fails CLOSED (untrusted_signer).
    """
    items: list[str] = []
    if explicit:
        items.extend(explicit)
    env_val = os.environ.get(env_var, "")
    if env_val:
        items.extend(part for part in env_val.split(",") if part.strip())
    normalized: set[str] = set()
    for it in items:
        it = it.strip()
        if not it:
            continue
        # Fingerprints are 64 hex chars; store them lowercased. Keys store
        # padding-stripped. (A 64-hex string is also a valid b64url token, so we
        # add both forms — harmless, and lets a fingerprint match either way.)
        normalized.add(_normalize_b64url(it))
        if len(it) == 64 and all(c in "0123456789abcdefABCDEF" for c in it):
            normalized.add(it.lower())
    return frozenset(normalized)


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

    verified: bool                 # True ONLY if signature + signer-pinning + request-binding
    #                                (+ replay + optional anchor) all passed, here, in-process.
    status: str                    # "verified" | "unsigned_evidence" | "verifier_unavailable"
    #                                | "signature_invalid" | "untrusted_signer" | "claim_mismatch"
    #                                | "anchor_required" | "replay" | "already_consumed"
    #                                | "verifier_error" | "no_evidence" | "rejected" | "timeout"
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

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        trusted_signer_keys: Optional["list[str]"] = None,
        require_anchor: bool = False,
        replay_store: Optional[ReplayStore] = None,
    ):
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
        # FIX 2: server-independent pinned signer set (explicit list +
        # EP_TRUSTED_SIGNER_KEYS env). Empty => the offline check fails closed.
        self.trusted_signer_keys = load_trusted_signer_keys(trusted_signer_keys)
        # FIX 3: opt-in anchor enforcement (see verify_receipt_offline note on
        # why this defaults off) and the single-use ledger.
        self.require_anchor = require_anchor
        self.replay_store = replay_store if replay_store is not None else _DEFAULT_REPLAY_STORE

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
        expected: Optional[dict] = None,
    ) -> VerifiedReceipt:
        """Poll the receipt to a terminal state, then — on approval — FETCH and
        VERIFY the signed evidence OFFLINE (signature + signer pinning + request
        binding + single-use + optional anchor). Returns a VerifiedReceipt whose
        `.verified` is True only when ALL of those checks passed in this process.
        A timeout, a rejection, an already-consumed receipt, or any failed check
        all yield verified=False.

        `expected` (FIX 1) is the original mint request:
        {receipt_id, action_type, amount, currency, target_resource_id,
        approver_id}. The tool/release paths always pass it so the signed claim
        is bound to what the agent actually asked for.
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
                    return self.verify_receipt_offline(receipt_id, expected=expected)
                if st in CONSUMED_STATUSES:
                    # FIX 3: already spent — must BLOCK, never re-authorize.
                    logger.info("emilia: %s already consumed (status=%s) — blocking", receipt_id, st)
                    return VerifiedReceipt(
                        verified=False, status="already_consumed",
                        detail="receipt already consumed (single-use spent)", raw=rec,
                    )
                logger.info("emilia: %s resolved without approval (status=%s)", receipt_id, st)
                return VerifiedReceipt(
                    verified=False, status="rejected", detail=f"signoff {st}", raw=rec
                )
            time.sleep(interval_s)
        logger.info("emilia: signoff for %s timed out after %ss", receipt_id, timeout_s)
        return VerifiedReceipt(verified=False, status="timeout", detail=f"no decision in {timeout_s}s")

    # 5: the headline feature — fetch signed evidence and verify it OFFLINE.
    def verify_receipt_offline(
        self, receipt_id: str, expected: Optional[dict] = None
    ) -> VerifiedReceipt:
        """Fetch the evidence packet and verify it locally: Ed25519 signature,
        server-independent signer pinning, request binding to `expected`,
        single-use, and (if self.require_anchor) the Merkle anchor.

        The /evidence endpoint returns the evidence packet. When that packet
        carries a signed EP-RECEIPT-v1 `document` plus the signer's `public_key`
        (base64url SPKI), we run emilia_verify.verify_receipt over it — the SAME
        check anyone can run offline with `pip install emilia-verify`. `verified`
        is True only if the signature is valid, the signer is pinned, the claim
        matches the request, the receipt is unspent, and (when required) the
        anchor verifies.
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
        return _verify_evidence_offline(
            ev,
            expected=expected,
            trusted_signer_keys=self.trusted_signer_keys,
            require_anchor=self.require_anchor,
            replay_store=self.replay_store,
        )


# ── Request binding (FIX 1) ──────────────────────────────────────────────────
# After the signature verifies we require the SIGNED claim to equal what THIS
# agent requested. The signed payload comes in two real shapes, so the binders
# read BOTH:
#
#   PRODUCTION (lib/guard-evidence-receipt.js signEvidenceReceipt):
#     payload.receipt_id
#     payload.claim.action_type          <- the action enum
#     payload.claim.canonical_action     <- the WYSIWYS action object
#                                            (amount/destination/currency live here)
#     payload.authorization.approver_id
#
#   FIXTURE / public-demo (packages/python-verify/tests/fixtures/receipt.json):
#     payload.receipt_id
#     payload.claim.action               <- e.g. "payment.release"
#     payload.claim.approver
#     payload.claim.context.{amount,destination,currency}
#
# receipt_id + amount + destination are the unambiguous bindings and MUST match.
# action_type↔claim.action is a non-1:1 mapping across shapes, so we bind it
# loosely (only when both sides clearly express the same token) and never let a
# mapping gap WEAKEN the hard bindings.


def _signed_payload(document: Any) -> dict:
    p = document.get("payload") if isinstance(document, dict) else None
    return p if isinstance(p, dict) else {}


def _signed_action_context(payload: dict) -> dict:
    """The money-bearing sub-object, across both payload shapes."""
    claim = payload.get("claim") if isinstance(payload.get("claim"), dict) else {}
    # Fixture/demo: claim.context. Production: claim.canonical_action (the
    # canonical action object the signature was taken over).
    ctx = claim.get("context")
    if isinstance(ctx, dict):
        return ctx
    canon = claim.get("canonical_action")
    if isinstance(canon, dict):
        return canon
    return {}


def _signed_receipt_id(payload: dict) -> Any:
    return payload.get("receipt_id")


def _signed_amount(payload: dict) -> Any:
    return _signed_action_context(payload).get("amount")


def _signed_currency(payload: dict) -> Any:
    return _signed_action_context(payload).get("currency")


def _signed_destination(payload: dict) -> Any:
    ctx = _signed_action_context(payload)
    # Accept the common destination aliases used across canonical-action shapes.
    for k in ("destination", "target_resource_id", "destination_account", "to"):
        if k in ctx and ctx[k] is not None:
            return ctx[k]
    return None


def _signed_approver(payload: dict) -> Any:
    claim = payload.get("claim") if isinstance(payload.get("claim"), dict) else {}
    if claim.get("approver") is not None:  # fixture/demo shape
        return claim.get("approver")
    authz = payload.get("authorization")
    if isinstance(authz, dict):
        return authz.get("approver_id")
    return None


def _amounts_equal(signed: Any, requested: Any) -> bool:
    """Numeric-tolerant equality for amounts (50000 == 50000.0)."""
    try:
        return float(signed) == float(requested)
    except (TypeError, ValueError):
        return signed == requested


def _bind_claim(payload: dict, expected: dict) -> Optional[str]:
    """Return None if the signed claim matches the expected request, else a
    human-readable mismatch detail. Fails CLOSED: any provided expected field
    that does not match the signed value is a mismatch.

    Hard bindings (always enforced when provided): receipt_id, amount, currency,
    destination, approver. action_type is bound loosely (see module note).
    """
    # PRIMARY binding — receipt_id. A different receipt has a different id; this
    # alone defeats substitution / replay-of-another-receipt.
    exp_rid = expected.get("receipt_id")
    if exp_rid is not None:
        if _signed_receipt_id(payload) != exp_rid:
            return (
                f"receipt_id mismatch: signed={_signed_receipt_id(payload)!r} "
                f"requested={exp_rid!r}"
            )

    exp_amount = expected.get("amount")
    if exp_amount is not None:
        if not _amounts_equal(_signed_amount(payload), exp_amount):
            return (
                f"amount mismatch: signed={_signed_amount(payload)!r} "
                f"requested={exp_amount!r}"
            )

    exp_currency = expected.get("currency")
    if exp_currency is not None:
        sc = _signed_currency(payload)
        # Only enforce when the signed payload actually carries a currency.
        if sc is not None and str(sc).upper() != str(exp_currency).upper():
            return f"currency mismatch: signed={sc!r} requested={exp_currency!r}"

    exp_dest = expected.get("target_resource_id")
    if exp_dest is not None:
        sd = _signed_destination(payload)
        if sd is not None and sd != exp_dest:
            return f"destination mismatch: signed={sd!r} requested={exp_dest!r}"

    exp_approver = expected.get("approver_id")
    if exp_approver is not None:
        sa = _signed_approver(payload)
        if sa is not None and sa != exp_approver:
            return f"approver mismatch: signed={sa!r} requested={exp_approver!r}"

    return None


def _verify_evidence_offline(
    evidence: dict,
    expected: Optional[dict] = None,
    trusted_signer_keys: Optional["frozenset[str]"] = None,
    require_anchor: bool = False,
    replay_store: Optional[ReplayStore] = None,
) -> VerifiedReceipt:
    """Pure function: given an evidence packet, verify the signed receipt inside
    it offline AND enforce signer pinning, request binding, single-use, and
    (optionally) the Merkle anchor. Extracted so the sync and async guards share
    one implementation and tests can exercise it without any network.

    Order (every step fails CLOSED):
      - packet carries no signed doc / malformed types -> "unsigned_evidence"
      - verifier not importable                        -> "verifier_unavailable"
      - verifier raises                                -> "verifier_error"
      - Ed25519 signature invalid                      -> "signature_invalid"
      - require_anchor and anchor not True             -> "anchor_required"
      - signer not in pinned set (or no set configured)-> "untrusted_signer"
      - signed claim != requested claim                -> "claim_mismatch"
      - receipt_id already redeemed                    -> "replay"
      - all pass                                        -> verified=True "verified"

    We NEVER return verified=True off a server status string alone, and we NEVER
    trust the inline public_key as the trust root.
    """
    # The signed receipt lives under `document` with the signer's `public_key`
    # (base64url SPKI Ed25519). Type-check both: a hostile body might send a str,
    # int, list, or junk — none of which is a signed document.
    document = evidence.get("document") if isinstance(evidence, dict) else None
    public_key = evidence.get("public_key") if isinstance(evidence, dict) else None

    if not isinstance(document, dict) or not isinstance(public_key, str) or not public_key:
        # Current production /evidence returns a plaintext, DB-tamper-evident
        # packet (schema ep-guard-evidence-v1) with no embedded signature. That
        # is server-attested, NOT offline-verifiable — say so plainly rather
        # than implying a cryptographic guarantee we didn't check. A malformed /
        # hostile body lands here too: fail closed, never raise.
        return VerifiedReceipt(
            verified=False,
            status="unsigned_evidence",
            detail=(
                "evidence packet carries no signed EP-RECEIPT-v1 document — "
                "server-attested only, not verified offline"
            ),
            raw=evidence if isinstance(evidence, dict) else {},
        )

    if not _HAVE_VERIFIER:
        return VerifiedReceipt(
            verified=False,
            status="verifier_unavailable",
            detail="unverified — install emilia-verify to verify offline (pip install emilia-verify)",
            raw=evidence,
        )

    # FIX 4 (defense-in-depth): the verifier promises not to raise, but a future
    # version or a pathological document must NEVER crash the gate. Any raise is
    # a failed verification, not an exception that propagates to the agent.
    try:
        result = _verify_receipt(document, public_key)  # type: ignore[misc]
    except Exception as e:  # noqa: BLE001 - any verifier raise fails closed
        logger.warning("emilia: OFFLINE verifier RAISED — treating as unverified: %s", e)
        return VerifiedReceipt(
            verified=False,
            status="verifier_error",
            detail=f"verifier raised: {e}",
            raw=evidence,
        )

    checks = dict(getattr(result, "checks", {}) or {})

    # FIX 4: strict identity — only an exact `True` counts. A truthy non-bool
    # (e.g. a stray object) must NEVER be read as a passing signature.
    if getattr(result, "valid", None) is not True:
        logger.warning(
            "emilia: OFFLINE signature FAILED — checks=%s error=%s",
            checks, getattr(result, "error", None),
        )
        return VerifiedReceipt(
            verified=False,
            status="signature_invalid",
            detail=getattr(result, "error", None) or "signature did not verify",
            checks=checks,
            raw=evidence,
        )

    # ── Signature verified. Now the request-level gates, all fail-closed. ──

    # FIX 3 (anchor): when required, a complete, valid Merkle anchor is
    # mandatory. emilia_verify reports checks["anchor"] as True (valid),
    # False (present but invalid), or None (absent). Only exact True passes.
    if require_anchor and checks.get("anchor") is not True:
        logger.warning("emilia: anchor required but checks[anchor]=%r", checks.get("anchor"))
        return VerifiedReceipt(
            verified=False,
            status="anchor_required",
            detail=(
                "require_anchor=True but the receipt carries no complete, valid "
                f"Merkle inclusion proof (anchor={checks.get('anchor')!r})"
            ),
            checks=checks,
            raw=evidence,
        )

    # FIX 2 (signer pinning): the trust root is server-INDEPENDENT. The inline
    # public_key is only believed if it is a member of the pinned set. No pinned
    # set => fail closed; we do NOT fall back to trusting whatever key the server
    # served alongside the document.
    pinned = trusted_signer_keys if trusted_signer_keys is not None else frozenset()
    if not pinned:
        logger.warning("emilia: NO trusted signer keys configured — failing closed")
        return VerifiedReceipt(
            verified=False,
            status="untrusted_signer",
            detail=(
                "no trusted signer keys configured — set EP_TRUSTED_SIGNER_KEYS "
                "(or pass trusted_signer_keys=) so the signer is pinned to a "
                "server-independent trust root; refusing to trust the inline key"
            ),
            checks=checks,
            raw=evidence,
        )
    if not _is_pinned(public_key, pinned):
        logger.warning("emilia: signer key NOT in pinned set — untrusted_signer")
        return VerifiedReceipt(
            verified=False,
            status="untrusted_signer",
            detail=(
                "signing key is not in the pinned trusted set (a compromised "
                "server signing with its own key and serving its own pubkey is "
                "rejected here)"
            ),
            checks=checks,
            raw=evidence,
        )

    # FIX 1 (request binding): the signed claim must equal what we requested.
    if expected:
        mismatch = _bind_claim(_signed_payload(document), expected)
        if mismatch is not None:
            logger.warning("emilia: CLAIM MISMATCH — %s", mismatch)
            return VerifiedReceipt(
                verified=False,
                status="claim_mismatch",
                detail=(
                    "signed receipt does not match the requested action — "
                    + mismatch
                ),
                checks=checks,
                raw=evidence,
            )

    # FIX 3 (replay): single-use. Record the receipt_id; a second presentation of
    # the same id is a replay. Keyed on the SIGNED receipt_id (the value the
    # signature covers), not a server-supplied envelope field.
    payload = _signed_payload(document)
    signed_rid = _signed_receipt_id(payload)
    store = replay_store if replay_store is not None else _DEFAULT_REPLAY_STORE
    if signed_rid is not None and store.seen(str(signed_rid)):
        logger.warning("emilia: REPLAY — receipt_id %r already redeemed", signed_rid)
        return VerifiedReceipt(
            verified=False,
            status="replay",
            detail=f"receipt {signed_rid!r} already redeemed (single-use)",
            checks=checks,
            raw=evidence,
        )

    logger.info(
        "emilia: OFFLINE signature VERIFIED + signer pinned + request bound + single-use — checks=%s",
        checks,
    )
    return VerifiedReceipt(
        verified=True, status="verified", checks=checks, raw=evidence
    )


# ── Async mirror (httpx) ─────────────────────────────────────────────────────
# A faithful async twin of EmiliaGuard for async backends (FastAPI, aiohttp,
# async agent loops). EVERY security property of the sync class is preserved:
#   - https-only (the token is never sent in cleartext; non-https is rejected)
#   - Idempotency-Key on mint (a retried mint returns the same receipt)
#   - approver bound in the POST body, never in the approval URL (no PII in URLs)
#   - offline Ed25519 verification on approval — `verified=True` ONLY if the
#     signature checks out locally; the server's "approved" string is never
#     trusted on its own, and it degrades exactly as the sync path does
#     (unsigned_evidence / verifier_unavailable / signature_invalid).
# The offline check reuses the SAME pure function (_verify_evidence_offline), so
# the two paths cannot drift apart.


async def _ahttp(
    client: "httpx.AsyncClient",
    method: str,
    url: str,
    api_key: str,
    body: Optional[dict] = None,
    timeout: int = 15,
    idempotency_key: Optional[str] = None,
) -> tuple[int, dict]:
    """Async sibling of `_http`. Same contract: HTTP status codes come back as
    data (a 4xx policy `deny` is a normal outcome, not an exception); only a
    genuine transport failure raises EmiliaAPIError."""
    # SECURITY: pin to https, exactly like the sync path. A plain http base_url
    # would leak the Bearer token in cleartext (CWE-319); anything but https is
    # refused before a byte goes on the wire.
    if not url.lower().startswith("https://"):
        raise ValueError(f"refusing non-https URL (token would be exposed): {url!r}")
    headers = {"Authorization": f"Bearer {api_key}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    # SECURITY: an Idempotency-Key makes a retried mint return the SAME receipt
    # instead of creating a duplicate (and a duplicate audit trail / signoff).
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    try:
        resp = await client.request(
            method,
            url,
            content=(json.dumps(body).encode("utf-8") if body is not None else None),
            headers=headers,
            timeout=timeout,
        )
    except httpx.HTTPError as e:  # type: ignore[union-attr]  # no response at all (network/DNS/TLS)
        raise EmiliaAPIError(f"cannot reach EMILIA at {url}: {e}") from e
    # A 4xx/5xx is a normal outcome the caller interprets (e.g. a policy deny).
    # Return it as data, never raise — the agent gets a structured "blocked".
    try:
        return resp.status_code, (resp.json() if resp.content else {})
    except Exception:  # noqa: BLE001
        return resp.status_code, {"error": "http_error"}


class AsyncEmiliaGuard:
    """Async (httpx) twin of EmiliaGuard. Identical behaviour and guarantees.

    Use as an async context manager so the underlying httpx client is closed:

        async with AsyncEmiliaGuard() as guard:
            res = await guard.guard(action_type=..., ...)

    or construct directly and call `await guard.aclose()` when done. Requires
    `httpx`; constructing without it raises a clear ImportError.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional["httpx.AsyncClient"] = None,
        trusted_signer_keys: Optional["list[str]"] = None,
        require_anchor: bool = False,
        replay_store: Optional[ReplayStore] = None,
    ):
        if not _HAVE_HTTPX:
            raise ImportError(
                "AsyncEmiliaGuard requires httpx (pip install httpx). "
                "The synchronous EmiliaGuard is stdlib-only and needs nothing extra."
            )
        # Use the www host: the apex 307-redirects, and a redirect would drop the
        # Authorization header on the cross-origin hop.
        self.base_url = (
            base_url or os.environ.get("EMILIA_BASE_URL", "https://www.emiliaprotocol.ai")
        ).rstrip("/")
        # SECURITY: the key is NEVER hardcoded — env (EP_API_KEY) or constructor.
        self.api_key = api_key or os.environ.get("EP_API_KEY", "")
        if not self.api_key:
            raise ValueError("AsyncEmiliaGuard: set EP_API_KEY (env) or pass api_key=...")
        # SECURITY: https only. Fail loudly at construction, not mid-flight.
        if not self.base_url.lower().startswith("https://"):
            raise ValueError(
                f"AsyncEmiliaGuard: base_url must be https (got {self.base_url!r})"
            )
        # FIX 2/3: same server-independent signer pinning, anchor policy, and
        # single-use ledger as the sync guard — the two share the pure verify
        # function so they cannot diverge on what counts as verified.
        self.trusted_signer_keys = load_trusted_signer_keys(trusted_signer_keys)
        self.require_anchor = require_anchor
        self.replay_store = replay_store if replay_store is not None else _DEFAULT_REPLAY_STORE
        # An injectable client lets tests supply a mock transport; otherwise we
        # own the client and close it in aclose()/__aexit__.
        self._client = client or httpx.AsyncClient()
        self._owns_client = client is None

    async def aclose(self) -> None:
        """Close the underlying httpx client (only if this guard created it)."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncEmiliaGuard":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    # 1+2: mint a pre-action receipt and, if the policy demands it, open a signoff.
    async def guard(
        self,
        action_type: str,
        target_resource_id: str,
        organization_id: str,
        amount: Optional[float] = None,
        currency: str = "USD",
        risk_flags: Optional[list[str]] = None,
        target_changed_fields: Optional[list[str]] = None,
        enforcement_mode: Optional[str] = None,
        actor_role: Optional[str] = None,
        approver_id: Optional[str] = None,
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

        status, mint = await _ahttp(
            self._client,
            "POST",
            f"{self.base_url}/api/v1/trust-receipts",
            self.api_key,
            mint_body,
            idempotency_key=idem,
        )
        # Real success signal: a receipt_id on a 2xx. The MINT endpoint returns
        # 201, but presence of receipt_id — not a hardcoded 201 — is what tells
        # us a receipt was created.
        receipt_id = mint.get("receipt_id")
        if status not in (200, 201) or not receipt_id:
            return GuardResult(
                False,
                "deny",
                reason=f"mint failed ({status}): {mint.get('detail') or mint.get('error')}",
                raw=mint,
            )

        # Decision enum is lowercase: allow | observe | allow_with_signoff | deny.
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
        status, sreq = await _ahttp(
            self._client,
            "POST",
            f"{self.base_url}/api/v1/signoffs/request",
            self.api_key,
            {
                "receipt_id": receipt_id,
                # SECURITY: bind the approver in the POST BODY, never in a URL
                # query string, so the approval URL stays free of PII.
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
    # ⚠ BLOCKS (asynchronously). Use this only in a worker / batch coroutine,
    # NEVER inside a live tool call — a tool call must return promptly. For the
    # tool-calling pattern, return approval_url and resume later (see
    # release_large_payment, the default non-blocking pattern).
    async def wait_for_approval(
        self,
        receipt_id: str,
        timeout_s: int = 600,
        interval_s: int = 3,
        expected: Optional[dict] = None,
    ) -> VerifiedReceipt:
        """Async poll to a terminal state, then — on approval — FETCH and VERIFY
        the signed evidence OFFLINE (signature + signer pinning + request binding
        + single-use + optional anchor). `.verified` is True only when ALL of
        those checks passed in this process. Timeout, rejection, an
        already-consumed receipt, or any failed check all yield verified=False.

        `expected` (FIX 1) is the original mint request; the release/resume paths
        always pass it so the signed claim is bound to the requested action."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout_s
        while loop.time() < deadline:
            status, rec = await _ahttp(
                self._client,
                "GET",
                f"{self.base_url}/api/v1/trust-receipts/{receipt_id}",
                self.api_key,
            )
            st = rec.get("receipt_status")
            if status == 200 and st in TERMINAL_STATUSES:
                if st in APPROVED_STATUSES:
                    logger.info(
                        "emilia: %s approved (status=%s key_class=%s) — verifying offline",
                        receipt_id, st, rec.get("signoff_key_class"),
                    )
                    # DO NOT trust the "approved" string. Verify the signature.
                    return await self.verify_receipt_offline(receipt_id, expected=expected)
                if st in CONSUMED_STATUSES:
                    # FIX 3: already spent — must BLOCK, never re-authorize.
                    logger.info("emilia: %s already consumed (status=%s) — blocking", receipt_id, st)
                    return VerifiedReceipt(
                        verified=False, status="already_consumed",
                        detail="receipt already consumed (single-use spent)", raw=rec,
                    )
                logger.info("emilia: %s resolved without approval (status=%s)", receipt_id, st)
                return VerifiedReceipt(
                    verified=False, status="rejected", detail=f"signoff {st}", raw=rec
                )
            await asyncio.sleep(interval_s)
        logger.info("emilia: signoff for %s timed out after %ss", receipt_id, timeout_s)
        return VerifiedReceipt(verified=False, status="timeout", detail=f"no decision in {timeout_s}s")

    # 5: the headline feature — fetch signed evidence and verify it OFFLINE.
    async def verify_receipt_offline(
        self, receipt_id: str, expected: Optional[dict] = None
    ) -> VerifiedReceipt:
        """Async fetch of the evidence packet; the OFFLINE check itself is the
        SAME pure function the sync path uses (_verify_evidence_offline) with the
        SAME pinned signer set, request binding, anchor policy, and single-use
        ledger — so the async and sync guards cannot diverge on what counts as
        verified."""
        status, ev = await _ahttp(
            self._client,
            "GET",
            f"{self.base_url}/api/v1/trust-receipts/{receipt_id}/evidence",
            self.api_key,
        )
        if status != 200 or not ev:
            return VerifiedReceipt(
                verified=False, status="no_evidence",
                detail=f"evidence fetch failed ({status})", raw=ev or {},
            )
        return _verify_evidence_offline(
            ev,
            expected=expected,
            trusted_signer_keys=self.trusted_signer_keys,
            require_anchor=self.require_anchor,
            replay_store=self.replay_store,
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


# ── Request-binding glue (FIX 1) ─────────────────────────────────────────────
def expected_from_args(args: dict, receipt_id: Optional[str]) -> dict:
    """Build the `expected` claim from the agent's tool args + the server-issued
    receipt_id. This is the request the signed receipt MUST match. The tool and
    release/resume paths always pass this so the verified signature is bound to
    the exact action the agent asked for, not merely to *some* valid receipt.

    Field paths the binder compares (see _bind_claim):
      receipt_id        -> payload.receipt_id            (PRIMARY)
      amount            -> payload.claim.context.amount  | claim.canonical_action.amount
      currency          -> ...context.currency           | ...canonical_action.currency
      target_resource_id-> ...context.destination         | ...canonical_action.destination
                                                          | ...canonical_action.target_resource_id
      approver_id       -> payload.claim.approver         | payload.authorization.approver_id
    """
    return {
        "receipt_id": receipt_id,
        "action_type": args.get("action_type"),
        "amount": args.get("amount"),
        "currency": args.get("currency", "USD"),
        "target_resource_id": args.get("target_resource_id"),
        "approver_id": args.get("approver_id"),
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

    # Blocking worker path: poll, then verify the signature OFFLINE — BOUND to
    # this exact request (FIX 1). `expected` carries the server-issued receipt_id
    # plus the action the agent actually asked for, so a genuinely-signed receipt
    # for a different action/amount cannot satisfy this gate.
    expected = expected_from_args(args, res.receipt_id)
    verified = guard.wait_for_approval(res.receipt_id, timeout_s=timeout_s, expected=expected)
    return {
        # proceed=true requires a human approval AND a signature that verified
        # locally AND a pinned signer AND the signed claim matching THIS request
        # AND an unspent receipt. Strict identity: only an exact True proceeds, so
        # a non-bool can never slip through. A server that merely *says*
        # "approved" is not enough.
        "proceed": verified.verified is True,
        "status": verified.status,
        "reason": verified.detail or f"signoff {verified.status}",
        "receipt_id": res.receipt_id,
        "signoff_id": res.signoff_id,
        "offline_verified": verified.verified is True,
        "verifier_checks": verified.checks or None,
    }


# ── Async tool pattern (the headline) — return the URL, don't block ──────────
# This is the shape an async agent/orchestrator actually wants: the tool mints
# the receipt, opens the signoff, and RETURNS the approval_url instead of
# blocking on a human. The orchestrator notifies the approver (Slack/SMS/email)
# and moves on. A SEPARATE resume step — a signoff webhook, or a later tool call
# that runs resume_release_large_payment() / guard.wait_for_approval() — does
# the offline Ed25519 verification and only then executes the irreversible
# action. The blocking wait_for_approval() poll below is for synchronous
# batch/worker coroutines only, never inside a live tool call.
async def release_large_payment(
    args: dict,
    guard: Optional[AsyncEmiliaGuard] = None,
    execute=None,
) -> dict:
    """Async tool the orchestrator calls *instead of* moving money directly.

    Returns one of:
      {"status": "executed", ...}            — policy allowed it outright (no human)
      {"status": "denied", ...}              — policy denied it
      {"status": "approval_required", "approval_url": ..., "receipt_id": ...}
                                             — a named human must sign on-device;
                                               resume later and verify offline
    On `allow`, runs `execute(args)` if provided (your real money-movement call).
    It never executes on `approval_required` — the receipt is not yet a verified
    signature over this exact action.
    """
    owns = guard is None
    guard = guard or AsyncEmiliaGuard()
    try:
        res = await guard.guard(
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
            # Allowed by policy with no human in the loop. Execute now.
            result = None
            if execute is not None:
                result = execute(args)
                if asyncio.iscoroutine(result):
                    result = await result
            return {
                "status": "executed",
                "reason": "allowed by policy (no signoff needed)",
                "receipt_id": res.receipt_id,
                "result": result,
            }

        if res.decision == "deny":
            return {
                "status": "denied",
                "reason": res.reason,
                "receipt_id": res.receipt_id,
            }

        # Signoff required — the headline path. Hand the OPAQUE approval URL back
        # to the orchestrator and return immediately, ALONG WITH the `expected`
        # claim (FIX 1) so the resume step can bind the signed receipt to THIS
        # request. A separate resume step (webhook or later tool call) re-checks
        # status and runs the OFFLINE signature + pinning + binding + single-use
        # verification before any money moves.
        return {
            "status": "approval_required",
            "reason": "named human signoff required — awaiting device signature",
            "approval_url": res.approval_url,
            "receipt_id": res.receipt_id,
            "signoff_id": res.signoff_id,
            # The request the resume step must enforce the signed claim against.
            "expected": expected_from_args(args, res.receipt_id),
        }
    finally:
        if owns:
            await guard.aclose()


async def resume_release_large_payment(
    receipt_id: str,
    guard: AsyncEmiliaGuard,
    execute=None,
    timeout_s: int = 600,
    expected: Optional[dict] = None,
) -> dict:
    """The resume step a webhook or follow-up tool call invokes once a human has
    (or hasn't) approved. Verifies the signature OFFLINE — and binds the signed
    claim to `expected` (the request returned by release_large_payment), pins the
    signer, and enforces single-use — executing ONLY if every check passes. A
    server that merely *says* "approved", or one that serves a genuinely-signed
    receipt for a DIFFERENT action, is not enough.

    `expected` MUST be threaded through from release_large_payment's
    `approval_required` result so the binding is enforced. If it is omitted the
    other gates (signature, signer pinning, single-use, anchor) still apply, but
    the request-binding gate cannot — so callers should always pass it."""
    verified = await guard.wait_for_approval(
        receipt_id, timeout_s=timeout_s, expected=expected
    )
    if verified.verified is not True:
        return {
            "status": verified.status,        # rejected | timeout | claim_mismatch | untrusted_signer | ...
            "executed": False,
            "reason": verified.detail or f"signoff {verified.status}",
            "receipt_id": receipt_id,
            "offline_verified": False,
        }
    result = None
    if execute is not None:
        result = execute(receipt_id)
        if asyncio.iscoroutine(result):
            result = await result
    return {
        "status": "executed",
        "executed": True,
        "reason": "device signature VERIFIED offline (signer pinned, request bound, single-use)",
        "receipt_id": receipt_id,
        "offline_verified": True,
        "verifier_checks": verified.checks or None,
        "result": result,
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
#   # FIX 2: pin the signer to a server-independent trust root. With this set,
#   # a fully compromised EMILIA server cannot make the agent proceed. (Without
#   # it the offline check fails closed with status=untrusted_signer.)
#   #   export EP_TRUSTED_SIGNER_KEYS="<base64url SPKI>,<sha256-fingerprint>"
#   guard = EmiliaGuard()  # or EmiliaGuard(trusted_signer_keys=[...], require_anchor=True)
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
# EP-Verified Execution conformance class), and supplying a PERSISTENT replay
# store (the executor's DB) rather than this example's per-process default.


if __name__ == "__main__":
    # Smoke demo against a running EMILIA. Needs EP_API_KEY (+ optional
    # EMILIA_BASE_URL). For offline verification, put the verifier on the path:
    #   PYTHONPATH=packages/python-verify EP_API_KEY=ep_live_... \
    #     EP_TRUSTED_SIGNER_KEYS="<base64url SPKI or sha256 fingerprint>" \
    #     python examples/grok_guard.py
    # Mints an $82k release, opens a signoff, prints the (opaque) approval URL,
    # then blocks (wait=True, worker mode) until you approve it in the browser —
    # and only prints proceed=true after the signature verifies locally, the
    # SIGNER is pinned (EP_TRUSTED_SIGNER_KEYS), and the signed claim matches the
    # requested $82k action. Without EP_TRUSTED_SIGNER_KEYS the offline check
    # fails CLOSED (status=untrusted_signer) by design — that is the secure
    # default, not a bug.
    if not os.environ.get("EP_API_KEY"):
        raise SystemExit(
            "Set EP_API_KEY (and optionally EMILIA_BASE_URL), then re-run.\n"
            "Offline verify also needs emilia-verify on the path:\n"
            "  pip install emilia-verify   (or  PYTHONPATH=packages/python-verify)"
        )
    if not os.environ.get("EP_TRUSTED_SIGNER_KEYS"):
        print("[warn] EP_TRUSTED_SIGNER_KEYS not set — offline verification will "
              "fail closed with status=untrusted_signer (secure default). Set it "
              "to the operator's pinned signer key(s) to allow proceed=true.")
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
