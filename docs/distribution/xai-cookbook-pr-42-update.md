# xAI Cookbook PR #42 — staging update

> **This is staging content.** The user pushes it to the **xai-org/xai-cookbook** fork
> branch by hand. **Do not commit to that repo from here**, and do not push from this
> repository. Everything below is ready-to-paste material for that external PR; nothing
> here is wired into a build.

PR under update: <https://github.com/xai-org/xai-cookbook/pull/42>

Single source of truth for the code is
[`examples/grok_guard.py`](https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/grok_guard.py)
in the EMILIA repo. The recipe **links to** that file and shows a minimal snippet — it does
**not** fork a divergent copy of the guard.

---

## (a) Ready-to-paste recipe

### Human approval for a Grok agent's irreversible actions

Grok can reason, plan, and call tools. The moment a tool call is **irreversible** — releasing
a large payment, changing a payee bank account, deleting records — you want a **named human**
to approve *that exact action* on their own device, and you want the agent to proceed only
after that approval has been **cryptographically verified**, not merely asserted by a server.

EMILIA's hardened guard, [`grok_guard.py`](https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/grok_guard.py),
does this. When a signoff resolves it fetches the signed evidence and verifies the Ed25519
signature **offline, in the agent's own process**. It returns `proceed=True` only when every
independent check passes (each fails closed):

1. **Signature** — the Ed25519 signature over the canonical EP-RECEIPT-v1 payload verifies.
2. **Signer pinning** — the signing key is a member of a **server-independent** pinned set
   (`EP_TRUSTED_SIGNER_KEYS` / `trusted_signer_keys=`). The guard does **not** trust the
   `public_key` the `/evidence` response served; with no pinned set it fails closed
   (`untrusted_signer`).
3. **Request binding** — the signed `receipt_id` / amount / currency / destination / approver
   equal what the agent actually requested. A genuinely-signed $1 receipt cannot approve an
   $82k wire (`claim_mismatch`).
4. **Single-use** — a `receipt_id` is redeemable at most once (`replay`); an already-spent
   receipt is rejected (`already_consumed`).
5. **Anchor** (opt-in, `require_anchor=True`) — the Merkle inclusion proof must be present and
   valid (`anchor_required`).

The receipt proves that a *named, pinned key* signed the *exact* canonical action the agent
requested — accountable, request-bound, single-use. It does **not** prove the approver was
wise, that the action is lawful, or that what the human saw rendered faithfully matched the
signed bytes.

#### Install

```bash
pip install emilia-verify httpx        # offline verifier (+ httpx for the async guard)
export EP_API_KEY=ep_live_...          # your EMILIA API key — never hardcode it

# The real defense: pin the signer out of band (config management / a vault),
# NOT from the server you verify against. Comma-separated base64url SPKI keys
# and/or SHA-256 fingerprints:
export EP_TRUSTED_SIGNER_KEYS='<base64url-SPKI>,<sha256-fingerprint>'
```

Point an OpenAI-compatible client at the xAI endpoint — for example set
`XAI_BASE_URL` to your xAI base URL and use `model="grok-4"`. The guard is identical for any
OpenAI-compatible provider.

#### Minimal hardened flow — mint → approval_url → resume → offline-verify

```python
import json, os
from openai import OpenAI
from examples.grok_guard import (
    EmiliaGuard,
    dispatch_emilia_tool,
    EMILIA_TOOL_SCHEMA,
)

# Pin the signer to a server-independent trust root. With EP_TRUSTED_SIGNER_KEYS set,
# a fully compromised EMILIA server cannot make the agent proceed. (Without a pinned
# set the offline check fails closed with status=untrusted_signer — the secure default.)
guard = EmiliaGuard()  # reads EP_API_KEY + EMILIA_BASE_URL + EP_TRUSTED_SIGNER_KEYS
#   For convenience bootstrap (not a full trust root — same operator over https):
#       from examples.grok_guard import fetch_well_known_signer_keys
#       keys  = fetch_well_known_signer_keys("https://www.emiliaprotocol.ai")
#       guard = EmiliaGuard(trusted_signer_keys=keys)

# Example: an xAI / OpenAI-compatible client (replace the base URL with your xAI endpoint).
client = OpenAI(api_key=os.environ["XAI_API_KEY"], base_url=os.environ["XAI_BASE_URL"])

messages = [{"role": "user", "content": "Pay the $82k Acme invoice to the new account."}]
resp = client.chat.completions.create(
    model="grok-4", messages=messages,
    tools=[EMILIA_TOOL_SCHEMA], tool_choice="auto",
)

for call in (resp.choices[0].message.tool_calls or []):
    if call.function.name == "emilia_require_human_signoff":
        args = json.loads(call.function.arguments)

        # DEFAULT (non-blocking): mint a pre-action receipt, open a signoff, and
        # RETURN the opaque approval_url. A tool call must return promptly — never
        # block a model's tool call on a human.
        result = dispatch_emilia_tool(args, guard=guard, notify=send_to_slack)
        #   -> {"proceed": False, "status": "approval_required",
        #       "approval_url": ".../signoff/<opaque-id>", "receipt_id": "tr_..."}
        # proceed is False here: a receipt is minted, NOT yet signed. The agent
        # must refuse to run the irreversible action until proceed=True.

        messages.append({"role": "tool", "tool_call_id": call.id,
                         "content": json.dumps(result)})

# ... the named human opens approval_url and approves on-device (Face ID), out of band ...

# RESUME (worker / batch — BLOCKS; never inside a live tool call): poll to a terminal
# state, then verify the device signature OFFLINE, bound to THIS exact request, pinned
# signer, single-use. proceed=True only if every check passed in-process.
final = dispatch_emilia_tool(args, guard=guard, wait=True, timeout_s=900)
if final["proceed"] is True:        # strict: only an exact True proceeds
    release_payment(args)           # your real money-movement call
```

For an async agent loop, `release_large_payment(args, guard=AsyncEmiliaGuard())` returns the
`approval_url` plus an `expected` claim, and a separate
`resume_release_large_payment(receipt_id, guard, expected=..., execute=...)` does the offline
verification and executes only on a verified approval. Both paths share the same offline
verification function, so they cannot drift.

> **Production note.** The default in-memory replay store is **per-process only** — inject a
> persistent, atomic store (the executor's DB) for a real single-use guarantee. The guarantee
> holds end-to-end only if your `release_payment` refuses to run unless `proceed=True`,
> ideally re-verifying at the executor.

---

## (b) Suggested PR description / changelog entry

**Title:** Harden the EMILIA human-approval recipe — offline verification, signer pinning,
request-binding, replay/anchor, red-team suite

**Body / changelog:**

This updates the human-approval recipe to reflect the hardened guard
([`examples/grok_guard.py`](https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/grok_guard.py)).
The earlier recipe described a server-attested approval; the recipe now reflects a guard that
re-derives trust from the signature itself. Honestly summarized, the hardening adds:

- **Offline signature verification.** On approval the guard fetches the signed evidence and
  verifies the Ed25519 signature over the canonical EP-RECEIPT-v1 payload **in-process** with
  the pure-Python `emilia-verify`. A server saying "approved" is never sufficient.
- **Server-independent signer pinning.** The signing key must be in a pinned set
  (`EP_TRUSTED_SIGNER_KEYS` / `trusted_signer_keys=`); the inline `public_key` is never the
  trust root. With no pinned set the guard fails closed (`untrusted_signer`).
- **Request-binding.** The signed `receipt_id` / amount / currency / destination / approver
  must equal what the agent requested (`claim_mismatch` otherwise), so a genuinely-signed
  receipt for a different action cannot be substituted.
- **Replay / single-use + optional anchor.** A `receipt_id` is redeemable at most once
  (`replay` / `already_consumed`); `require_anchor=True` additionally requires a valid Merkle
  inclusion proof (`anchor_required`).
- **A red-team regression suite.** Six adversarial vectors are re-run permanently
  ([`examples/tests/test_grok_guard_redteam.py`](https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/tests/test_grok_guard_redteam.py)):
  tampered action → `signature_invalid`; attacker self-signs → `untrusted_signer`;
  wrong amount/id/destination → `claim_mismatch`; stripped anchor → `anchor_required`;
  replay/consumed → `replay` / `already_consumed`; hostile evidence bodies → `verified=False`,
  never raises. Plus a genuine-fixture control that proceeds.

Honest residuals, stated in the recipe: the default replay store is per-process (inject a
DB-backed atomic store in production); canonicalization is not yet RFC 8785 / JCS-strict and
currently fails **closed** (Python may reject some valid JS-signed receipts, never the
reverse — a false-negative risk, not a forgery vector); the receipt does not prove the
approver was wise, the action lawful, or that the rendered approval screen matched the signed
bytes.

The recipe links to `examples/grok_guard.py` rather than vendoring a copy, so it cannot drift
from the maintained guard.

---

## (c) Push checklist (for the user)

This repo never touches the external fork. To ship the update, do this by hand:

- [ ] In your local **xai-org/xai-cookbook** fork, check out the PR #42 branch
      (`git fetch origin && git checkout <pr-42-branch>`).
- [ ] Paste section **(a)** into the recipe markdown/notebook the PR updates; keep the link to
      `examples/grok_guard.py` (do **not** vendor a copy of the guard into the cookbook).
- [ ] Sanity-check the snippet against the live guard API
      ([`examples/grok_guard.py`](https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/grok_guard.py)):
      `EmiliaGuard`, `AsyncEmiliaGuard`, `dispatch_emilia_tool`, `release_large_payment` /
      `resume_release_large_payment`, `fetch_well_known_signer_keys`, `expected_from_args`,
      `EMILIA_TOOL_SCHEMA`.
- [ ] Use section **(b)** as the PR description / changelog comment.
- [ ] `git commit` and `git push` to **your fork's** PR branch — never from this repository.
- [ ] Confirm the PR diff still points readers at `EP_TRUSTED_SIGNER_KEYS` as the real defense
      and keeps the honest residuals paragraph (no "unbreakable", no
      "compromised-server-proof" without the pinning caveat).
