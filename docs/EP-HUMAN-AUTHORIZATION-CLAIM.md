<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-HUMAN-AUTHORIZATION-CLAIM — the human-authorization assertion as a reusable, embeddable claim

**Status:** Profile (spec-level). EXPERIMENTAL. Carves the human-authorization
assertion out of EP so OTHER receipt formats can embed it directly. Additive
over [draft-schrock-ep-authorization-receipts] and [draft-schrock-ep-quorum].

## The opportunity

Across the agent-authorization receipt cluster, EP is the only effort that binds
a named, accountable **human** (or a quorum of distinct humans) to an exact
action. Several adjacent formats have a *slot* for this and no semantics behind
it: [draft-lee-orprg-permit-receipts] lists a `threshold_signature` authenticity
claim but defines no human-quorum meaning; delegation receipts
([draft-nelson-agent-delegation-receipts]) attest the agent's authority but not a
contemporaneous human approval of the specific action.

The highest-leverage move for EP is therefore not to win a format war but to make
its primitive **embeddable**: define the human-authorization assertion as a
compact, self-describing claim that any receipt, token, or chain can carry. Every
adopter that embeds it propagates EP's semantics rather than reinventing them.

## The claim

`ep_human_authorization` — a self-contained object asserting that one or more
named, accountable humans authorized a specific action:

```json
{
  "ep_human_authorization": {
    "v": "EP-HAC-v1",
    "action_digest": "sha256:<hex>",          // JCS(action) — the binding
    "mode": "single | quorum",
    "approvals": [
      { "approver": "ep:approver:fd_morales",
        "role": "finance_director",
        "key_class": "A",                       // device-bound / WebAuthn
        "signoff": { ...EP-SIGNOFF-v1... } }
      // ... additional distinct approvers for quorum
    ],
    "policy": "org:policy:high-value@v4",
    "quorum": { "required": 2, "distinct_humans": true, "ordered": true }
  }
}
```

Properties an embedding format inherits for free:

* **Action binding** — `action_digest` is the JCS digest of the exact action; an
  embedding receipt's own action digest MUST equal it (else the human approved a
  different action).
* **Accountability** — each approval names a human and carries that human's own
  device-class signature (EP-SIGNOFF-v1), verifiable offline.
* **Separation of duties** — `mode: quorum` carries the distinct-human / ordered
  / threshold semantics of [draft-schrock-ep-quorum].

## How others embed it

* **As a CWT/EAT claim** — register `ep_human_authorization` (see
  [EP-COSE-EAT-PROFILE]) so it rides in EAT submodules and SCITT statements.
* **As a JSON member** — any JSON receipt (permit, delegation, decision) adds the
  object; its verifier calls EP's `verifyQuorum` / signoff verifier on the
  embedded value and checks the digest matches the host receipt's action.
* **As an EP-AEC component** — the chain
  ([draft-schrock-ep-authorization-evidence-chain]) treats it as the `ep-quorum`
  / `ep-receipt` leg.

## Verification

An embedder verifies the claim with EP's existing offline predicate: every
approval's signature valid, every approval bound to `action_digest`, approvers
pairwise distinct, roles admitted, threshold/order satisfied, within window.
Reference code: `verifyQuorum` / `verifyReceipt` in `@emilia-protocol/verify`.

## Why this beats "another receipt"

A format only EP ships competes with a dozen others. A *claim everyone can embed*
makes EP the human-authorization primitive of the whole cluster — adopted by
inclusion, not by displacement. It is the most defensible long-run position for a
single-author effort: maximize how many other specs carry your semantics.

[draft-schrock-ep-authorization-receipts]: https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/
[draft-schrock-ep-quorum]: https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/
[EP-COSE-EAT-PROFILE]: ./EP-COSE-EAT-PROFILE.md
