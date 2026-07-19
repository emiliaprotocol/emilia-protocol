<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright EMILIA Protocol, Inc. -->

# EP-PROVENANCE-CHAIN-v1 — Chained Provenance Receipt (SPECIFICATION PROPOSAL)

**Status:** Draft / Experimental specification proposal
**Type:** Extension (additive composite over EP Core v1.0)
**Requires:** PIP-001 (EP Core v1.0 Freeze), EP-RECEIPT-v1
(`standards/draft-schrock-ep-authorization-receipts-03.md` §6.2–6.3)
**Wire tag:** `EP-PROVENANCE-CHAIN-v1`

> This is a **specification proposal** plus a **reference implementation**
> (`lib/provenance/chain.js`). It is **experimental**. It is **not** a
> production claim, has **no** customers asserted, and reports **no**
> metrics. It MUST be ratified by a PIP before it can be called part of the
> protocol. It adds **no new trust assumptions** beyond those already
> required to verify an EP-RECEIPT-v1 receipt.

---

## 1. Abstract

The Chained Provenance Receipt is an **additive composite object** that
**bundles existing artifacts** to make one claim end-to-end verifiable:

> *"This irreversible action was executed because a named human signed off
> at the root, that authority flowed down an ordered, scope-narrowing chain
> of delegations, and a per-action human approval authorized this exact
> action — and every link is offline-verifiable with no new trust."*

It does this by **composition, not ownership**. It embeds, by value or by
hash reference:

- a **root human signoff** — an EP-RECEIPT-v1 receipt whose signoff is the
  root authority for the whole bundle;
- an **ordered delegation chain** — references to DRP delegation records
  (`draft-nelson-agent-delegation-receipts`), each of which MUST be
  scope-contained within its parent (DelegateCannotExceedPrincipal);
- a **per-action approval** — an EP-RECEIPT-v1 receipt authorizing the
  exact executed action;
- an **execution reference** — a hash/id binding to what was actually done;
- (optional) an **agent_identity claim** — identified, attestable, scoped;
  never asserted as proof of strong agent identity;
- (optional) a **liability attestation** — a named owner who accepts
  accountability. Evidence, not a legal determination.

**The EP Core is frozen (PIP-001).** This object does **not** modify the
EP-RECEIPT-v1 wire format, its canonicalization, or its signature. Each
embedded receipt verifies **byte-identically** under the existing
`verifyTrustReceipt()` (I-D §6.3). Verifying the composite =
verify each linked v1 receipt + check the chain + check scope containment
+ check the fail-closed obligations below. **No new trust is added.**

---

## 2. Why composition (and not a new core object)

PIP-001 freezes exactly three Core Objects: Trust Receipt, Trust Profile,
Trust Decision. A change is **additive (Extension-class)** iff it does not
modify a frozen object's wire format, canonicalization, or signature path,
and old verifiers keep working unchanged. This object qualifies:

- It introduces a **new outer envelope** (`EP-PROVENANCE-CHAIN-v1`) that
  *carries* v1 receipts; it never alters them.
- A verifier that predates this spec still verifies each embedded
  EP-RECEIPT-v1 receipt with no change.
- The DRP delegation reference reuses the I-D §10 composition point
  (a delegation referenced from an Action Object's `provenance`) and the
  I-D §8 constraint **DelegateCannotExceedPrincipal**.

The composite is therefore governed as an **Extension PIP**, never a
breaking change.

---

## 3. Object structure

```jsonc
{
  "@version": "EP-PROVENANCE-CHAIN-v1",

  // The root of authority: a full EP-RECEIPT-v1 receipt whose human
  // signoff(s) anchor the whole bundle. REQUIRED. Verified verbatim by
  // verifyTrustReceipt(). This is the "termination in a root human
  // signoff" the verifier requires.
  "root_signoff": {
    "receipt": { /* full EP-RECEIPT-v1 §6.2 receipt */ },
    // Material to verify THIS receipt offline (pinned, not fetched).
    "verification": {
      "approver_keys": { "ep:key:...#1": { "public_key": "b64u...", "key_class": "A", "valid_from": "...", "valid_to": "..." } },
      "log_public_key": "b64u-SPKI-DER",
      "rp_id": "approvals.example",
      "allowed_origins": ["https://approvals.example"]
    },
    // At least one signoff in receipt.signoffs MUST be a human signoff.
    // A Class-A (WebAuthn UV) signoff is the strongest human evidence;
    // see §6 "human_signoff" rule.
    "human_key_classes": ["A"]
  },

  // Ordered delegation chain, root -> leaf. Each entry references a DRP
  // delegation record. index 0's parent is the root_signoff approver;
  // every later entry's parent is entry[i-1]. Each child scope MUST be
  // contained in its parent scope (parent-scope-containment). MAY be [].
  "delegation_chain": [
    {
      "sequence": 0,
      "delegation_id": "ep_dlg_...",        // DRP delegation id
      "delegator": "ep:approver:...|ep:key:...",  // parent authority
      "delegatee": "ep:agent:...",           // who receives authority
      "scope": ["wire.release", "payment.*"],// granted action types (glob ok)
      "max_value_usd": 2500000,              // optional cap (null = uncapped)
      "expires_at": "2026-06-14T00:00:00Z",
      "constraints": { /* optional, opaque to this verifier */ },
      // Binding of this delegation back to its parent. The first entry MUST
      // bind to a root_signoff approver; later entries bind to the prior
      // delegatee. This is what makes the chain "ordered".
      "parent_ref": "ep:key:root-approver#1",
      // OPTIONAL: a DRP delegation receipt + the public key + algorithm to
      // verify the delegation record's own signature offline. When present,
      // the verifier checks it; when absent, the delegation is treated as
      // UNVERIFIED evidence and (fail-closed) the bundle is rejected for
      // irreversible actions unless opts.allowUnsignedDelegations is set.
      "proof": {
        "signed_payload_b64u": "b64u...",    // canonical bytes that were signed
        "signature_b64u": "b64u...",
        "algorithm": "Ed25519",
        "public_key": "b64u-SPKI-DER"
      }
    }
  ],

  // The per-action approval: a full EP-RECEIPT-v1 receipt authorizing the
  // EXACT action that was executed. REQUIRED when the action is
  // irreversible (§6 rule "per_action_required_for_irreversible"). MAY be
  // omitted only for reversible actions.
  "action_approval": {
    "receipt": { /* full EP-RECEIPT-v1 §6.2 receipt */ },
    "verification": {
      "approver_keys": { /* ... */ },
      "log_public_key": "b64u",
      "rp_id": "approvals.example",
      "allowed_origins": ["https://approvals.example"]
    }
  },

  // What was actually executed, bound by hash to the approved action.
  // execution.action_hash MUST equal action_approval.receipt.action_hash
  // (the per-action approval authorized THIS execution, not a different one).
  "execution": {
    "execution_id": "ex_...",
    "action_hash": "sha256:...",            // MUST match action_approval
    "irreversible": true,                    // drives fail-closed obligations
    "executed_at": "2026-06-13T17:25:10Z",
    "target": { "system": "treasury.example", "resource": "wire/8841" }
  },

  // OPTIONAL. Agent identity is a CLAIM: identified and attestable, scoped.
  // EP does NOT assert this proves strong agent identity. Carried as a
  // verifiable-but-scoped field; the verifier reports it, never trusts it
  // as identity proof.
  "agent_identity": {
    "agent_id": "ep:agent:recon-7",
    "claimed_by": "ep:operator:acme",
    "attestation": {                         // optional self-describing proof
      "method": "operator_signed",
      "signed_payload_b64u": "b64u...",
      "signature_b64u": "b64u...",
      "algorithm": "Ed25519",
      "public_key": "b64u-SPKI-DER"
    },
    "scope_note": "Identity is a scoped claim by the operator, not proof of strong agent identity."
  },

  // OPTIONAL. Liability/owner attestation: assigns a NAMED owner who
  // accepts accountability for the bundle. This is EVIDENCE, not a legal
  // determination. The verifier checks the signature (if present) and
  // reports the named owner; it never adjudicates liability.
  "liability": {
    "owner": "ep:org:acme-treasury",
    "owner_name": "ACME Treasury Operations",
    "statement": "ACME accepts operational accountability for this action.",
    "attestation": {
      "signed_payload_b64u": "b64u...",
      "signature_b64u": "b64u...",
      "algorithm": "Ed25519",
      "public_key": "b64u-SPKI-DER"
    }
  },

  // OPTIONAL metadata; NOT trusted, NOT part of any security decision.
  "provenance_metadata": {
    "chain_depth": 1,
    "assembled_at": "2026-06-13T17:25:11Z",
    "note": "Composition of existing EP-RECEIPT-v1 receipts + DRP delegation references. No new trust."
  }
}
```

### 3.1 Field reuse table (real v1 field names)

| Composite field | Reuses v1 / source field | Source of truth |
|---|---|---|
| `root_signoff.receipt` | full EP-RECEIPT-v1 (`action`, `action_hash`, `contexts`, `signoffs`, `consumption`, `log_proof`) | I-D §6.2; `packages/issue/index.js` `assembleAuthorizationReceipt()` |
| `root_signoff.verification.*` | Optional transport hints only; never a trust root | ignored for acceptance |
| `opts.rootVerification` / `opts.actionVerification` | relying-party-pinned `approver_keys`, `log_public_key`, WebAuthn `rp_id`, and exact `allowed_origins` | `packages/verify/index.js` `verifyTrustReceipt()` |
| `*.receipt.signoffs[i].key_class` | `key_class` (`A`\|`B`\|`C`); `A` = WebAuthn human | I-D §5.3 |
| `delegation_chain[i].delegation_id` etc. | DRP delegation (`delegation_id`, `principal_id`→`delegator`, `agent_entity_id`→`delegatee`, `scope`, `max_value_usd`, `expires_at`, `constraints`) | `lib/delegation.js` |
| `execution.action_hash` | `action_hash` (`"sha256:<hex>"`) | I-D §3; `actionHash()` in `packages/issue` |

> **Implementation note (single source of cryptographic truth).** The
> reference verifier `lib/provenance/chain.js` imports the **frozen**
> `verifyTrustReceipt()` from `packages/verify/index.js` and
> `canonicalize()` from `packages/issue/index.js`, and adds exactly one
> local primitive — detached Ed25519 verification of a delegation /
> attestation `proof` — which grants no trust on its own. The
> `delegation_chain[]` field names above mirror `lib/delegation.js`
> (`delegator` ← `principal_id`, `delegatee` ← `agent_entity_id`); the
> module reuses that file's record *shape*, not its `verifyDelegation()`
> call path. No frozen file is modified.

---

## 3.2 Distinct object: `EP-PROVENANCE-ENTRY-v1` (MCP-guard ledger)

`packages/mcp-guard/index.js` maintains an append-only
`ProvenanceLedger` whose entries carry the tag
**`EP-PROVENANCE-ENTRY-v1`**. This is a **separate additive object**, not
the composite specified here. The distinction is deliberate and
normative:

| | `EP-PROVENANCE-CHAIN-v1` (this spec) | `EP-PROVENANCE-ENTRY-v1` (mcp-guard ledger) |
|---|---|---|
| Shape | root signoff + ordered delegation chain + per-action approval + execution (+ optional agent_identity / liability) | one append-only ledger entry: a single `receipt_ref` (`receipt_id` + content hash) + `prev_entry_hash` |
| Granularity | one end-to-end authorization bundle | one executed irreversible tool call |
| Produced by | `lib/provenance/chain.js` `assembleProvenance()` | `packages/mcp-guard` `ProvenanceLedger.append()` |
| Verified by | `verifyProvenanceOffline()` (this spec §5) | `ProvenanceLedger.verifyChain()` (append-only hash-chain integrity only) |

The relationship is compositional: a run of `EP-PROVENANCE-ENTRY-v1`
ledger entries is the in-process anchor from which an
`EP-PROVENANCE-CHAIN-v1` bundle can later be assembled. Both are
experimental, additive, and frozen-Core-safe (each only *references*
already-issued v1 receipts and re-signs nothing). **Implementations MUST
NOT conflate the two wire tags.**

---

## 4. Scope containment (parent-scope-containment)

At each hop the child's authority MUST be a subset of its parent's
authority. The reference rule, applied per hop, is the conjunction of:

1. **Action-type containment.** Every action type in `child.scope` is
   permitted by `parent.scope`. A parent entry `"x.*"` or `"*"` permits the
   matching children; otherwise membership is exact-string. The executed
   `execution.action_hash`'s action type (taken from the per-action
   approval's `receipt.action.action_type`) MUST be permitted by the
   **leaf** delegation's effective scope.
2. **Value containment.** If the parent sets `max_value_usd`, the child's
   `max_value_usd` MUST be `<= parent.max_value_usd` (a missing/`null`
   child cap is treated as "inherits parent cap", not "uncapped").
3. **Temporal containment.** `child.expires_at <= parent.expires_at`, and
   the per-action approval's `committed_at` MUST be `<= leaf.expires_at`.

This is the I-D §8 **DelegateCannotExceedPrincipal** property applied along
the whole chain: *effective scope = intersection of every ancestor grant*.
Any violation fails the bundle closed.

The chain's **head** (sequence 0) MUST bind to the root signoff: its
`delegator`/`parent_ref` MUST name an approver (or approver key id) that
actually signed `root_signoff.receipt`. A chain that does not terminate
upward in the root human signoff fails closed.

---

## 5. Offline verification algorithm (fail-closed)

Input: the composite document; `opts` (verifier knobs, all default to the
strict/fail-closed setting). Output:
`{ valid, checks, errors, links, agent_identity, liability }`.

**The algorithm calls the FROZEN v1 verifier verbatim; it adds NO new
trust.** It fails closed: any failure of any obligation ⇒ `valid:false`.

```
verifyProvenanceOffline(doc, opts):
  REJECT unless doc["@version"] == "EP-PROVENANCE-CHAIN-v1"          # version

  # ── 1. Root human signoff (the termination) ─────────────────────────────
  REJECT unless opts.rootVerification carries relying-party-pinned
                approver_keys, log_public_key, rp_id, and allowed_origins
  r0 = verifyTrustReceipt(doc.root_signoff.receipt,
                          opts.rootVerification)                     # FROZEN v1
  REJECT unless r0.valid                                            # root_receipt_valid
  # Human classes are VERIFIER-side policy (opts.humanKeyClasses, default ['A']).
  # The per-document root_signoff.human_key_classes field is NOT trusted to
  # widen 'human' — a producer cannot relabel a Class-B software key as human.
  REJECT unless some signoff in root receipt has key_class in
                opts.humanKeyClasses                                 # root_human_signoff

  # ── 2. Per-action approval (required by default; fail-closed) ────────────
  # The producer's execution.irreversible flag is UNTRUSTED and can never DROP
  # this requirement. Approval is required UNLESS reversibility is asserted
  # INDEPENDENTLY via opts.reversibilityAsserted(exec) -> true.
  needApproval = requireActionApprovalAlways OR
                 NOT (opts.reversibilityAsserted?(doc.execution) == true)
  if needApproval:
     REJECT unless doc.action_approval present                      # per_action_required
  if doc.action_approval present:
     REJECT unless opts.actionVerification carries relying-party pins
     ra = verifyTrustReceipt(doc.action_approval.receipt,
                             opts.actionVerification)               # FROZEN v1
     REJECT unless ra.valid                                         # action_receipt_valid
     REJECT unless ra binds a human signoff when execution.irreversible
                                                                    # action_human_signoff
     REJECT unless doc.execution.action_hash ==
                   doc.action_approval.receipt.action_hash          # execution_binding

  # ── 3. Ordered delegation chain + scope containment ─────────────────────
  # Root authority is DERIVED from what the root receipt authorized — NEVER '*'.
  rootScope = [ doc.root_signoff.receipt.action.action_type ]        # derived, not assumed
  parent = { scope: rootScope,
             max_value_usd: null,
             expires_at: max human-context expires_at in root receipt,
             id: "(root human signoff)" }
  if chain non-empty:
     REJECT unless chain[0].parent_ref names a root-receipt approver # chain_anchored
  prevDelegatee = null
  for each link in delegation_chain (in sequence order):
     if prevDelegatee != null:                                      # inter-hop binding
        REJECT unless link.parent_ref == prevDelegatee
                  AND link.delegator  == prevDelegatee              # chain_links_bound
     REJECT unless link.expires_at not in the past at opts.now      # delegations_not_expired
     if link.proof present:
        REJECT unless signature(link.proof) verifies
                  AND link.proof.signed_payload_b64u bytes ==
                      canonicalize({delegation_id, delegator, delegatee,
                                    scope, max_value_usd, expires_at,
                                    constraints})                    # delegations_signed
        REJECT unless link.proof.public_key ==
                      opts.delegationKeys[link.delegator].public_key # proof_key_bound
     else:
        REJECT unless opts.allowUnsignedDelegations                 # (fail-closed default)
     REJECT unless scopeContained(parent, link)                     # scope_containment
       # action-type subset  AND  value cap <=  AND  expires <=
     parent = link; prevDelegatee = link.delegatee
  # The executed action MUST be permitted by the leaf authority — and when the
  # chain is EMPTY, the leaf authority IS the derived root authority (so a
  # chain-less execution is still constrained to the root's actual scope).
  REJECT unless leafScopePermits(parent, executedActionType)        # leaf_permits_action
  REJECT unless committedAt(action_approval) <= parent.expires_at    # temporal_containment

  # ── 4. Optional claims (reported, NOT trusted) ──────────────────────────
  agent_identity = report+verify-if-signed(doc.agent_identity)       # advisory
  liability      = report+verify-if-signed(doc.liability)            # advisory

  valid = every REJECT-gated check above passed
  return { valid, checks, errors, links, agent_identity, liability }
```

### 5.1 Fail-closed obligations (each, individually, rejects the bundle)

1. **Broken signature** — any embedded v1 receipt fails
   `verifyTrustReceipt()` (action hash, context commitments, signoff
   signatures, SoD, inclusion, checkpoint signature, or windows).
2. **Scope-containment violation** — a child action type, value cap, or
   expiry exceeds its parent's; or the executed action type is outside the
   leaf's effective scope; or, with an EMPTY chain, outside the DERIVED root
   authority (root scope is `[root.action.action_type]`, never `'*'`).
3. **Tampered leaf** — any receipt's Merkle leaf no longer reconstructs the
   signed checkpoint root (caught inside `verifyTrustReceipt`); or a
   delegation `proof` does not sign the `canonicalize()` bytes of that
   link's own fields (a producer cannot widen `scope`/`max_value_usd`/
   `expires_at` after signing).
4. **Substituted delegation proof key** — a link's `proof.public_key` is
   not the key bound to that link's named `delegator` in
   `opts.delegationKeys`.
5. **Broken inter-hop link** — a hop after the head whose `parent_ref` or
   `delegator` does not equal the prior hop's `delegatee`.
6. **Missing per-action approval** — approval is REQUIRED by default and
   only droppable when reversibility is INDEPENDENTLY asserted via
   `opts.reversibilityAsserted`. A producer's `execution.irreversible:false`
   flag alone never drops it. (When `execution.irreversible == true`, the
   approval MUST additionally bind a human signoff.)
7. **No termination in a root human signoff** — the root receipt has no
   signoff whose `key_class` is in `opts.humanKeyClasses` (the per-document
   `human_key_classes` field is ignored for this check), or the delegation
   chain head does not bind to a root-receipt approver.
8. **Execution mismatch** — `execution.action_hash` does not equal the
   per-action approval's `action_hash` (approval authorized a *different*
   action than what executed).

The optional `agent_identity` and `liability` blocks are **advisory**:
they are verified-if-signed and reported, but a malformed/absent/unsigned
optional block NEVER flips `valid` to true and NEVER, on its own, flips it
to false. (A *present-but-signature-invalid* optional block is reported in
`errors` as advisory and does not gate `valid` — it is evidence, not a
trust anchor.)

---

## 6. Verifier knobs (`opts`) and their fail-closed defaults

| Option | Default | Effect |
|---|---|---|
| `rootVerification` | none | REQUIRED relying-party-pinned `{ approver_keys, log_public_key, rp_id, allowed_origins }` for the root receipt. Document-carried values are ignored as trust roots. |
| `actionVerification` | none | REQUIRED relying-party-pinned `{ approver_keys, log_public_key, rp_id, allowed_origins }` whenever an action-approval receipt is present. |
| `humanKeyClasses` | `['A']` | The ONLY source of human-class truth. The per-document `root_signoff.human_key_classes` field is NOT trusted to widen it. Default requires WebAuthn UV (Class A). Set `['A','B','C']` only in test. |
| `delegationKeys` | `{}` | Pinned proof keys per `delegator` id (`{ "<delegator>": { public_key } }`), mirroring root `approver_keys`. A delegation whose `delegator` has no pinned key, or whose `proof.public_key` differs, rejects the bundle. |
| `reversibilityAsserted` | `undefined` | Verifier-supplied `(exec) => boolean` that INDEPENDENTLY asserts reversibility. Only this (never the producer's `execution.irreversible` flag) can drop the per-action approval requirement. Absent it, approval is required (fail-closed). |
| `allowUnsignedDelegations` | `false` | When `false`, a delegation with no verifiable `proof` rejects the bundle. |
| `now` | `Date.now()` | Reference time for expiry checks (injectable for vectors). |
| `requireActionApprovalAlways` | `false` | When `true`, require a per-action approval even when reversibility is independently asserted. |

All defaults are the strict / fail-closed setting. There is **no** knob
that disables the frozen v1 checks — those always run verbatim, and no knob
can mark a non-human key as human or accept a producer's reversibility
self-label.

---

## 7. What this object does and does NOT prove

**Proves (by composition, no new trust):** that a named human signed the
root authority; that authority narrowed monotonically down an ordered,
in-scope delegation chain; that a per-action human approval authorized the
exact executed action (for irreversible actions); and that every receipt
in the bundle independently verifies offline under the frozen v1 verifier.

**Does NOT prove:** strong agent identity (the `agent_identity` block is a
scoped *claim*, never proof); legal liability (the `liability` block is
*evidence*, never an adjudication); that a key was unrevoked after commit
time (an I-D §6.3 limitation inherited verbatim); or what a human *saw*
when signing (I-D §11.3, also inherited).

---

## 8. Governance

This object MUST be ratified by an **Extension PIP** (template
`PIPs/PIP-000-process.md`; example `PIPs/PIP-007`). It modifies no frozen
Core Object. It is **experimental** until that PIP reaches Accepted.
Apache-2.0, irrevocable.
