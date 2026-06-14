# PIP-009: Provenance Chain — Chained Provenance Receipt

**Status:** Draft
**Type:** Extension (Core-adjacent / additive)
**Created:** 2026-06-13
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP defines a new composite object, the **Chained Provenance
Receipt** (wire tag **`EP-PROVENANCE-CHAIN-v1`**), that **bundles
existing artifacts** so that one end-to-end claim becomes
offline-verifiable:

> *a named human signed off at the root; that authority flowed down an
> ordered, scope-narrowing delegation chain; a per-action human approval
> authorized the exact action that executed; and that execution is
> hash-bound to the approval — with **no new trust** beyond verifying
> each embedded `EP-RECEIPT-v1`.*

The composite is a single JSON object with exactly these members:

- `root_signoff` — a full `EP-RECEIPT-v1` (the I-D §6.2 object, frozen
  under PIP-001) whose **human** signoff anchors the bundle;
- `delegation_chain[]` — an ordered list of DRP delegation references
  (`draft-nelson-agent-delegation-receipts`), root → leaf, each one
  **parent-scope-contained** (DelegateCannotExceedPrincipal, I-D §8) and
  bound hop-to-hop;
- `action_approval` — a full `EP-RECEIPT-v1` authorizing the exact
  executed action;
- `execution` — a hash/id reference whose `action_hash` MUST equal the
  approval's `action_hash`;
- `agent_identity` (OPTIONAL) — a **scoped claim**, identified and
  attestable, never proof of strong agent identity;
- `liability` (OPTIONAL) — a **named-owner attestation**, evidence of an
  accountable owner, never a legal determination.

The composite is **purely additive and by-composition only**: it does
**not** modify `EP-RECEIPT-v1`, its JCS canonicalization (RFC 8785), its
Ed25519 signature, or the frozen §6.3 offline-verification algorithm.
Each embedded receipt remains a byte-for-byte unmodified `EP-RECEIPT-v1`
that existing verifiers verify without change. Verifying the composite
introduces **no new trust assumptions**: it is exactly "verify each
embedded `EP-RECEIPT-v1` under its own log/approver keys, then check the
delegation chain's scope-containment and the fail-closed obligations" —
no new signer, key, root of trust, or cryptographic primitive is trusted
that an `EP-RECEIPT-v1` verifier did not already trust. The one
signature primitive the composite adds — verifying a detached delegation
/ attestation proof — grants **no** trust by itself; its result is
reported as evidence and gates only as the fail-closed rules require.
The composite **fails closed**: any broken link rejects the whole
bundle. This PIP is a spec proposal accompanied by an **experimental**
reference implementation; it makes no production or customer claims and
reports no metrics.

## Motivation

A single authorization receipt proves that named humans approved one
exact action before it ran. Real workflows are sequences under delegated
authority: a user signs off at the root, delegates a bounded slice of
that authority to an operator, who sub-delegates a still-narrower slice
to an agent, which then runs one specific irreversible action under a
per-action approval. Four facts that today live in separate artifacts
need to be presentable, and checkable, as one bundle:

1. **A human root.** The whole thing bottoms out in at least one real
   human signoff on an `EP-RECEIPT-v1` — not an agent authorizing
   itself.
2. **An ordered, scope-narrowing delegation chain.** Where authority is
   delegated, DRP binds the user-to-operator (and operator-to-agent)
   grants. The I-D already states the composition point — "a DRP
   delegation can be referenced in an EP Action Object's provenance
   field" (I-D §10) — and §8 already requires
   `DelegateCannotExceedPrincipal`. What is missing is a *named
   composite* that carries those references at the bundle level and
   specifies how a verifier walks them hop-to-hop.
3. **A per-action approval bound to what ran.** For an irreversible
   action, a per-action `EP-RECEIPT-v1` must authorize the exact action,
   and the execution must be hash-bound to it (no approve-A-run-B
   substitution).
4. **Scoped, honest side-claims.** Optionally, who the acting agent
   claims to be (a *scoped claim*, not strong identity) and who accepts
   accountability (a *named-owner attestation*, evidence, not an
   adjudication).

The cleanest way to provide all four without touching frozen Core is a
composite that *bundles* existing receipts plus delegation references.
This is composition, not ownership: the Chained Provenance Receipt owns
no signed truth-bearing field of any receipt and re-signs nothing. It is
the bundle-level analogue of what PIP-007 did at the context level —
additive, non-breaking, claim-bearing where appropriate, and verified by
inherited primitives rather than new ones.

## Specification

The normative object structure and the full offline verification
algorithm live in **`docs/EP-PROVENANCE-RECEIPT-SPEC.md`** and the JSON
shape schema in **`docs/EP-PROVENANCE-RECEIPT.schema.json`**
(`$id` `EP-PROVENANCE-CHAIN-v1.schema.json`). This section summarizes
the object and the verification obligations that the PIP ratifies; the
spec is authoritative on field-level detail.

### 1. The `EP-PROVENANCE-CHAIN-v1` object

An `EP-PROVENANCE-CHAIN-v1` document is a single JSON object:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `@version` | REQUIRED | string | MUST be the literal `"EP-PROVENANCE-CHAIN-v1"`. |
| `root_signoff` | REQUIRED | object | `{ receipt, verification, human_key_classes? }`. `receipt` is a complete, unmodified `EP-RECEIPT-v1` (I-D §6.2); `verification` is the pinned offline material (`approver_keys`, `log_public_key`) to verify it; at least one `signoffs[]` entry MUST be a human signoff (default human class = `A`, WebAuthn UV). |
| `delegation_chain` | REQUIRED | array | Ordered root → leaf DRP delegation references (Section 2). MAY be empty (`[]`) when no delegated authority is involved. |
| `action_approval` | conditional | object | `{ receipt, verification }` — a complete, unmodified `EP-RECEIPT-v1` authorizing the exact executed action. REQUIRED at verify time when `execution.irreversible == true`. |
| `execution` | REQUIRED | object | Hash/id reference to what actually ran (Section 3). |
| `agent_identity` | OPTIONAL | object | A scoped agent-identity **claim** (Section 4). Reported, never trusted as identity proof. |
| `liability` | OPTIONAL | object | A named-owner accountability **attestation** (Section 4). Evidence, never a legal determination. |
| `provenance_metadata` | OPTIONAL | object | Advisory, non-signed summary. Carries no truth-bearing field; verifiers MUST NOT base any decision on it. |

The composite object itself is **not signed** and introduces no new
signature. All trust derives from the signatures already inside the
embedded `EP-RECEIPT-v1` receipts and the referenced/attested DRP
delegations. The embedded receipts are carried **by value, unmodified**:
each is canonicalized and verified exactly as a standalone receipt
would be. The Chained Provenance Receipt is a *carrier*, not a
re-issuer.

### 2. Delegation chain entry

Each member of `delegation_chain` is an ordered DRP delegation
reference:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `sequence` | REQUIRED | integer | 0-based position; the chain is verified in sequence order (root → leaf). |
| `delegation_id` | REQUIRED | string | The DRP delegation id (`ep_dlg_…`). |
| `delegator` | REQUIRED | string | Parent authority (`ep:approver:` / `ep:key:` id). |
| `delegatee` | REQUIRED | string | Recipient of authority (`ep:agent:` / `ep:entity:` id). |
| `scope` | REQUIRED | array | Granted action types; `'*'` and `'x.*'` globs permitted. |
| `max_value_usd` | OPTIONAL | number\|null | Value cap. `null`/absent **inherits the parent cap** (NOT "uncapped"). |
| `expires_at` | REQUIRED | string | Delegation expiry (RFC 3339). |
| `constraints` | OPTIONAL | object\|null | Opaque to this verifier. |
| `parent_ref` | REQUIRED | string | Binds this hop to its parent. `sequence 0` MUST name a `root_signoff` approver / approver_key_id; later hops name the prior `delegatee`. This hop-to-hop binding is what makes the chain ordered. |
| `proof` | OPTIONAL | object | A detached Ed25519 attestation over the delegation record (`{ signed_payload_b64u, signature_b64u, algorithm: "Ed25519", public_key }`). When present it is verified; when **absent** the delegation is unverified and (fail-closed default) the bundle is rejected unless `opts.allowUnsignedDelegations` is set. |

The field names mirror `lib/delegation.js` (`delegator` ← `principal_id`,
`delegatee` ← `agent_entity_id`, plus `scope`, `max_value_usd`,
`expires_at`, `constraints`) so a reference resolves cleanly to a DRP
delegation record.

### 3. `execution`

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `action_hash` | REQUIRED | string | `"sha256:<hex>"`. MUST equal `action_approval.receipt.action_hash` — the per-action approval authorized **this** execution, not a different one. |
| `irreversible` | REQUIRED | boolean | When `true`, a valid `action_approval` binding a human signoff is REQUIRED (fail-closed). |
| `execution_id` | OPTIONAL | string | |
| `executed_at` | OPTIONAL | string | RFC 3339. |
| `target` | OPTIONAL | object | What was acted on. |

### 4. Optional side-claims (`agent_identity`, `liability`)

Both are **advisory**: the verifier reports them and verifies any
detached signature they carry, but a malformed / absent / unsigned
optional block NEVER flips the verdict to `true`, and a
present-but-signature-invalid block is reported in `errors` as advisory
without flipping the verdict to `false`. `agent_identity` is a scoped
claim by the operator (`agent_id`, `claimed_by`, optional `attestation`,
`scope_note`); EP does not assert it proves strong agent identity.
`liability` names an accountable `owner` (optional `owner_name`,
`statement`, `attestation`); it is evidence of who attested to
ownership, not a legal determination.

### 5. Composite verification (additive, no new trust assumptions)

A verifier MUST establish all of the following. **Every gating step
reuses an existing primitive; none introduces a new trust root, key, or
cryptographic assumption beyond those an `EP-RECEIPT-v1` verifier already
relies on** (the lone added primitive — detached-signature verification
of a delegation/attestation proof — grants no trust by itself and gates
only per the fail-closed rules). The algorithm **fails closed**: any
failed obligation ⇒ `valid: false`.

1. **Version.** Reject unless `@version == "EP-PROVENANCE-CHAIN-v1"`.
2. **Root human signoff (the termination).** Run the frozen I-D §6.3
   verifier on `root_signoff.receipt` under its own pinned
   `approver_keys` / `log_public_key`; reject unless it verifies. Reject
   unless at least one signoff carries a human `key_class`
   (default `['A']`, WebAuthn UV). A bundle that does not bottom out in a
   real human signoff confers no authority.
3. **Per-action approval.** When `execution.irreversible == true` (or
   `opts.requireActionApprovalAlways`), reject unless `action_approval`
   is present, its receipt passes the frozen §6.3 verifier, and (for
   irreversible actions) it binds a human signoff. Reject unless
   `execution.action_hash == action_approval.receipt.action_hash`.
4. **Ordered chain + scope containment
   (`DelegateCannotExceedPrincipal`).** The head (`sequence 0`)
   `parent_ref` MUST name a `root_signoff` approver. Walking root → leaf,
   each hop MUST be not-expired at reference time, carry a verifiable
   `proof` (unless unsigned delegations are explicitly allowed), and be
   **scope-contained in its parent**: action-type subset, value cap
   `<=` parent (a `null` child cap inherits, never uncaps), and
   `expires_at <=` parent. The **leaf** scope MUST permit the executed
   action type (taken from `action_approval.receipt.action.action_type`),
   and the per-action approval's `committed_at` MUST be
   `<= leaf.expires_at`.
5. **Optional side-claims (reported, not trusted).** `agent_identity` and
   `liability` are verified-if-signed and reported; they can never make
   an invalid bundle valid (Section 4).

`valid` is the conjunction of the gating checks **only**. No step trusts
the unsigned composite wrapper: a verifier that strips it and verifies
each embedded `EP-RECEIPT-v1` independently obtains the same per-receipt
result. The composite adds *checks* (ordering, containment, binding,
termination), never new *trust*.

### 6. What the composite does and does not prove

- It proves the embedded authorization receipts are individually valid;
  that a named human signed the root authority; that authority narrowed
  monotonically down an ordered, in-scope delegation chain; and that a
  per-action human approval authorized the exact executed action (for
  irreversible actions), hash-bound to what ran.
- A delegation hop without a verifiable `proof` is an unverified
  assertion: under the fail-closed default it rejects the bundle (for the
  obligations that depend on it), following the I-D's stance that
  authority carried into a receipt is a scoped, attestable claim, not
  proof of strong external identity (I-D §1.2).
- It does **not** prove currency: as in I-D §6.3, offline verification
  establishes validity at commit time, not that any embedded receipt's
  keys or delegations remain unrevoked now. A relying party with
  freshness requirements MUST additionally consult current
  directory/log heads online.
- It does **not** prove strong agent identity (`agent_identity` is a
  scoped claim) or legal liability (`liability` is evidence), and it does
  not prove what a human *saw* when signing (I-D §11.3, inherited).

## Rationale

- **Why a composite, not a Core change.** Every property above
  (human root, ordered scope-narrowing delegation, per-action binding)
  is expressible by *referencing* existing artifacts. Touching
  `EP-RECEIPT-v1` to add bundle fields would break the frozen object and
  every deployed verifier for zero gain. The composite reads existing
  signed values; it adds none to a receipt.
- **Why an unsigned wrapper.** Signing the bundle would introduce a new
  key and a new trust assumption — the opposite of the goal. Every truth
  the bundle asserts is already signed inside an embedded receipt or a
  referenced DRP delegation. An unsigned carrier is exactly what makes
  "no new trust assumptions" true and checkable.
- **Why embed receipts by value.** Embedding the full `EP-RECEIPT-v1`
  keeps the bundle offline-verifiable end to end, consistent with the
  I-D's offline-first design (§6.3).
- **Why parent-scope-containment hop-to-hop.** It is the I-D §8
  `DelegateCannotExceedPrincipal` property applied along the whole
  chain: effective scope = the intersection of every ancestor grant.
  Checking it at the bundle level is what lets a relying party verify a
  multi-hop delegation in one pass.
- **Why fail closed.** A chained authorization is only as strong as its
  weakest link; a permissive composite that surfaced a partially valid
  chain as "valid" would be an overclaim and a bypass surface. The
  Security Considerations state the rejection rule normatively.

## Backwards Compatibility

Purely additive; no migration required, and nothing frozen is touched.

- **PIP-001 Core freeze intact.** The frozen Core objects are the Trust
  Receipt / Authorization Receipt, Trust Profile, and Trust Decision
  (`PIPs/PIP-001-core-freeze.md`; the receipt's canonical name is the
  subject of the separate Core PIP-008, which this PIP does not depend on
  and does not pre-empt). The `EP-PROVENANCE-CHAIN-v1` object modifies
  none of them. Embedded receipts are carried by value, byte-for-byte;
  their wire format, JCS canonicalization, Ed25519 signature, and the
  frozen §6.3 verification algorithm are unchanged. Receipts verify
  identically whether standalone or embedded.
- **Old verifiers, new bundle.** A verifier that does not understand
  `EP-PROVENANCE-CHAIN-v1` can extract each embedded receipt
  (`root_signoff.receipt`, `action_approval.receipt`) and verify it as a
  standalone `EP-RECEIPT-v1` with no modification; it simply does not
  perform the chain-level containment and termination checks. No existing
  receipt is invalidated.
- **New verifiers, old receipts.** A chain-aware verifier presented with
  a lone `EP-RECEIPT-v1` (no wrapper) verifies it exactly as today.
- **No new trust roots.** A relying party that already trusts a given log
  key and approver directory to verify `EP-RECEIPT-v1` needs to trust
  nothing additional to verify a bundle under those same keys. DRP
  delegation verification uses DRP's own roots, which a party checking
  delegated authority already had to trust under I-D §8.

## Reference Implementation

The reference implementation is **experimental** and accompanies this
Draft as a spec proposal; it is not production- or customer-deployed, and
no metric or adoption claim is made for it. It is new code that edits no
shared middleware and no frozen package.

- **Assembler + verifier (implemented).**
  **`lib/provenance/chain.js`** exports:
  - `assembleProvenance({ rootSignoff, delegationChain, actionApproval,
    execution, agentIdentity, liability, metadata })` — pure data
    composition over already-issued `EP-RECEIPT-v1` receipts and DRP
    delegation references. It mints no keys, signs no receipts, and
    re-signs nothing. It emits the `EP-PROVENANCE-CHAIN-v1` object above.
  - `verifyProvenanceOffline(doc, opts)` — performs Section 5 fully
    offline and fail-closed, returning
    `{ valid, checks, errors, links, agent_identity, liability }`.
  - `PROVENANCE_VERSION` — the literal `"EP-PROVENANCE-CHAIN-v1"`.

  The module imports the **frozen** `verifyTrustReceipt()` from
  `packages/verify/index.js` and `canonicalize()` from
  `packages/issue/index.js` as the single source of cryptographic truth,
  and adds exactly one local primitive — detached Ed25519 verification of
  a delegation / attestation `proof` — which grants no trust on its own.
  Delegation links are verified **self-containedly and offline**: each
  hop's `proof` signature is checked against the `canonicalize()` bytes of
  that link's own fields (`delegation_id`, `delegator`, `delegatee`,
  `scope`, `max_value_usd`, `expires_at`, `constraints`), the proof key is
  bound to the named `delegator` via a caller-supplied `delegationKeys`
  map (mirroring `root_signoff` `approver_keys`), each hop is bound to the
  prior `delegatee`, and the head is bound to a root approver. Its
  delegation-reference field names mirror `lib/delegation.js`'s record
  *shape* (`delegator` ← `principal_id`, `delegatee` ← `agent_entity_id`);
  the offline verifier does **not** call that file's async, store-backed
  `verifyDelegation()`. It modifies none of those files.

- **Spec + schema (implemented).**
  `docs/EP-PROVENANCE-RECEIPT-SPEC.md` (normative object + algorithm) and
  `docs/EP-PROVENANCE-RECEIPT.schema.json` (JSON shape; `$id`
  `EP-PROVENANCE-CHAIN-v1.schema.json`) describe exactly the object this
  PIP ratifies.

- **Conformance vectors (companion track).** A
  **`conformance/vectors/provenance-chains.v1.json`** — following the
  pattern of `conformance/vectors/receipts.v1.json` — SHOULD include at
  minimum: a minimal valid bundle (root signoff + execution, empty
  chain); a valid bundle with a scope-narrowing delegation chain and a
  per-action approval; and explicit **fail-closed** negatives — a
  tampered embedded leaf, an `execution.action_hash` that does not match
  the approval, a child delegation hop outside its parent's scope, a
  missing per-action approval for an irreversible action, and a bundle
  whose root carries no human signoff — each of which MUST be rejected.
  The vector file is produced by the conformance track; this PIP does not
  introduce a separate generator.

No change to `packages/verify`, `packages/issue`, the MCP server, the
`require-receipt` demand hook, or any nav/middleware is required or
permitted by this PIP.

### Relationship to the MCP-guard provenance ledger

`packages/mcp-guard/index.js` maintains an append-only
**`ProvenanceLedger`** whose entries carry the tag
**`EP-PROVENANCE-ENTRY-v1`**. That is a **distinct, additive object**: a
per-tool-call ledger entry that *references* a single v1 receipt
(`receipt_id` + content hash) for one executed irreversible tool call and
hash-chains entries together. It is **not** the same object as
`EP-PROVENANCE-CHAIN-v1` and is not produced or consumed by
`lib/provenance/chain.js`. The relationship is compositional: a sequence
of `EP-PROVENANCE-ENTRY-v1` ledger entries is the in-process anchor from
which an `EP-PROVENANCE-CHAIN-v1` bundle can later be assembled, but the
two have different shapes (ledger entry = one receipt reference + chain
hash; provenance chain = root signoff + delegation chain + per-action
approval + execution). Both are experimental and governed by an Extension
PIP; neither modifies frozen Core. Implementations MUST NOT conflate the
two wire tags.

## Security Considerations

**(a) Fail closed on any link.** A verifier MUST reject the entire bundle
if any of the following holds: an embedded `EP-RECEIPT-v1` fails the
frozen §6.3 verification (bad signature, bad inclusion proof, SoD
violation, expired window, tampered leaf); the root carries no
human-class signoff; `execution.irreversible == true` with no valid
`action_approval`, or an `action_approval` that does not bind a human
signoff; `execution.action_hash` does not equal the approval's
`action_hash`; the delegation head does not bind to a root-receipt
approver; any delegation hop is expired, unsigned (under the fail-closed
default), or signature-invalid; any scope-containment violation
(action-type, value cap, or expiry) along the chain; or the leaf scope
does not permit the executed action type. There is no partial-credit or
best-effort "valid" outcome for a broken bundle.

**(b) No new trust assumptions, restated as a requirement.** A conforming
verifier MUST NOT trust the unsigned `EP-PROVENANCE-CHAIN-v1` wrapper for
any truth-bearing claim. Every accepted fact MUST trace to a signature
inside an embedded `EP-RECEIPT-v1` (verified under its own keys) or a
verified DRP delegation `proof`. The wrapper's `provenance_metadata` MUST
NOT influence the result. The one local primitive (detached-signature
verification of a delegation/attestation `proof`) grants no standalone
trust; its result is evidence gated by the fail-closed rules.

**(c) Delegation authority is a verifiable-but-scoped claim, not strong
identity.** A delegation hop without a verifiable `proof` is an
unverified assertion and (fail-closed default) rejects the bundle for the
obligations that depend on it; EP does not claim to prove strong upstream
agent identity, only to carry a scoped, attestable authority claim that
is verifiable when its DRP proof is present (I-D §1.2, §8). Likewise the
optional `agent_identity` block is a scoped **claim**, never proof of
strong agent identity; treating it as established identity is a
conformance violation.

**(d) Human-root termination is mandatory.** The chief value of the
composite is that a long agent-driven sequence still bottoms out in a
named human's device-bound approval. A verifier MUST establish the root
human signoff (Section 5 step 2); a "bundle" that is purely agent
self-authorization confers no authority and MUST be rejected, mirroring
the I-D's rule that the initiator is identified but never trusted with
approval authority over its own actions (I-D §2).

**(e) Privacy.** Embedding two full receipts plus delegation records
concentrates operational context (counterparties, amounts, delegation
relationships) into one long-lived, portable artifact. Producers SHOULD
bundle only what a relying party needs, SHOULD prefer hashed parameter
values where the executor can recompute them (I-D §3), and MUST apply the
same retention and disclosure controls to a bundle as to its most
sensitive embedded receipt.

**(f) Liability attestation is evidence, not a legal determination.**
Where the bundle names a `liability.owner`, that assignment is evidence
of who attested to ownership at commit time; it is not a legal
determination, and nothing in this PIP is legal advice.

## References

- `standards/draft-schrock-ep-authorization-receipts-01.md` — Sections
  1.2 (Scope of Identity), 2 (Terminology), 3 (Action Object), 4
  (Authorization Context), 6.2 (Trust Receipt), 6.3 (Offline
  Verification Algorithm), 8 (Delegation Constraints,
  `DelegateCannotExceedPrincipal`), 10 (Relationship to Other Work — DRP
  composition via the Action Object provenance field), 11.3
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- `docs/EP-PROVENANCE-RECEIPT-SPEC.md` — normative object + offline
  verification algorithm for `EP-PROVENANCE-CHAIN-v1`
- `docs/EP-PROVENANCE-RECEIPT.schema.json` — JSON shape schema (`$id`
  `EP-PROVENANCE-CHAIN-v1.schema.json`)
- `lib/provenance/chain.js` — `assembleProvenance()`,
  `verifyProvenanceOffline()`, `PROVENANCE_VERSION`
- `packages/verify/index.js` — `verifyTrustReceipt()` (frozen §6.3
  verifier reused verbatim)
- `packages/issue/index.js` — `canonicalize()` (frozen canonicalizer)
- `lib/delegation.js` — delegation-record field *shape* mirrored by
  `delegation_chain[]` (`delegator` ← `principal_id`, `delegatee` ←
  `agent_entity_id`). NOTE: the offline chain verifier does not call this
  file's async `verifyDelegation()`; it verifies each link's proof
  self-containedly (canonical-byte signature + delegator key binding).
- `packages/mcp-guard/index.js` — `EP-PROVENANCE-ENTRY-v1` ledger entry
  (a distinct additive object; see "Relationship to the MCP-guard
  provenance ledger")
- `PIPs/PIP-001-core-freeze.md` — frozen Core objects and the extension
  mechanism
- `PIPs/PIP-007-initiator-attestation.md` — prior additive,
  composition-by-inheritance extension; advisory-report discipline
- `PIPs/PIP-008-authorization-receipt-rename.md` — Core rename of the
  receipt object; cross-referenced for naming only, not a dependency
- `draft-nelson-agent-delegation-receipts` (IETF I-D) — DRP; the upstream
  delegation referenced by this composite
- `conformance/vectors/receipts.v1.json` — vector pattern the companion
  `conformance/vectors/provenance-chains.v1.json` follows
