<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP SEP submission package — Consent + Authorization Receipt for irreversible tool calls

*Prepared 2026-06-14. Three parts: (A) the ready-to-submit SEP, (B) the socialization
post to find a sponsor, (C) sponsor targets + the step sequence. Iman submits — these
are interactively-authenticated surfaces (GitHub / Discord), so the actual posting is
yours; everything here is copy-paste ready.*

Process confirmed from the live MCP docs: SEPs are PR-based against the `seps/` directory
of `modelcontextprotocol/modelcontextprotocol`; a **Draft needs a Core-Maintainer/Maintainer
sponsor** or it goes **Dormant after 6 months**; the recommended path is to **socialize in
the relevant Working/Interest Group (Discord) or GitHub Discussions first**, then tag 1–2
maintainers. Acceptance requires a **prototype** (we have one) and, for observable behavior,
a **conformance scenario** in the conformance repo (we have vectors to port).

---

## PART A — The SEP (drop into `seps/0000-consent-authorization-receipt.md`, rename to the PR number)

> **Title:** Consent + Authorization Receipt for irreversible tool calls
> **Author:** Iman Schrock <team@emiliaprotocol.ai>
> **Status:** Draft (Awaiting Sponsor)
> **Type:** Extensions Track
> **Created:** 2026-06-14
> **PR:** TBD

### Abstract

MCP standardizes how an agent discovers and calls tools, how a server authenticates
(OAuth), and how a server elicits mid-call input (elicitation). It does not standardize
the moment that matters most for safety: when a tool call is **irreversible** — releasing
a payment, changing a vendor's bank details, deleting a record, deploying — there is no
portable, interoperable way to prove that a **named human authorized that exact call**
before it executed. `destructiveHint` already marks which calls are dangerous; this SEP
defines, as an opt-in **Extensions Track** capability, what happens *at* such a call and
what verifiable artifact it leaves behind: a **consent step** that names a human approver,
a **device-bound signoff** over the canonical tool name + arguments hash, and a **portable
authorization receipt** returned alongside the result that any third party can verify
**offline**, without trusting the server. The capability is additive and fails closed:
no valid receipt, no irreversible execution. Read-only/reversible calls are untouched.

### Motivation

`destructiveHint` / `readOnlyHint` (SEP-973) tell a client a call is dangerous, but the
protocol is silent on what should happen when one runs and what evidence it should
produce. Today, the proof that "a human approved this" — if it exists at all — is a log
entry on the server that performed the action: **testimony controlled by the party whose
conduct is in question.** As agents move from answering to acting, this is the wrong trust
model. Each MCP host reinvents approval ad hoc, none of it interoperable or independently
checkable. The result is that the highest-consequence moment in the agent loop has the
weakest, least portable accountability. A standard consent + receipt hook makes
"authorized by a named human" **evidence** — checkable by a third party, offline — rather
than testimony, and lets any host/server/auditor interoperate on it.

### Specification

This capability is **opt-in and negotiated**. Terms "MUST", "MUST NOT", "SHOULD" per RFC 2119.

1. **Capability negotiation.** A client and server MAY advertise
   `capabilities.experimental.authorizationReceipts` during `initialize`. The capability
   applies only when both sides advertise it.

2. **Trigger.** When a tool to be invoked carries `destructiveHint: true` (or a new
   `requiresAuthorization: true` annotation, defined here as a stronger, non-advisory
   signal), and the capability is active, the host **MUST** obtain a per-action
   authorization before dispatching the tool body.

3. **Consent.** The host **MUST** present the *exact* action to a human approver — the
   canonical tool `name` and its arguments — reusing MCP **elicitation** for the prompt.
   The presented action **MUST** be the same bytes that are hashed in step 4 (no
   paraphrase the human did not see).

4. **Action binding.** The host **MUST** compute an `action_hash` =
   `SHA-256(canonical_json({ tool, arguments }))` over a deterministic (sorted-key)
   canonical JSON serialization, so the approval binds to the exact call.

5. **Signoff.** The approver **MUST** produce a signature over `action_hash` using a
   user-verification-gated, device-bound credential (e.g. WebAuthn). The signature
   **MUST NOT** be produced by the host's own key on the human's behalf.

6. **Receipt.** On a valid signoff the host emits a **portable authorization receipt** —
   an object carrying the action hash, the approver identity/key reference, the signoff
   signature, and the verification metadata needed to check it **offline**. The receipt
   **MUST** be returned to the client alongside the tool result (e.g. in the result
   `_meta`). The on-the-wire receipt format is referenced, not reinvented: the reference
   format is the IETF Internet-Draft `draft-schrock-ep-authorization-receipts`
   (`EP-RECEIPT-v1`), but the SEP fixes the *hook and semantics*; the community MAY shape
   the exact format.

7. **Fail closed.** If no valid receipt is produced (declined, timed out, signature
   invalid, key unbound), the host **MUST NOT** execute the tool body and **MUST** return
   a structured `authorization_required` error (a `402`-style "receipt required" result).

8. **Verification.** A verifier given a receipt and the public key **MUST** be able to
   confirm offline that the named approver signed that exact `action_hash`, with no call
   back to the host. A verifier **MUST** fail closed on any mismatch.

### Rationale

- **Compose, don't reinvent.** The prompt reuses elicitation (SEP-1330, SEP-1036
  out-of-band); the danger signal reuses `destructiveHint` (SEP-973); the receipt format
  reuses an open IETF draft with multi-language verifiers. The SEP adds only the missing
  hook + fail-closed semantics.
- **Why a receipt, not a log.** A log is testimony controlled by the acting party; a
  signed, offline-verifiable receipt is evidence checkable by a third party (auditor,
  counterparty, regulator) without trusting the server.
- **Alternatives considered.** (a) Per-vendor approval UIs — no interoperability, no
  portable evidence. (b) Server-side audit logs — not third-party-verifiable. (c)
  Mandating one receipt format in core — too heavy; Extensions Track + a referenced open
  format keeps the core small and the format swappable.

### Backward Compatibility

Fully backward compatible. The capability is opt-in and negotiated; servers/clients that
do not advertise it behave exactly as today. Read-only and reversible calls are never
affected. No change to existing message formats beyond an additive `_meta` receipt on
results of authorized calls.

### Reference Implementation

- **`@emilia-protocol/mcp-guard`** — middleware that wraps an MCP tool dispatcher:
  classifies reversible vs irreversible (honoring `destructiveHint`/`readOnlyHint`), runs
  consent → signoff → receipt, and refuses the call with a structured "receipt required"
  error otherwise.
- **Offline verifiers** in JavaScript, Python, and Go (npm `@emilia-protocol/verify` +
  siblings); a published IETF Internet-Draft for the receipt format; conformance vectors
  runnable across all three verifiers.
- **Demo:** `npx @emilia-protocol/issue demo` issues a receipt and verifies it offline in
  ~60 seconds. (Prototype satisfies the SEP "working implementation / proof-of-concept"
  bar; not production-deployed by a relying party yet.)

### Security Implications

- **What it provides:** non-repudiable, offline-verifiable proof that a *named* human
  approved the *exact* irreversible action (UV-gated, device-bound); fail-closed execution
  so a missing/invalid approval cannot silently run.
- **Residual (explicitly out of scope):** a fully compromised host can render one action to
  the human and attest another (the WYSIWYS residual) — addressed only by device/TEE
  attestation (App Attest, Play Integrity, WebAuthn device binding), a layer below this
  hook. One-time-use / replay prevention is relying-party server-state, not an offline
  property. These limits MUST be stated wherever the capability is documented; offline
  verification proves authenticity + binding, not currency.

### Conformance

For the observable behavior (fail-closed on missing/invalid receipt; receipt verifies
offline), a conformance scenario can be ported from the existing EP conformance vectors
into the MCP conformance repo, tagged with the SEP number, with a `sep-NNNN.yaml`
traceability file mapping each MUST/MUST NOT to a check.

---

## PART B — Socialization post (Security Interest Group on Discord, and/or GitHub Discussions)

> **Title:** Standardizing consent + a portable authorization receipt for irreversible tool calls
>
> MCP already marks dangerous calls with `destructiveHint`, authenticates servers with
> OAuth, and elicits mid-call input. What it doesn't standardize is the highest-stakes
> moment: when an irreversible tool call runs (payment release, vendor bank-detail change,
> delete, deploy), there's no portable, interoperable way to prove a *named human*
> approved *that exact call* before it executed. Today that proof is a server log —
> testimony controlled by the acting party — not third-party-verifiable evidence.
>
> I'd like to gauge interest in a small **Extensions Track** capability: an opt-in
> consent → device-bound signoff → portable, offline-verifiable **authorization receipt**
> hook for calls annotated irreversible, that **fails closed** (no valid receipt, no
> execution). It composes existing primitives (elicitation for the prompt,
> `destructiveHint` for the signal) and references an open receipt format rather than
> reinventing one.
>
> There's a working reference implementation (an MCP dispatcher middleware), offline
> verifiers in JS/Python/Go, and conformance vectors I can port. Happy to bring a draft
> SEP + a 60-second demo. Is this a fit for the Security IG, and would a maintainer be
> open to sponsoring? (Apache-2.0; not a vendor pitch — the goal is one interoperable
> consent+evidence hook for the ecosystem, shaped however the community prefers.)
>
> — Iman Schrock, EMILIA Protocol · team@emiliaprotocol.ai

---

## PART C — Sponsor targets + sequence

A Draft SEP **must** have a sponsor (Core Maintainer/Maintainer) or it goes Dormant in 6
months. Target order:

1. **Den Delimarsky** — Lead Maintainer; **co-leads the Security Interest Group**;
   co-authored the MCP authorization spec and multiple security SEPs. **Best-fit sponsor.**
   Approach via the Security IG channel first, then tag on the PR.
2. **The Security Interest Group** as a whole — socialize there before any PR; a WG/IG can
   shepherd a SEP in its domain. This is the single highest-leverage step.
3. **David Soria Parra** — Lead Maintainer (overall direction).
4. **Clare Liguori** — Core Maintainer (AWS Sr. Principal Engineer); enterprise/security lens.

**Sequence (do these in order):**
1. Post Part B in the **Security IG Discord** channel (and/or GitHub Discussions). Refine
   from feedback; build early support. *Do not cold-submit the PR.*
2. If there's interest, open the PR adding `seps/0000-consent-authorization-receipt.md`
   (Part A), then rename to the PR number per the workflow.
3. Tag Den (and one other security maintainer) as sponsor; share the PR link in the IG
   channel. If no response in ~2 weeks, ask in `#general`.
4. On sponsorship → status `draft` → informal review → `in-review`. Port a conformance
   scenario early (it surfaces normative ambiguities cheaply).
5. Check alignment with the 2026 roadmap + design principles before/while drafting.

**Links:** SEP guidelines `modelcontextprotocol.io/community/sep-guidelines` ·
maintainer list `github.com/modelcontextprotocol/modelcontextprotocol/blob/main/MAINTAINERS.md` ·
spec repo `seps/` dir · conformance repo `github.com/modelcontextprotocol/conformance` ·
source proposal `docs/strategy/MCP-CONSENT-RECEIPT-PROPOSAL.md`.
