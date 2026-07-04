<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol — protocol mapping table (staged, pending stable claim IDs)

Prepared for the AGENTPROTO claim registry proposed on the agent2agent list
(Songbo Bu's "Security Principal and Verifier Binding for Agent Communication
Protocols", in progress). Claim names below use the initial list from the
2026-07-04 thread; **IDs will be re-keyed to the registry the day its claim IDs
stabilize.** Fields follow the registry's proposed set — claim, carrier,
verifier, binding, freshness, layer, failure behavior, implementation status,
specification status, external dependency/inheritance — plus the optional
**vector** column we proposed on-list, so every mapped row is checkable rather
than asserted.

Framing note (as stated on-list): EP is not an agent communication protocol.
It is the artifact layer several candidate protocols already reference for the
authority and action-evidence claims. This table exists so that a candidate
protocol marking those rows "Inherited" can point at a concrete mechanism with
a named verifier, binding, and failure path.

Status vocabulary (per the thread's discipline): *specified* = in a current
public draft/spec; *implemented* = running code in the public repo;
*planned* = stated intent, not yet a guarantee. All EP Internet-Drafts are
**active individual submissions, not IETF-adopted or endorsed**.

---

## Claims EP maps

### 1. Authority (named-human / quorum authorization)

- **Mechanism**: EP-RECEIPT-v1 — a device-bound signature by a named human
  principal (or EP-QUORUM: M-of-N distinct principals, optionally ordered)
  over the canonical bytes (RFC 8785 / JCS) of one action.
- **Carrier**: a self-contained signed JSON artifact; transport-agnostic
  (HTTP header, message field, file, SCITT Signed Statement).
- **Verifier**: any conforming verifier, offline, no account. Reference
  verifiers in JavaScript, Python, and Go — one repository, a consistency
  check, **not** independent implementations; an independent clean-room
  reimplementation (COSA) is underway, result will be recorded either way.
- **Binding**: Ed25519 over the canonical action bytes; the signed payload
  covers the action digest, so the same record cannot satisfy authority for a
  different action. Digest equality itself neither authorizes nor proves
  completeness.
- **Freshness**: validity window (`not_before`/`expires_at`); one-time-use is
  enforcement-point state (consumption committed before allow), represented
  but not offline-verifiable.
- **Layer**: application-layer artifact; rides any session/transport layer
  (layer stated per the registry's open-ended row convention).
- **Failure behavior**: fail-closed. Missing/invalid/stale/replayed/
  out-of-scope receipt → action refused + machine-readable challenge
  (HTTP 428, `application/authorization-evidence-challenge+json`).
- **Implementation status**: implemented. **Specification status**: specified
  (draft-schrock-ep-authorization-receipts; quorum draft posted).
- **Inheritance**: none — this is EP's native claim.
- **Vectors**: `conformance/vectors/receipts.v1.json`,
  `conformance/vectors/quorum.v1.json`, `conformance/vectors/signoffs.v1.json`
  (positive + negative; run: `node conformance/run.mjs`).

### 2. Action evidence

- **Mechanism**: EP-AEG-v1 action evidence graph — content-addressed
  references to heterogeneous signed artifacts; edges are presenter claims
  verified against artifact bytes (a lying edge → unverifiable; a required
  absent edge → missing_evidence); deterministic policy replay to a 5-state
  verdict with a replay digest; verdict signable as EP-RELIANCE-RESULT-v1
  (accountability, never authority). Every gate decision (allow or deny)
  appends to a tamper-evident evidence log.
- **Carrier / Verifier / Layer**: as row 1 — offline, transport-agnostic.
- **Binding**: each evidence node bound by content digest; the graph digest is
  disclosure-independent; the verdict is bound to policy + graph + purpose.
- **Freshness**: staleness is a first-class verdict state (`stale`).
- **Failure behavior**: verdict precedence is fail-closed
  (unverifiable > missing_evidence > stale > conflicted > admissible).
- **Implementation status**: implemented (15+ tests, deterministic vector).
  **Specification status**: specified (draft-schrock-ep-action-evidence-graph).
- **Vectors**: `examples/evidence-graph/evidence-graph-vector.mjs` +
  `evidence-graph-vector.json` (deterministic, negatives enforced),
  `tests/evidence-graph.test.js`.

### 3. Freshness / revocation

- **Mechanism**: validity windows on every artifact; portable offline
  revocation statement + server-state revocation; signed time-attestation.
- **Binding**: revocation statements are digest-addressed to the artifact they
  revoke; bounded-staleness semantics stated.
- **Implementation status**: implemented — JS/Python/Go verifiers agree on the
  revocation suites. **Specification status**: specified for EP-native
  artifacts; a generalized credential-revocation-statement I-D (revoking any
  digest-addressed artifact) is **planned** (drafted, filing when the
  datatracker reopens) — listed as planned, not a current guarantee.
- **Failure behavior**: a revoked or stale artifact fails verification closed.
- **Vectors**: `conformance/vectors/revocation.v1.json`,
  `conformance/vectors/revocation.exec.v1.json`,
  `conformance/vectors/time-attestation.v1.json`.

### 4. Delegation (partial)

- **Mechanism**: scoped delegation records (delegator principal → delegate,
  bounded scope and window), verified like receipts.
- **Implementation status**: implemented with single-repo tests
  (`lib/delegation.js`, `tests/delegation.test.js`). **Not yet in the
  cross-language conformance suite** — that gap is stated here so the row
  cannot read as more than it is. **Specification status**: documented;
  not yet an I-D.
- **Failure behavior**: out-of-scope or expired delegation fails closed.

### 5. Failure behavior (as a claim in itself)

- **Mechanism**: deny-by-default everywhere; machine-readable 428 challenge
  names exactly the missing evidence; refusals can themselves be signed
  evidence (refusal receipts in the grid-curtailment profile).
- **Implementation status**: implemented; negative vectors are mandatory in
  every EP suite (each MUST be rejected with the failing check named).
- **Vectors**: negative cases across all suites; `conformance/vectors/aec.json`.

## Claims EP intentionally does NOT map

Per the registry's request to "state explicitly where your draft
intentionally differs":

- **Live agent instance** — not claimed. Agent/workload identity is a
  different leg (WIMSE, AGTP, IACP territory). EP composes with it through
  the shared action-digest join key; it never asserts which agent acted.
- **Tool or resource identity** — not claimed as identity. The tool/resource
  appears inside the canonical action bytes a human signs; adjacent (not a
  substitute): the agent-action manifest / `x-agent-action-control` declares
  per-endpoint consequence metadata on the demand side.
- **Session continuity** — not claimed. Session semantics belong to the
  communication protocols; an EP receipt is deliberately valid for one exact
  action, not a session.

---

*Maintained at `docs/standards-engagement/EP-CLAIM-MATRIX-MAPPING.md`; will be
PR'd to the registry repo (`agentproto-claim-matrix` or successor) once claim
IDs stabilize.*
