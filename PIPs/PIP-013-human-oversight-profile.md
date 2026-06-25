# PIP-013: Human-Oversight Profile (Meaningful Human Control for Autonomous Systems)

**Status:** Draft
**Type:** Extension / Applicability Profile
**Created:** 2026-06-25
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze), PIP-003 (Signoff), PIP-010 (WYSIWYS Execution Integrity)
**Composes with:** EP-QUORUM (two-person rule), PIP-008 (agent binding / L4→L7 freshness), PIP-011 (revocation & continuous evaluation)

## Abstract

This PIP profiles the EMILIA Protocol authorization receipt as the **verifiable
human-authorization evidence layer** for autonomous and cyber-physical systems — proof
that a named, accountable human (or quorum) authorized a specific action under a specific
policy, supporting the human-oversight regimes (DoD Directive 3000.09's "appropriate levels
of human judgment"; the broader "meaningful human control" discussion; EU AI Act Article 14
for civilian high-risk AI; NIST AI RMF; the UN CCW LAWS debate). It addresses both
human-on-the-loop (HOTL) and human-in-the-loop (HITL) regimes. It introduces **no new cryptography and no Core change**: the EP
receipt already proves that a named, accountable human authorized an exact action,
offline-verifiable without trusting the operator. This profile specifies how to
*apply* that primitive at **authorization boundaries** in an autonomous system, a
small set of OPTIONAL Authorization Context conventions for the autonomy domain,
and the relying-party (Policy Enforcement Point) rules that make "a human was
meaningfully in control" a **verifiable artifact** rather than an operator-owned
log entry.

The profile is deliberately scoped to **evidence**, not cognition. It proves the
*fact, scope, currency, and authority* of human authorization; it does not and
cannot prove that the human understood or that the decision was wise. Those remain
client-conformance (PIP-010 WYSIWYS) and out-of-band concerns. The contribution is
**necessary, not sufficient** — and stated as such throughout.

## Motivation

Every governing instrument for autonomy requires a human to remain meaningfully in
control of consequential actions, but none specifies an artifact that **proves it
after the fact**, to a third party, without trusting the system operator:

- **DoD Directive 3000.09** requires "appropriate levels of human judgment over the
  use of force."
- **EU AI Act Article 14** requires high-risk AI be "effectively overseen by natural
  persons," who can interpret output, decide not to use it, and intervene/halt. (Scope:
  the AI Act, Art. 2(3), excludes systems used exclusively for military, defense, or
  national-security purposes — treat it as a *civilian* applicability hook, not a defense one.)
- **NIST AI RMF** (GOVERN/MAP/MEASURE/MANAGE) calls for documented, auditable human
  oversight.
- **UN CCW / LAWS** debate turns entirely on demonstrating "meaningful human control."

The unsolved problem across all of them is the **evidence gap**: when an autonomous
system acts, the record that a named human authorized *that exact* engagement — at
the right scope, currently, under the right authority — is today a log the operator
controls and could forge, backfill, or rubber-stamp. EP closes exactly that gap. This
profile makes the mapping explicit so a program, prime, or oversight body can adopt EP
as the MHC evidence layer without re-deriving it.

## Specification

### §1 — Control modes and the authorization boundary

This profile does NOT require per-machine-cycle human approval (incompatible with
machine-tempo engagements). EP receipts are issued at **authorization boundaries** —
the discrete points where a human grants, scopes, or renews autonomous authority:

- **`in_the_loop`** — a human authorizes each discrete consequential action before it
  executes (one receipt per action; the system fails closed without it).
- **`on_the_loop`** — a human authorizes a **bounded engagement envelope** (action
  class, target/effect set, geofence, time window) within which the system may act
  autonomously, and retains a revocation/halt authority (PIP-011). One receipt
  authorizes the envelope; autonomy operates only inside it and only while unrevoked.

A conforming relying party (PEP) MUST treat any consequential action outside a valid,
unrevoked, in-scope, unexpired authorization as **unauthorized** and fail closed.

### §2 — OPTIONAL Authorization Context conventions for autonomy

A producer MAY include a `human_oversight` member in an `ep.signoff.v1` context. When
present it MUST be a JSON object with only:

- `control_mode` (REQUIRED) — `"in_the_loop"` or `"on_the_loop"`.
- `authorization_scope` (REQUIRED for `on_the_loop`) — the bounded envelope the human
  authorized. An object with OPTIONAL members: `effect_class` (e.g. non-kinetic /
  kinetic / data), `target_set` (opaque reference or list), `geofence` (opaque ref),
  `window` (`{not_before, not_after}` RFC 3339). Absent members are unbounded and MUST
  be flagged by the verifier as broad.
- `roe_ref` (OPTIONAL) — reference to the rules-of-engagement / policy that constrains
  the authority (complements the context's existing `policy_id`/`policy_hash`).

The whole context is JCS-canonicalized and covered by the approver signature exactly as
in Core; no new signature or digest is introduced. The action being authorized is the
existing Action Object — the envelope is described, the *exact* action(s) remain bound
by `action_hash` (HITL) or by scope membership the PEP checks (HOTL).

### §3 — Mapping EP mechanisms to MHC requirements (normative intent)

| MHC requirement | EP mechanism (existing) |
|---|---|
| Named, accountable human (not a console login) | Class-A device-bound signoff, WebAuthn + user verification (PIP-003) |
| Two-person rule / launch authority | EP-QUORUM m-of-n, distinct humans, ordered chain |
| Authority bounded by rules of engagement | Delegation constraints (monotonic / tighten-only) + `roe_ref`/`policy_hash` |
| Authorization is current, not a stale standing order | Validity window (`expires_at`) + L4 freshness `observed_at` (PIP-008 §2.1) |
| Revocable / halt authority (on-the-loop) | Revocation & continuous evaluation (PIP-011) |
| Survives contested / disconnected / classified ops | Offline verification (Core §6.3); air-gap verifier |
| "No verified human authorization → no effect" | Fail-closed PEP (Receipt-Required rail) |
| The human saw the real action, not a label | WYSIWYS execution integrity (PIP-010) — client conformance |

### §4 — What the profile proves and does NOT prove

A conforming deployment proves: a specific, pinned human key (or quorum of distinct
humans) authorized **this exact action or this bounded envelope**, at a stated scope,
within a validity window, under a referenced authority, and that the record cannot be
forged, replayed, moved to another action, or repudiated — verifiable offline by a
third party.

It does **not** prove: that the human understood the action (WYSIWYS/cognition gap,
PIP-010 mitigates, does not eliminate); that the human was uncoerced; that a key maps to
the intended natural person (Approver Directory / enrollment is the trust root and the
explicit boundary); or that the action was lawful or wise. **The profile is a necessary,
not sufficient, condition for meaningful human control, and MUST be represented as such.**

### §5 — Relying-party (PEP) requirements

For `on_the_loop`, before permitting an autonomous action the PEP MUST verify a receipt
exists whose `authorization_scope` admits the action (effect class, target/geofence
membership, and current time within `window`), whose signatures verify against pinned
keys, whose quorum threshold (if any) is met, and which is not revoked. Any failure →
fail closed. For `in_the_loop`, the per-action receipt's `action_hash` MUST match the
action being executed (Core §6.3).

## Security Considerations

- **No new trust, no new crypto.** The profile rides Core verification unchanged;
  receipts carrying `human_oversight` verify on verifiers that predate this profile.
- **Over-trust is the primary risk.** Treating "a receipt exists" as "the action was
  legitimate" is a misuse. The receipt proves authorization occurred at a scope — not
  legitimacy. Deployments and marketing MUST NOT overstate this (necessary ≠ sufficient).
- **Scope breadth is a finding.** An `on_the_loop` envelope with unbounded members is a
  weak control; verifiers SHOULD surface breadth so oversight bodies can judge it.
- **Coercion and identity root** remain out of scope (see §4); device-bound UV and
  quorum raise but do not eliminate these.
- **Export / classification.** Deployment into defense or classified contexts is subject
  to applicable export-control and security regimes; the open verifier and format are
  designed to operate offline/air-gapped, but compliance is the deployer's responsibility.
