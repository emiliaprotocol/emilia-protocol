<!-- SPDX-License-Identifier: Apache-2.0 -->
# Seed Text: The WHO Leg — Named-Human and Quorum Authorization Binding

This note is proposed seed text for `draft-mih-sato-agent-accountability-composition-00`.
It is scoped to Iman's proposed responsibility area: the WHO leg — which named,
accountable human, or quorum of distinct humans, authorized this exact action,
as distinct from which agent executed it.

## Design Rule

The WHO leg is one participating accountability profile at the composition seam.
It answers a single question: *which named human — or quorum of distinct humans —
authorized this exact action before it ran.* It is deliberately narrow:

- It does NOT define the composition seam, a sufficiency or policy decision, a
  new audit-record format, or a replacement for agent/workload identity. "Which
  agent acted" is a different leg; "was this authorization sufficient for this
  action" is a layer above the seam.
- It binds a human, or quorum, authorization to the shared action digest and
  exposes the binding metadata a Composition Verifier needs — and nothing more.

The native WHO record is an authorization receipt: a device-bound signature by a
named principal — or a set of distinct principals — over the canonical bytes of
one action, verifiable offline against the signer's public key.

## Conformance Classes

### WHO Producer

A WHO Producer emits an authorization receipt and its binding metadata.

A conforming WHO Producer MUST state:

- the authorizing principal identifier(s) — the named human(s), not the agent;
- for a quorum, the quorum descriptor: threshold (M-of-N) or an ordered
  sequence, and the eligible or actual signer identifiers;
- the subject of the action being authorized;
- the covered action bytes or data model over which the digest is computed;
- the canonicalization rule, if any;
- the digest algorithm and version;
- the domain-separation context for the digest;
- the binding between the digest and the receipt signature(s) — the signed
  payload MUST cover the action digest;
- the authorization's validity window and any freshness or one-time-use
  semantics; and
- the failure behavior when a required binding input, signer, or quorum member
  is absent — fail closed: absence of authorization is not authorization.

### WHO Verifier

A WHO Verifier validates a WHO authorization receipt independently of the
composition profile.

A conforming WHO Verifier MUST be able to produce a result that states:

- whether each receipt signature validates under the WHO profile rules;
- the exact action-digest bytes recomputed by the verifier;
- the canonicalization and hash parameters used;
- whether the digest is covered by each signature;
- for a quorum: whether the threshold is met, whether the counted signers are
  DISTINCT principals, and — for an ordered quorum — whether the required order
  held;
- whether the receipt is within its validity window (a freshness result), and
  whether it is presented within any one-time-use constraint; and
- the verified-versus-accepted distinction (below).

The WHO Verifier MUST keep signature validation, digest recomputation, quorum
evaluation, and freshness as separate results. It MUST NOT collapse them into a
single opaque "authorized" boolean.

### Verified versus accepted

The WHO leg separates two claims a Composition Verifier must never conflate:

- VERIFIED — the signature(s) and the digest binding hold, given a public key.
  Objective and offline.
- ACCEPTED — the relying party additionally trusts the authorizing principal(s)
  via out-of-band key pinning. A relying-party decision, not a property of the
  receipt.

A WHO Verifier MUST surface these separately. A valid signature over the bound
digest proves VERIFIED; it never implies ACCEPTED, and neither implies the
authorization was *sufficient* for the action — sufficiency is the layer above
the seam, not a property the WHO leg asserts.

## The WHO Reference at the Seam

To let a Composition Verifier join a WHO authorization to other legs, the WHO
leg exposes a minimal, disclosure-aware reference:

- the action digest (the shared join key) and its declared digest context;
- the authorizing principal identifier(s) — or, under selective disclosure, a
  commitment to them;
- the quorum descriptor, if any (threshold or order, plus a distinctness
  assertion); and
- the binding assertion: that the signature(s) cover the action digest.

The reference carries no agent identity, no policy verdict, and no sufficiency
claim. It is the WHO leg's contribution to the join, and nothing more.

## Quorum and Distinctness

Where more than one human authorization is required, the WHO leg MUST express:

- the threshold model — M-of-N or an ordered sequence;
- that the counted signers are DISTINCT principals — the two-person rule fails
  closed if one principal satisfies two slots; and
- that every counted signer signed the same canonical action bytes under the
  same digest context.

An ordered quorum additionally binds the required signer order; a WHO Verifier
MUST reject an out-of-order satisfaction as unmet.

## Registration and Receipt Binding

Where the WHO leg is also registered with SCITT or another transparency service,
the transparency receipt proves registration of the submitted statement per the
service policy. It does not prove that a named human authorized the action; that
remains the WHO signature's job. A WHO Verifier MUST keep native signature
validation, digest recomputation, and transparency-receipt validation as
separate results, per the composition profile's separate-verification rule.

## WHO Test Vectors

Consistent with the composition profile's test-vector gate, a WHO digest and
binding rule is not frozen until at least two independent implementations
recompute the same digest bytes for each positive vector and reject each negative
vector. EP's JavaScript, Python, and Go verifiers are offered as two-or-more
independent implementations for this leg.

Positive vectors:

- a single-human authorization bound to a minimal action record;
- a single-human authorization with optional fields present;
- an M-of-N quorum authorization by distinct signers over the same action;
- an ordered quorum authorization satisfied in the required order; and
- an authorization presented with a transparency receipt over the same digest.

Negative vectors — each MUST be rejected, and the verifier MUST report which
check failed:

- semantically similar action input with different canonical bytes;
- a changed subject;
- a changed authorizing-principal (WHO) reference;
- replay of the receipt under a different action identifier;
- a quorum satisfied by a non-distinct principal filling two slots;
- an ordered quorum satisfied out of order;
- a threshold not met (M-1 of N);
- a mismatched or absent receipt signature;
- an authorization outside its validity window (stale); and
- a signature that verifies but whose signed payload does not cover the action
  digest (an unbound signature).

## Open Issues for -00

- Reference vs commitment: should the seam carry the authorizing-principal
  identifier directly, or a commitment that supports selective disclosure?
- Should the quorum distinctness assertion be verifier-recomputable from the
  receipt set, or a producer claim the verifier only checks for internal
  consistency?
- One-time-use / consumption is enforcement-point state, not offline-verifiable
  — how, if at all, should it be represented at the seam?
- What is the minimum WHO reference that lets a Composition Verifier join
  without forcing every adjacent profile to model human principals?
