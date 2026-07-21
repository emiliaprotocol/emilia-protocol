<!-- SPDX-License-Identifier: Apache-2.0 -->
# Staged composition note: AEB, AUDIT, C2PA, OTEL, and SCITT

Status: **STAGED, NOT SENT**. This is a technical contribution outline, not a
claim of AUDIT or C2PA endorsement and not a new EMILIA core protocol.

## The boundary

The current AUDIT discussion is about reconstructing complex interactions:
sessions, tools, delegation, authorization transitions, cross-domain joins,
and the distinction between in-situ and after-the-fact records. C2PA provides
cryptographically verifiable provenance for content and its history under a
declared trust model. OTEL provides observability and trace correlation.
SCITT can preserve signed statements and their transparency history.

Those layers answer **what was produced, carried, observed, or recorded**.
They do not, by themselves, answer whether a relying party permitted one
exact consequential action on independently verified evidence immediately
before the effect.

The proposed composition is therefore:

| Layer | Native responsibility | AEB relationship |
| --- | --- | --- |
| C2PA | Provenance and tamper-evident assertions about an asset or content history | Optional provenance input or output reference; not human authorization by itself |
| OTEL | Telemetry, span, and trace correlation | Operational transport for references; not an authorization verdict |
| SCITT | Signed statement preservation and transparency history | Optional preservation layer for the decision/evidence digest |
| AUDIT | Interoperable interaction, delegation, authorization-transition, and outcome records | Records AEB decisions and consumed evidence as events; does not inherit AEB trust semantics |
| AEB | Exact-action matching, relying-party evidence satisfaction, pre-effect policy gate, single-use consumption, and explicit indeterminate outcome | The effect-boundary evidence contract |

This is deliberately compositional. A C2PA manifest does not become an
authorization receipt because it is referenced by an AEB event. An AEB receipt
does not become a complete audit record because it is carried in OTEL or
SCITT. AUDIT remains free to define its own record model and trust profile.

## Minimal event profile to test

An implementation profile can carry the following fields in an AUDIT record,
SCITT statement, or deployment-specific C2PA assertion. The names below are a
profile sketch, not a registration claim:

```json
{
  "event_type": "emilia.aeb.decision.v1",
  "caid": "caid:1:<action-type>:jcs-sha256:<digest>",
  "decision": "SATISFIED",
  "authorization_state": "AUTHORIZED",
  "consumption_state": "CONSUMED",
  "evidence_requirement_digest": "sha256:<digest>",
  "evidence_digests": ["sha256:<receipt-or-chain-digest>"],
  "mapping_profile_digests": ["sha256:<profile-digest>"],
  "provenance_refs": [
    { "format": "c2pa", "manifest_digest": "sha256:<digest>" },
    { "format": "otel", "trace_id": "<trace-id>" },
    { "format": "scitt", "statement_digest": "sha256:<digest>" }
  ],
  "occurred_at": "2026-07-20T12:00:00Z"
}
```

The profile MUST preserve the following distinctions:

1. `VERIFIED`, `MATCH`, `SATISFIED`, `AUTHORIZED`, `CONSUMED`, `EXECUTED`,
   and `INDETERMINATE` are not interchangeable.
2. A missing or lossy action mapping is `INDETERMINATE`, not a successful join.
3. `EXECUTED` is an executor assertion about the effect, not a consequence of
   `AUTHORIZED`.
4. `INDETERMINATE` is preserved when the provider boundary may have been
   entered but the effect cannot be established safely; it is not rewritten as
   failure or success for the sake of a clean trace.
5. Native C2PA, OTEL, SCITT, and authorization verifiers retain their own
   trust roots and validation rules. A reference is not a trust transfer.

## Concrete interoperability work

The first useful test is small and cross-layer:

1. Construct one canonical action and compute its CAID.
2. Produce an AEB authorization receipt and an optional C2PA provenance
   reference for the same action or output asset.
3. Emit the AEB decision with the CAID and receipt digest into an AUDIT-shaped
   record and, optionally, an OTEL span or SCITT statement.
4. Verify each native artifact independently.
5. Recompute the CAID and receipt digest from the presented bytes.
6. Accept the cross-layer join only when every digest and profile pin matches.
7. Include negative vectors for a changed C2PA manifest, a changed action, a
   receipt/action splice, an absent mapping profile, and an indeterminate
   provider outcome.

This produces a testable answer to the AUDIT question “how do records refer to
the same trajectory or action?” without asking AUDIT to standardize an
authorization ceremony or asking C2PA to make an authorization decision.

## Coalition posture

The constructive ask is narrow:

- To the AUDIT authors: should an authorization-transition record carry a
  relying-party-pinned action identifier and evidence digest, and how should an
  indeterminate effect be represented?
- To C2PA implementers: is an optional reference to an independently verified
  action/evidence record useful for agentic provenance, without changing the
  meaning of a C2PA provenance assertion?
- To OTEL/SCITT implementers: which correlation and preservation fields are
  stable enough to carry references without importing authorization semantics?

The proposal is to exchange vectors and field-level review first. It does not
ask any group to adopt EMILIA, and it does not reopen the already-completed
DMSC discussion.
