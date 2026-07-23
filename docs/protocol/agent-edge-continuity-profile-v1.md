# EP-AGENT-EDGE-CONTINUITY-v1

Status: private implementation profile. This is not an IETF submission and is
not a claim of MCP, A2A, discovery, attestation, or model-behavior conformance.

## 1. Purpose and boundary

Agent Edge Continuity carries signed provenance and action-lineage evidence
across the places where a material action can drift:

* a user gives structured intent to a harness;
* a harness invokes and receives output from a model;
* a harness constructs a tool request;
* one agent delegates to another; and
* an executor reports an observed effect.

The profile does not authorize an action. AEC composes evidence, AEB evaluates
whether the relying party's evidence requirements are satisfied, and the Gate
alone returns `AUTHORIZED` after local policy and atomic consumption succeed.
Continuity is one optional input to that decision.

The profile does not establish that a model actually ran, behaved safely, or
produced a claimed output. A digest proves equality with a pinned artifact; it
does not prove the artifact's identity, truth, discovery correctness,
attestation validity, or use. Those properties require independent native
verification before their digests are admitted.

## 2. Envelope

The wire object is `EP-AGENT-EDGE-CONTINUITY-v1`. Its closed field set is:

`continuity_id`, `parent_continuity_id`, `edge`, `source`, `destination`,
`relying_party_id`, `pinned_config_digest`, `initiator_id`, `executor_id`,
`caid`, `action_digest`, `proposal_digest`, `operation_id`, `evidence_refs`,
`claims`, `sequence`, `issued_at`, `expires_at`, `handoff_nonce`, and
`signature`.

The body is canonicalized with the AEB I-JSON/RFC 8785 profile and UTF-8.
`continuity_id` is `ec:` followed by the lowercase hexadecimal SHA-256 digest
of the canonical body without `continuity_id` or `signature`. The Ed25519
signature covers the canonical body including `continuity_id`, prefixed by the
exact domain-separation bytes `EP-AGENT-EDGE-CONTINUITY-v1\0`. Signature bytes
use unpadded canonical base64url. Unknown fields or claims are refused.

Every envelope binds the same execution context:

* relying party and pinned configuration;
* initiator and executor;
* CAID and normalized action digest;
* proposal digest and operation ID; and
* validity interval and one handoff nonce.

A parent and child that disagree on any of those fields do not join.

## 3. Relying-party policy

Presented data never selects its own trust policy. The relying party supplies:

* signer keys with active/revoked status, validity interval, allowed sources,
  and allowed edge types;
* accepted root and edge types;
* allowed parent-to-child transitions;
* edge types required before execution;
* maximum path depth, envelope lifetime, and evidence age;
* expected CAID, action, operation, proposal, relying party, configuration,
  initiator, and executor; and
* optional identity, discovery, and platform-attestation digest pins.

A cryptographically valid signature from a key that is not authorized for the
envelope's source and edge is refused. A stale or revoked signer pin is also
refused.

Endpoint evidence is never fetched during verification. A caller may provide a
digest only after a separately pinned adapter verifies the native identity,
discovery document, or attestation. A missing or mismatched required pin fails
closed.

## 4. Edge profiles

The neutral core recognizes these v1 edges:

* `user-harness` binds structured intent and the exact material display;
* `harness-model` binds model and harness provenance plus prompt-context and
  output digests;
* `model-harness` binds the returned output digest;
* `harness-tool` carries a tool mapping profile;
* `agent-agent` carries a delegation mapping and contained scope; and
* `effect` carries an executor observation.

The reference `harness-tool` mapping uses MCP and computes the request digest
from the structured request. The reference `agent-agent` mapping uses A2A and
computes the delegation and scope digests from structured inputs. These are
mapping profiles, not claims that MCP or A2A supplies EMILIA authority.

An A2A child scope cannot widen its parent's action types, resources, or
maximum amount. Delegation is not exact-action approval; the concrete CAID
still needs an execution-authorizing AEB decision.

## 5. Pre-effect authorization

`authorizeAgentContinuityExecution` is a single-process reference path.
`authorizeAgentContinuityExecutionDurable` is the production path.

Both functions:

1. derive CAID, action, operation, relying party, pinned configuration,
   initiator, and executor from the signed AEB evaluation;
2. require a separately pinned proposal digest;
3. verify the graph under a trusted Gate clock;
4. reject any `effect` envelope before execution reservation;
5. require at least one policy-selected execution edge;
6. require an AEB verification with both `valid` and
   `execution_authorizing`;
7. require local Gate authorization and one-time consumption; and
8. reserve every AEB native replay identity, continuity ID, and signer-scoped
   handoff nonce atomically.

Historical AEB verification is deliberately non-authorizing. The in-memory
store is test-only. Production execution requires a durable,
ownership-fenced, permanent, atomic replay store.

## 6. Post-effect observation and reconciliation

An `effect` envelope is append-only outcome evidence. It is not accepted by
the pre-effect authorization function and cannot create retroactive authority.
Its outcome is one of `COMMITTED`, `NOT_COMMITTED`, or `INDETERMINATE`.

The Proposal-to-Effect lifecycle owns custody and reconciliation:

* `COMMITTED` consumes the existing reservation only after authenticated
  provider evidence;
* `NOT_COMMITTED` releases it only after authenticated provider evidence; and
* `INDETERMINATE` keeps custody locked, forbids blind retry, and requires
  reconciliation.

Continuity verification alone never commits or releases money, budget, or
other consequential state.

## 7. Reference refusal cases

`conformance/vectors/agent-edge-continuity.v1.json` is a reference
refusal-case registry executed by the TypeScript package tests. It covers
action and operation substitution, parent and sequence failures, scope
widening, nonce replay, signer-authority escalation, stale/revoked signers,
historical AEB verification, missing execution edges, cross-wrapper replay,
pre-execution effect injection, malformed graphs, insecure stores, and
indeterminate outcomes.

This is not yet a cross-language conformance suite. It must not be added to
the JS/Python/Go verifier totals until independent ports execute equivalent
static signed fixtures.
