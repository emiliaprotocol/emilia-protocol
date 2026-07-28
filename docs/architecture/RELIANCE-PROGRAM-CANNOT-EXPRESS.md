<!-- SPDX-License-Identifier: Apache-2.0 -->

# What a Reliance Program cannot express

**Applies to:** `EP-RELIANCE-PROGRAM-SOURCE-v1` and
`EP-RELIANCE-PROGRAM-v1`

A Reliance Program is intentionally not a general policy language. It names
customer-pinned admissibility profiles, orders their evaluations, binds one
exact action, and selects one existing downstream consequence owner. Anything
outside that closed role must remain in the native artifact, profile,
verifier, Gate deployment, downstream owner, system of record, or human and
legal process that actually owns the claim.

## 1. Native evidence truth

The source cannot express or establish:

- that a signature, credential, attestation, receipt, permit, or status
  artifact is authentic;
- that a subject is a particular civil person;
- that two labels denote distinct people;
- that a key is hardware bound or controlled by the named subject;
- that an issuer, registry, trust root, or verifier is trustworthy;
- that an external record is complete, accurate, current, or unaltered;
- that revocation was checked against an authoritative source; or
- that a native artifact has the legal meaning its producer assigns to it.

Those are outputs of independently configured native verifiers under
relying-party trust. A profile pin selects a policy; it does not prove the
policy's inputs.

## 2. Semantic equivalence and exact action

The source cannot infer that differently shaped actions are equivalent. It
cannot create a CAID mapping, repair a lossy mapping, infer omitted material
fields, or turn `INDETERMINATE` into `MATCH`.

The signed source binds a supplied `root_caid` and `action_digest`. The executor
must still derive both from executor-controlled facts under the pinned action
and mapping definitions. A signature over mismatched identifiers does not make
the mismatch true.

The source also cannot express a category of future actions, a wildcard tool
call, an open-text intent, or “anything needed to complete the goal.” Version 1
targets one exact consequential action. A materially different action requires
a different source and signed envelope.

## 3. Human understanding and authority

The source cannot establish:

- that a human saw a complete and accurate presentation;
- that the human understood, intended, or voluntarily authorized the action;
- that the person was free from coercion or conflict;
- that an approval was wise, clinically appropriate, lawful, or ethical;
- that a reviewer held a current license, role, or delegated authority;
- that a machine-policy `ALLOW` result is human authorization; or
- that a signed denial, recommendation, or acknowledgment is permission to
  execute.

A customer may pin profiles that require evidence for some of these
properties. The resulting evaluation remains bounded by those profiles,
verifiers, enrollment systems, and source records. Orchestration cannot
upgrade weak evidence.

## 4. Clinical and Da Vinci PAS claims

The source cannot encode medical necessity, diagnose a condition, select a
treatment, judge a clinician's rationale, or determine whether an adverse
benefit decision is substantively correct.

It cannot establish Da Vinci PAS conformance merely by naming a PAS profile.
Conformance requires validation of the actual FHIR artifacts and applicable
implementation-guide rules. It cannot establish compliance with a statute,
regulation, payer contract, accreditation rule, or utilization-management
policy.

The published payer fixture is synthetic and contains no PHI. It is not
connected to a payer, provider, member record, production FHIR endpoint, or
adjudication system.

## 5. Audit claims

The source cannot define audit scope, materiality, sampling sufficiency,
professional judgment, independence, competence, chain of custody, retention
law, or the form of an audit opinion. It cannot make an EMILIA-generated report
an auditor's workpaper or opinion without the auditor's own procedures and
acceptance.

“Proof of human authorization” in the fixture means only that the customer's
pinned profiles are intended to evaluate specified action-bound evidence. It
does not prove that every relevant control operated, that management assertions
are fairly stated, or that an audit standard was satisfied.

## 6. MCP and platform claims

The source cannot determine that:

- an MCP server or client correctly implements a protocol version;
- a tool is safe, non-malicious, or accurately described;
- tool arguments have no hidden or downstream effect;
- delegated scope is valid or current;
- a workload, device, build, or platform is genuine;
- a model's plan is aligned with the customer's intent;
- a tool response proves the provider-side effect; or
- all administrative, break-glass, direct API, and alternate tool paths are
  mediated by Gate.

Those properties require pinned protocol adapters, authority and platform
verifiers, executor-controlled argument binding, durable state, provider
evidence, and deployment controls outside this source.

## 7. Execution, outcome, and remedy

Compilation and envelope verification do not start a Trust Program instance,
fill a stage, authorize a claim, enter a provider, or execute an effect.

Even after every compiled stage is satisfied:

- Gate readiness is not authorization by the downstream owner;
- a Gate claim is not provider receipt;
- provider receipt is not success;
- an `INDETERMINATE` result is not retry permission;
- a claimed outcome is not independently observed effect; and
- revocation cannot retroactively erase an already claimed or observed effect.

Receipt Program or Action Escrow owns its separate reserve, effect,
finalization, uncertainty, and reconciliation state machine. A dispute or
remedy is a new action with its own CAID, policy, authorization, claim, and
outcome; it does not rewrite the original record.

## 8. Production and legal effect

The source and envelope cannot establish durable storage, high-availability
behavior, KMS/HSM custody, clock integrity, tenant isolation, secure key
rotation, operational monitoring, incident response, retention, privacy,
complete mediation, or production deployment.

They cannot create a contract, transfer liability, satisfy a legal duty,
establish admissibility in a legal proceeding, certify a product, create an
audit opinion, or prove standards adoption. Those consequences depend on
separate agreements, applicable law, qualified professional judgment, actual
deployment, and external evidence.

## 9. No extension by unknown fields

Unknown fields are not a way to add any of the meanings above. Source,
envelope, relying-party, stage, profile-reference, execution, and signature
objects are closed. An implementation must refuse an unknown field rather than
ignore it, reinterpret it, or preserve it as unsigned metadata.

If a real customer program requires a property not representable by pinned
admissibility profiles, closed stage rules and ordering, and one consequence
owner, that gap must be designed explicitly. It must not be smuggled into a
free-text field or claimed from a passing v1 compilation.
