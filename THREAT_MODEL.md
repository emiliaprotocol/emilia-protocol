<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol Threat Model

- **Canonical status:** current repository threat model
- **Reviewed against:** `5d474fd240bc764fa41951c05c39130e38afa7ff`
- **Review date:** 2026-08-26

This is the single canonical threat model for the public EMILIA repository.
Earlier threat-model documents remain as historical Git revisions, not as
parallel statements of current behavior.

EMILIA is the authority control plane for autonomous work. A customer defines a
finite operating mandate outside the governed agent. EMILIA Gate evaluates each
covered consequential action at an executor or system-of-record boundary. It
binds the authority and required evidence to the exact action, reserves accepted
authority before provider entry, admits or refuses the crossing, and preserves
an `EXECUTED` or `INDETERMINATE` consequence state without reopening blind
replay.

The core security claim is deliberately narrower than "exactly once":

> On completely mediated paths that share one durable authority domain, Gate
> admits at most one provider attempt for a covered authorization instance.

EMILIA does **not** claim exactly-once physical execution. A provider may commit
an effect and lose its response, misreport an outcome, violate its idempotency
contract, or be reached through an unmediated path. Those cases require explicit
deployment controls and, after provider entry, authenticated reconciliation.

## 1. Scope and security objectives

This model covers the public protocol, Gate enforcement, approval and evidence
services, tenant-facing control plane, and deployment assumptions that can alter
a consequential authorization or its evidence.

For each declared protected action, the deployment is intended to provide:

1. **Finite customer-owned authority.** The mandate defines mission, action
   types, limits, evidence, audience, expiry, delegation, and exception rules.
   Agent-local code may narrow that authority but cannot invent or widen it.
2. **Exact-action binding.** Authority and required evidence are matched to an
   immutable action derived from executor-owned, effect-relevant facts.
3. **Separated decisions.** Native verification, material-action matching,
   evidence satisfaction, local authorization, provider admission, and observed
   outcome remain distinct conclusions.
4. **Complete mediation.** Every path capable of the declared mutation reaches
   Gate at the real executor, system of record, or actuator, or is independently
   rejected there.
5. **Reserve before provider entry.** One-time authority or bounded budget is
   atomically reserved before any covered external effect can begin.
6. **At-most-one admitted attempt.** A stable operation identifier, exact action,
   tenant or organization, and authority instance share a durable, ownership-
   fenced state transition across all replicas. A consumed or unresolved
   instance cannot be admitted again.
7. **Conservative uncertainty.** Once provider entry begins, loss of the response
   becomes `INDETERMINATE`, not a retryable failure. Authority remains consumed.
   Authenticated, same-provider, same-operation, same-action evidence may
   reconcile the recorded outcome without re-execution.
8. **Portable evidence.** A relying party can re-perform the disclosed
   cryptographic and structural checks under its own pinned roots. Offline
   verification does not silently become current revocation, global replay, or
   physical-outcome proof.

The product claim is: **Protocol proves. Gate prevents.** Prevention is scoped to
the declared actions and completely mediated execution paths.

## 2. Decision and lifecycle vocabulary

These states must not be collapsed into one `valid`, `allow`, or `success` flag.
The terms describe the security lifecycle even where an individual adapter uses
different wire labels.

| State | Meaning | Does not mean |
| --- | --- | --- |
| `VERIFIED` | One native artifact passed its own structural and cryptographic verifier under relying-party-pinned trust and freshness rules. | It fills an authorization role, refers to the executor's action, or permits execution. |
| `MATCH` | Independently verified artifacts denote the same material action by exact equality or a pinned, loss-aware mapping profile. | Either artifact is authoritative or sufficient. |
| `SATISFIED` | The verified and matched bundle fills every slot in one relying party's evidence requirement. | A universal policy decision or permission to execute. |
| `AUTHORIZED` | The consequence-owning executor's local policy permits this exact action, at this time and audience, under the finite mandate. | Provider entry or a completed effect. |
| `ADMITTED` | Required authority was durably reserved and the provider-entry control permitted one covered attempt for this authorization instance. | Provider acceptance, success, or physical effect. |
| `EXECUTED` | The consequence-owning executor has authoritative evidence that the exact protected effect was applied. | Wisdom, legality, safety, permanence, or absence of a later remedy. |
| `INDETERMINATE` | Provider entry began but the executor cannot establish whether the effect was applied. Replay authority remains consumed. | Success, failure, or permission to retry. |

The intended transition is:

```text
challenge -> VERIFIED -> MATCH -> SATISFIED -> AUTHORIZED
          -> reserve -> ADMITTED -> provider entry
          -> EXECUTED | INDETERMINATE
INDETERMINATE -> authenticated reconciliation -> EXECUTED | INDETERMINATE
```

Missing, stale, revoked, exhausted, ambiguous, mismatched, or wider-than-mandate
authority is refused before provider entry. A human approval is one possible
authority source or exception path; EMILIA does not require a fresh human action
for every operation inside a valid mandate.

## 3. Trust boundaries

### 3.1 Customer authority and configuration

The customer owns the mandate, protected-action inventory, evidence
requirements, trust anchors, mapping profiles, policy epochs, provider
configuration, and exception paths. These inputs are trusted only after
authenticated administrative change control. Requesters cannot select or
replace them for the transaction being evaluated.

### 3.2 Agent and requester

Prompts, models, tools, retrieved content, request fields, selector metadata,
presented issuer labels, embedded keys, and caller-asserted assurance are
untrusted. They may propose an action and present artifacts; they do not define
the action that will actually mutate the protected system.

### 3.3 Native issuers and approvers

Identity, delegation, machine policy, human approval, status, and transparency
artifacts retain their native semantics and roots. Gate verifies each under the
relying party's pinned profile. One role cannot silently substitute for another.

### 3.4 Gate enforcement domain

Gate must run outside the governed agent's decision context. Its code,
configuration, verifier registry, trusted keys, action mapping, execution
adapter, and signing material are part of the trusted computing base. If the
requester can replace Gate or its configuration, the enforcement claim fails.

### 3.5 Shared durable authority domain

Reservation, consumption, capability budget, provider-entry, replay,
revocation, evidence-head, and reconciliation state must be shared across every
replica and survive restart. Transitions must be atomic, ownership-fenced, and
tenant-bound. Process-local state is suitable only for labeled demonstrations.

### 3.6 Executor, provider, and system of record

The executor constructs the observed action from the same effect-relevant facts
that reach the provider. The provider or system of record is authoritative only
for the outcome facts within its control. Provider idempotency is an external
contract, not a property created by a receipt.

### 3.7 Reconciliation source

Evidence used to resolve `INDETERMINATE` must be authenticated and bound to the
same provider environment, operation identifier, action digest, material effect
fields, and expected source. An unauthenticated webhook or caller-supplied status
string cannot reopen or close the operation.

### 3.8 Hosted control plane

The production application, database, identity provider, deployment platform,
and service credentials are operational trust boundaries. Database constraints
and row-level security are defense in depth against route bugs and races; they
do not make a fully compromised service tier honest.

## 4. Primary threats and required controls

### 4.1 Mandate widening or policy substitution

**Attack.** An agent, tenant peer, stale administrator, or request payload widens
scope, amount, duration, audience, delegation, or evidence requirements.

**Required controls.** Mandates and policy roots are customer-controlled,
versioned, authenticated, finite, and evaluated outside the agent. Local policy
may narrow but never widen them. Changes require explicit administrative
authority and produce append-only evidence. Missing or conflicting policy fails
closed.

**Residual risk.** A legitimately authorized administrator can configure a bad
mandate. EMILIA proves and enforces configured authority; it does not determine
whether the authority was prudent or lawful.

### 4.2 Action substitution and selector confusion

**Attack.** Evidence is valid for one action while different function arguments,
tenant data, provider parameters, or selector identities reach the effect.

**Required controls.** The executor derives one immutable observed action from
effect inputs it owns. All material fields participate in the action binding.
Independent selector identities resolve conjunctively; ambiguity or conflict is
protected and refused. Presenter-supplied descriptions are never execution
facts. Sealed adapters or registered operations minimize trusted mapping code.

**Residual risk.** A deployer-supplied observed-action mapper remains trusted
integration code. If it omits an effect-relevant field, the exact-action claim is
only as strong as that mapping.

### 4.3 Incomplete mediation and alternate execution paths

**Attack.** A caller bypasses Gate through a direct SDK, alternate API, shell,
database credential, administrator path, local actuator channel, or unmanaged
break-glass mechanism.

**Required controls.** Inventory every mutation path; remove direct credentials
and routes; enforce at the system of record or actuator; deny non-Gate network
paths; and govern break-glass paths separately. Monitoring or scan coverage is
not proof of mediation.

**Residual risk.** Middleware, an MCP proxy, a sidecar, or an egress gateway
cannot constrain a path that does not traverse it. No prevention claim applies
to an unmediated path.

### 4.4 Replay, race, and cross-replica double admission

**Attack.** Concurrent or repeated requests spend one receipt, capability, or
authorization more than once, including under a relabeled operation.

**Required controls.** Bind a stable operation identifier and exact action to a
tenant-scoped authority instance. Atomically reserve before provider entry in a
shared durable store. Use ownership fencing, unique constraints, monotone state
transitions, and no TTL-based reopening of consumed authority. Fail closed if
the required store is unavailable.

**Residual risk.** Offline artifacts cannot enforce global non-replay across
disconnected authority domains. Deployments that do not share the state domain
do not share the at-most-one-admission guarantee.

### 4.5 Provider response loss and outcome ambiguity

**Attack.** The provider applies the effect but its response is lost, delayed, or
malformed. A naive retry duplicates the effect.

**Required controls.** Provider entry follows durable reservation. Any exception
after entry records `INDETERMINATE` and keeps replay authority consumed.
Reconciliation accepts only authenticated, pinned, same-operation and
same-action provider evidence, and does not call the provider again.

**Residual risk.** `INDETERMINATE` can require human or provider-specific
investigation. A provider statement proves what the pinned signer asserted, not
independent physical truth.

### 4.6 Credential and approval compromise

**Attack.** An attacker steals a passkey, session, bearer token, provisioning
token, or mobile pairing; enrolls an unauthorized approver; replays a ceremony;
uses an expired or revoked credential; launders another person's identity; or
socially engineers a legitimate approver.

**Required controls.** Bind enrollment to the authenticated tenant, directory
identity, credential, relying-party ID, allowed origin, challenge, exact action,
validity window, assurance floor, and monotonic counter where applicable.
Consume challenges atomically, recheck revocation and expiry after locks, apply
least privilege, rotate exposed secrets, and separate initiator from approver
when policy requires it.

**Residual risk.** A valid ceremony proves control of an enrolled credential
under its profile. It does not prove civil identity, comprehension, freedom from
coercion, or that the human was not deceived.

### 4.7 Issuer, signing-key, and trust-root compromise

**Attack.** A presenter supplies its own issuer key, a trusted signing key is
stolen, a stale root remains accepted, a rotation is incomplete, or a service
signer fabricates evidence.

**Required controls.** Pin issuer identity and keys out of band; require issuer
participation proofs where specified; enforce key purpose, audience, validity,
status, and rotation; isolate private keys in deployment-controlled custody; and
preserve key identifiers and verification material needed for later
re-performance. Never trust embedded keys or issuer labels by themselves.

**Residual risk.** Compromise of a currently trusted root or signer can produce
cryptographically valid false evidence. Transparency and witnesses improve
detection; they do not make a malicious key honest.

### 4.8 Tenant, organization, and identity confusion

**Attack.** A same-organization peer exceeds its role; a cross-tenant query leaks
or mutates data; an attacker squats an organization identifier; SAML or SCIM
state is confused between tenants; or continuity and pairing flows transfer
authority to an unowned identity.

**Required controls.** Derive tenant and accountable actor from authenticated
server context. Bind every object and transition to its tenant and owner; enforce
explicit capabilities in addition to membership; use server-owned organization
namespaces; pin SAML destination, recipient, issuer, audience, and canonical
service origin; bind SCIM tokens to one live organization; and serialize
identity-continuity transitions with durable ownership proofs.

**Residual risk.** A compromised tenant administrator can misuse legitimate
tenant powers. Cross-tenant isolation also depends on deployed database policy,
function grants, migrations, and service-role custody matching the reviewed
revision.

### 4.9 Malicious or non-conforming provider

**Attack.** A provider ignores its idempotency key, applies different fields,
lies about its outcome, signs evidence for another environment, or permits a
second mutation outside the reviewed adapter.

**Required controls.** Pin provider identity and environment, derive provider
arguments from the authorized action, bind the stable operation identifier,
validate output, and reconcile only exact signed evidence. Use a system-of-
record integration or independent outcome source when the risk requires it.

**Residual risk.** EMILIA controls admission to the configured provider boundary.
It does not force an external provider to be truthful, correct, available, or
idempotent.

### 4.10 Deployment, service-role, and configuration failure

**Attack.** Production runs stale code or migrations; required secrets are
missing; row-level security or grants are permissive; local state replaces the
durable store; an origin is derived from an attacker-controlled request;
security events are dropped; or logs expose bearer material.

**Required controls.** Pin the deployed source revision; apply and verify the
governed migration ledger; fail closed on missing production configuration;
force tenant isolation and least-privilege grants; prohibit process-local
production custody; use canonical configured origins; keep secrets out of URLs
and logs; make security state plus audit append atomic; and exercise live schema
and route contracts after deployment.

**Residual risk.** Source-level tests do not prove the deployed revision, schema,
secrets, routing, or cloud policy. Those are separate operational evidence.

### 4.11 Parser, resource-exhaustion, and availability attacks

**Attack.** Untrusted documents, JSON, XML, archives, or question sets trigger
expansion bombs, entity expansion, unbounded model calls, oversized bodies, or
long-held resources. A denial of service prevents authorization or auditing.

**Required controls.** Apply strict formats, size and ratio limits, bounded
parsers, aggregate request and model-call budgets, deadlines, durable rate
limits, and fail-closed behavior when a security budget or throttle is
unavailable. Keep security decisions independent from attacker-controlled free
text.

**Residual risk.** Availability controls reduce amplification; they do not
guarantee service under infrastructure-scale denial of service.

### 4.12 Cryptographic, canonicalization, and supply-chain failure

**Attack.** Algorithm or implementation failure, canonicalization disagreement,
hash collision, malicious dependency, compromised build, or unsigned generated
artifact invalidates verification assumptions.

**Required controls.** Pin algorithms, profiles, canonical bytes, dependencies,
generated artifacts, build inputs, and verifier keys; run cross-language vectors
and negative cases; preserve hashes for governed evidence; and separate
same-team consistency from external implementation evidence.

**Residual risk.** The model assumes the accepted cryptographic primitives are
sound and the running binary corresponds to the reviewed source and
configuration. Reproducible tests are not a proof of an uncompromised supply
chain or host.

### 4.13 Presentation substitution and approver deception

**Attack.** The approval surface displays benign, incomplete, truncated, stale,
or separately generated text while the credential signs a different material
action. A requester may hide risk-bearing fields, swap locale or units, exploit
ambiguous labels, or pressure a legitimate approver into accepting the exact
bytes shown.

**Required controls.** Derive the approval presentation deterministically from
the same immutable canonical action that reaches verification and execution.
Bind the action digest, presentation digest, decision, relying-party audience,
policy, challenge, and validity window into the device ceremony. Refuse any
surface or action mismatch. Display all effect-relevant fields, units,
destination identities, exceptions, and material risk signals without trusting
requester-authored summaries. Preserve the signed presentation bytes or their
verifiable digest for re-performance.

**Residual risk.** Surface binding detects substitution; it does not prove that
the interface was usable, the briefing was truthful, or the human understood,
was attentive, or was free from deception, fatigue, or coercion.

### 4.14 Outbound-request SSRF and DNS rebinding

**Attack.** A webhook, adapter, evidence fetch, redirect, or tenant-configured
URL causes the hosted service to connect to loopback, link-local, private,
metadata, administrative, or cross-tenant infrastructure. A hostname may resolve
to a permitted address during registration and a forbidden address at delivery.

**Required controls.** Use deployment-configured or explicitly allowlisted HTTPS
destinations where possible. Canonicalize the target, resolve it again at
connection time, reject forbidden IPv4 and IPv6 ranges, revalidate every
redirect, bind the connected address to the validated resolution, constrain
egress at the network layer, and keep requester-supplied URLs out of security
decisions. Apply the same policy to webhook delivery, MCP adapters, evidence
retrieval, and any future connector.

**Residual risk.** Application validation depends on the deployed resolver,
proxy, redirect, service-mesh, and egress configuration. Source checks do not
prove that production networking preserves the validated destination.

### 4.15 Security-event omission and evidence-log equivocation

**Attack.** A service commits an authority transition without its required audit
append, acknowledges an append it did not durably store, omits a refusal or
provider-entry event, or presents different evidence-log histories to different
reviewers.

**Required controls.** Make each security state transition and its required
audit append one atomic operation. Require strict append acknowledgements that
the caller independently rehashes and matches to the submitted identifier,
sequence, predecessor, and content. Scope monotone heads by tenant, Gate, stream,
and capture point; detect same-sequence conflicts; and permanently fail closed
for an equivocated stream until the relying party provisions and pins a new
identity. Alert on append failure without rewriting the underlying consequence
state.

**Residual risk.** A fully compromised service and evidence store can omit facts
before they reach an independently held witness. Witnesses prove what they
observed under pinned keys; they do not establish population completeness,
physical outcome, or independent operation by themselves.

### 4.16 Privacy, minimization, and disclosure misuse

**Attack.** Receipts, evidence packages, logs, exports, or support tooling copy
direct identifiers, protected records, secrets, free text, or correlatable
stable identifiers beyond the relying party's stated purpose and retention
window.

**Required controls.** Define a closed disclosure schema for each profile;
reject unknown or direct sensitive fields; prefer pairwise references and keyed
source-record commitments; bind audience, purpose, policy, retention, artifact
type, and key scope; encrypt retained source material; apply tenant-scoped access
control; and export the minimum projection needed for the named verification
procedure. Keep sensitive source records outside portable receipts unless the
profile explicitly requires and governs them.

**Residual risk.** Minimization is not anonymity, differential privacy, or legal
compliance. Permitted opaque values may still become covert channels, overlapping
exports may enable differencing, and authorized recipients may mishandle data.

## 5. Deployment assumptions

The strongest Gate claims require all of the following:

- every declared protected mutation path is completely mediated;
- the mandate and relying-party trust configuration are authentic and correct;
- the observed action includes every effect-relevant field from executor-owned
  facts;
- authority, tenant, operation, and action state share one durable linearizable
  domain across replicas;
- reservation occurs atomically before provider entry and cannot TTL-reopen;
- credentials, issuer keys, Gate code, service credentials, database ownership,
  and administrative configuration remain protected;
- clocks and freshness inputs meet the configured tolerance;
- the provider receives the bound operation and action, and any relied-upon
  idempotency behavior is an explicit provider contract;
- reconciliation sources are authenticated, pinned, action-bound, and truthful
  about the facts they control;
- an approval surface is deterministically bound to the same action bytes used
  by verification and execution when human authority is required;
- outbound connectors preserve destination validation through DNS resolution,
  redirects, proxies, and deployed egress controls;
- required security transitions and audit appends are atomic, and any relied-on
  evidence-log head is durable and fork-aware;
- disclosure profiles, audience, purpose, retention, and tenant access controls
  match the sensitivity of the evidence; and
- the deployed source, database migrations, routes, and required configuration
  have been verified independently of branch-local tests.

If an assumption fails, the affected claim narrows or fails. A deployment must
not silently promote a partial topology or test fixture into a production claim.

## 6. Explicit non-claims

EMILIA does not claim that:

- a consequential effect occurs exactly once in the physical or external world;
- an `AUTHORIZED` or `ADMITTED` action was executed;
- an `INDETERMINATE` action succeeded, failed, or is safe to retry;
- a valid receipt proves an action was wise, legal, safe, fair, fraud-free, or
  commercially correct;
- a signature proves civil identity, comprehension, voluntariness, or physical
  truth;
- presentation binding proves that the approver understood or was not deceived,
  fatigued, or coerced;
- a middleware-only Gate covers routes that can bypass it;
- an offline receipt proves current revocation status or global non-replay
  across independent executors;
- a provider statement is an independent observation of the provider or the
  physical world;
- a customer-authored mapping is a certification, audit opinion, regulatory
  conclusion, or insurance determination;
- a data-minimization profile establishes anonymity, privacy-law compliance, or
  safe handling by every authorized recipient;
- JavaScript, Python, and Go same-team agreement is independent implementation;
- a source remediation, green branch, merge, deployment, and external retest are
  the same status;
- an individual Internet-Draft is an RFC, an adopted working-group item, or IETF
  endorsement; or
- "universal" means all actions are currently covered or that EMILIA operates a
  central global authority network.

## 7. Evidence and current finding status

Use the machine-readable artifacts for claim status and counts:

- [`security/security-case.json`](security/security-case.json) for executable
  security claims, assumptions, exclusions, and evidence hashes;
- [`conformance/conformance-manifest.json`](conformance/conformance-manifest.json)
  for current conformance suites and vectors;
- [`lib/proof-stats.json`](lib/proof-stats.json) for generated proof and test
  statistics;
- [`docs/architecture/GATE-ENFORCEMENT-PROFILE.md`](docs/architecture/GATE-ENFORCEMENT-PROFILE.md)
  for the required Gate processing order and deployment topologies;
- [`docs/RECEIPT-CLAIMS.md`](docs/RECEIPT-CLAIMS.md) for receipt-specific proof
  boundaries; and
- [`docs/security/STRIX_REMEDIATION_2026-07-18.md`](docs/security/STRIX_REMEDIATION_2026-07-18.md)
  for the current per-finding source, deployment, and independent-retest status.

The Strix register is the source of truth for those findings. Do not infer
external closure from a source fix, regression test, merge, or deployment.

Relevant executable paths include
[`packages/gate/src/index.ts`](packages/gate/src/index.ts) and the
[`indeterminate-effect reconciliation example`](examples/indeterminate-effect-reconciliation/README.md).
Repository evidence demonstrates properties only under each artifact's stated
assumptions and exclusions.

## 8. Security review checklist for an integration

Before claiming Gate prevention for a deployment, verify:

1. the exact protected actions and every mutation path are declared;
2. every effect-relevant field is derived at the executor boundary;
3. trust roots, mappings, evidence roles, policy, and mandate are
   relying-party-controlled and transaction-immutable;
4. all replicas share durable tenant-scoped reservation and replay state;
5. reserve completes before provider entry and ambiguous reservation transitions
   refuse entry;
6. the provider-entry control admits at most one covered attempt per authority
   instance;
7. post-entry exceptions consume replay authority and record
   `INDETERMINATE`;
8. reconciliation authenticates the exact provider, environment, operation,
   action, and effect fields without re-execution;
9. credentials, revocation, tenant isolation, database grants, migrations,
   secrets, origins, and audit append match the reviewed production revision;
10. any human approval presentation is derived from and bound to the same exact
    material action used for authorization and execution;
11. every outbound connector revalidates destinations at connection and redirect
    time under deployed egress controls;
12. required audit appends are atomic with security transitions, and relied-on
    evidence-log heads detect omission or equivocation within their stated scope;
13. disclosure schemas minimize sensitive fields and bind audience, purpose,
    retention, and tenant access; and
14. any bypass, break-glass, provider, privacy, or physical-world limitation is disclosed
    beside the claim.

## Reporting

Report suspected vulnerabilities through the process in
[`SECURITY.md`](SECURITY.md). Do not open a public issue for an undisclosed
security vulnerability.
