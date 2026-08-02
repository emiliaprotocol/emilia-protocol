<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Bounded Execution Program v1

**Status:** architecture freeze for reference implementation

`EP-BOUNDED-EXECUTION-PROGRAM-v1` constrains a closed, versioned program of
separately authorized consequential actions. It raises the autonomy ceiling
without turning a natural-language goal, an agent-authored plan, or a program
signature into authority.

The program is not another authorization engine. Trust Program continues to
decide whether the evidence required for one action is satisfied. Bounded
Capability Receipts continue to own delegated scope and aggregate resource
authority. AdmissionStore remains the only owner of the one-time execution
right. The Execution Program adds the missing cross-action question: whether
this exact action occurrence is reachable now under the signed program.

## Closed source object

A signed program binds:

- `program_id`, `tenant_id`, monotonically increasing `version`, subject, and
  audience;
- objective, human-authorization, presentation, and optional predecessor-
  program digests;
- issue, activation, and expiry instants;
- a total retained-occurrence ceiling and one or more attempt-budget dimensions;
- a finite acyclic node graph; and
- the explicit claim boundary.

Each node binds:

- a unique `node_id`;
- either one exact `(CAID, action_digest)` pair or a pinned action-profile ID
  and profile digest;
- a pinned Trust Program digest;
- outcome-specific predecessor conditions;
- an occurrence ceiling; and
- fixed charges against named attempt-budget dimensions.

`budget_id`, not `unit`, identifies an independent budget dimension. `unit` is
a signed descriptive label, so separately enforced budget IDs may carry the
same unit label without aliasing their limits or accounting.

Unknown fields, unknown outcomes, duplicate identifiers, duplicate budget
dimensions, cyclic graphs, missing predecessors, nonpositive limits, and node
charges exceeding the program budget fail closed. Profile mode never treats a
profile name as evidence: the AdmissionSnapshot must bind independently
verified action-match evidence under the pinned profile digest.

## Program-aware admission

Program execution MUST use a program-aware AdmissionStore implementation. The
store registers only a program whose signature and relying-party context were
verified. Registration also fences the program's `authorization_digest`: an
ordinary admission carrying that same root authorization can no longer bypass
the program, and registration refuses while such an ordinary reservation
remains live. An action authorized under a genuinely different authorization
remains independent.

The store, not the registration caller, owns the program-authorizer trust pins
and verification clock. A v1 pin is eligible only when its role is
`program_authorizer` and its status is `ACTIVE`. The caller supplies a closed
relying-party context, but cannot nominate keys, authorizer identity, or time.

For every linked admission the store derives one deterministic
`execution_program` resource from the tenant, program digest, node, occurrence,
and admission expiry. That resource is sealed into the immutable
AdmissionSnapshot. A caller-supplied snapshot that omits it or substitutes any
binding is refused. Resource and reservation IDs are fixed-length digests of
the structured `(tenant, program, node, occurrence)` tuple, avoiding delimiter
aliases and caller-controlled identifier-length growth.

The store atomically:

1. verifies the active program version and digest;
2. verifies the node and outcome-specific predecessor state;
3. fences the unique occurrence ID;
4. reserves the occurrence ceiling and every program attempt budget;
5. reserves the ordinary AdmissionSnapshot and its resources; and
6. on `beginInvocation`, consumes both the program attempt and the ordinary
   execution right before releasing the invocation capability.

The signed total-occurrence ceiling counts retained occurrences, including
released reservations; a node ceiling counts its non-released occurrences.
Per-node counts and terminal outcomes are indexed in the transaction domain,
so reserve and dependency checks do not scan retained history.

An admission reserved under a program MUST be refused by the ordinary
`beginInvocation` path. Release before provider entry restores the program
reservation. Once invocation begins, the occurrence and its attempt-budget
charges remain consumed even when the provider result is `INDETERMINATE`.
Admission expiry cannot exceed program expiry. At program expiry, reserved work
can be expired or is atomically released when a begin attempt is refused.

Program and admission state share one linearizable transaction domain. A
compensating call between independent stores is not atomic and does not satisfy
this profile.

## State and dependency semantics

Occurrence states are:

```text
RESERVED -> INVOKING -> COMMITTED
                    \-> PROVEN_NOT_COMMITTED
                    \-> INDETERMINATE -> COMMITTED | PROVEN_NOT_COMMITTED
RESERVED -> RELEASED
```

Dependencies name accepted terminal outcomes. `INDETERMINATE`, `INVOKING`,
`RESERVED`, and `RELEASED` never satisfy a dependency. A dependent node unlocks
only when every named predecessor has at least one occurrence in an explicitly
accepted terminal outcome.

For profile-mode nodes, caller-authored `MATCH` flags are not evidence. The
store passes an opaque artifact to its configured authenticated verifier and
accepts only a closed result bound to the profile, subject, tenant, operation,
CAID/action, evidence payload, verifier, and trust state. The evidence payload
must already be sealed into the singleton AEB input for the program subject.

`DIVERGED` is an observed-effect relation, not a provider outcome. It remains
attached to the AdmissionRecord and program reconciliation; it never rewrites
program reachability or the historical authorization.

## Supersession and replanning

Programs are immutable. Replanning creates a newly authorized version that
increments the predecessor version by exactly one and binds the predecessor
program digest. Supersession refuses new reservations and
new invocation starts under the predecessor. Reserved predecessor occurrences
must be released before supersession. Already-invoking or indeterminate
occurrences remain reconcilable, but they cannot unlock nodes in the successor
unless the successor explicitly imports a separately verified terminal receipt.

No budget, occurrence, evidence, or terminal state silently carries forward.
The successor receives fresh ceilings and fresh authorization.
Tenant, program ID, subject, audience, objective, and presentation are frozen
across v1 supersession. The successor uses a distinct authorization digest that
has not already been registered in the store.

## Authorization and suspension boundary

The program signature belongs to the relying party's pinned program-authorizer
service. It is not, by itself, proof that a human touched an Ed25519 key. Human
approval remains a separately verified evidence leg and is bound into the
program through `authorization_digest` and `presentation_digest`. Deployments
may use WebAuthn/P-256 for that human ceremony while the program-authorizer
issues the canonical Ed25519 artifact.

The reference store rechecks ordinary admission currentness and configuration
epoch immediately before provider entry. It also reads program status from its
configured authoritative source at reserve and immediately before provider
entry. `SUSPENDED`, `REVOKED`, stale, malformed, unavailable, or expired status
observations fail closed and atomically release pre-entry resources, occurrence
capacity, and budget reservations. `REVOKED` is sticky. Work already invoking
or indeterminate remains reconcilable after suspension, revocation, expiry, or
supersession because provider entry cannot be erased.

That authoritative status source is mandatory; locally initialized `ACTIVE`
state is not current-status evidence. External status, profile-match, and
admission-currentness checks run under a bounded deadline outside the mutation
lock. The store then samples its clock and revalidates the exact locked program
and admission state before committing, preventing a slow or reentrant verifier
from authorizing with a stale observation or deadlocking mutation progress.

The PostgreSQL RPCs are transaction boundaries, not cryptographic verifiers.
A deployment therefore uses a general runtime database principal for ordinary
lifecycle/read RPCs and a separately credentialed verifier-service principal
for assertion-bearing program register, reserve, begin, and supersede RPCs.
The runtime principal MUST NOT receive those assertion-bearing grants.

## Claim boundary

Verification can establish that a pinned authorizer signed one canonical
program and that the reference state machine enforced its typed reachability,
occurrence, budget, and supersession rules at the Gate boundary.

It does not establish that:

- natural-language intent was understood or correctly compiled;
- an action profile is sound;
- a plan is safe, lawful, optimal, or free of prompt injection;
- provider evidence or an observed effect is true;
- every mutation path was mediated by Gate; or
- an out-of-program refusal identifies the cause of the divergence.

The honest statement is: the action was or was not admitted under this exact
signed execution program. It is not “prompt injection detected” or “the agent's
reasoning was explained.”
