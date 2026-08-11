# OAuth Transaction Challenge and AE-CHALLENGE Composition Profile

Status: experimental application profile and implementation note. Both
referenced documents are active individual Internet-Drafts, not IETF
working-group documents. This profile records one tested coexistence shape.
It supplies the composition rules required by AE Section 1.1 when both
mechanisms are carried or referenced together. It does not modify either
draft or assign executor admission semantics to the OAuth transaction
challenge.

Referenced specifications:

- TXN: draft-rosomakho-oauth-txn-challenge-00
- AE: draft-schrock-ae-challenge-07

## 1. Distinct protocol jobs

TXN is a native OAuth authorization path. A protected resource selects a
trusted authorization server, issues a signed transaction challenge, and
later evaluates the transaction-bound access token and its authorization
details.

AE is transport-neutral evidence negotiation. A relying party describes
evidence that is missing, stale, or unverifiable and the presentation
profiles it can evaluate. An AE challenge is not a grant and does not replace
the TXN challenge, the authorization server's decision, or the resulting
access token. This is the non-substitution boundary in AE Sections 1.1 and
3.1.

This note applies only when one protected resource deployment uses both
mechanisms for one refused operation.

## 2. Routing rule

The protected resource evaluates two separate questions against local policy:

1. Is a transaction-specific native OAuth grant required?
2. Is independently verifiable evidence beyond that grant also required?

The resulting routing is:

1. If only the native OAuth grant is missing, the refusal carries TXN alone.
2. If the native grant and additional evidence are both missing, TXN remains
   the native authorization path. The response may also carry AE for the
   additional evidence requirement, but satisfying AE does not satisfy or
   advance the OAuth grant requirement.
3. If no native OAuth grant is required, AE may be used alone to negotiate the
   evidence forms accepted by local policy.

The protected resource never offers AE presentation as a substitute for a
required OAuth transaction authorization. In routing case 2, TXN is the
primary challenge for the native grant refusal.

## 3. Exact-action and audience join

Before inspecting presented evidence, the protected resource derives one
snapshot of the operation it is actually being asked to perform. From that
same snapshot it independently derives:

- the AE action binding required by the selected AE presentation profile; and
- the TXN `authorization_details` describing the challenged OAuth operation.

The join is the protected resource's common derivation from its own action
snapshot. It is not identifier equality.

The protected resource must reject a presentation when either mechanism
describes a materially different operation from the operation it freshly
rederives at evaluation time.

The audience join is also conjunctive, not equality. The TXN challenge
audience identifies the selected authorization server, and the resulting
access token is verified for the protected resource under TXN. The AE
challenge audience identifies the expected presenter; on return, the relying
party authenticates that presenter and binds it to the pinned effective
audience under AE. A combined evaluation succeeds only when both native
audience checks succeed. No audience value from one mechanism is substituted
for an audience value from the other.

## 4. Non-substitution and state separation

The two mechanisms retain separate identifiers, audiences, and state:

- an AE challenge identifier or nonce is not a TXN `txn` value;
- a TXN `txn` value is not an AE challenge identifier or nonce;
- consuming an AE presentation attempt does not consume, reserve, invalidate,
  or advance an OAuth transaction or access token; and
- OAuth replay state does not satisfy the AE presentation-attempt replay
  requirement.

Any server-side correlation between the two mechanisms is private state that
the presenter cannot choose or use to substitute one mechanism for the other.

TXN Section 6.2 already states the protected resource's single-use and replay
state requirements where those semantics apply. This note does not redefine
that requirement or prescribe its storage mechanism. A deployment may use a
shared durable storage service for native TXN replay state and downstream
admission state, but the state keys and transitions remain protocol-specific,
and neither is inferred from consumption of an AE nonce.

## 5. Executor admission remains downstream

Neither challenge authorizes a physical effect merely by being issued or
answered. After native verification and local policy evaluation, the executor
still applies its own admission and reconciliation rules.

Durable authority reservation, provider-entry admission, cross-gateway
conservation, and reconciliation of an unknown physical outcome are outside
this coexistence note. An implementation may compose those downstream
controls, but it must not describe them as properties supplied by AE or TXN.

## 6. Graph and loop execution

Workflow continuity is not authority continuity. After task decomposition,
tool selection, retry, parameter rewriting, or a new resource-server hop, the
receiving protected resource rederives the concrete operation it is about to
perform.

A materially changed operation is a new action. Evidence or tokens bound to
an earlier action do not carry authorization across that change merely
because the workflow, graph node, task identifier, or agent identity stayed
the same.

## 7. Tested negative cases

The runnable demonstration in this directory exercises the Section 1.1
composition boundary, including:

- AE presentation cannot satisfy a required native OAuth grant;
- AE and TXN identifiers cannot substitute for one another;
- a materially changed action is refused;
- presenter substitution and challenge replay are refused; and
- a lost provider response is not treated as permission for a blind retry by
  the demonstration's separate downstream admission layer.

The final case tests the composed executor demonstration. It is not attributed
to either challenge specification.

Run:

```text
node --test demo.test.mjs
```

The demonstration is same-team experimental code. Passing its tests does not
establish interoperability, working-group agreement, or independent
implementation.
