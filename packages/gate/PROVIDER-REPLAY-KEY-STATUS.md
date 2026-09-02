# provider-replay-key: status, prior art, and what it may be called

Written 2026-09-02, after the refuters and the patent read.

## What this is

An adapter feature. It replaces caller-supplied idempotency strings with a
value derived from the authorization instance digest and the frozen action,
so a retry reuses the provider's stored result and a second authorization
does not. That is a real improvement to our own Gate: the previous Stripe
path took `operation_id` from the caller, which is not restart-stable and
carries no binding to the authorization.

## What it is not

It is not white space, not a plate, and not the second consumer story it was
proposed as. Three refuters ran against that thesis and two refuted it.

- The Agentic Commerce Protocol (OpenAI and Stripe) rewrote its idempotency
  section; the carriers this table targets are normatively owned elsewhere.
- The provider treats the value as opaque. It gets identical behavior from a
  random UUID, so the party we called compelled is not compelled to read
  anything we put there. That is the cheaper-document rule, and it applies.
- The corpus refuter did not refute, but found one half already published
  with conformance vectors by a single author, and the other half
  contradicted in print by that same author.

The join half survives on its own terms: a reconciler holding the
authorization can recompute the expected provider reference without a lookup
table. That is useful and it is ours to use. It is not land.

## Patent position, as of 2026-09-02

Read from WIPO PATENTSCOPE this day, OCR text, certified PDF not yet pulled.
DAS WO 2026/150382 (PCT/IB2026/055615), earliest priority 2025-12-09.

This derivation is **clear of every independent claim** on the all-elements
rule. The terms idempotency, deduplication, uniqueness, single-use,
end-to-end and keyed hash return zero hits across the whole 214-claim set.
That is why this branch was released for pushing.

Separately and importantly: claim 2 read with dependent claim 7 of the same
application reads on the pre-effect Gate as a category. That exposure is not
created or reduced by this file, and it is recorded where it belongs, in the
private company repository and in the standing IP hold. Nothing here should
be cited as evidence about the Gate's position.

## Before this is published as a rule rather than shipped as code

The carriage table marks every unverified field with the literal string
`unverified`, and a test asserts those marks are present. Read them. The
retention-versus-authorization-lifetime measurement decides whether the
provider-side fence is real in a given deployment or whether only the join
half works; Stripe expires keys after 24 hours, which is shorter than many
authorization lifetimes.
