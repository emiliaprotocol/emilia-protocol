# The lost-response challenge

One approval per call is not enough to prevent a duplicate consequential
action. A provider can accept an action and lose its response. After a restart,
the agent may obtain an entirely new, valid approval for the same business job.

This is a public, competitor-neutral test case for an executor or gateway. It
does not prescribe an authorization token, receipt format, policy language, or
product. An implementation may use its own native artifacts and state names.

## The case

The business system has one immutable refund job: refund 5,000 minor units
against payment `pi_refund_test` under operation
`refund:order-123:01`. A gateway holds the provider credential. The first
approval permits this exact job. The provider accepts the refund, but its
response never reaches the gateway.

The gateway restarts. A second human approval and a fresh authorization token
are valid for the same job. The provider's idempotency cache has expired. The
provider is briefly unavailable to answer a status query. Later, its
authenticated account-scoped API returns one refund with the exact operation,
request digest, payment, and amount.

The expected behavior is:

1. After the lost response, record **unknown**, not **failed** or **unused**.
2. A fresh approval or token must not cause another provider-entry attempt for
   that business operation, even after process restart and idempotency-cache
   expiry.
3. An unavailable, incomplete, conflicting, or unauthenticated status view
   must not release the operation for retry or claim success.
4. Matching authenticated provider evidence may close the operation as
   accepted. That does not claim funds have settled.
5. Changing the amount while keeping the operation ID must not execute.

An implementation also has to identify the authority for the **stable business
operation ID**. If the business system creates a new ID for what it regards as
the same job, this test cannot infer that identity. If an agent retains a
separate provider credential, the gateway cannot claim complete mediation.

The [portable case file](case.v1.json) records the input and expected states.
It is a review fixture, not a certification scheme. A successful self-run does
not prove production credential custody, durable deployment, provider truth, or
interoperability with another implementation.

## Run EMILIA's bounded reference case

From the repository root:

```sh
node examples/effect-boundary-challenge/demo.mjs
node --test --test-name-pattern='lost response remains indeterminate' packages/gate/adapters/stripe-refund-durable.test.mjs
```

The demo prints its observed trace and exits nonzero if the assertions fail.
It uses real Gate authorization and the opt-in durable Stripe connector with a
deterministic mock provider and attempt store. It does **not** call Stripe or
move money. The demo gives the restarted Gate a distinct signed receipt; it
does not pass an OAuth token into the connector. Token variation in the case
file is a requirement for implementations that use one, not a claim tested by
this demo. The focused test covers fresh authorization after a simulated
restart; the broader connector suite exercises mutation, concurrency, lost
rows, ambiguous provider views, and stale owners. The separate
`stripe-refund-durable-postgres.test.mjs` uses real PostgreSQL only when
`ADMISSION_STORE_POSTGRES_TEST_URL` is configured; a skipped run is not
PostgreSQL evidence.

For an independent implementation, replace the mocked provider and state
store with its own test doubles, submit the same sequence, and report the
provider-entry count, stable operation key, state transitions, source of
status evidence, and the exact scope of credential custody. No one should
grade their own homework: a claim of live deployment needs operator-side
evidence beyond this fixture.
