# OAuth transaction challenge at the consequence boundary

This profile keeps the OAuth authorization server in charge of its native grant and puts EMILIA at the protected resource's consequence boundary.

The native adapter verifies two artifacts under relying-party-pinned keys:

1. the protected resource's signed transaction challenge; and
2. the authorization server's issued access token for that challenge.

The checked-in JSON pair is a local EMILIA harness wrapper. It is not a media type or wrapper defined by `draft-rosomakho-oauth-txn-challenge-00`.

After native verification, the AEB native compiler maps the transaction, exact
RAR details, actor, and verified OAuth issuer, audience, subject, and client
context to one CAID. The compiler does not authorize, reserve, invoke, or
reconcile anything. The consequence kernel models the separate admission and
outcome states. For the twin-token case, two signed AEB evaluations enter the
same in-process atomic reservation store through a `Promise.all` barrier.
Exactly one reserves.

## What this profile tests

The nine deterministic cases cover:

- the exact challenge and access token;
- a material payment-detail change;
- a transaction-identifier mismatch;
- a challenge without an issued access token;
- two valid access tokens with different `jti` values racing for the same transaction;
- timeout after dispatch;
- blind retry while the outcome is unknown;
- reconciliation with the wrong provider binding; and
- AEB wrapper-reference changes around the same native evidence.

The profile pins `nonreusable-protected-resource-transaction` as its
replay-equivalence rule. The replay identity uses a stable OAuth transaction
namespace, the protected-resource issuer, and `txn`. Access-token reissuance,
Authorization Server migration, mapping revision, and AEB wrapper changes do
not create another spend for the same protected-resource transaction. The
local reservation race returns one authorization and one consumption
conflict.

This is an explicit EMILIA application-profile choice under review, not a claim that OAuth or the draft authors require it. It is deliberately stricter than the base draft's minimum rule, which requires `txn` uniqueness for the challenge and issued-token lifetime. A deployment using this profile must issue a fresh, never-reused `txn` for every new consequential operation.

## Semantic-loss contract

The CAID-bound action carries both native issuers and audiences, the access-token
subject and client, the transaction, exact RAR details, and the required actor.
Those fields are material. A different client or acting workload is a different
action, not harmless metadata.

The mapping declares every verified field it leaves out. JWT `alg`, `kid`, and
`typ` select and constrain verification. `iat` and `exp` constrain freshness.
Each `jti` identifies one artifact instance, while this profile fences replay at
the protected-resource transaction. `reason` and optional `reason_uri` explain
the challenge but do not change the action the relying party may execute. The
mapping definition pins those relying-party bases and refuses an incomplete
omission list.

## Fixed evidence

[`native-fixture.json`](./native-fixture.json) contains literal Ed25519 compact JWT bytes and literal DER SPKI public keys. The runner does not generate keys or signatures. Each string has a checked-in SHA-256, and two complete report runs must be byte-equivalent as JSON.

[`source-lock.json`](./source-lock.json) pins the reviewed IETF archive object:

- URL: `https://www.ietf.org/archive/id/draft-rosomakho-oauth-txn-challenge-00.txt`
- bytes: `70435`
- SHA-256: `a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead`

It also pins the exact source and runtime bytes for the adapter, compiler,
consequence kernel, adapter contract, CAID implementation, and this profile
runner. Those local hashes are same-repository implementation pins. They are
not a measured build, independent reproduction, or immutable commit reference.

The ordinary source-lock check is offline. It checks the manifest, local
implementation bytes, and static fixture hashes; it does not fetch or
revalidate the IETF bytes. Network revalidation is explicit and separate.

## Run it

```bash
npm --prefix packages/verify run build
node --test packages/verify/aeb-oauth-transaction-challenge-adapter.test.js
node --test conformance/composition/oauth-txn-challenge-aeb-v0.1/run.node-test.mjs
node conformance/composition/oauth-txn-challenge-aeb-v0.1/run.mjs --check
node conformance/composition/oauth-txn-challenge-aeb-v0.1/verify-source-lock.mjs
```

Optional network revalidation:

```bash
node conformance/composition/oauth-txn-challenge-aeb-v0.1/verify-source-lock.mjs --network
```

## Exact boundaries

- A challenge is not authorization.
- A pending `transaction_authorization_id` is not authorization.
- An access token does not prove a named human's identity or approval ceremony.
- This profile does not reperform the authorization server's policy or consent decision.
- This profile does not establish sender-constrained token or channel binding such as DPoP or mTLS.
- This is a narrow signed-JWT profile with inline RAR details that must exactly match the relying party's action. It does not cover opaque or introspected tokens, reference-form authorization details, or grant narrowing.
- A compiler report is neither a credential nor an authorization decision.
- Native verification does not prove provider entry, execution, or outcome.
- Local atomic admission does not prove remote atomicity or downstream exactly-once execution.
- The in-process `Promise.all` race does not establish distributed-store concurrency safety or complete AEB conformance.
- `INDETERMINATE` proves neither provider success nor failure.
- This same-team test harness is not an independent implementation or production deployment.
- An individual Internet-Draft is not IETF adoption or endorsement.
