# Opt-in provider replay-key v2

This experimental adapter feature supports recomputable joins and a provider's
own bounded idempotency behavior. It does not turn provider behavior into
attestation, prove a payment occurred or establish durable replay history.
V1 APIs and previously derived values remain available for reconciliation.

## Stripe setup and authority

Trusted deployment code constructs `createStripeAllowanceConnectorV2({ stripe,
stripeAccount })` with a fixed official Stripe SDK client, provider endpoint,
credentials and Connect account. Action callers must not control or mutate those
objects. The constructor uses the same client and fixed `stripeAccount` request
option for `accounts.retrieve(null, {}, options)` and `balance.retrieve({},
options)`. It requires the returned account id to equal that fixed account and
the Balance object's `livemode` to be a boolean. Missing, mismatched or failed
probes prevent connector construction. The payout request uses the same fixed
account context and a captured payout method. Arbitrary SDK substitutes, changed
credentials, malicious endpoints and compromised deployment code are outside
this authentication assumption; a boolean supplied by an action caller is not
accepted as a mode probe.

The official Stripe SDK's generated resource describes Balance retrieval as
based on the authentication used for the request and defines `livemode`:
[Balance resource](https://github.com/stripe/stripe-node/blob/master/src/resources/Balance.ts).
The account resource supports retrieving the current context using a null id:
[Account resource](https://github.com/stripe/stripe-node/blob/master/src/resources/Accounts.ts).
These source checks justify the probe shape, not a live-provider acceptance claim.

`stripeAllowanceConnectorIdentity(connector)` returns the setup identifier
`stripe:<account>:<live|test>`. The separately issued signed allowance must name
that exact identifier. Deployments can inspect it before signing. The normal
`guardStripeAllowanceMutation` selects v2 only for this opaque v2 connector.
Action-supplied provider environments, account overrides and retry-epoch digests
are refused. Generic receipt-based `guardStripeMutation` and MCP helpers retain
their existing behavior and do not gain these v2 controls.

The retry epoch is the digest of the exact signed allowance artifact. This
binds one stable epoch to signed authority without accepting caller-selected
rotation. `executeWithGateAllowance` verifies the allowance, status, native
capability, expiry and consumption before the payout callback can run. Changing
the signed artifact requires the existing issuer authority; the v2 primitive
does not independently authenticate its input digests. Only the fixed default
attempt group `'1'` is supported; there is no epoch-rotation API.

The epoch selection is reproducible from retained signed authority. That is
**not** a durable antirollback epoch registry. Durable history and native
consumption remain the configured store's responsibility. A memory store is
still process-local. This patch does not integrate an independent replay-history
authority, detect store restoration or emit `REPLAY_HISTORY_UNCERTAIN` for an
unknown restored epoch. Do not deploy it as if those gaps were solved.

## Immutable carriage and encoding

V2 rejects proxy objects, accessors and unknown contract fields, copies accepted
plain-data values once, and validates one snapshot for commitment and encoding.
It commits to every normalized carrier field plus
`EP-PROVIDER-REPLAY-CARRIAGE-v2`: slot id, ordered charset, encoded length,
maximum length, prefix, prefix charset rule, minimum entropy and forbidden
leading/trailing/substrings. The Stripe adapter pins a literal SHA-256
commitment to `stripe.idempotency-key.v2`, whose prefix is `ep2_`. A changed row
under that contract refuses. A new slot/version requires a reviewed new pin.
Standalone callers of `providerCarriageContractDigestV2` must keep the expected
commitment in relying-party configuration; computing a digest over an attacker's
row does not authenticate that row.

The derivation binds that carriage digest, authorization-instance digest,
action identifier, provider domain and epoch digest under
`EP-PROVIDER-REPLAY-KEY-v2`. Its domain-separated deterministic HMAC stream uses
rejection sampling for capacities below 2^256: blocks at or above the largest
multiple of the output capacity below 2^256 are discarded. Accepted blocks alone
are reduced to the target space. Larger spaces carry the whole 256-bit block.
There is no nondeterministic RNG. After 128 rejected blocks, derivation refuses.
Distribution claims model the domain-separated public HMAC stream as uniform
hash blocks. The version-label HMAC key is public; this is not a secret-key PRF
security claim, capability, or unpredictability guarantee. Reported entropy is
an encoding bound under that model, capped at 256 bits; a fixed known input has
a fixed known output.
Constraints that could exclude any possible output are refused until exact
valid-space accounting exists; unreachable constraints such as SEPA's slash
prohibition on an alphanumeric carrier are supported.

`matchesProviderReplayKeyV2` requires an explicit v2 version and never falls back
to v1. A v1 value cannot be promoted by relabeling it. Stripe stores the v2 opaque
value in both Idempotency-Key and `ep_replay_key` metadata.

## Upgrade, retry and expiry

V2 is an explicit new connector path. Deployment code must preserve operation
provenance and must not rederive an existing operation under v2. The wrapper
does not enforce persisted v1/v2 provenance or perform migration reconciliation. Drain or reconcile preexisting v1/non-default-group attempts
using their original signed authority, group, domain and provider key. Retain
that history. Do not rerun them under the v2 connector or substitute group `'1'`,
even after losing the local store: those changes mint another provider key and
may duplicate an effect. Missing or ambiguous history requires operator recovery
while dispatch stays closed. A new signed allowance must not be used as an
implicit retry of an uncertain historical payout.

Retries of one signed allowance/material payout in the same fixed domain select
the same v2 key. Local action fencing still refuses a new operation id for the
same material payout. Expired allowances refuse before payout entry; provider
key retention does not extend authority expiry. Conversely, an allowance lasting
longer than Stripe's idempotency retention still depends on durable local/native
history after the provider forgets its key. The balance probe does not measure
that retention or guarantee indefinite duplicate suppression.
