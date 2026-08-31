<!-- SPDX-License-Identifier: Apache-2.0 -->
# WPT-02 token binding at the OAuth transaction boundary

This pack found a useful seam and a hard protocol collision.

The useful seam is WPT-02 token binding. A signed Workload Proof Token can
bind a standard `Txn-Token` through `tth`. It can also bind a relying party's
understood authorization-context token headers through `oth`. The verifier
hashes the exact ASCII token value for `tth`, and the trimmed ASCII header
field value for every `oth` entry. Missing, mismatched, substituted, and
unknown entries fail closed. JSON member order does not matter; the normalized
header-name set does.

The WPT audience uses one closed comparison rule. The pinned value is a
canonical HTTPS origin and path with no query or fragment. The received target
must have that exact origin and path after its query is removed. This profile
does not accept aliases, rewritten authorities, rewritten paths, or
noncanonical URI spellings.

The artifact carries a canonical absolute HTTPS `target_uri`; the verifier
projects its path and query into the origin-form value covered by
`@request-target`. That proves the exact relying-party observation supplied to
the adapter, not the raw request-line bytes seen by an HTTP server. The same
boundary applies to headers. Case-folded duplicate keys that can be represented
in the object fail closed, but an object or map cannot prove raw-wire singleton
cardinality. The HTTP stack must establish that before constructing the
artifact.

The collision is in HTTP carriage. WPT-02 requires `Authorization: WPT ...`
and says the request cannot carry another authentication scheme in that
field. OAuth Transaction Authorization Challenge -00 requires its issued
bearer access token to be presented as `Authorization: Bearer ...`. One HTTP
request cannot satisfy both rules.

The runner therefore treats `OAuth-Transaction-Access-Token` and
`OAuth-Transaction-Challenge` as names in an EMILIA candidate wrapper. WPT can
bind those bytes through `oth`, but the custom access-token header is not a
native OAuth transaction-challenge presentation. The positive wrapper case is
evidence for a possible application profile, not a claim that the two drafts
already compose.

Txn-Tokens -11 defines `aud` as the Trust Domain and says `txn` should be
unique within that domain. The replay key therefore uses a stable native
namespace plus the exact `aud` and `txn`. The draft revision and optional
`iss` remain verification metadata. They cannot rekey an existing spend.

The adapter only emits that replay identity. It does not reserve it or keep a
cache of HTTP Signature nonces or WPT `jti` values. A downstream AEB
consumption store must make the replay reservation atomically. Deployments that
enforce nonce or WPT-identifier reuse need a separate cache with the applicable
validity window.

## Strict application subset

This is a strict EMILIA application subset, not general Txn-Tokens -11 or
WIMSE HTTP Message Signatures -06 conformance. It requires a Txn-Token with
`iss`, `nbf`, and `tctx`; a nonempty request body with `Content-Digest`; Ed25519
keys; a canonical HTTPS target projected to origin form; and the request-only
message-signature path. Some of those fields or choices are optional or more
permissive upstream. The optional -06 signed-response negotiation is refused
because this adapter cannot enforce the later response. A present Txn-Token
`rctx` is also refused until a versioned closed mapping profile classifies and
projects that downstream request context.

## What the eighteen cases cover

- a candidate wrapper binds one standard Txn-Token plus the exact challenge
  and access-token bytes;
- missing and mismatched `tth` values fail when `Txn-Token` is present;
- missing, mismatched, substituted, and unknown `oth` entries fail;
- reversing JSON member order preserves the same `oth` result;
- fully re-signed target-authority and target-path substitutions fail the WPT
  audience check;
- noncanonical target spelling fails before origin-form projection;
- the optional HTTP Signature -06 signed-response request is refused because
  this request verifier cannot enforce or verify the later response;
- a signed Txn-Token twin containing `rctx` fails before action mapping;
- case-folded duplicate object headers fail without claiming raw-wire
  singleton cardinality;
- `tth` is absent when no `Txn-Token` is present, and an orphan `tth` fails;
- a draft-revision migration cannot open a second spend for the same Trust
  Domain and transaction identifier;
- the exact WPT-02 and OAuth transaction-challenge HTTP rules produce an
  explicit Authorization-scheme collision.

The accepted WIMSE result has the role `delegated-workload`. It proves
workload possession and request token binding under pinned keys. It does not
authorize the payment, admit a provider call, or prove an effect.

## Source lock

[`source-lock.json`](./source-lock.json) pins these exact archive objects:

- `draft-ietf-wimse-wpt-02`, 43,002 bytes,
  SHA-256 `6a629ffd6bcc0e75ae1deb3e2ddd543ef09d0da6f108e85d085b09d2b9b42f82`;
- `draft-ietf-wimse-http-signature-06`, 45,388 bytes,
  SHA-256 `e44e2bc1340854e1c3aab3887bba4e9d89f4b9edb54865c43bfbd9c0e7d40f44`;
- `draft-ietf-wimse-workload-creds-02`, 58,413 bytes,
  SHA-256 `b111e4e85a7f3bc5c844560db87276c184a04db28ffeaccb057c13eb034dbed5`;
- `draft-ietf-oauth-transaction-tokens-11`, 80,218 bytes,
  SHA-256 `937eeaac88c19eb00c7a3581f3de850c79c32aa7e4484ded329c15c123718364`;
- `draft-coetzee-oauth-spt-txn-tokens-03`, 32,752 bytes,
  SHA-256 `5ebba0db429816a7fe887128f08d51c3840209bf17de74d66581ce935966e195`;
- `draft-rosomakho-oauth-txn-challenge-00`, 70,435 bytes,
  SHA-256 `a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead`.

The same manifest pins the complete local module closure executed by the
runner: the runner, adapter compatibility entry point, built adapter, strict
JSON runtime, and CAID implementation. It also pins the adapter source,
vectors, static OAuth fixture, and both AEB adapter-contract compatibility
surfaces named by the revision audit. The WPT adapter uses a type-only contract
import, so the broad contract module and its unrelated re-exports are not part
of this pack's executed runtime closure. Ordinary tests are offline. Network
revalidation of the six archive objects is a separate command.

The deterministic report currently passes 18 of 18 cases with digest
`sha256:10ff9732c900d36aeb8538ef2bfd9b7a90890bdf1c871b2b7c5a97e81851fde6`.

## Compatibility boundary

The older `conformance/vectors/wimse-oauth-spt-aeb.v1.json`, v1 profile, and v1
source lock remain separately labeled historical reference files for Workload
Proof -01 and Txn-Tokens -08. Adapter v2 does not import or reinterpret them,
and this pack does not expose a v1 runtime. This pack is the current v2 request
path: WPT-02, HTTP Message Signatures -06, Workload Credentials -02, and
Txn-Tokens -11. It supports the required -06 request fields but not the
optional signed-response negotiation. A v1 artifact needs a frozen v1 verifier
or must be reissued and reverified under v2; passing the old vectors is not
evidence of v2 conformance.

## Run it

```bash
npm --prefix packages/verify run build
node --test packages/verify/aeb-wimse-oauth-adapter.test.js
node --test conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.node-test.mjs
node conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.mjs --check
node conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/verify-source-lock.mjs
```

Optional network revalidation:

```bash
node conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/verify-source-lock.mjs --network
```

## Claim boundary

This is a same-team deterministic test harness over pinned draft bytes. It is
not an independent implementation, production mediation, IETF adoption, or
author endorsement. A WPT does not validate the OAuth challenge or access
token. The OAuth adapter must do that separately. Neither native verifier
makes the local admission decision, reserves an operation, invokes a provider,
or establishes what happened after provider entry. The artifact records a
relying party's structured observation; it is not raw-wire HTTP evidence.
