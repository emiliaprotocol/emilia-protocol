<!-- SPDX-License-Identifier: Apache-2.0 -->
# WPT-02 token binding at the OAuth transaction boundary

This pack found a useful seam and a hard protocol collision.

The source lock verifies the exact archived draft bytes named below. The
executable cases implement a labeled, same-team interpretation of those
requirements; they do not execute or independently validate the draft prose.

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
the adapter, not the raw request-line bytes seen by an HTTP server. The request
header profile is closed: only its required protocol and signature fields plus
the profile's two fixed candidate token fields are accepted. Configuration
cannot reclassify a semantic header such as `If-Match` as an `oth` field.
Unknown headers fail closed,
and signed `Content-Type` is projected into the action rather than discarded.
The body remains opaque bounded UTF-8 bytes committed by `Content-Digest`; the
profile does not claim to validate that those bytes conform to the named MIME
type.
Case-folded duplicate keys that can be represented in the object also fail,
but an object or map cannot prove raw-wire singleton cardinality. The HTTP
stack must establish that before constructing the artifact.

The collision is in HTTP carriage. WPT-02 requires `Authorization: WPT ...`
and says the request cannot carry another authentication scheme in that
field. The OAuth Transaction Authorization Challenge -00 bearer path exercised
here presents its issued token as `Authorization: Bearer ...`. One HTTP
request cannot satisfy both of those exact forms. This pack does not claim
that every transaction-challenge token format is a bearer token.

The runner therefore treats `OAuth-Transaction-Access-Token` and
`OAuth-Transaction-Challenge` as names in an EMILIA candidate wrapper. WPT can
bind those bytes through `oth`, but the custom access-token header is not a
native OAuth transaction-challenge presentation. The positive wrapper case is
evidence for a possible application profile, not a claim that the two drafts
already compose.

Txn-Tokens -11 defines `aud` as the Trust Domain, carries one `txn` through a
call chain, and describes single-use refusal at the same receiving workload.
The replay key therefore uses a stable native namespace plus the exact `aud`,
a constructor-pinned receiving logical workload, and `txn`. The receiver is
relying-party configuration, not a presenter claim or Txn-Token field. The
draft revision and optional `iss` remain verification metadata. They cannot
rekey an existing spend.

The Txn-Token's original `req_wl` is pinned separately. At the first hop it is
normally the immediate WIT sender. At a later hop the same token remains
unchanged, so `req_wl` still names the original requester while the new WIT
names the immediate sender. Both values are verified. `req_wl` is treated as
authenticated provenance rather than provider-action identity, so it remains
explicitly nonmaterial to the CAID projection.

The adapter only emits that replay identity. It does not reserve it or keep a
cache of HTTP Signature nonces or WPT `jti` values. A downstream AEB
consumption store must make the replay reservation atomically. A store shared
by several receiving workloads refuses a second use at the same logical
workload without consuming the transaction for a different workload in the
call chain. Deployments that enforce nonce or WPT-identifier reuse need a
separate cache with the applicable validity window.

Receiver identity must remain stable for the configured acceptance window.
Renaming or aliasing a logical workload requires an explicit replay-state
migration or canonical alias policy; silently changing the receiver string can
open a new replay class. Store retention is an application policy bounded by
the accepted token window. This profile does not claim permanent replay
retention.

## Strict application subset

This is a strict EMILIA application subset, not general Txn-Tokens -11 or
WIMSE HTTP Message Signatures -06 conformance. It requires a Txn-Token with
`iss`, `nbf`, and `tctx`; a constructor-pinned canonical receiving-workload
identifier; a separately pinned canonical original-requesting workload; a
request with `Content-Digest`; Ed25519 keys; a canonical HTTPS target projected
to origin form; an exact request-header set with material `Content-Type`; and
the request-only message-signature path. Some of those fields or choices are
optional or more permissive upstream. The optional -06
signed-response negotiation is refused because this adapter cannot enforce the
later response. A present Txn-Token `rctx` is also refused until a versioned
closed mapping profile classifies and projects that downstream request
context.

Admission limits run before canonical hashing: 32 request headers, a 32-byte
method, an 8,192-byte target, a 262,144-byte body, 256-byte header names,
131,072-byte individual header values, a 262,144-byte aggregate header
section, and nine Signature-Input components. The complete artifact is also
bounded to 10,000 JSON nodes and 786,432 string bytes. Malformed Unicode and
oversized inputs receive the fixed invalid-evidence digest; only an admitted
strict-canonical artifact can produce a verified evidence digest.

## What the twenty-three cases cover

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
- an extra unsigned semantics-changing header fails, and a fully signed
  `Content-Type` substitution produces an action mismatch;
- configuration cannot bless `If-Match` as a nonmaterial token field;
- `tth` is absent when no `Txn-Token` is present, and an orphan `tth` fails;
- two fully verified signed hops preserve the exact Txn-Token bytes while the
  WIT sender advances; a second presentation at one receiving workload is
  refused, while the next receiving workload gets its distinct replay class;
- two valid current-v3 profiles under different pinned issuers and token bytes
  produce the frozen replay identity; a future revision must preserve that
  derivation or explicitly migrate replay state;
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
- `draft-ietf-wimse-identifier-02`, 25,443 bytes,
  SHA-256 `3789600b5295bed271970fc318d1bcbd317b46883aab42f58e5620ab31a766b8`;
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
revalidation of the seven archive objects is a separate command.

The deterministic report currently passes 23 of 23 cases. Its checked-in
reference binds both the full report digest and the raw source-lock digest.

## Compatibility boundary

The older `conformance/vectors/wimse-oauth-spt-aeb.v1.json`, v1 profile, and v1
source lock remain separately labeled historical reference files for Workload
Proof -01 and Txn-Tokens -08. Adapter v3 does not import or reinterpret them,
and this pack does not expose a v1 runtime. This pack is the current v3 request
path: WPT-02, HTTP Message Signatures -06, Workload Credentials -02, and
Txn-Tokens -11. It supports the required -06 request fields but not the
optional signed-response negotiation. A v1 artifact needs a frozen v1 verifier
or must be reissued and reverified under v3; passing the old vectors is not
evidence of v3 conformance.

This source candidate is not cleared for an ordinary `3.21.x` npm release.
The published v1 subpath is incompatible with this v3 constructor and action
shape. Packaging must preserve v1 and expose v3 separately, or move the
package to a new major version.

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

This is a source-pinned, same-team deterministic interpretation. It is not an
independent implementation, production mediation, IETF adoption, or author
endorsement. A WPT does not validate the OAuth challenge or access token. The
OAuth adapter must do that separately. Neither native verifier makes the local
admission decision, reserves an operation, invokes a provider, or establishes
what happened after provider entry. The artifact records a relying party's
structured observation; it is not raw-wire HTTP evidence.
