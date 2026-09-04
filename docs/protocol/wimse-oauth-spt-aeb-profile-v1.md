# Experimental WIMSE/OAuth/SPT AEB Profile v1

Status: historical experimental profile, revision-pinned, no current runtime.

The current source-tree `@emilia-protocol/verify/aeb-wimse-oauth-adapter`
export is the v3 request profile for WPT-02, HTTP Message Signatures -06, Workload Credentials
-02, and Transaction Tokens -11. It does not accept this v1 configuration or
reinterpret these v1 vectors. The current tree does not retain a frozen v1
runtime. A v1 artifact needs a separately recovered and pinned v1 verifier, or
it must be reissued and reverified under v3. This document, its vectors, and
its source lock are historical evidence, not a runnable current conformance
claim.

Vectors:
`conformance/vectors/wimse-oauth-spt-aeb.v1.json`

Source lock:
`standards/observatory/wimse-oauth-spt-source-lock.v1.json`

## 1. Purpose and claim boundary

This historical profile described how an AEB relying party could verify one
native workload/delegation leg made from:

1. a WIMSE Workload Identity Token (WIT);
2. a WIMSE Workload Proof Token (WPT);
3. a WIMSE HTTP Message Signature over the protected request;
4. an OAuth Txn-Token; and
5. optionally, an SPT TXN signed intent binding.

Every compact token and the HTTP request signature is verified directly with
Node Ed25519 cryptography. Issuers, keys, algorithms, audiences, trust domain,
workload subject, role, clock skew, and maximum ages are immutable constructor
pins. The same config and trust-root values must also be supplied by AEB and
must match the constructor pins by digest.

The adapter returns only the AEB role `delegated-workload` with subject kind
`workload`. It never returns a human subject or human-authorization role.

The following facts do not establish human authorization:

- a valid WIT;
- possession of the WIT confirmation key;
- a valid WPT;
- a valid WIMSE HTTP request signature;
- an OAuth Txn-Token `sub`, `scope`, or `tctx`;
- an SPT `human_anchor`, holder key, scope, or intent digest; or
- a native machine-policy or token-service decision.

If a relying party requires accountable human approval, its AEB requirement
must include a separate natively verified human-authorization leg.

## 2. Exact source revisions

This profile is locked to:

- [draft-ietf-wimse-http-signature-03](https://www.ietf.org/archive/id/draft-ietf-wimse-http-signature-03.txt)
- [draft-ietf-wimse-workload-creds-01](https://www.ietf.org/archive/id/draft-ietf-wimse-workload-creds-01.txt)
- [draft-ietf-wimse-wpt-01](https://www.ietf.org/archive/id/draft-ietf-wimse-wpt-01.txt)
- [draft-ietf-oauth-transaction-tokens-08](https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-08.txt)
- [draft-coetzee-oauth-spt-txn-tokens-03](https://www.ietf.org/archive/id/draft-coetzee-oauth-spt-txn-tokens-03.txt)

The source-lock JSON records the exact archive bytes and SHA-256 values. A
newer Datatracker revision does not silently change this implementation.
Supporting another revision requires a new lock, profile review, vectors, and
adapter version.

Open WIMSE working-group changes published after the source lock are review
inputs, not normative dependencies of this profile. Their counterexamples can
justify stricter relying-party checks, but they do not silently alter the
locked wire semantics.

RFC 9421 supplies the native HTTP Message Signature construction, RFC 9530
supplies `Content-Digest`, RFC 7515/7519 supply compact JWS/JWT processing, and
RFC 8785 supplies JCS for the SPT intent digest and CAID action.

## 3. No new wire format

This profile does not define an HTTP header, token, JWT claim, or transport
format. The object passed as `artifact` is only an AEB invocation envelope. It
carries exact native values and the HTTP request as observed by the relying
party:

```json
{
  "wit": "<exact compact WIT>",
  "wpt": "<exact compact WPT>",
  "txn_token": "<exact compact OAuth Txn-Token>",
  "request": {
    "method": "POST",
    "target_uri": "https://payments.example/commit?mode=atomic",
    "headers": {
      "Content-Type": "application/json",
      "Content-Digest": "sha-256=:...:",
      "Txn-Token": "<same exact compact OAuth Txn-Token>",
      "Workload-Identity-Token": "<same exact compact WIT>",
      "Workload-Proof-Token": "<same exact compact WPT>",
      "Signature-Input": "wimse=(...);created=...;expires=...;nonce=\"...\";tag=\"wimse-workload-to-workload\";wimse-aud=\"...\"",
      "Signature": "wimse=:...:"
    },
    "body": "<exact UTF-8 request body>"
  },
  "spt_txn": "<optional exact compact SPT TXN>",
  "spt_intent": {
    "tool": "<string>",
    "params": {},
    "target": "<string>"
  }
}
```

`spt_txn` and `spt_intent` must either both be present or both be absent.

Header names in the invocation envelope are case-insensitive. The adapter
rejects case-folded duplicates, CR/LF injection, non-singleton required token
values, malformed Structured Fields, and unsupported derived components.

## 4. Constructor pins

`createWimseOAuthSptAebAdapter` requires:

- exactly one WIT issuer Ed25519 root;
- exactly one OAuth transaction-token issuer Ed25519 root;
- exactly one SPT transaction-token issuer Ed25519 root;
- exactly one workload-holder Ed25519 key;
- exact key IDs and `EdDSA`;
- an exact workload subject URI and trust-domain authority;
- exact WIMSE, OAuth, and SPT audiences;
- exact OAuth subject and scope;
- an opaque exact SPT `holder_key` value mapped out of band to the pinned
  workload-holder key;
- an exact CAID action type;
- bounded clock skew; and
- separate maximum ages for WIT, WPT, OAuth Txn-Token, SPT TXN, HTTP signature,
  and AEB status.

The token header never selects a verification key. A `kid` is checked only
against the key already selected by artifact type and constructor use.
Unexpected algorithms, embedded keys, missing key IDs, and wrong signatures
fail closed.

The constructor refuses any evidence role other than `delegated-workload` and
any subject kind other than `workload`.

The workload subject uses a conservative, scheme-generic comparison profile.
The adapter accepts deployment-selected lowercase schemes, including `wimse`
and `spiffe`, while requiring an exact lowercase trust-domain authority and
non-empty ASCII URI-unreserved path segments. It rejects percent encoding,
dot segments, empty segments, trailing slashes, user information, ports,
queries, fragments, non-ASCII spelling, and values longer than 2,048 octets.
This is a local relying-party admission rule. It is not a new WIMSE wire
format or a claim that all deployments must use the same scheme.

## 5. Native verification

### 5.1 Time

Every accepted compact JWT must contain integer `iat`, `nbf`, and `exp`. This
is an additional relying-party profile constraint where a source draft makes a
registered claim optional.

For each token, the adapter verifies:

- `exp > iat`;
- `exp > nbf`;
- `iat` is not in the future beyond pinned skew;
- `nbf` is not in the future beyond pinned skew;
- `exp` has not passed, accounting for pinned skew;
- `now - iat` does not exceed the artifact-specific maximum age; and
- `exp - iat` does not exceed the same maximum age.

The WIMSE HTTP signature separately enforces `created`, `expires`, clock skew,
and its constructor-pinned maximum lifetime.

### 5.2 WIT and workload subject

The adapter:

1. parses exactly three canonical base64url compact-JWS segments;
2. rejects invalid UTF-8, duplicate JSON member names, and non-object JOSE or
   claims values;
3. requires the exact JOSE fields `alg`, `typ`, and `kid`;
4. requires `alg = EdDSA` and `typ = wit+jwt`;
5. verifies the signature with the constructor-selected WIT issuer key;
6. requires exact `iss` and `sub`;
7. requires `sub` to satisfy the constructor's canonical workload-subject
   comparison profile;
8. requires its exact URI authority to equal the constructor trust domain; and
9. requires `cnf.jwk` to be the exact pinned Ed25519 workload-holder key with
   `alg = EdDSA`.

The adapter compares the complete URI. It performs no prefix, wildcard,
ancestor, or descendant match. A different scheme at the same authority and a
sibling path sharing the pinned prefix are different subjects and fail closed.
The relying party verifies the pinned issuer's signed subject assertion and
the pinned holder key. It does not independently establish where the workload
bytes originated or how the issuer assigned the identifier.

The WIT is validated before the HTTP Message Signature, as required by the
locked WIMSE HTTP-signature revision.

### 5.3 OAuth Txn-Token

The adapter requires:

- compact JWS/JWT;
- `alg = EdDSA`;
- `typ = txntoken+jwt`;
- exact pinned `kid` and issuer;
- exact pinned trust-domain `aud`;
- exact pinned `sub`;
- exact pinned `scope`;
- exact WIT workload subject in `req_wl`;
- a non-empty `txn`; and
- a plain, JCS-safe `tctx` object.

The adapter verifies signature and time before using any transaction context.
It does not infer that the OAuth `sub` is a human approver or that token-service
issuance is a human ceremony.

### 5.4 WPT

The adapter verifies the WPT with the WIT confirmation key and requires:

- `alg = EdDSA`;
- `typ = wpt+jwt`;
- exact pinned WIMSE audience;
- a non-empty `jti`;
- `wth = base64url(SHA-256(ASCII(exact WIT)))`; and
- `tth = base64url(SHA-256(ASCII(exact Txn-Token)))`.

If an OAuth bearer token is present, the WIMSE HTTP signature must cover the
`Authorization` field and WPT must contain the matching `ath`. If no bearer
token is present, an `ath` claim is rejected.

This version does not define an application-specific WPT `oth` mapping.
Presence of `oth` is therefore `INDETERMINATE`, not silently ignored.

### 5.5 Signed HTTP request

The locked -03 draft uses the request signature parameter named `wimse-aud`.
It does not use a `Wimse-Audience` HTTP header. This profile implements the
requested WIMSE audience check against the native signed `wimse-aud` parameter,
which is covered through the final `@signature-params` line.

The adapter requires one signature labeled `wimse`, with these covered
components:

- `@method`;
- `@request-target`;
- `content-digest`;
- `txn-token`; and
- `workload-identity-token`.

It also requires coverage of `content-type` and `authorization` when those
fields exist.

The signature parameters must be exactly:

- `created`;
- `expires`;
- `nonce`;
- `tag = "wimse-workload-to-workload"`; and
- `wimse-aud`.

`keyid` and `alg` are not accepted as Signature-Input parameters. The key and
algorithm come from the validated WIT confirmation key and constructor pins.

The target action uses the signed `@request-target` value (path and query), not
an unsigned reconstruction of scheme and authority. The pinned signed
`wimse-aud` supplies the relying-party audience.

The adapter always requires `Content-Digest` for this exact-action profile and
recomputes SHA-256 over the exact UTF-8 body before signature acceptance.

### 5.6 Optional SPT intent binding

When an SPT TXN is present, the adapter verifies:

- a compact Ed25519 JWS under the constructor-selected SPT issuer key;
- exact issuer, subject, audience, `holder_key`, and `txn_token_type = TXN`;
- `iat`, `nbf`, `exp`, maximum age, and non-empty `jti`;
- a non-empty opaque `human_anchor`; and
- `spt_intent_digest` over:

```text
base64url(
  SHA-256(
    "spt-txn-intent-v1" || 0x00 || JCS(spt_intent)
  )
)
```

Revision -03 describes full-chain parent-byte commitments and a
transaction-context hash but does not assign exact interoperable claim names or
encodings to them. This adapter does not invent those claims. It therefore
uses an SPT TXN only as a signed intent-binding adjunct under a directly pinned
issuer. It does not claim full SPT chain verification or accept the SPT token
as standalone authorization.

If the SPT token contains a status reference, this version returns
`INDETERMINATE` because no pinned SPT status-list snapshot is in the profile.

## 6. Exact action projection and CAID

After native verification, the adapter projects only material action fields:

```json
{
  "action_type": "payment.release.1",
  "http": {
    "method": "POST",
    "request_target": "/commit?mode=atomic",
    "content_digest": "sha-256=:...:",
    "wimse_audience": "https://payments.example/commit"
  },
  "transaction": {
    "scope": "payment.release",
    "context": {}
  },
  "spt_intent": {
    "tool": "payment.release",
    "params": {},
    "target": "payments.example/escrow_4821"
  }
}
```

`spt_intent` is present only when the optional SPT binding is present.

The projection deliberately excludes evidence metadata:

- WIT issuer, subject, key ID, and token ID;
- OAuth issuer, audience, subject, `txn`, and `req_wl`;
- WPT token ID;
- HTTP signature nonce; and
- SPT issuer, subject, `human_anchor`, and token ID.

Those values are still verified and can affect acceptance or replay. They do
not become CAID material merely because they appear in signed evidence.

The mapper requires the relying party's `expected_action` to have exactly the
profile shape. Then it:

1. compares the projected native action with `expected_action`;
2. returns `MISMATCH` for different complete material content;
3. returns `INDETERMINATE` for a missing, incomplete, extra, or ambiguously
   shaped action;
4. computes CAID with `jcs-sha256` and the pinned action definition; and
5. requires the CAID implementation's lowercase-hex action digest to equal
   AEB's independently recomputed action digest.

No CAID is returned for `MISMATCH` or `INDETERMINATE`.

CAID identifies the exact projected material action. It does not prove
identity, authority, execution, safety, legality, or human approval.

## 7. Replay

The native replay unit is:

```text
digestAeb({
  native_protocol: "draft-ietf-oauth-transaction-tokens-08",
  trust_domain: oauth.aud,
  txn: oauth.txn
})
```

It is intentionally independent of:

- AEB artifact reference;
- AEB operation identifier;
- AEB consumption nonce;
- WPT `jti`; and
- WIMSE HTTP signature nonce.

Generating a new proof-of-possession value around the same OAuth transaction
cannot create a new native transaction authority. Gate must atomically reserve
this replay unit before effect. The adapter is pure and does not mutate a
replay cache itself.

Origin-wide identifier uniqueness and safe reassignment remain issuer and
deployment lifecycle properties. This adapter does not infer either property
from a valid signature. If the authenticated external status needed to
establish a current, unconsumed assignment is unavailable or stale, native
cryptography may still be `VERIFIED`, but admission is `INDETERMINATE` and the
effect must not proceed.

## 8. AEB outcomes

The adapter keeps these decisions separate:

- `VERIFIED`: all required native signatures, structures, times, subjects,
  audiences, protected-request coverage, and token bindings passed.
- `ACCEPTED`: native verification passed and the external AEB status input is
  fresh, checked, unrevoked, and unconsumed.
- `MATCH`: the verified native action equals the complete expected action and
  CAID recomputation agrees.
- `SATISFIED`: a separate AEB/AEC evaluation determines that all required
  evidence roles are present for one CAID.
- `AUTHORIZED`: a separate local execution policy permits effect.

Malformed pins, unavailable status, unsupported SPT status, missing exact
action, or ambiguous mapping are `INDETERMINATE`. Cryptographic, audience,
subject, expiry, digest, and binding failures are rejected. Explicitly revoked
or consumed external status is rejected.

## 9. Test coverage

The historical test used fresh runtime-generated Ed25519 key pairs and real
signatures for the positive path. Its recorded hostile cases cover:

- malformed compact JWS;
- unexpected `alg`;
- wrong pinned key;
- wrong WPT, OAuth, SPT, and WIMSE audiences;
- non-canonical constructor workload subjects;
- wrong scheme, sibling workload subject, and trust domain;
- issuer-signed rebinding to an unpinned confirmation key;
- expired, not-yet-valid, and over-age tokens;
- missing HTTP method/target/content-digest/Txn-Token coverage;
- changed body bytes;
- wrong WPT `tth`;
- wrong SPT intent digest;
- missing and mismatched exact action;
- replay under a new AEB wrapper;
- unavailable or stale identifier-lifecycle status; and
- attempted substitution into a human-authorization role.

The current package export is v3 and does not run these cases as v1. The
checked-in v1 vectors and source lock preserve the historical claim boundary,
not current executable conformance.
