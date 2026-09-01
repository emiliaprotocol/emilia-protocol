# AIC exact-action crossing composition profile

This kit maps two pinned AIC credential forms into one
`EP-AEB-CROSSING-RECORD-v1` decision without claiming the credential forms are
interchangeable:

- pure-JSON AIC-JWT with protected-header `typ=aic+jwt` and an RFC 7638 JWK
  thumbprint (`hash_alg=jkt`); and
- AIC identity certificates with a SHA-2 hash of the X.509 Subject Public Key
  Info (SPKI).

The v0.2 profile adds four relying-party-owned checks before a native AIC
decision can be recorded:

1. the pinned capability-to-action projection must equal the executor's exact
   `caid` and `action_digest`;
2. the projection must bind the same relying-party identifier, audience,
   executor, and state domain used by the boundary;
3. source status must be explicitly `CURRENT` and carry both an observation
   time (`status.checked_at`) and a source-head digest; and
4. that observation must not be future, older than the fixed 60-second v0.2
   freshness limit, or outside the native credential's validity window.

The bound v2 mappings carry that evaluation time and freshness limit in the
relying-party context. The exported unbound v1 compatibility mappings require
the same relying-party-owned temporal context as a separate argument and
refuse without it; they cannot emit `rp_acceptance=ACCEPTED` from a free
`CURRENT` label alone.

The crossing-record contract digest also commits to `relying_party_id`, so a
record cannot be transplanted to another relying party by retaining the same
audience, executor, and state domain.

The adapter keeps the native-verifier result and relying-party policy as
separate arguments. The native result carries the claimed issuer anchor,
verifier descriptor, verification-evidence digest, and evaluated artifact.
Only the relying-party policy carries the trusted-anchor set, expected native
verifier, mapping profile, and action-projection profile. A presented result
cannot establish acceptance by changing both a claimed anchor and a colocated
"trusted" list. The relying-party context also pins the exact requested-
capability digest, action, and admission domain, so a presented projection
cannot mint a second replay identity by changing one of those values.

The relying party supplies and authenticates the mapping-profile provenance
and digest. The reusable v0.2 adapter enforces the profile identifier and
exactly 60 seconds of source-status freshness, but it does not load or
recompute this directory's `mapping-profile.json` as a trust decision.

The adapter checks a supplied capability-to-action projection for exact
equality. It does not create that projection. Unknown schemes, ambiguous
mappings, and unmapped material parameters must refuse upstream.

The adapter consumes a successful native-verifier result. It does not
reimplement AIC-JWT signatures, delegation, capability or constraint
validation, token-status retrieval, or X.509 path validation. The native
verifier and the closed action-projection profile remain separately pinned
prerequisites. Unknown capability schemes, ambiguous mappings, or unmapped
material parameters must refuse before this adapter is called. The pinned
gateway bearer helper does not pass `ExpectedAudience`, `RequestCapability`,
`PrincipalMaterial`, or `PresenterKey` into the upstream validator. This
adapter derives and checks the compact token audience and the RFC 7638
thumbprint of explicit public JWK material, but it does not prove possession of
that key or prove that the upstream helper evaluated the requested capability.
Production wiring therefore needs an authenticated native-result wrapper that
attests the same capability evaluation.

The pinned `gateway-core` revision can verify an AIC-JWT bearer token and
return a synthesized `x509.Certificate` for its certificate-oriented pipeline.
That returned object is bare: the inspected implementation does not attach an
authenticated original-carrier tag, raw certificate DER, raw SPKI, or a public
key. This adapter therefore derives provenance from the exact raw source. The
JWT/JKT path requires the original compact token and derives its `typ`, artifact
digest, audience, issuer/JTI replay identity, signed `iat`/`nbf`/`exp` envelope,
claimed JKT, and the RFC 7638 thumbprint of explicit public JWK material. The
signed temporal envelope must exactly match the native wrapper's validity
window, so a stale or faulty wrapper cannot extend the token. The native
X.509/SPKI path requires
real, distinct agent and principal certificate DER and derives the bundle
digest, agent serial, and principal SHA-256 SPKI hash. The local distinct-DER
rule is stricter than the pinned upstream `VerifyBundle`, which requires both
chain slots but does not itself compare the leaf bytes for inequality. A
JWT-origin synthesized object has no native certificate bundle bytes and is
refused by the X.509 path while remaining eligible only for the JWT/JKT path.

Raw DER does not establish every native-result field. X.509 issuer, subject,
status, validity, constraints, trust-anchor selection, and verifier-evidence
digest remain outputs of the trusted native wrapper. The DER-derived bundle
identity prevents free wrapper labels from fragmenting replay, but those labels
must still be authenticated before they cross a process boundary.

The adapter derives raw-carrier fingerprints from the bytes it receives. Those
fingerprints do not prove the native verifier saw the same bytes unless an
authenticated wrapper binds them to the verifier result.

That is a local fail-closed boundary, not an upstream integration claim. A
deployment crossing a Go or JSON process boundary still needs a tagged or
authenticated verifier-result wrapper that preserves the original carrier.
The inspected repository had no non-test `VerifyBearer` call site, and the
helper is not evidence of a wired or deployed bearer path.

The deterministic positive fixtures are adapter-boundary stubs, not upstream
interoperability vectors. Native `VERIFIED` is stipulated: the compact JWT uses
a placeholder signature, and the parseable X.509 certificates do not carry the
AIC and principal-authorization extensions required by the pinned native
bundle verifier. The report records this explicitly and does not claim those
verifiers accepted the fixtures.

## Reproduce

From the repository root:

```sh
npm --prefix packages/verify run build
node conformance/composition/aic-aeb-crossing-v0.2/verify-source-lock.mjs
node --test \
  packages/verify/aeb-aic-crossing-adapter.test.js \
  conformance/composition/aic-aeb-crossing-v0.2/run.node-test.mjs
node conformance/composition/aic-aeb-crossing-v0.2/run.mjs --check
```

The deterministic report covers nineteen cases: two stipulated native-result mappings
and hybrid-signed crossing records; separation of jkt and SPKI profiles;
DER-stable X.509 replay identity; principal-binding mismatch; relying-party
self-pin refusal; native type
confusion; rejection of a JWT-origin synthesized X.509 carrier in the native
X.509 mapping while retaining its JWT/JKT route; failed or indeterminate native
verification; exact-action and requested-capability substitution; relying-party
domain and compact-token audience substitution; stale and future status
observations; refusal to widen the fixed 60-second freshness profile; signed
JWT temporal relabeling; revoked and unavailable status;
native-validity failure; and
signed-record relying-party substitution.

`source-lock.json` pins the exact IETF draft bytes and the exact Varwof source
revisions inspected. `report.reference.json` embeds that source lock and the
claim limits so the deterministic output cannot silently outgrow its evidence.

## Claim boundary

A passing report means the EMILIA reference implementation produced the
committed results for the pinned inputs. It is not an independent
implementation of AIC, does not establish production deployment or
IETF adoption, and does not prove every relying party made the correct native
trust decision. It also does not authenticate a native-verifier result crossing
an untrusted process boundary. A verified crossing record remains evidence of
one past local boundary decision. It is never fresh authority for another
action.
