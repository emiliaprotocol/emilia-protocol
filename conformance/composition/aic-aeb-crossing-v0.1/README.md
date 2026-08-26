# AIC crossing composition profile

This kit maps two pinned AIC credential forms into
`EP-AEB-CROSSING-RECORD-v1` without claiming they are interchangeable:

- pure-JSON AIC-JWT with the exact protected-header type `aic+jwt` and an
  RFC 7638 JWK thumbprint (`hash_alg=jkt`), and
- AIC identity certificates with a SHA-2 hash of the X.509 Subject Public Key
  Info (SPKI).

The adapter consumes a successful native-verifier result. It does not
reimplement AIC-JWT signature, delegation, capability, constraint, or status
validation, and it does not reimplement X.509 path validation. Before mapping,
the relying party must independently pin the native issuer trust anchor and
must compare the claimed principal binding with the presented key material.

## Strict JWT-SVID projection

The optional JWT-SVID helper does **not** pass native `aic+jwt` through as a
JWT-SVID. It emits a to-be-signed workload-identity projection with:

- protected-header `typ=JWT`,
- exactly one `aud` value,
- an explicit list of omitted AIC semantics,
- `new_signature_required=true`, and
- no compact token or authorization decision.

Changing only the native protected header would invalidate the AIC-JWT
signature. A deployment therefore has to sign the projection with a key in its
JWT-SVID bundle. The projection refuses any request to preserve AIC authority
semantics because the strict JWT-SVID shape does not carry the AIC principal,
delegation, constraint, confirmation-key, or complete capability model.

## Reproduce

From the repository root:

```sh
npm --prefix packages/verify run build
node conformance/composition/aic-aeb-crossing-v0.1/verify-source-lock.mjs
node --test \
  packages/verify/aeb-aic-crossing-adapter.test.js \
  conformance/composition/aic-aeb-crossing-v0.1/run.node-test.mjs
node conformance/composition/aic-aeb-crossing-v0.1/run.mjs --check
```

The deterministic report covers ten cases: two successful native mappings and
hybrid-signed crossing records, separation of jkt and SPKI profiles, binding
mismatch, untrusted issuer, native type confusion, failed or indeterminate
native verification, a strict JWT-SVID projection, multiple-audience refusal,
and authority-semantic-loss refusal.

`source-lock.json` pins the exact IETF draft bytes and the exact Varwof source
revisions inspected. `report.reference.json` embeds that source lock and the
claim limits so the deterministic output cannot silently outgrow its evidence.

## Claim boundary

A passing report means the EMILIA reference implementation produced the
committed results for the pinned inputs. It is not an independent
implementation of AIC or JWT-SVID, does not establish production deployment or
IETF adoption, and does not prove every relying party made the correct native
trust decision. A verified crossing record remains evidence of one past local
boundary decision. It is never fresh authority for another action.
