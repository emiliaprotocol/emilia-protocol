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
4. that observation must not be future, older than the pinned freshness limit,
   or outside the native credential's validity window.

The crossing-record contract digest also commits to `relying_party_id`, so a
record cannot be transplanted to another relying party by retaining the same
audience, executor, and state domain.

The adapter consumes a successful native-verifier result. It does not
reimplement AIC-JWT signatures, delegation, capability or constraint
validation, token-status retrieval, or X.509 path validation. The native
verifier and the closed action-projection profile remain separately pinned
prerequisites. Unknown capability schemes, ambiguous mappings, or unmapped
material parameters must refuse before this adapter is called.

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

The deterministic report covers thirteen cases: two successful native mappings
and hybrid-signed crossing records; separation of jkt and SPKI profiles;
principal-binding mismatch; untrusted issuer; native type confusion; failed or
indeterminate native verification; exact-action substitution; relying-party
domain substitution; stale and future status observations; revoked and
unavailable status; native-validity failure; and signed-record relying-party
substitution.

`source-lock.json` pins the exact IETF draft bytes and the exact Varwof source
revisions inspected. `report.reference.json` embeds that source lock and the
claim limits so the deterministic output cannot silently outgrow its evidence.

## Claim boundary

A passing report means the EMILIA reference implementation produced the
committed results for the pinned inputs. It is not an independent
implementation of AIC, does not establish production deployment or
IETF adoption, and does not prove every relying party made the correct native
trust decision. A verified crossing record remains evidence of one past local
boundary decision. It is never fresh authority for another action.
