<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS-09 receipt compatibility and optional AEB mapping

This profile checks whether EMILIA's existing CCS v1.3 receipt adapter can
verify the 22-field receipt construction in CCS-09 and, when the relying party
chooses it, map the receipt to an exact tool action through AEB/CAID.

It is a bounded compatibility test, not a complete CCS-09 implementation or
an end-to-end Gate deployment. The underlying adapter keeps its CCS-05 name
and source lock. The historical CCS-05 report is unchanged.

## Reproduce

From a repository checkout with Node 20.19 or newer:

```sh
npm ci --ignore-scripts
npm run conformance:composition:ccs09-aeb
```

The receipt suite runs offline. It verifies deterministic fixture receipts
and checks that the generated report and sample set match the committed
files. The keys are public test material. Never use them as deployment keys.

Verify the actual source documents separately:

```sh
npm run conformance:composition:ccs09-sources
```

That command downloads only the two exact IETF archive URLs in
[source-lock.json](source-lock.json), checks their byte lengths and SHA-256
hashes, and fails on a download error or any byte change. It does not save
files or silently replace pins. To check previously downloaded originals
without network access:

```sh
node conformance/composition/ccs09-aeb-v1/verify-sources.mjs \
  --directory /path/to/drafts
```

The directory must contain `draft-correctover-ccs-08.txt` and
`draft-correctover-ccs-09.txt` with their original bytes. A passing receipt
report does not imply this separate source-byte check has been run. Routine
CI runs the offline suite and preserves the historical CCS-05 check; it does
not depend on availability of the IETF archive.

After a reviewed fixture change, regenerate with:

```sh
npm run build:standalone-runtimes
node conformance/composition/ccs09-aeb-v1/run.mjs --write
npm run conformance:composition:ccs09-aeb
```

Edit `.mts` sources, not their generated `.mjs` companions. Keep the source
lock, fixture changes, and resulting report together in review.

## What changed from CCS-08

This comparison uses the exact archived
[CCS-08](https://www.ietf.org/archive/id/draft-correctover-ccs-08.txt) and
[CCS-09](https://www.ietf.org/archive/id/draft-correctover-ccs-09.txt), not
mutable latest-version URLs.

| Topic | CCS-08 | CCS-09 |
| --- | --- | --- |
| AEB and CAID references | Normative references | Informative references, section 22.2 |
| External action mapping, section 6.4 | Required for Evidence Chain integration under a pinned CAID/AEB mapping | Optional; CCS defines its action identifier without depending on either external mechanism |
| Receipt signature and action digest | Detached Ed25519 over fields 1-21; full canonical-parameter SHA-256 in `action` | These constructions remain the same |
| EMILIA implementation credit | Historical CCS-05 profile | Section 20.5 still credits that historical profile; section 1.7 identifies it as the only independently developed third-party profile |

CCS-09 section 1.7 describes the revision as leaving normative protocol
behavior unchanged. The receipt constructions above are unchanged, but the
section 6.4 external mapping requirement has become optional. Reference
classification and dependency should not be conflated with unchanged wire
bytes. This profile implements the optional composition; it does not claim
that CCS requires EMILIA.

The credited result remains the
[CCS-05 profile at commit 5fb2eae](https://github.com/emiliaprotocol/emilia-protocol/tree/5fb2eae9b20d17685e1ecbe061eb4ced03dbe64e/conformance/composition/ccs-v13-aeb-v1).
It is not external validation of this new CCS-09 run. CCS is an individual
Internet-Draft; this package does not imply working-group adoption or IETF
endorsement.

## What the result means

Native verification checks receipt structure and signed bytes under the
relying party's issuer key. Local acceptance separately checks audience,
freshness, policy verdict, and supplied status. Optional mapping then compares
the full action digest with independently supplied tool arguments. A valid
signature can coexist with a refused or indeterminate mapping.

The existing mapper accepts its bounded JSON subset: printable ASCII string
values and keys, safe integers, booleans, null, arrays, and objects. It does
not claim mappings for Unicode or fractional arguments. Unicode in signed
receipt metadata is a separate signature test, not an expansion of the
mapping profile.

A CCS `allow` is machine-policy-decision evidence. It does not establish
human approval, satisfy every evidence requirement, authorize execution, or
prove that a provider performed the requested effect. A signed response hash
is a commitment by the issuer, not independent observation of the provider.

CCS-09 section 4.2 makes the final 22-field receipt post-execution evidence
and separately requires durable pre-execution admission recording. This
suite does not implement or test that durable lifecycle, complete mediation,
crash recovery, evidence propagation, capability manifests, challenge loops,
or all CCS conformance levels. It also does not verify the legacy HMAC as a
cross-domain trust root; that field is covered by the Ed25519 signature.

Consumed and unavailable status cases exercise the adapter's response to
explicit relying-party status inputs. They do not prove a durable replay
store or independently establish the truth or freshness of that status.
The result is locally reproduced compatibility evidence, not a new external
operator run, certification, or support claim for a newer Correctover package.
