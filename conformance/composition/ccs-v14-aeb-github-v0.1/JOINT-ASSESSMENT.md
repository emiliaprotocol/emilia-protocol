# Joint Interoperability Assessment — CCS v1.4 receipt as EMILIA pre-admission evidence

**Status:** DRAFT v3 for joint review — not final and must not be merged or represented as jointly approved until both parties approve the exact bytes.
**Date:** 2026-08-30
**Revision:** v3 supersedes v2 (2026-08-29): per joint review — (a) bundle-scope counts in section 3 reflect the full pinned bundle (489 manifest-covered files, 64 expected-outcome cases); (b) the Correctover checker is described as a standalone package-independent check that operates without importing the CCS verifier package; (c) wording aligned for the public repository. Vectors, the eight composition outcomes, artifact pins, and all product boundaries are unchanged.
**Parties:**
- **EMILIA Protocol, Inc.** — Iman Schrock (`team@emiliaprotocol.ai`)
- **Correctover** — Guigui Wang (`wangguigui@correctover.com`)

---

## 1. Question

In the EMILIA standalone composition harness at commit `995d803`, can the pinned
CCS v1.4 L1 conformance receipt (`upstream-01-allow`, 30 fields, Ed25519 over JCS)
be **independently verified by a party that imports none of the issuer's code**, then
**bound to one exact EMILIA action and one relying-party admission domain**, with the
current authority state in the harness and provider entry kept separate and closed
(fail-closed; at-most-one applies to the counting provider entry, not to a physical
effect)?

**Answer: yes, for this fixture** — established from bytes each side ran independently.

## 2. Pinned artifacts

| Artifact | Pin |
|---|---|
| CCS conformance bundle | `https://github.com/DSHCorrectover/ccs-conformance-vectors` |
| Bundle commit | `a3503b2bc48922f92a28c372003885a0831da02b` |
| Bundle manifest sha256 | `3e77eae3045eb2bc824c52b8d022b75029beaf56623841ce7c035a99e65a2ddd` |
| EMILIA standalone harness | `https://github.com/emiliaprotocol/emilia-protocol` |
| Harness commit | `995d80367f99601bb16509c6c89a5f9e72c74885` |
| Harness dir | `conformance/composition/ccs-v14-aeb-github-v0.1/` |
| Standalone entrypoint sha256 | `c809c257348ab635819d1cffe33f7051d285b1ffe5d06903dc2989b033ca514a` |
| Upstream ALLOW receipt sha256 | `889855dc9fcebdb642bd7e0f369651015781b4c004227aef510feb1fb7cb4361` |
| Reference report sha256 | `a197793b835f00f1bd350f29101a47b234ea63240df29a6a372e350ad599c9d4` |
| Reference vectors sha256 | `3f61bc9eb2ce3d2d1e6a771aa94d2be1cfb964eac93babe3c5334f883ab72cd7` |
| Composition results digest | `sha256:ad2256f5c22f0c8c6a185f7ce5675955db8019789bd42b04bbd47ab5227166f6` |
| Receipt public-key fingerprint | `26a02d86f5d0a10f` (CCS public deterministic conformance seed key) |

The standalone runner requires only Node.js >= 20.19 and imports only Node built-ins;
the six-file handoff has no `node_modules` and no repository parent at run time.

## 3. EMILIA-side verification (performed by EMILIA)

EMILIA pinned commit `a3503b2` and ran the published v1.4 bundle in a fresh environment:

- The manifest covered all **489** non-manifest vector files in the pinned bundle.
- The standalone package-independent Python checker classified all **64** expected-outcome
  conformance cases as expected.
- Regenerating the vectors reproduced the committed bundle **byte-for-byte**.
- EMILIA also pinned the published CCS v1.4 specification text used for comparison
  (153,156 bytes, sha256 `fbac2a025f11baec104687ee04ba5c9fb0dad1b5bbb5ad38494965565a977cd3`).
  That pin **anchors the specification version used for comparison**; the pin itself
  does not validate the bundle, and it is not a claim of full specification conformance
  or of completed composition.

## 4. Correctover-side verification (performed by Correctover)

Correctover ran the EMILIA handoff as an external verifier — fresh isolated directory,
no repository checkout, no `node_modules`, Node v22:

- `node run.standalone.mjs --check`: **all eight cases passed, exit 0.**
- EMILIA's own Node test harness: **2/2**, including the audit that the runner imports
  only Node built-ins.
- Hashes lined up: entrypoint `c809c257…` matches the manifest; upstream receipt
  `889855dc…`; reference report `a197793b…` and vectors `3f61bc9e…` match the manifest
  support files.
- The produced `results_digest` was
  `sha256:ad2256f5c22f0c8c6a185f7ce5675955db8019789bd42b04bbd47ab5227166f6`,
  **byte-identical to `report.reference.json`**.
- Correctover then re-verified the receipt with the **standalone package-independent**
  Python check — standard library plus `cryptography` plus JCS (JSON Canonicalization
  Scheme), operating **without importing the CCS verifier package** and with zero lines
  of EMILIA code: 30 fields, 64-byte Ed25519 signature,
  32-byte key, 1221-byte JCS signing input → **valid**.
- Two negative controls — a flipped signature byte, and the verdict changed from
  `allow` to `deny` — were **both correctly rejected**.
- The closing detail: the receipt's public-key fingerprint `26a02d86f5d0a10f` is the
  CCS public deterministic conformance seed key. EMILIA's harness pins this key;
  Correctover's verifier validated the same signed receipt bytes against it. **Both
  parties independently verified the same bytes under the public deterministic
  conformance key. That establishes fixture integrity, not a production identity
  chain.**

Correctover re-ran the same handoff on 2026-08-29 after fetching the six files
directly from harness commit `995d803`; all file sha256 values matched the manifest
and the eight cases produced the identical results digest.

## 5. The eight composition outcomes

| # | Case | Expected | Result |
|---|---|---|---|
| 1 | CCS-V1.4-PUBLIC-VECTOR-PIN | byte-pinned vector, valid Ed25519 + companion hashes | pass |
| 2 | CCS-ALLOW + EMILIA authority | counting provider entered exactly once | pass |
| 3 | Receipt tampering | refused, zero provider entries | pass |
| 4 | Wrong relying party | refused, zero provider entries | pass |
| 5 | Stale status | refused, zero provider entries | pass |
| 6 | Action substitution (issue 538 → 539) | refused, zero provider entries | pass |
| 7 | CCS ALLOW with absent EMILIA authority | refused, zero provider entries | pass |
| 8 | Lost provider response | `INDETERMINATE`, blind retry blocked, provider entered at most once | pass |

The valid composition enters the provider exactly once; the five hostile/boundary
cases enter it zero times; `INDETERMINATE` blocks blind retry and still enters the
provider at most once. All provider references in this section are to the counting
test stub in the harness.

## 6. Product boundaries (authoritative)

1. **CCS supplies machine-policy evidence; it is never execution authority.** A
   verified CCS ALLOW receipt does not by itself prove what the provider ultimately
   executed. Provider entry additionally requires a current AEB evaluation for the
   exact action and a separate relying-party authorization decision.
2. **The GitHub-shaped receipt in the fixture is EMILIA-authored and CCS-source-
   compatible; it is not a Correctover certification or a Correctover-issued upstream
   vector.** Both receipts use the public deterministic conformance key
   (`26a02d86f5d0a10f`), which is test material and not a production trust root. The
   provider in the harness is a counting test stub; no live GitHub issue or external
   account is changed. At-most-one provider entry is not exactly-once physical effect;
   an `INDETERMINATE` result requires authenticated reconciliation, and blind retry
   remains prohibited.

## 7. Verdict

In this harness, the pinned CCS v1.4 L1 conformance receipt **can be independently
verified** by a party that imports none of the issuer's code, and **can be bound to
one exact EMILIA action** (`github.issue-update.1`, CAID
`caid:1:github.issue-update.1:jcs-sha256:hcpVY2uUgF1xTGcDoqhuSzYB2avddWtiPXEQVE6p-kk`)
**and one relying-party admission domain** (`rp:emilia-github-gate`), with the
current authority state in the harness and provider entry separate and closed
(at-most-one concerns the counting provider entry, not a physical effect). Both
sides reached this verdict from bytes they ran themselves. This is a fixture-
integrity result under the public deterministic conformance key, not a production
identity chain.

## 8. Signatures

This report is jointly authored. It is not final or jointly approved until both
parties approve the exact bytes.

- Iman Schrock — EMILIA Protocol, Inc. — _________________ (date)
- Guigui Wang — Correctover — _________________ (date)
