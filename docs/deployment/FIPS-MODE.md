<!-- SPDX-License-Identifier: Apache-2.0 -->
# Running EMILIA Protocol against a FIPS 140-3 validated OpenSSL provider

**Status:** deployment guidance. The runtime module is `packages/verify/src/fips-mode.ts` (EP-FIPS-MODE-v1); its tests are `packages/verify/fips-mode.test.ts`.

## The one sentence this earns

A deployment configured as described here, running on a provider covered by a CMVP certificate that lists the algorithms it actually uses, earns exactly this:

> FIPS-based algorithms, with a validated-provider deployment mode.

It does not earn "FIPS compliant" and it does not earn "FIPS validated". Those are not stylistic preferences, they are two different facts:

- Validation is a property of a **cryptographic module**, awarded by the NIST/CCCS Cryptographic Module Validation Program (CMVP) to a specific module at a specific version on specific platforms against a published security policy. EP is an application that calls a module. Applications do not get certificates.
- Compliance is a property of a **system**, determined by an assessor against a policy regime (FedRAMP, FISMA, CMMC, a customer's own control catalogue). No configuration file makes that determination.

EP is not FIPS compliant and not FIPS validated. No EP package, receipt, or deployment carries a CMVP certificate. What the deployment mode gives you is a defensible, testable statement about which algorithms run inside a validated module's boundary and which do not, plus a runtime that refuses by name when it cannot tell.

**This is enforced repo-wide.** `scripts/check-language-governance.ts` scans `docs/`, `content/`, `app/`, `sdks/`, `conformance/`, `standards/staged/`, `packages/verify/src/`, `README.md`, and `openapi.yaml`, and fails the build on the compliant/validated/certified forms of the claim unless the line negates them. Run it with `node scripts/check-language-governance.js`.

## Read this before anything else: two traps

### Trap 1: the flag can be on while nothing works

`crypto.getFips() === 1` is not evidence that a FIPS provider is loaded. **Measured on this repo's dev host** (Node v26.5.0, statically linked OpenSSL 3.6.3, no `fipsmodule.cnf`):

```
$ node -e 'const c=require("crypto"); c.setFips(true);
           console.log("getFips=",c.getFips());
           try{c.createHash("sha256").update("x").digest("hex")}catch(e){console.log(e.code)}'
getFips= 1
ERR_OSSL_EVP_UNSUPPORTED
```

`setFips(true)` succeeded, `getFips()` returns 1, and then **every** EVP operation fails, SHA-256 included. With OpenSSL 3 these calls only add `fips=yes` to the default property query; they do not install, load, or initialise a provider. A monitoring dashboard that reported "FIPS mode: on" from the flag alone would be reporting a dead process as a hardened one.

This is why `assertClassicalFips()` requires the flag **and** a live digest probe, and why the posture carries `openssl_operational` separately from `fips_status`.

### Trap 2: Ed25519 can succeed while being outside the certificate

EdDSA is an approved signature algorithm under **NIST FIPS 186-5**, effective 2023-02-03. That is a statement about the standard, not about any particular module. Whether Ed25519 is inside a given provider's validated boundary is a per-certificate fact, and for upstream OpenSSL the answer is no.

Worse, the code and the certificate disagree in the dangerous direction on OpenSSL 3.0.x: the provider **registers Ed25519 with property `fips=yes`**, so the operation succeeds under an active FIPS mode, while the certificate governing that exact module lists Ed25519 as non-Approved. Nothing errors. You simply sign outside the boundary.

Because no runtime check can settle this, EP treats boundary membership as an **operator declaration** read off the security policy PDF, and refuses Ed25519 under an active FIPS mode until it is declared.

## Algorithm boundary tables

Every row below was read from the primary source named in it. Rows are labelled **VERIFIED** (the cited document was retrieved and read) or **REPORTED** (secondary or inferential).

### Upstream OpenSSL certificates

| Certificate | Module | Version(s) | Standard | Validated | Ed25519 / Ed448 | Label |
|---|---|---|---|---|---|---|
| [#4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282) | OpenSSL FIPS Provider (The OpenSSL Project) | 3.0.8, 3.0.9 | FIPS 140-2 | 2022-08-23 | **Non-Approved** (Table 8) | VERIFIED |
| [#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985) | OpenSSL FIPS Provider (The OpenSSL Project) | 3.1.2 | FIPS 140-3 | 2025-03-11 | **Non-Approved, Not Allowed** | VERIFIED |
| none | any OpenSSL 3.4.x / 3.5.x upstream provider | 3.4, 3.5 | - | **no certificate exists** | n/a | VERIFIED |

- #4282's security policy states the non-Approved entries "shall not be used when operating in the FIPS Approved mode of operation", and its revision history records "Updated to move EdDSA to the non-Approved mode - 26 January 2023". VERIFIED (`140sp4282.pdf`).
- #4985's Table 6 (Approved Algorithms, CAVP cert A3548) does not contain EdDSA; Ed25519 and Ed448 appear under "Non-Approved, Not Allowed Algorithms" alongside X25519, X448, and Triple-DES. VERIFIED (`140sp4985.pdf`).
- A CMVP search restricted to `ModuleName=OpenSSL, Standard=140-3, Status=Active` returned 55 certificates, of which **#4985 is the only one whose vendor is The OpenSSL Project**. VERIFIED.
- A newer upstream submission ("The OpenSSL Corporation - OpenSSL FIPS Provider - FIPS 140-3", Comment Resolution) appears on the Modules In Process list; no version number is stated on the row. REPORTED.
- HP #5475 and Splunk #5444 are rebrands of the 3.1.2 module with identical policy text, so they carry the same Ed25519 placement. VERIFIED.

### Approved in both upstream certificates

SHA2-256 (FIPS 180-4), HMAC-SHA2-256 (FIPS 198-1), ECDSA KeyGen/KeyVer/SigGen/SigVer including P-256 (FIPS 186-4), RSA KeyGen/SigGen/SigVer (FIPS 186-4), AES including GCM/GMAC (SP 800-38D), and the SP 800-90A Rev.1 DRBGs (Counter / Hash / HMAC). VERIFIED from the approved-algorithm tables of #4282 and #4985.

### Whether the code exposes Ed25519 under `fips=yes`

Read from `providers/fips/fipsprov.c` at each release tag; the file defines `FIPS_DEFAULT_PROPERTIES = "provider=fips,fips=yes"` and `FIPS_UNAPPROVED_PROPERTIES = "provider=fips,fips=no"`.

| OpenSSL | `PROV_NAMES_ED25519` registered with | Ed25519 usable under `fips=yes`? | Label |
|---|---|---|---|
| 3.0.8, 3.0.9, 3.0.17 | `FIPS_DEFAULT_PROPERTIES` | **yes - and outside cert #4282** | VERIFIED |
| 3.1.0 - 3.3.5 | `FIPS_UNAPPROVED_PROPERTIES` | no, fetches fail | VERIFIED |
| 3.4.0, 3.5.0 | `FIPS_DEFAULT_PROPERTIES` | yes, and no certificate covers these yet | VERIFIED |

The change landed in commit [`5f04124aab4a`](https://github.com/openssl/openssl/commit/5f04124aab4a) ("Add EDDSA FIPS self tests", PR [#22112](https://github.com/openssl/openssl/pull/22112), merged 2024-08-14), first shipped in **OpenSSL 3.4.0**. VERIFIED. There is no `CHANGES.md` entry announcing it; cite the commit, not the changelog. VERIFIED (negative claim, scope: `CHANGES.md` on the `openssl-3.4` and `openssl-3.5` branches, keywords `186-5`, `eddsa`, `ed25519`, `ed448`).

Do not use `OSSL_PROVIDER-FIPS(7)` as a boundary source. The 3.0 page lists `X25519, see EVP_SIGNATURE-ED25519(7)` under asymmetric signatures, which is a naming bug in the POD. VERIFIED.

### Distribution providers: separate certificates, different answers

None of these inherits #4282 or #4985. Each is separately validated with its own version string and its own algorithm tables.

| Certificate | Module | Version | Validated | EdDSA Approved? | Label |
|---|---|---|---|---|---|
| #4857 | Red Hat Enterprise Linux 9 OpenSSL FIPS Provider | `3.0.7-395c1a240fbfffd8` | 2024-10-29 | **no** (absent entirely) | VERIFIED |
| #4794 | Canonical Ubuntu 22.04 OpenSSL Cryptographic Module | `3.0.5-0ubuntu0.1+Fips2.1` | 2024-09-11 | **no** (absent entirely) | VERIFIED |
| #5115 | Canonical Ubuntu 24.04 OpenSSL Cryptographic Module | `3.0.13-0ubuntu3+Fips1` | 2026-01-06 | **no** (absent entirely) | VERIFIED |
| #5021 | Amazon Linux 2023 OpenSSL FIPS Provider | `3.0.8-d694bfa693b76001` | 2025-05-26 | **no** | VERIFIED |
| #5438 | Amazon Linux 2023 OpenSSL FIPS Provider | `3.2.2-799901ad7ab41d45` | 2026-07-27 | **no** | VERIFIED |
| #5242 | AWS OpenSSL FIPS Module | - | 2026-04-14 | **no** | VERIFIED |
| **#5116** | Ctrl IQ / Rocky Linux 9 OpenSSL FIPS Provider | `Rocky9.20250210` | 2026-01-06 | **yes** - EDDSA KeyGen/SigGen/SigVer, CAVP A6328, FIPS 186-5 | VERIFIED |
| **#5132** | Chainguard FIPS Provider for OpenSSL | - | 2026-01-14 | **yes** - EDDSA KeyGen/KeyVer/SigGen/SigVer, CAVP A6676, FIPS 186-5; self-tests name Ed25519 and Ed448 | VERIFIED |
| **#5373** | TuxCare OpenSSL FIPS Provider | `3.2.2-f9f9d133a30b6eb5` | 2026-07-07 | **yes** - EDDSA KeyGen/SigGen/SigVer, CAVP A7098, curves ED-25519 and ED-448, FIPS 186-5 | VERIFIED |
| #5200, #5207, #5229, #5257, #5384 | Rocky Linux 8, Forescout, Xage, NTT DATA, Nasuni | - | - | EDDSA rows present in the approved tables | REPORTED (row presence checked, table placement not individually inspected) |

Security policies live at `https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp<CERT>.pdf`.

**Deployment consequence.** If your receipts are Ed25519 and you need them inside a validated boundary today, RHEL 9, Ubuntu 22.04/24.04, and Amazon Linux 2023 will not give you that. Rocky Linux 9 (#5116), Chainguard (#5132), and TuxCare (#5373) will. The alternative is to move issuer signing to ES256 (ECDSA P-256), which is Approved in every certificate above; see [`EP-CRYPTO-PROFILE`](../EP-CRYPTO-PROFILE.md) for the `fips` profile and its remaining P-256 issuer-verify gap.

### ML-DSA (FIPS 204)

**Implemented is not validated, and here the gap is total.**

- OpenSSL **3.5.0** implements ML-DSA: `CHANGES.md` records "Add ML-DSA as specified in FIPS 204", and `providers/fips/fipsprov.c` at tag `openssl-3.5.0` registers `PROV_NAMES_ML_DSA_44/65/87` with `FIPS_DEFAULT_PROPERTIES`. VERIFIED.
- **No OpenSSL-derived module is CMVP-validated for ML-DSA.** A sweep of 31 security policies covering essentially every OpenSSL-derived module on the Active FIPS 140-3 list found zero occurrences of "ML-DSA". VERIFIED (negative claim; scope: the 31 certificates enumerated in the sweep, as of 2026-08-16).
- **EP does not use OpenSSL for ML-DSA at all.** EP's backend is `@noble/post-quantum` v0.7.0, a pure-JavaScript FIPS 204 implementation loaded by `packages/verify/src/pq-hybrid.ts` and `packages/verify/src/pq-signature-agility.ts`. It is not a validated module, it is inside no certificate, and running it in a FIPS-mode process changes none of that.

## Which EP operations are OpenSSL-backed

| EP operation | Implementation | Inside a validated boundary? |
|---|---|---|
| Receipt / evidence-record digests, Merkle leaf and node hashing (`sha256()` in `packages/verify/src/index.ts`) | `node:crypto` `createHash('sha256')`, so OpenSSL-backed | Yes, when a validated provider is active. SHA2-256 is Approved in every certificate above. |
| Ed25519 issuer signing and receipt verification (`crypto.sign` / `crypto.verify` in `index.ts` and `pq-signature-agility.ts`) | `node:crypto`, so OpenSSL-backed | **Provider-dependent.** See the certificate tables. Not in #4282 or #4985. |
| WebAuthn Class-A signoff verification, ES256 (`crypto.verify('sha256', ...)` in `index.ts`) | `node:crypto`, so OpenSSL-backed | Yes. ECDSA P-256 is Approved in every certificate above. |
| JCS-style canonicalization (`packages/verify/src/strict-json.ts`) | Pure JavaScript string construction, **no cryptography at all** | Not applicable. It produces the bytes that are then hashed by OpenSSL. |
| ML-DSA-65 signing and verification | `@noble/post-quantum`, pure JavaScript | **No, and never.** Outside every module boundary. |
| Browser / edge verification (`packages/verify/src/web.ts`) | W3C Web Crypto (`globalThis.crypto.subtle`) | Out of scope. This is a browser or edge runtime, not a Node process with an OpenSSL provider. |

The canonicalization row matters: a reviewer sometimes assumes a JSON canonicalizer must contain a hash. It does not. `strict-json.ts` contains no reference to any crypto API; it emits a string, and `index.ts` hashes that string through `node:crypto`.

## Configuring the runtime

### 1. Get a validated provider onto the host

Pick a distribution whose OpenSSL FIPS provider carries a certificate covering the algorithms in your profile (see the tables above). Install its FIPS provider package and generate the module configuration:

```bash
openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf \
  -module /usr/lib/ossl-modules/fips.so
```

`fipsinstall` runs the module's self-tests and writes the integrity MAC. If you build the provider from source, understand that you are then running a module that is **not** the validated binary: certificates attach to a specific build on a specific platform.

### 2. Activate the provider in `openssl.cnf`

```ini
config_diagnostics = 1
openssl_conf = openssl_init

.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```

Keep `base` activated. The FIPS provider does not supply encoders and decoders, so key loading breaks without it. REPORTED (standard OpenSSL 3 guidance; not re-read from `fips_module(7)` when this document was written). Module and config paths vary by distribution: take them from your provider package, not from this example.

### 3. Point Node at it

Node exposes the FIPS support of the OpenSSL it links; **Node is not itself FIPS validated**, and the Node documentation says so directly. With OpenSSL 3 the requirement is provider-shaped, not build-flag-shaped: a `fips` provider must be installed, configured, activated in Node's library context, and selected via `default_properties = fips=yes`.

```bash
OPENSSL_CONF=/usr/local/ssl/openssl.cnf \
OPENSSL_MODULES=/usr/lib/ossl-modules \
node --force-fips server.js
```

- `--enable-fips` enables FIPS mode at startup; with OpenSSL 3 a provider named `fips` must be available and initialise successfully. VERIFIED (Node CLI docs).
- `--force-fips` does the same and prevents script code from turning it off. Prefer this in production: it removes `crypto.setFips(false)` as an in-process downgrade path.
- `crypto.getFips()` reports whether the default property query includes `fips=yes`. It does **not** establish that a provider is loaded or validated. VERIFIED (Node crypto docs, and reproduced in trap 1 above).

A stock Node binary with statically linked OpenSSL 3 ships no FIPS provider module and no `fipsmodule.cnf`, so `--enable-fips` will not find a provider. In practice, use a Node built with `--shared-openssl` against a distribution OpenSSL whose provider carries one of the certificates above. REPORTED (the Node docs state the four requirements; they do not state this consequence in these words).

### 4. Containers

Use a base image whose OpenSSL provider is the validated one, and do not rebuild the provider in the image. Rocky Linux 9 (#5116), Chainguard (#5132), and TuxCare (#5373) images give you Ed25519 inside the boundary; RHEL 9, Ubuntu, and Amazon Linux images do not. Bake `OPENSSL_CONF`, `OPENSSL_MODULES`, and `--force-fips` into the image rather than leaving them to the orchestrator, so a missing environment variable cannot silently drop the deployment out of FIPS mode.

Verify the result inside the running container rather than trusting the Dockerfile:

```bash
node -e 'import("@emilia-protocol/verify/fips-mode").then(m =>
  console.log(m.formatFipsPosture(m.getFipsPosture({ ed25519InValidatedBoundary: true }))))'
```

## Using the runtime posture module

### Integration status

The module and its tests are in the tree and green (`npx tsx --test packages/verify/fips-mode.test.ts`), and the package wiring is complete: `@emilia-protocol/verify/fips-mode` resolves (tsconfig include, `exports` entry, `files` entry, and the root shim all present; verified by import from `examples/fips-deployment/posture-check.mjs`).

The custody signing path consults `checkOperationPolicy()` at issuance. See "Consult points in the custody signing path" below for the exact call sites, what a denial looks like, and the boundary this does and does not establish.

A runnable posture reporter and a Rocky Linux 9 reference container live in `examples/fips-deployment/`.

### Report the posture at startup

```js
import { getFipsPosture, formatFipsPosture, assertClassicalFips }
  from '@emilia-protocol/verify/fips-mode';

// Declare, from your certificate, whether EdDSA is Approved in your provider.
const posture = getFipsPosture({ ed25519InValidatedBoundary: true });
console.log(formatFipsPosture(posture));

const classical = assertClassicalFips({ posture });
if (!classical.ok) console.warn(`EP: classical FIPS posture refused: ${classical.reason}`);
```

`assertClassicalFips()` returns `ok: true` only when the flag is active **and** an actual SHA-256 digest completed. Its named refusals are `fips_mode_inactive`, `fips_status_unavailable`, `openssl_provider_not_operational`, `openssl_provider_unprobed`, and `malformed_posture`.

### The one-line adoption at a call site

`fips-mode.ts` decides; it never wraps a signing or verification call. Issuance and verification sites consult it and refuse on `permitted === false`:

```js
import { checkOperationPolicy } from '@emilia-protocol/verify/fips-mode';

const policy = checkOperationPolicy(alg, posture, { allow_unvalidated_mldsa: false });
if (!policy.permitted) return { verified: false, reason: policy.reason };
```

Capture `posture` once at startup and pass it in. Probe results are memoized per observed FIPS status, so a per-operation call does not re-run an Ed25519 key generation, but passing an explicit posture is clearer and makes the decision reproducible in logs.

### The ML-DSA acknowledgment flag

ML-DSA runs in pure JavaScript. Under an active FIPS mode, and under an indeterminate one, EP refuses it by default with reason `mldsa_implementation_unvalidated`. To run it anyway, the deployment must say so explicitly:

```js
checkOperationPolicy('ML-DSA-65', posture, { allow_unvalidated_mldsa: true });
```

Only the literal `true` acknowledges; `'true'`, `1`, and `{}` do not. Permission is never a validation claim: the result still carries `validated_module: false` and `boundary: 'javascript_outside_any_validated_module'`.

On an ordinary non-FIPS deployment (`fips_status: 'inactive'`, which is what EP's own test suite runs under) the acknowledgment is not required and ML-DSA is permitted, so adopting `checkOperationPolicy` at existing call sites does not change their behavior.

### Decision table

| Algorithm | FIPS status | Provider live | Ed25519 works | Boundary declared | Flag | Result |
|---|---|---|---|---|---|---|
| any OpenSSL-backed | inactive / unavailable | - | - | - | - | permitted |
| any OpenSSL-backed | active | no | - | - | - | `openssl_provider_not_operational` |
| any OpenSSL-backed | active | unprobed | - | - | - | `openssl_provider_unprobed` |
| SHA-256, ES256 | active | yes | - | - | - | permitted |
| Ed25519 | active | yes | no | - | - | `ed25519_unavailable_in_provider` |
| Ed25519 | active | yes | unprobed | - | - | `ed25519_provider_support_unknown` |
| Ed25519 | active | yes | yes | declared outside | - | `ed25519_outside_validated_boundary` |
| Ed25519 | active | yes | yes | undeclared | - | `ed25519_boundary_undeclared` |
| Ed25519 | active | yes | yes | declared inside | - | permitted |
| ML-DSA-65 | inactive | - | - | - | any | permitted |
| ML-DSA-65 | active / unavailable | - | - | - | absent | `mldsa_implementation_unvalidated` |
| ML-DSA-65 | active / unavailable | - | - | - | `true` | permitted |
| outside the registry | any | - | - | - | - | `unknown_algorithm` |

Every cell is exercised by `packages/verify/fips-mode.test.ts` against injected posture objects, so the matrix is deterministic on FIPS and non-FIPS hosts alike.

## Consult points in the custody signing path

`checkOperationPolicy()` is consulted at three issuance-time call sites, all gated on the same existing config surface: `EP_FIPS_REQUIRED=true`, read through `getKeyCustodyConfig().fipsRequired` (`lib/env.ts`). This is the deployment's declaration that it runs under a FIPS posture; it is a different flag from `EP_KEY_CUSTODY_MODE` (which selects local-dev/env/kms/hsm custody) and from `EP_GOV_STRICT`, and all three compose independently.

**With `EP_FIPS_REQUIRED` unset or `false`, the consult does not run at all** -- `getFipsPosture()` and `checkOperationPolicy()` are never called, so an unconfigured deployment's signing path is byte-identical to the one that existed before this consult was wired in. This is pinned by a regression test at each call site (see below), not just asserted in this doc.

**With `EP_FIPS_REQUIRED=true`**, each call site reads the live process posture (`getFipsPosture()`, no options -- see "Report the posture at startup" above for declaring `ed25519InValidatedBoundary` at process startup if your deployment needs Ed25519 inside an active FIPS mode) and consults `checkOperationPolicy()` for the algorithm about to sign, BEFORE the provider-side signing call. A denial throws a named error identifying both the general refusal and the fips-mode module's own reason, of the form:

```
fips_policy_denied (Ed25519: ed25519_boundary_undeclared)
```

Nothing throws on malformed caller input at these sites -- the honesty/validation gates already in place (drift detection, required-argument checks) are unchanged; this consult adds exactly one more named, fail-closed refusal ahead of the signing effect, driven entirely by the deployment's own declared posture, never by data an untrusted caller supplied.

### The three call sites

| Call site | File | Algorithm(s) checked | Runs before |
|---|---|---|---|
| Commit issuance, classical leg | `lib/commit.ts`, `issueCommit()` (via `consultFipsIssuancePolicy`, resolved before the `custodySigner` / env-key signing branch) | `Ed25519` | `custodySigner.sign()` or the built-in `signPayload()` fallback |
| Commit issuance, hybrid proof | `lib/commit-hybrid.ts`, `createCommitHybridProof()` (exported `consultFipsIssuancePolicy`, checked per required algorithm) | `Ed25519`, `ML-DSA-65` | `signer.signSet()` |
| Execution-integrity attestation | `lib/execution/integrity.ts`, `bindExecution()` (via `consultFipsIssuancePolicy`) | `Ed25519` | the executor's `signer.sign()` |

`ML-DSA-65` is checked without an `allow_unvalidated_mldsa` acknowledgment at these sites: no config surface for that acknowledgment exists yet, so under `EP_FIPS_REQUIRED=true` with a genuinely active FIPS posture, the hybrid leg refuses by default with `mldsa_implementation_unvalidated` -- the fail-closed default the module itself documents, not a gap in the wiring. A deployment that wants ML-DSA-65 permitted under an active FIPS posture needs a call-site change to thread that acknowledgment through, which this consult deliberately does not add on its own.

Each call site accepts a test-only `fipsPosture` (or, in `lib/commit.ts`'s internal helper, `posture`) parameter so its regression and denial paths can be exercised with an injected posture object against the REAL `checkOperationPolicy()`, without needing a genuinely FIPS-active Node process. Production callers never pass it; the live process posture is read automatically.

### The honest boundary

This consult enforces the OPERATOR'S DECLARED FIPS posture (`EP_FIPS_REQUIRED=true` plus, where relevant, the operator's own `ed25519InValidatedBoundary` declaration read off their CMVP certificate). It is not FIPS validation and it does not make EP FIPS compliant -- see "What this earns" and "What to say, and what not to say" above; nothing about wiring `checkOperationPolicy()` into more call sites changes that ceiling.

The software ML-DSA-65 leg still does not satisfy `kms`/`hsm` custody requirements. `assertProductionKeyCustody()` (`lib/key-custody.ts`) only ever recognizes `EP_KEY_CUSTODY_MODE=kms` or `hsm` as satisfying government/production custody, and it evaluates the classical signer's mode only -- there is no ML-DSA custody mode for it to bless, because EP's ML-DSA-65 backend is software-held (`@noble/post-quantum`, pure JavaScript) at every custody mode, including `kms` and `hsm`. A hybrid proof passing the FIPS operation-policy consult is a statement about the declared posture permitting the operation to proceed; it is never a statement that the PQ leg's key custody meets the classical leg's KMS/HSM bar. Those are two different boundaries and this consult only speaks to the first.

### Same pattern, other program partitions (not wired here)

The following call sites are queued to gain the identical opt-in consult, same config surface, same before-the-signing-effect placement, same no-posture-no-change regression discipline. They are listed here as a map of the intended rollout, not implemented in this document's change:

- Status issuance (`packages/verify/src/revocation.ts` / `lib/revocation/*` signing paths)
- Receipt-program issuance (`packages/issue/src/hybrid-issuance.ts` and the trust-receipt issuer)
- Remedy-program signing sites
- Health-program signing sites (`lib/health-program-integrity` family)

## What to say, and what not to say

Permitted, given the configuration above and a certificate that covers your algorithms:

- "EP runs on FIPS-based algorithms, with a validated-provider deployment mode."
- "Receipt hashing and ES256 signoff verification are serviced by the OpenSSL FIPS provider covered by certificate #NNNN."
- "ML-DSA is outside the validated boundary and is refused unless the deployment explicitly acknowledges that."

Not permitted, in any material, ever:

- "EP is FIPS compliant." EP is not FIPS compliant.
- "EP is FIPS validated" or "our receipts are FIPS certified." EP is not FIPS validated and not FIPS certified.
- "Ed25519 receipts are inside the validated boundary" without naming the certificate that says so. On the two upstream OpenSSL certificates, they are not.
- "ML-DSA is validated because it implements FIPS 204." Implementing a standard is not validation, and no OpenSSL-derived module is validated for ML-DSA.

## Related

- [`EP-CRYPTO-PROFILE`](../EP-CRYPTO-PROFILE.md) - the declared, fail-closed algorithm profile (`default` and `fips`) and the custody requirement.
- `packages/verify/src/pq-signature-agility.ts` - EP-SIG-AGILITY-v1, the closed `{Ed25519, ML-DSA-65}` registry.
- `scripts/check-language-governance.ts` - the repo-wide guard enforcing the claim boundary above.

*Certificate data and OpenSSL source references in this document were read from NIST CSRC and the OpenSSL repository on 2026-08-16. CMVP status changes; re-check before quoting a certificate in an outbound claim.*
