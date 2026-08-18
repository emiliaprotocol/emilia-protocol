<!-- SPDX-License-Identifier: Apache-2.0 -->
# The two post-quantum boundary items code cannot close

**Status:** decision document. It exists because the hybrid signature program in
[`docs/protocol/pq-hybrid-program.md`](../protocol/pq-hybrid-program.md) is
finished as an engineering matter and two of its named boundaries are not
engineering problems at all. One is a deployment decision. The other is a
purchase.

The program's own closing sentence names them (`docs/protocol/pq-hybrid-program.md:286`):

> every hybrid profile is OPT-IN, none is a deployment default, the software
> ML-DSA leg does not satisfy kms/hsm custody, and nothing here is FIPS validated.

Writing more code does not move any clause in that sentence. This document says
exactly what would, what it costs, and who decides.

Every claim below about EP behaviour cites the file and line it was read from,
in this session, against the working tree. Claims about the outside world are
labelled VERIFIED (primary source retrieved and read) or ESTIMATE.

---

## 1. Deployment path: what must be true to run the post-quantum leg on

### 1.1 The config surface, named from source

The first thing to understand is that **there is no environment variable that
turns the post-quantum leg on.** A repository-wide search for `EP_HYBRID`,
`EP_PQ_`, `EP_MLDSA`, and `EP_ML_DSA` across every `.ts`, `.js`, `.mjs`, and
`.md` file outside `node_modules` returns nothing. The switch is a boot-time
code path, not configuration.

What environment variables do exist gate the custody seam the leg hangs off:

| Variable | Read at | What it does for the PQ leg | EP's shipped default |
|---|---|---|---|
| `EP_KEY_CUSTODY_MODE` | `lib/env.ts:420` | Must be `kms` or `hsm`. `resolveIssuerSigner()` returns the registered signer only for those two modes (`lib/key-custody.ts:419-431`) and returns `null` for `local-dev`/`env` (`lib/key-custody.ts:437`). The hybrid block in `issueCommit()` runs only when a signer was resolved AND it is a hybrid signer (`lib/commit.ts:611`). On `local-dev` the PQ leg is unreachable. | `local-dev` (`.env.example:70`) |
| `EP_KMS_KEY_ID` / `EP_HSM_KEY_ID` | `lib/env.ts:421` | Required whenever gov-strict or production is in effect; absent, `assertProductionKeyCustody()` refuses `missing_custody_key_id` (`lib/key-custody.ts:55-57`). | empty (`.env.example:71-72`) |
| `EP_GOV_STRICT` | `lib/env.ts:423` | Turns on the custody assertion. Note it is ORed with `isProduction()`, so a production deployment is gov-strict whether or not the flag is set. | `false` (`.env.example:64`) |
| `EP_FIPS_REQUIRED` | `lib/env.ts:422` | If `true`, the FIPS operation-policy consult runs before signing at three call sites. **This flag currently blocks the PQ leg rather than helping it.** See 1.3. | `false` (`.env.example:73`) |

The Gate-side profile is likewise not environment-driven. `hybrid_issuance` is a
config value handed to `resolveHybridReceiptProfile()` in
`packages/gate/src/hybrid-receipt-profile.ts`, and when the operator sets
nothing the default is **resolved from custody**, not fixed. See 1.2, which is
the part that decides whether EP's own deployment can turn the leg on at all.

**Turning the leg on is therefore, today, a code change**, of roughly this
shape, at process boot:

```js
import { registerCustodySigner } from './lib/key-custody.js';
import { hybridSigner, vaultTransitSigner, softwareMldsaSigner } from './lib/custody-signers.js';

registerCustodySigner(hybridSigner({
  classical: vaultTransitSigner({ vault, keyName, publicKeySpkiB64u }),
  pq: softwareMldsaSigner({ keyId: 'ep:key:pq#1', secretKey, publicKeyRawB64u }),
}));
```

That recipe is in the repository as a doc comment (`lib/custody-signers.ts:161-163`).
**It is not called anywhere in production code.** Every occurrence of
`registerCustodySigner(` in the tree outside `node_modules` and `dist` is either
its own definition (`lib/key-custody.ts`), a doc comment
(`lib/custody-signers.ts:23,161`), or a test (`tests/key-custody-signer.test.ts`,
`tests/commit-hybrid.test.ts`, `tests/guard-evidence-receipt-hybrid.test.ts`,
`tests/key-custody-hybrid.test.ts`, `tests/custody-signers.test.ts`,
`tests/commit.test.ts`). EP's own application has no boot registration path at
all, which means `EP_KEY_CUSTODY_MODE=kms` today would not enable the PQ leg, it
would throw `custody_signer_not_registered` (`lib/key-custody.ts:421-428`) and
refuse to issue.

### 1.2 The custody-resolved default, and why it closes the door on EP's own production

*(Read from the working tree on 2026-08-18. `describeHybridCustodyPosture()` in
`lib/key-custody.ts` and `resolveHybridIssuancePosture()` in
`packages/gate/src/hybrid-receipt-profile.ts` are landing in parallel with this
document, so they are cited by symbol name rather than line number. Re-read them
before quoting this section outward.)*

The issuance default is no longer a static `disabled`. `resolveHybridIssuancePosture()`
states the rule in three parts: an explicit `hybrid_issuance` setting wins in
both directions; with no explicit setting the default is `dual` when a
dual-signer custody signer is registered AND custody permits the post-quantum
leg; otherwise the default is `disabled` carrying the custody layer's named
reason.

The custody half of that is `describeHybridCustodyPosture()`, and it contains
the sentence that governs everything:

- **Below gov-strict**, a software-held post-quantum leg is permitted. That is
  the posture dev, test, and non-gov deployments actually run under, and those
  deployments get `dual` by default once a dual signer is registered.
- **Under gov-strict**, the post-quantum leg is refused with
  `pq_custody_not_permitted`, because the PQ leg's custody label is `'software'`
  and `CUSTODY_BOUNDARY_LABELS` is `['kms', 'hsm']`. A gov-strict deployment
  that requires kms/hsm custody must not be quietly handed a software-held PQ
  key, so it is not.

Now join that to `lib/env.ts:423`: `govStrict` is
`process.env.EP_GOV_STRICT === 'true' || isProduction()`. **EP's own production
reference deployment is gov-strict whether or not anyone sets the flag.**

The consequence is the single most decision-relevant fact in this document:

> EP's own production deployment cannot reach the custody-resolved `dual`
> default at all. Registering a hybrid signer there resolves to `disabled` with
> reason `pq_custody_not_permitted`. The only way in is an explicit operator
> `hybrid_issuance` setting, which the module itself frames as an operator
> attestation about custody they operate.

EP could not truthfully make that attestation today. There is no KMS or HSM
ML-DSA-65 signing path available to EP (`lib/key-custody.ts:138-143`). So the
honest options for EP's own deployment are exactly two: run the leg somewhere
that is not gov-strict (a staging or reference environment, with the
software-custody label stated), or wait for hardware custody. Overriding the
refusal in production and calling it deployed would be asserting a custody
boundary EP does not have, which is precisely the claim this repository is built
not to make.

### 1.3 The `EP_FIPS_REQUIRED` interaction, which is the second sharp edge

`consultFipsIssuancePolicy` checks `ML-DSA-65` at the hybrid call site **without
passing an acknowledgment**, because no config surface for that acknowledgment
exists (`docs/deployment/FIPS-MODE.md:283`). `mldsaPolicy()` arms the
acknowledgment requirement whenever `fips_status !== 'inactive'`
(`packages/verify/src/fips-mode.ts:529`), and that includes the
`'unavailable'` case, deliberately: an indeterminate posture never authorizes
(`packages/verify/src/fips-mode.ts:501-505`).

Consequence, stated plainly: **with `EP_FIPS_REQUIRED=true` on a host whose FIPS
status is anything other than verifiably inactive, the post-quantum leg refuses
by design** with `mldsa_implementation_unvalidated`
(`packages/verify/src/fips-mode.ts:540-547`). `consultFipsIssuancePolicy()`
then throws `createCommitHybridProof: refusing: fips_policy_denied (ML-DSA-65:
mldsa_implementation_unvalidated)` (`lib/commit-hybrid.ts:238-254`), and
`issueCommit()` wraps it as `commit hybrid signing failed: ...`
(`lib/commit.ts:618-623`). That is the fail-closed default the module documents,
not a bug. But it means the two flags are, right now, mutually exclusive at the
commit path: either `EP_FIPS_REQUIRED` stays false, or somebody threads the
acknowledgment through the call site.

### 1.4 Custody prerequisite

| Leg | What honest custody looks like | Status |
|---|---|---|
| Ed25519 (classical) | AWS KMS and GCP Cloud KMS do not sign Ed25519 at all (`lib/custody-signers.ts:11-16`). The real options are HashiCorp Vault Transit or a PKCS#11 HSM (`lib/custody-signers.ts:6-9`). | Adapters exist (`vaultTransitSigner`, `hsmEd25519Signer`, `externalSigner`); no EP deployment uses one. |
| ML-DSA-65 (post-quantum) | There is no KMS or HSM ML-DSA-65 signing path available to EP (`lib/key-custody.ts:138-143`, `lib/custody-signers.ts:25-31`). `createPqCustodySigner()` defaults `custody` to the literal `'software'` and treats any other value as an operator attestation (`lib/key-custody.ts:248,260-262`). The secret key lives in process memory. | Software only. |

Two further facts that are easy to miss:

- `assertProductionKeyCustody()` was **deliberately not extended** to bless the
  software PQ key. It reads `config.mode` and nothing else
  (`lib/key-custody.ts:41-59`); the reasoning is recorded at
  `lib/key-custody.ts:150-152`. A gov-strict deployment that requires kms/hsm
  custody still requires it, and the PQ leg does not satisfy it. Turning the leg
  on does not change that and must not be described as if it did.
- **There is no provisioning path for the ML-DSA secret key.** It is 4032 bytes
  (`lib/key-custody.ts:171`), and `softwareMldsaSigner()` takes it as a
  constructor argument (`lib/custody-signers.ts:127-131`). No environment
  variable, no secret-manager adapter, and no key-generation ceremony for it
  exists in the repository. Somebody has to design where that key comes from,
  how it is rotated, and how its public half is published for pinning. That work
  is not done and is not small.

### 1.5 Operational cost: sizes, payloads, and storage

The size ratio is the whole operational story. Constants read from
`packages/verify/src/pq-hybrid.ts:150-153` and mirrored at
`lib/key-custody.ts:170-172`:

| | Ed25519 | ML-DSA-65 | Ratio |
|---|---|---|---|
| Signature, raw bytes | 64 | 3309 | 51.7x |
| Signature, base64url characters | 86 | 4412 | 51.3x |
| Public key, raw bytes | 32 | 1952 | 61x |
| Public key, base64url characters | 43 | 2603 | 60.5x |
| Secret key, raw bytes | 32 (seed) | 4032 | - |

So a hybrid artifact carries roughly **4.4 KB of additional base64url signature
per artifact** over its classical twin, before JSON framing. Public keys are
pinned out of band by the relying party rather than carried on the artifact
(`lib/commit-hybrid.ts:120-143` shows the proof carrying `signatures` only, with
the public halves supplied separately as `CommitHybridVerificationKeys`), so the
2603-character public key is a distribution cost, not a per-artifact one.

**Storage: safe as is. No migration is required to turn the post-quantum leg on.**
This was verified against the live production database (project
`xmiiwehtivksdjbultym`, read-only queries against `information_schema`,
`pg_indexes`, and `pg_constraint`, run 2026-08-18), not inferred from repository
migrations:

- Every signature and key column in `public` is unbounded `text` with
  `character_maximum_length` NULL: `commits.signature`, `commits.public_key`,
  `protocol_events.signature`, `entities.public_key`, `authorities.public_key`,
  `entity_signing_key_history.public_key`, `approver_credentials.public_key_spki`,
  `approver_credentials.public_key_cose`, `release_lock_credentials.public_key_spki`
  and `.public_key_cose`, `arena_sessions.public_key`,
  `mobile_enrollments.public_key_spki` and `.platform_public_key`. Proof-bearing
  columns are `jsonb`: `continuity_claims.proofs`, `identity_bindings.proof_payload`,
  `receipts.merkle_proof`. VERIFIED.
- **No btree index exists over any signature or public-key VALUE.** The only
  indexed proof-ish columns are `works_authority_invitations.proof_digest` (a
  digest) and `zk_proofs.proof_id` (an id), both fixed size. VERIFIED. This
  matters more than it looks: a Postgres btree entry above roughly 2700 bytes
  fails at insert time, so a 4412-character ML-DSA-65 signature would have been a
  hard runtime failure had such an index existed. It does not.
- Exactly one length CHECK touches a key column:
  `mobile_executor_keys_public_key_check` caps `public_key` at 4096 characters
  with a base64url character-class pattern. VERIFIED.

**The one warning worth carrying forward.** That 4096-character cap is
comfortable for an ML-DSA-65 public key (2603 characters) and **would reject an
ML-DSA-65 signature by 316 characters**. Nobody should copy the convention onto
a future signature column. The design rule: **a length cap sized for keys is not
valid for post-quantum signatures. Any new signature column must be unbounded
`text`, or capped no lower than 8192.**

EP's highest-traffic hybrid profile sidesteps the question entirely. The
`EP-COMMIT-HYBRID-v1` proof is detached: it is returned to the issuer as
`hybrid_proof` and is deliberately not written to the `commits` table, so the
profile needs no column, no migration, and no change to the DB contract
(`lib/commit-hybrid.ts:23-26`, and the same statement at the call site,
`lib/commit.ts:607-609`). Verified against both files.

### 1.6 Verification prerequisite for anyone consuming those receipts

A hybrid artifact is not a v1 artifact with an extra field. It carries its own
`@version`, and deployed v1 verifiers refuse it on the version marker before
inspecting any signature (`packages/issue/src/hybrid-issuance.ts:39-48`). That
is the intended outcome, and it means every consumer must be moved deliberately.

- **Server-side JavaScript, Python, and Go can verify it.** Verification parity
  exists in three languages: the JS verifiers, a Python port (`conformance/py`)
  and a Go port (`packages/go-verify` plus `conformance/go` with a live CIRCL
  backend), per `docs/protocol/pq-hybrid-program.md:284`.
- **Browser and edge consumers cannot.** `packages/verify/src/web.ts` pins
  `SUPPORTED_VERSIONS = ['EP-RECEIPT-v1']` (`packages/verify/src/web.ts:44`) and
  refuses anything else (`:197`), because Web Crypto has no ML-DSA-65
  (`docs/protocol/pq-hybrid-program.md:278`). The twins refuse by version marker
  rather than shipping a verifier that could only ever pass on the classical leg.
  Any relying party who verifies in a browser gets nothing from the PQ leg.
- **Requiring the PQ leg is a relying-party pin, not an issuer control.** The
  commit ROW remains a valid v1 artifact by design, so a relying party handed
  only the row, who never asks for the proof, gets a v1 Ed25519 verdict
  (`lib/commit-hybrid.ts:57-64`). Issuance makes the pin available; it cannot
  manufacture a verifier that asks for it.

### 1.7 Rollback

| Configuration | Rolling back means | Sharp edge |
|---|---|---|
| Hybrid custody signer registered at boot | Register the classical signer alone, or call `clearCustodySigner()` (`lib/key-custody.ts:407`). The hybrid block does not execute and issuance is byte-identical to the v1 path (`lib/commit.ts:600-609`), pinned by a regression test. | None. This is the clean one. |
| Gate `hybrid_issuance: 'enabled'` or `'dual'` | Set it back to `disabled`. New issuance is classical only. Already-issued hybrid twins remain valid and independently verifiable, because the classical twin is a real `EP-RECEIPT-v1` (`packages/gate/src/hybrid-receipt-profile.ts:68-71`). | A `disabled` Gate REFUSES a hybrid receipt presented for acceptance with `hybrid_receipt_not_accepted` rather than partially checking it (`packages/gate/src/hybrid-receipt-profile.ts:41-47`). Rolling back the issuer also rolls back the acceptor. |
| Gate `hybrid_issuance: 'required'` | Same, but every artifact issued while `required` was on is hybrid only, and a rolled-back Gate will not accept it. | This is the rollback with teeth. Do not enter `required` before the acceptors have moved. |

One thing does not roll back, and it runs the other way. **A receipt cannot be
retroactively given a post-quantum leg.** Turning hybrid on later leaves a
permanent window of actions with no PQ leg; re-attestation
(`EP-EVIDENCE-REATTESTATION-v1`) can re-anchor an old receipt's integrity, but
only while the classical algorithm is still unbroken, and re-anchored evidence is
not a signature the issuer made at the time
(`packages/gate/src/hybrid-receipt-profile.ts:72-79`). That asymmetry is the
entire argument for `dual` sooner rather than `required` later.

### 1.8 Done and not done

| Item | State |
|---|---|
| Hybrid profiles implemented across every internally signed EP evidence surface | DONE (`docs/protocol/pq-hybrid-program.md:275`) |
| Dual-signer custody seam (`createHybridCustodySigner`, `signSet`) | DONE (`lib/key-custody.ts:293-337`) |
| Anti-stripping byte commitment (required set inside the signed bytes) | DONE (`lib/commit-hybrid.ts:28-49`) |
| Verification in JS, Python, and Go | DONE (`docs/protocol/pq-hybrid-program.md:284`) |
| DB storage able to hold a 4412-character signature | DONE, and verified against live prod (1.5) |
| Detached commit proof needing no migration | DONE (`lib/commit-hybrid.ts:23-26`) |
| Boot registration of a hybrid custody signer in EP's own application | **NOT DONE.** No non-test caller of `registerCustodySigner` exists. |
| ML-DSA-65 secret-key provisioning, rotation, and public-key publication | **NOT DONE.** No env surface, no adapter, no ceremony. |
| Ed25519 custody actually behind Vault Transit or a PKCS#11 HSM | **NOT DONE.** Adapters exist; `EP_KEY_CUSTODY_MODE` ships as `local-dev`. |
| An acknowledgment surface letting `EP_FIPS_REQUIRED=true` coexist with the PQ leg | **NOT DONE** (`docs/deployment/FIPS-MODE.md:283`). |
| Browser/edge verification of the PQ leg | **NOT POSSIBLE TODAY.** Web Crypto has no ML-DSA-65. |
| Hardware custody for the ML-DSA-65 key | **NOT AVAILABLE TODAY.** See the boundary table in section 4. |

---

## 2. What "deployed" would and would not mean

Three claims get conflated constantly, and they are three different facts:

1. EP's own reference deployment runs the post-quantum leg.
2. Customers run the post-quantum leg.
3. The classical artifact got safer.

Turning it on establishes (1). It does not establish (2), and (3) is not true at
all.

One scoping note carried forward from 1.2: the deployment that can truthfully
turn this on today is a **non-gov-strict** one. Under gov-strict, which includes
EP's own production by virtue of `isProduction()`, custody refuses the
software-held post-quantum leg. So the sentences below are the ones EP earns for
a reference or staging environment. Saying them about production would require
either hardware ML-DSA custody or an operator attestation EP cannot honestly
make.

### The exact sentence EP could truthfully say the day its own deployment turns it on

For the configuration described in section 1 (hybrid custody signer registered,
commit issuance emitting the detached proof):

> EMILIA Protocol's own reference deployment issues every authorization commit
> with a detached `EP-COMMIT-HYBRID-v1` proof carrying an Ed25519 and an
> ML-DSA-65 signature over the same set-committed bytes, verifiable in
> JavaScript, Python, and Go. The ML-DSA-65 key is software-held, so this
> deployment is not gov-strict.

If instead the Gate is moved to `dual`:

> EMILIA Protocol's own Gate deployment runs `hybrid_issuance: dual`: every
> action mints both an `EP-RECEIPT-v1` receipt and its `EP-RECEIPT-HYBRID-v1`
> twin over one canonical payload. The ML-DSA-65 key is software-held.

The trailing custody clause is not decoration and is not a hedge. It is the
difference between the two legs, and dropping it turns a true sentence into a
false one.

### The sentences EP still could not say

| Cannot say | Why |
|---|---|
| "Our customers' receipts are hybrid." | One deployment is one deployment. EP would be its own relying party. Adoption is measured by an external party's merge or configuration, never by EP's own switch position. |
| "EP receipts are harder to forge." | Two signatures over one payload is a compatibility arrangement, not a security upgrade to the classical artifact. The `EP-RECEIPT-v1` twin is exactly as strong as it was alone, and a verifier that checks only the classical twin has gained nothing (`packages/gate/src/hybrid-receipt-profile.ts:86-91`). |
| "Hybrid receipts cannot be downgraded." | Within a proof, one leg alone never verifies. But the commit row remains a valid v1 artifact, so a relying party that never asks for the proof gets a v1 verdict. Requiring the PQ leg is a relying-party pin (`lib/commit-hybrid.ts:57-64`). |
| Anything using the words FIPS compliant, FIPS certified, or FIPS validated about EP. | EP is not FIPS validated and not FIPS compliant. `mldsa_validated_module` is the hard-coded literal `false` in every posture the module can produce (`packages/verify/src/fips-mode.ts:60-67,209,398-400`). |
| "The post-quantum key is in a KMS/HSM like the classical one." | It is not, and `assertProductionKeyCustody()` still does not bless it (`lib/key-custody.ts:150-152`). |
| "Anyone can verify it." | Not in a browser or at the edge. `packages/verify/src/web.ts:44,197`. |
| "Receipts we already issued are protected." | They are not, and cannot retroactively be (`packages/gate/src/hybrid-receipt-profile.ts:72-79`). |
| "EP has post-quantum receipts." | The earned phrasing is the opt-in one already in the program document: hybrid post-quantum signatures available across every internally signed EP evidence surface, verified in JS, Python, and Go, with the named boundaries. Reuse it verbatim rather than compressing it. |

---

## 3. CMVP validation scoping

### 3.1 What EP's cryptographic boundary would even be

This is the crux, and it is worth being precise before any number is quoted.

FIPS 140-3 validation is awarded to a **cryptographic module**: a defined set of
software, firmware, or hardware implementing approved security functions inside
a defined cryptographic boundary, tested by an accredited laboratory against a
written security policy, on named operational environments. It is never a
property of an application that links the module. EP already states this and
enforces it in code (`packages/verify/src/fips-mode.ts:14-19`,
`docs/deployment/FIPS-MODE.md:14`).

EP is an application, and it reaches two entirely different implementations:

| Leg | Implementation | Boundary posture |
|---|---|---|
| SHA-256, Ed25519, ES256 | `node:crypto`, therefore OpenSSL (`docs/deployment/FIPS-MODE.md:116-118`) | Can be inside a validated provider's boundary, provider and certificate dependent. This is the inheritance path, and it is already documented per certificate. |
| ML-DSA-65 | `@noble/post-quantum`, pure JavaScript (`docs/deployment/FIPS-MODE.md:110,120`) | Inside no boundary, and `mldsa_validated_module` is the hard-coded literal `false` (`packages/verify/src/fips-mode.ts:398-400`). |

So the honest answer to "would EP validate a module?" is: **for the classical
leg, no, and it should not want to, because the module it depends on is somebody
else's and is already validated.** For the post-quantum leg there are exactly
three options, and only one of them involves EP validating anything:

- **(A) Inherit.** Wait for an underlying validated provider to carry ML-DSA,
  then call it instead of the JavaScript library. EP validates nothing. This is
  a backend swap plus an operational change.
- **(B) Algorithm certificate only.** Take EP's ML-DSA implementation through
  ACVP/CAVP. This is not a module validation and does not become one.
- **(C) Validate a module of EP's own.** Define a cryptographic boundary
  containing an ML-DSA implementation, write a security policy, and take it
  through a lab and the CMVP queue.

### 3.2 An algorithm certificate is not a module certificate

These get conflated in sales conversations constantly, usually in EP's favour,
which is exactly why the distinction has to be written down before anyone is
tempted.

| | CAVP certificate (via ACVP) | CMVP certificate |
|---|---|---|
| What it attests | An algorithm implementation produced correct outputs for the program's known-answer and other test vectors. | A **module** met the FIPS 140-3 requirements at a stated security level, on stated operational environments, against a published security policy. |
| What it says nothing about | Key management, zeroization, self-tests, integrity checking at load, entropy, the operational environment, roles and services, or the module boundary. | n/a |
| Relationship | A **prerequisite input** to a module validation, not a substitute for it. Certificates carry an algorithm cert number that the module's security policy references (EP's own tables already show this pattern: certificate #5116 references CAVP A6328, `docs/deployment/FIPS-MODE.md:95`). | The thing a procurement document means when it says "FIPS 140-3 validated." |
| Obtainable independently | Yes. | Yes, but it is the expensive one. |

There is also **ESV** (Entropy Source Validation), a separate certificate for a
module's entropy source. It is relevant to (C) and not to (A) or (B).

**The claim discipline that follows.** A CAVP certificate would entitle EP to
say, precisely, that its ML-DSA-65 implementation holds a CAVP algorithm
certificate with a stated number. It would not entitle EP to say the
implementation, the module, the receipts, or the product is validated. The
language governance guard already refuses the wrong forms of that sentence
(`scripts/check-language-governance.ts:56-66`), and a certificate in hand does
not relax the guard.

### 3.3 The inheritance path, in the words a non-validated application is allowed

EP already owns the correct formulation and enforces it repo-wide. The earned
sentence is:

> FIPS-based algorithms, with a validated-provider deployment mode.

(`docs/deployment/FIPS-MODE.md:10`.) The permitted claims are enumerated at
`docs/deployment/FIPS-MODE.md:306-310` and the forbidden ones at `:312-317`. The
general shape: an application may say it **runs on** or **uses** a FIPS 140-3
validated cryptographic module, naming the certificate. It may never say it **is**
validated.

For the classical leg this path is complete and costs nothing but operations:
pick a distribution whose provider certificate covers the algorithms in use. EP's
own tables already name which ones cover Ed25519 (Rocky Linux 9 #5116,
Chainguard #5132, TuxCare #5373) and which do not (RHEL 9, Ubuntu 22.04/24.04,
Amazon Linux 2023) at `docs/deployment/FIPS-MODE.md:88-98,102`.

For ML-DSA the path is blocked on the outside world, not on EP:

- OpenSSL 3.5.0 implements ML-DSA and registers `PROV_NAMES_ML_DSA_44/65/87`
  with `FIPS_DEFAULT_PROPERTIES` (`docs/deployment/FIPS-MODE.md:108`, VERIFIED
  there).
- No certificate covers OpenSSL 3.4 or 3.5 (`docs/deployment/FIPS-MODE.md:57`,
  VERIFIED there).
- A sweep of 31 security policies covering essentially every OpenSSL-derived
  module on the Active FIPS 140-3 list found zero occurrences of ML-DSA
  (`docs/deployment/FIPS-MODE.md:109`, a negative claim with its scope and date
  stated, as of 2026-08-16).

The engineering cost of taking path (A) when a provider does arrive is bounded,
because the backend is already injectable rather than hard-wired: the agility
module accepts `mldsaBackend` / `mldsaBackendLoader`, threaded through the
profiles (`lib/commit-hybrid.ts:161-165`). Swapping `@noble/post-quantum` for a
provider-backed implementation is a backend change, not a protocol change.

### 3.4 Cost and elapsed time

**Evidence status, stated first so nobody quotes this section as priced.** The
cost structure below is the set of line items each path actually incurs, which is
what the recommendation in 3.5 turns on. **The dollar amounts and queue durations
were not sourced to primary documents in the session that wrote this document.**
They are therefore not stated here. Before any of this is used to justify or
refuse a spend, someone must retrieve and cite: the current CMVP cost recovery
fee schedule and its effective date from NIST CSRC, a real quote from an
NVLAP-accredited laboratory for a software module of this shape, and the current
Modules In Process queue depth from the CMVP MIP list. An order-of-magnitude
number carried in from memory is exactly the kind of claim this repository does
not make, and a wrong one here would move a real budget.

What each path costs, structurally:

| Path | Cost line items | Elapsed-time drivers |
|---|---|---|
| **(A) Inherit from a validated provider** | Engineering only: swap the ML-DSA backend behind the existing injectable interface, and run on a distribution whose provider certificate covers the algorithms. No lab, no fee, no security policy to author. | Bounded by somebody else's calendar: when a distribution provider carries ML-DSA into a validated boundary. EP controls none of it and pays for none of it. |
| **(B) CAVP algorithm certificate for EP's ML-DSA** | Lab engagement to run the ACVP test vectors against EP's implementation and submit. Substantially cheaper than (C), because there is no security policy, no operational-environment matrix, and no module-level testing. | Short relative to (C). Driven by lab scheduling rather than by the CMVP queue. |
| **(C) EP's own CMVP module certificate** | Lab testing fees; the NIST CMVP cost recovery fee; authoring a security policy; documentation and consulting; an operational-environment matrix (each named platform is scope); and a recurring revalidation obligation every time the module changes. | The CMVP Modules In Process queue, which is the dominant term and is measured in quarters rather than weeks. The module version is frozen while it waits. |

Two structural facts about (C) matter more than any price, and both are
independent of the numbers:

- **The operational environment is part of the boundary.** A software module is
  validated on named platforms. EP does not control where its code runs, and a
  pure-JavaScript implementation loaded from npm into an arbitrary Node process
  is an awkward fit for a boundary that must have a defined perimeter, a load-time
  integrity check, and self-tests. Whether a pure-JavaScript cryptographic module
  has ever been validated, and under what operational-environment constraints, is
  an open question this document does not answer and should not guess at. It is
  the first thing to establish if (C) is ever seriously considered.
- **Validation freezes the thing validated.** A certificate attaches to a
  specific version. EP's post-quantum surfaces are still moving, as the parallel
  work landing alongside this document shows. Validating a moving module means
  revalidating, repeatedly.

### 3.5 Recommendation, and the trigger that should start the spend

**Recommendation: take path (A), inherit. Do not seek EP's own CMVP module
certificate, and do not buy a CAVP algorithm certificate on spec.**

The argument is not primarily cost. It is relevance, and that matters because a
relevance argument does not change when a lab quotes a lower price.

1. **The module EP would want validated is not EP's code.** For the classical
   leg the right module already exists and is already validated, by OpenSSL
   distributors, on a revalidation cycle EP does not pay for. For ML-DSA the same
   thing will happen: OpenSSL 3.5.0 already implements it
   (`docs/deployment/FIPS-MODE.md:108`), and the distribution providers who
   revalidate on a cycle are the ones who will carry it into a boundary. EP's
   correct position is to be ready to call it.
2. **Validating an EP-defined module would not answer the buyer's question.**
   The question behind a FIPS requirement is "is the cryptography under my
   authorization evidence inside a validated boundary." Inheritance answers that,
   and answers it for whichever provider the buyer already runs. A certificate on
   a boundary EP invented around a JavaScript library EP did not write answers a
   question nobody asked, and it still would not make the product validated:
   applications do not get certificates (`packages/verify/src/fips-mode.ts:14-19`).
3. **The dependency is already isolated, so waiting is cheap.** The backend is
   injectable (`lib/commit-hybrid.ts:161-165`). Path (A) is a swap when the time
   comes, not a rewrite, and every month of waiting costs EP nothing while the
   providers do the work.
4. **A CAVP certificate bought on spec would be a claim asset with no buyer.**
   It would entitle EP to one narrow sentence about algorithm correctness against
   test vectors. No procurement document asks for that sentence.

**The trigger. Do not spend a dollar until all three of these hold:**

1. **A named buyer, not a category.** A specific organization with a written
   procurement requirement that names FIPS 140-3 validation as something **EP
   itself** must hold. The requirement text gets quoted verbatim into this
   document, with its source, before anything else happens. "Government buyers
   will want this" is not a trigger.
2. **That buyer confirms inheritance does not satisfy them.** This is the check
   that kills most of these, and it must be run before the other two. Most FIPS
   requirements are satisfied by running on a validated cryptographic module, and
   EP already has the configuration and the honest sentence for that
   (`docs/deployment/FIPS-MODE.md:10,306-310`). Ask, in writing, whether "runs on
   a FIPS 140-3 validated cryptographic module, certificate #NNNN" closes the
   requirement. Usually it does.
3. **Contract value clears the fully loaded cost with margin for the elapsed
   time.** Validation is not just a fee; it is a multi-quarter calendar item
   during which the module version is frozen. A deal that cannot survive the wait
   is not a deal that justifies the spend.

**One case that looks like a trigger and is not.** If a buyer's requirement is
specifically about the post-quantum leg, validation is still the wrong answer,
because there is no validated ML-DSA module to be measured against yet
(`docs/deployment/FIPS-MODE.md:109`). The right answer is to run classical-only
inside that buyer's validated provider and turn the PQ leg off for them. EP's
posture module already supports exactly that and already refuses to fake it: the
default for ML-DSA under an active FIPS posture is the named refusal
`mldsa_implementation_unvalidated` (`packages/verify/src/fips-mode.ts:540-547`).

**Whose decision this is.** Spending money is the founder's call, not an
engineering default. This document's recommendation is to spend none, and to
revisit only when the trigger above fires with a name attached to it.

---

## 4. The honest boundary table

One row per clause of EP's current public boundary sentence
(`docs/protocol/pq-hybrid-program.md:286` and the named exceptions at `:277-282`).
The point of the table is to stop treating six unrelated obstacles as one mood.
Two of them are ours. Four are not.

| Boundary clause | Who owns closing it | What specifically unblocks it | Current state |
|---|---|---|---|
| **Off by default.** Every hybrid profile is opt-in. | EP code, then EP operations | A boot path that calls `registerCustodySigner(hybridSigner({...}))`. The default then resolves itself: `resolveHybridIssuancePosture()` returns `dual` once a dual signer is registered and custody permits its PQ leg. Both sit on top of unfinished key provisioning (1.4). | Off everywhere. With no signer registered the custody-resolved default is `disabled` with reason `hybrid_signer_absent`, and no non-test caller of `registerCustodySigner` exists in the tree. |
| **Not deployed.** None is a deployment default. | EP operations, then a vendor | Everything in the NOT DONE half of 1.8. For a non-gov-strict environment no external dependency blocks it. For EP's own production, hardware ML-DSA custody does block it (1.2), so this clause and the custody clause below close together, not separately. | Not deployed anywhere, including EP's own reference deployment. `EP_KEY_CUSTODY_MODE` ships as `local-dev` (`.env.example:70`). |
| **Not FIPS validated.** | A NVLAP-accredited lab and the CMVP, or the vendor of an underlying validated module | See section 3. Either an upstream provider vendor lands ML-DSA inside a validated module boundary EP can call, or EP buys its own validation. | No EP package, receipt, or deployment carries a CMVP certificate (`packages/verify/src/fips-mode.ts:12-13`). A sweep of 31 security policies covering essentially every OpenSSL-derived module on the Active FIPS 140-3 list found zero occurrences of ML-DSA (`docs/deployment/FIPS-MODE.md:109`, negative claim, scope stated, as of 2026-08-16). |
| **ML-DSA signer software-held.** Does not satisfy kms/hsm custody. | A vendor (cloud KMS or HSM), then EP code | A KMS or HSM that actually signs ML-DSA-65, wrapped with `createPqCustodySigner()` and labelled with its real custody value instead of `'software'` (`lib/key-custody.ts:248`). The seam is already shaped to take it; `lib/custody-signers.ts:30-31` says so explicitly. | **PENDING SWEEP.** A dedicated sweep of KMS and HSM ML-DSA availability is in flight; this cell is not to be filled from memory. The repository's own recorded position as of this writing is that no such path exists for EP (`lib/key-custody.ts:138-143`). |
| **WebAuthn outside.** Quorum signoffs, Class A approver signatures, agent adoption, release locks. | A standards body (FIDO Alliance / W3C), then browser and authenticator vendors | PQC support landing in the WebAuthn/FIDO2 stack and shipping in real authenticators. EP does not choose what a hardware authenticator signs, so there is no EP code change that closes this (`docs/protocol/pq-hybrid-program.md:277`; the underlying ES256/P-256 surfaces are catalogued at `docs/protocol/pq-hybrid-program.md:24-25`). | **PENDING SWEEP.** A dedicated sweep of WebAuthn PQC status is in flight; this cell is not to be filled from memory. |
| **External / vendor signatures outside.** | The foreign signer, per ecosystem | The counterparty adopting a post-quantum algorithm on their side. EP's job is then to verify it, not to add a leg. Precedent exists: `aeb-mcgraw-delegation-adapter.ts` already verifies a foreign COSE_Sign1 signature under `cose-ml-dsa` for draft-mcgraw-httpapi-agent-budget-03 (`packages/verify/src/aeb-mcgraw-delegation-adapter.ts:3,30,36`), so one external ecosystem has already moved and EP's adapter already speaks it. | Mixed and permanently partial. RFC 3161 TSA tokens (RSA/ECDSA per CMS), RFC 9711 EAT platform attestation, Apple App Attest and Google Play Integrity, GitHub App RS256 JWTs, Procore's evidence format, and IdP-negotiated JWT sessions are all outside EP's control by construction (`docs/protocol/pq-hybrid-program.md:163-170`). |

Three further named exceptions from `docs/protocol/pq-hybrid-program.md:279-281`
sit outside the six clauses but belong in the same honest accounting:

- **DSSE / in-toto** (gate qualification): DSSE signatures carry no algorithm
  identifier and the PAE leaves no signed location for a required-algorithm set.
  Registration-gated; EP refuses with `alg_registration_pending`. Owner: a
  standards body.
- **`MEMORY-PROJECTION-RECORD-v1`**: the joint I-D wire (draft-ferro-schrock) is
  byte-for-byte unchanged and a detached EP-side co-signature exists. Owner: a
  co-author. Coordination-gated.
- **`authorization-server-confirmation.ts` / `policy-decision-evidence.ts`**: EP
  ships the sign and verify code, but the signer is logically a third-party
  authorization server or policy engine. Upgrading is technically an EP code
  change and practically a coordination problem: every integration that vendored
  the signing helper has to redeploy with new key material first
  (`docs/protocol/pq-hybrid-program.md:169`).

Reading the table honestly: **the first two rows are EP's to close, and in a
non-gov-strict environment nothing external blocks them.** In EP's own
gov-strict production they are coupled to the custody row, so they close with
it, not before it. The remaining four rows are somebody else's calendar
entirely. That is the useful separation, and it is why "when will EP be
post-quantum" has no single date and should never be answered with one.

---

## Related

- [`docs/protocol/pq-hybrid-program.md`](../protocol/pq-hybrid-program.md) - the
  signature-surface inventory, the `EP-REVOCATION-v2` migration pattern, and the
  migration status this document starts from.
- [`docs/deployment/FIPS-MODE.md`](./FIPS-MODE.md) - `EP-FIPS-MODE-v1`, the
  per-certificate algorithm boundary tables, and the consult points in the
  custody signing path.
- `lib/key-custody.ts` - the dual-signer custody seam and the software-custody
  note this document's section 1.4 is built on.
- `examples/fips-deployment/` - the runnable posture reporter and the reference
  container.
