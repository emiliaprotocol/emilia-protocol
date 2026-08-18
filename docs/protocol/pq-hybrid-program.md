# PQ Hybrid Program: Signature Surface Inventory

(Generated 2026-08-17 by read-only sweep; the targeting map for staged hybrid wiring. Wave order and boundary rules in the final sections. This inventory describes public code; it contains no strategy or key material.)

# EMILIA Protocol — Signature Surface Inventory (PQ hybrid program)

Scope swept: `packages/verify/src/`, `packages/gate/src/`, `packages/issue/`, `packages/attest/`, `lib/` (all subtrees), `mcp-server/`, plus every other package that imports `crypto.sign`/`crypto.verify`/Ed25519/ECDSA/HMAC (`packages/require-receipt`, `packages/mobile`, `packages/openai-guard`, `packages/langchain`, `packages/openai-agents`, `apps/*-service`, `caid/`, and the AEB adapter family). Findings below are grouped by package. Every row was confirmed against source, not inferred.

**Headline finding:** two generic post-quantum building blocks already exist and are production code, but only **one** artifact type is actually wired to them today:

- `packages/verify/src/pq-signature-agility.ts` (**EP-SIG-AGILITY-v1**) — closed registry `{Ed25519, ML-DSA-65}`, `signAgile`/`verifyAgileSignature`/`verifyAgileSignatureSet`, fail-closed, backend = `@noble/post-quantum` ML-DSA-65. **Consumed by exactly one caller: `packages/verify/src/evidence-record.ts`'s `EP-EVIDENCE-REATTESTATION-v1`** (`createReattestation`/`verifyReattestationChain`). It is also re-exported wholesale from `packages/verify/src/index.ts`, but `verifyReceipt`/`verifyTrustReceipt` themselves remain **hardcoded to Ed25519** (index.ts:397-407 explicitly rejects any `asymmetricKeyType !== 'ed25519'`).
- `packages/verify/src/pq-hybrid.ts` (**EP-HYBRID-v1**) — `signHybrid`/`verifyHybrid`, requires *both* Ed25519 and ML-DSA-65 to verify (anti-stripping, unlike agility's policy-only binding). **Not imported by any artifact module** — it's a standalone envelope with its own test file only. (Correction to the original sweep, which recorded this module's tag as `EP-HYBRID-SIGNATURE-v1`. That tag belonged to the duplicate below, never to this module; the two envelopes were not wire-compatible.)
- `lib/quantum-safe.ts` was a **near-duplicate** of `pq-hybrid.ts` living in `lib/` instead of `packages/verify/src/`, under its own `EP-HYBRID-SIGNATURE-v1` type tag and its own envelope shape, reachable only from one test. **RESOLVED in wave 2:** the file was deleted and its test repointed at the canonical module (`tests/pq-hybrid-envelope.test.ts`). See the consolidation note in the wave-2 section below.

Everything else catalogued below — every receipt, quorum signoff, revocation statement, capability receipt, consent grant, coverage artifact, field-origin evidence record, admission record, refusal statement, escrow statement, and internal attestation — signs/verifies **Ed25519 only**, with **no** import of either agility module.

---

## 1. `packages/verify/src/` (verification core)

| File / exports | Artifact | Algorithm today | Key loading | Canonical bytes | Agility/hybrid hook? | Hybrid-wiring difficulty |
|---|---|---|---|---|---|---|
| `index.ts` — `verifyReceipt`, `verifyTrustReceipt`, `verifyReceiptBundle`, `verifyMerkleAnchor`, `verifyCommitmentProof` | **EP-RECEIPT-v1 / EP-AUTHORIZATION-RECEIPT-v1** (the core receipt) | Ed25519 only — hardcoded guard: `if (keyObject.asymmetricKeyType !== 'ed25519') return {valid:false, error:"...requires Ed25519"}` (line ~403) | caller-supplied base64url SPKI DER public key | `canonicalize()` = recursive sorted-key JSON (JCS-equivalent), from `../../packages/issue/index.js` / `strict-json.ts` | **No** — re-exports `pq-signature-agility` symbols for other callers but does not call them internally | **Hard-with-schema-change** — `signature: {algorithm:'Ed25519', value}` is a single flat field on the wire-frozen `EP-RECEIPT-v1` envelope (PIP-001 says this core is frozen); adding a second signature means either a new envelope version or an additive `signatures[]` array, plus updating every consumer (issue, attest, gate, all adapters below) that assumes one signature |
| `index.ts` — `verifyWebAuthnSignoff` (Class A signoff) | **Class-A device signoff** inside a receipt context | **ECDSA P-256 (ES256)**, WebAuthn `authData‖SHA-256(clientDataJSON)` | approver's enrolled P-256 SPKI key | not JCS — WebAuthn assertion bytes per FIDO spec | No | **Hard** — the signer is a hardware authenticator/passkey; EP does not control what the device signs, so there is no path to add ML-DSA here without a new (non-WebAuthn) ceremony |
| `quorum.ts` — `verifyQuorum` | **EP-QUORUM-v1** (M-of-N / ordered signoff) | Composes `verifyWebAuthnSignoff` per member → **ES256**, not Ed25519 | per-member enrolled P-256 keys | WebAuthn assertion + `contextChainHash` (JCS SHA-256) for ordered chaining | No | **Hard** — same hardware-authenticator ceiling as above; a PQ upgrade here is gated on FIDO2/WebAuthn PQC support, not an EP code change |
| `revocation.ts` — `buildRevocation`(internal)/`verifyRevocation`, `isRevoked` | **EP-REVOCATION-v1 (revocation statement)** | Ed25519 only; `if (proof.algorithm !== 'Ed25519') fail(...)` | pinned revoker public key (relying-party supplied, base64url SPKI) | `canonicalize({@version, target_type, target_id, action_hash, revoker_id, revoked_at, reason})` | No | **Moderate** — small, self-contained artifact; algorithm field is already explicit (`algorithm: 'Ed25519'`), so extending to an array of `{algorithm, signature_b64u}` is a bounded, well-isolated change |
| `evidence-record.ts` — `verifyEvidenceRecord` (base record) | **EP-EVIDENCE-RECORD-v1** (RFC-4998-style renewal chain over time attestations) | Delegates to `verifyTimeAttestation` (Ed25519); no direct signature of its own | n/a | `canonicalize()` | No (base record) | Moderate |
| `evidence-record.ts` — `createReattestation`, `verifyReattestationChain` | **EP-EVIDENCE-REATTESTATION-v1** | **Already algorithm-agile**: `alg: 'Ed25519' \| 'ML-DSA-65'` via `signAgile`/`verifyAgileSignature` | `AgileSigningKey`/`AgileVerificationKey` (Ed25519 KeyObject or ML-DSA-65 raw bytes) | domain-separated bytes over `{prior_record_digest, digest_alg, reattested_at}` | **Yes — already wired** | **Trivial** (already done); the reference implementation for how every other surface should be extended |
| `pq-signature-agility.ts` | *(building block, not an artifact itself)* | Ed25519 + ML-DSA-65 registry | n/a | operates over caller-supplied `messageBytes` | **Is** the hook | n/a |
| `pq-hybrid.ts` | *(building block, not an artifact itself)* | Ed25519 AND ML-DSA-65 (both required) | n/a | domain-separated transcript + payload | **Is** the hook | n/a — currently orphaned (no artifact consumes it) |
| `consent-grant.ts` — `signConsentGrant`(implicit via signature helper)/`verifyConsentGrant`, `verifyGrantHash`, `verifyReceiptUnderGrant` | **EP-CONSENT-GRANT-v1** | Ed25519, `crypto.sign(null, bodyBytes, privateKey)` | principal's device-bound Ed25519 key | `canonicalize()` over grant body | No | Moderate |
| `authority-proof.ts` — `signAuthorityProof`(via `lib/authority/proof.ts`, verified here)/`verifyAuthorityProof` | **EP-AUTHORITY-PROOF-v1** | Ed25519 | issuer Ed25519 SPKI key | `canonicalize()` | No | Moderate |
| `witness.ts` — `verifyWitnessCosignature` | **witness cosignature over a Merkle checkpoint** | Ed25519, domain-tagged: `Ed25519(null, SHA-256(WITNESS_DOMAIN_TAG ‖ canonicalize(checkpoint)))` | pinned witness SPKI key | domain-separated digest over `canonicalize()` | No | Moderate |
| `reliance-agreement.ts` — `signRelianceAgreement`, `signRelianceEvent`, `verifyRelianceAgreement`, `verifyRelianceEvent` | **EP-RELIANCE-AGREEMENT-v1 / EP-RELIANCE-EVENT-v1** | Ed25519, `algorithm !== 'Ed25519'` hard guard | per-signer pinned key by role | `canonicalize()` | No | Moderate (multi-signer roster — same idiom as breakglass) |
| `discovery-permit-contract.ts` — `signDiscoveryPermitResolverAttestation`, `verifyDiscoveryPermitResolverAttestationSignature` | **EP-DISCOVERY-PERMIT-RESOLUTION-v1** (resolver attestation) | Ed25519 (`signer.private_key.asymmetricKeyType !== 'ed25519'` guard) | resolver Ed25519 key | domain-separated bytes | No | Moderate |
| `document-action-binding.ts` — `signDocumentActionBinding`, `verifyDocumentActionBinding` | **EP-DOCUMENT-ACTION-BINDING-v1** | Ed25519 | issuer Ed25519 key | `canonicalize()` | No | Moderate |
| `authorization-server-confirmation.ts` — `signAuthorizationServerConfirmation`, (verify inline) | **EP-AUTHORIZATION-SERVER-CONFIRMATION-v1** — evidence leg for an *independently signed* AS grant, but EP ships the sign+verify code the AS integration uses | Ed25519, JWS-like `b64u(header).b64u(payload)` ASCII signing input | AS's Ed25519 signer, root-pinned | ASCII `signingInput` (JWS-flavored, not raw JCS) | No | Moderate–Hard (touches a JWS-style envelope, and any third party who adopted this library needs to move together) — see §6 boundary note |
| `policy-decision-evidence.ts` — `signPolicyDecisionEvidence`, (verify inline) | **EP-POLICY-DECISION-EVIDENCE-v1** — OPA/Cerbos decision evidence leg | Ed25519, same ASCII signing-input convention as above | policy-engine integration's Ed25519 key | ASCII `signingInput` | No | Moderate–Hard, same third-party-coordination caveat |
| `reliance-profile-registry.ts` — `signRelianceProfileEntry`, `verifyRelianceProfileEntry` | **EP-RELIANCE-PROFILE-REGISTRY-v1** entry | Ed25519 | registrar Ed25519 key (never held in-repo) | `entrySigningBytes()` over `canonicalize()` | No | Moderate |
| `aeb-adapter-contract.ts` — `signAebNativeVerificationAttestation`, `verifyAebEvaluation` | **EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1** (native half; the adapter-specific verify halves are external, see §6) | Ed25519 (curve-pinned: `isEd25519PrivateKey`) | evaluator Ed25519 key, root-pinned per adapter | `nativeAttestationSigningBytes()` | No | Moderate (native half); adapter halves are external, see §6 |
| `status.ts` — `verifyRevokerAuthorityCertificate`, `verifyStatusArtifact` | **EP-REVOKER-AUTHORITY-v1 / EP-STATUS-v1** | Ed25519 (`algorithm !== 'Ed25519'` guard) | revoker Ed25519 key, delegated via certificate chain | domain-tagged `canonicalize()` bytes | No | Moderate |
| `time-attestation.ts` — `verifyTimeAttestation` | **EP-TIME-ATTESTATION-v1** | Ed25519 | pinned TSA Ed25519 key | domain digest over `canonicalize()` | No | Moderate |
| `timestamp-proof.ts` — `verifyTimestampProof` | consumes **RFC 3161 TSA tokens** | **RSA (PKCS#1 v1.5) or ECDSA P-256/384/521** — dictated by RFC 3161, not EP | pinned TSA cert/key (foreign PKI) | ASN.1 CMS SignedInfo, not JCS | No, and can't be (external PKI/CMS format) | **N/A / external** — flagged in §6 |
| `platform-attestation.ts` — `verifyPlatformAttestation` | consumes a **signed JSON EAT (RFC 9711) over compact JWS** — device/TEE attestation | Standard JOSE algorithms via pinned key per `kid` (Ed25519 example shown, but format is generic JWS) | relying-party trustedIssuer map | JWS signing input | No | External-leaning — flagged in §6 (format is a third-party EAT profile even though the signer can be pinned to an Ed25519 key) |
| `web.ts` | Browser (`SubtleCrypto`) mirror of `index.ts` | Same as `index.ts` (Ed25519 + ES256) | same | same | No | Same as `index.ts`, plus browser SubtleCrypto has no ML-DSA support today — additional constraint |
| `aeb-aps-adapter.ts`, `aeb-ccs-adapter.ts`, `aeb-chap-adapter.ts`, `aeb-mcgraw-delegation-adapter.ts`, `aeb-oasnt-adapter.ts`, `aeb-oauth-transaction-challenge-adapter.ts`, `aeb-psea-adapter.ts`, `aeb-wag-adapter.ts`, `aeb-wimse-oauth-adapter.ts`, `ap2-native-adapter.ts`, `fido-ap2-bridge.ts` | Verify **foreign protocol artifacts** (APS, CCS/PyPI HMAC, CHAP, mcgraw budget grants, OASNT, OAuth txn-challenge, PSEA, WAG, WIMSE/OAuth SPT, AP2 mandates, FIDO/WebAuthn-for-AP2) | Mixed foreign algorithms: **Ed25519, ES256/P-256, HMAC, EdDSA**, and — notably — `aeb-mcgraw-delegation-adapter.ts` already verifies **COSE_Sign1 with a `cose-ml-dsa` (ML-DSA) signature** from the *foreign* signer | foreign-party keys/roots, out of EP's control | foreign wire formats (COSE, JWT/JWS, HMAC-signed manifests) | Irrelevant — verification-only, foreign signer decides | **Out of scope — see §6** |

## 2. `packages/gate/src/` (enforcement / productized artifacts)

Every file below follows the identical pattern: `import { canonicalize, hashCanonical } from './execution-binding.js'` (or `strict-json.ts`'s `canonicalizeStrictJson`/`canonicalizeFiniteJson`), then `crypto.sign(null, bytes, ed25519PrivateKey)` / `crypto.verify(null, bytes, ed25519PublicKey, sig)`, with a hardcoded `algorithm: 'Ed25519'` field and an explicit `asymmetricKeyType !== 'ed25519'` guard. None import `pq-hybrid` or `pq-signature-agility`.

| File / exports | Artifact | Difficulty |
|---|---|---|
| `capability-receipt.ts` — `verifyCapabilityReceipt`, `verifyCapabilityScope` | **capability receipt** (`EP-CAPABILITY-RECEIPT-v1`) | Moderate |
| `field-origin-evidence.ts` — `signFieldOriginEvidence`, `verifyFieldOriginEvidence` | **field-origin evidence** (`EP-FIELD-ORIGIN-v0.1`) | Moderate |
| `coverage.ts` — `signEnforcementProbe`, `verifyEnforcementProbe` | **coverage / enforcement probe** (`EP-GATE-ENFORCEMENT-PROBE-v1`) | Moderate |
| `coverage-reconciliation-attestation.ts` — `signCoverageReconciliationAttestation`, `verifyCoverageReconciliationAttestation` | **coverage reconciliation attestation** (`EP-COVERAGE-RECONCILIATION-ATTESTATION-v2`) | Moderate |
| `coverage-reconciliation-runner.ts` — `signCoverageSourceInventory`, `verifyCoverageSourceInventory`, `verifyCoverageReconciliationReportBinding` | **coverage source inventory / coverage inventory** (`EP-COVERAGE-SOURCE-INVENTORY-v2`) | Moderate |
| `action-escrow-custodian.ts` — (sign inline), `verifyActionEscrowStateStatement`-adjacent | **escrow custodian observation** (`EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1`) | Moderate |
| `action-escrow-state.ts` — `signActionEscrowStateStatement`, `verifyActionEscrowStateStatement` | **escrow state statement** (`EP-ACTION-ESCROW-STATE-STATEMENT-v1`) | Moderate |
| `action-escrow-package.ts` / `action-escrow-evidence.ts` — `verifyActionEscrowEvidencePackage` | **escrow evidence package** (`EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1`) | Moderate |
| `action-escrow.ts` | escrow contract core (canonicalization only, composes the above) | Moderate |
| `admission-store.ts` / `admission-store-postgres.ts` — `verifyAdmissionJournal` | **admission record / journal** (`EP-GATE-ADMISSION-JOURNAL-v2` / `-RECORD-v2`) | **No signature at all today** — it's a `canonicalizeFiniteJson` **hash chain** (prev-hash linkage), not an asymmetric signature. There's nothing to make "hybrid" until/unless a checkpoint signature is added; flagged as **out of scope for hybrid** unless the design adds a signed checkpoint over the journal head |
| `action-refusal-statement.ts` — `signActionRefusalStatement`, `verifyActionRefusalStatement`, `verifyActionRefusalExternalEvidence` | **refusal statement** (`EP-ACTION-REFUSAL-STATEMENT-v1`) | Moderate |
| `bounded-execution-report.ts` — `signBoundedExecutionReport`, `verifyBoundedExecutionReport` | bounded-execution report (`EP-BOUNDED-EXECUTION-REPORT-v1`) | Moderate |
| `bounded-execution-program.ts` — `signBoundedExecutionProgram`, `verifyBoundedExecutionProgram` | bounded-execution program (`EP-BOUNDED-EXECUTION-PROGRAM-v1`) | Moderate |
| `bounded-execution-acceptance.ts` — `signBoundedExecutionAcceptanceProfile`, `verifyBoundedExecutionAcceptanceProfile`, `verifyBoundedExecutionEvidencePack` | bounded-execution acceptance profile | Moderate |
| `reliance-program.ts` — `signRelianceProgram`, `verifyRelianceProgram` (`RELIANCE_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519'`) | reliance program | Moderate |
| `reliance-risk-crypto.ts` — `signRiskBody`, `verifyRiskBody` | shared risk-artifact proof helper (used by loss-allocation, recovery-admission) | Moderate — this is a shared primitive, so fixing it fixes several callers at once |
| `cross-rail-authority.ts` — `signHumanInterruptionDecision`, `verifyHumanInterruptionDecision` | rail-entry permit / human interruption decision | Moderate |
| `recovery-admission.ts` — `signRecoveryCapability`, `verifyRecoveryCapability` | recovery capability (`EP-RECOVERY-CAPABILITY-v1`) | Moderate |
| `network-witness.ts` — `signNetworkWitnessStatement`, `verifyNetworkWitnessStatement` | network witness statement (`EP-GATE-NETWORK-WITNESS-v1`) | Moderate |
| `allowance.ts` — `signGateAllowance`, `verifyGateAllowance` | gate allowance (`EP-GATE-ALLOWANCE-v1`) | Moderate |
| `trust-program.ts` — (sign inline), `verifyTrustStageReceipt` | trust-stage receipt (`EP-GATE-TRUST-STAGE-RECEIPT-v1`) | Moderate |
| `trust-program-revocation.ts` — `verifyTrustProgramRevocation` | trust program revocation | Moderate |
| `receipt-program.ts` — (`RECEIPT_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519'`), `verifyReceiptProgramCertificate` | receipt-program certificate | Moderate |
| `trusted-context.ts` — `signTrustedContextBinding`, `verifyTrustedContextContinuity` | trusted-context binding (`EP-TRUSTED-CONTEXT-BINDING-v1`) | Moderate |
| `consequence-actuator.ts` — (`CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM = 'Ed25519'`), `signConsequenceExecutionEnvelope`, `verifyConsequenceExecutionEnvelope` | consequence execution envelope | Moderate |
| `reports/external-verification.ts` — `signExternalVerificationStatement`, `verifyExternalVerificationStatement` | external verification statement (`EP-EXTERNAL-VERIFICATION-STATEMENT-v1`) | Moderate |
| `loss-allocation-schedule.ts` — `signLossAllocationSchedule`, `verifyLossAllocationSchedule` | loss allocation schedule | Moderate |
| `loss-experience-feed.ts` — `signLossExperienceFeed`, `verifyLossExperienceFeed` | loss experience feed | Moderate |
| `execution-value.ts` — `signExecutionValueAttestation`, `verifyExecutionValueAttestation` | execution value attestation | Moderate |
| `remedy-program-receipt.ts` — (`sign` via injected `{sign: crypto.sign}` closure), `verifyRemedyProgramReceipt` | remedy program receipt | Moderate |
| `deployment-attestation.ts` — `verifyDeploymentAttestation` | deployment attestation profile | Moderate |
| `enterprise.ts` — (sign inline), `verifyEntitlement` | **license entitlement** (`EP-GATE-ENTITLEMENT-v1`) — "the license key IS an EP-style artifact" | Moderate |
| `breakglass.ts` — (sign inline per signer), `verifyBreakGlass` | **M-of-N Ed25519 multi-signature** over canonical JSON | Moderate — already multi-signer roster shaped (`signatures: [{kid, algorithm, value}]`), so adding a second `algorithm` per signer or a required-set is architecturally the closest of the gate surfaces to the agility pattern |
| `zk-range-proof.ts` — `verifyZkRangeReceipt` | ZK range receipt | Uses `ristretto255`/curve25519 (Pedersen-commitment-style ZK, not a signature) — **different primitive family entirely**; a PQ analogue is a research-level lattice-ZK problem, **hard, out of near-term scope** |

## 3. `packages/issue/` — receipt & attestation **issuance** (signing side)

`packages/issue/src/index.ts` is the single source of truth for minting `EP-AUTHORIZATION-RECEIPT-v1` documents (re-exported by `lib/trust-receipt/issuer.js`), used by `packages/attest/`, `lib/commit.ts`, and the CLI.

- **Artifact:** authorization receipt (Class-B/C signoffs over context digests), `EP-MERKLE-v2` checkpoint, log-signed checkpoint.
- **Algorithm:** Ed25519 exclusively — `softwareSignerFromPrivateKey` signs `crypto.sign(null, digest, key)`; `assembleAuthorizationReceipt`'s log checkpoint is `crypto.sign(null, sha256Bytes(canonicalize(checkpoint)), logPrivateKey)`.
- **Key loading:** raw `crypto.KeyObject` or base64url PKCS#8 DER (`privateKeyFromPkcs8B64u`); `generateEd25519KeyPair()` is the only keygen path.
- **Canonical bytes:** `canonicalize = canonicalizeStrictJson` (recursive sorted-key JSON, JCS-equivalent) — the single source of truth `packages/verify` and `packages/require-receipt` both import.
- **Agility hook:** none.
- **Difficulty:** **Hard-with-schema-change** — this is the issuance twin of `verifyReceipt`/`verifyTrustReceipt` in `packages/verify/src/index.ts`; the two must move together (frozen-core discipline, PIP-001), and every downstream consumer (`packages/attest`, `packages/require-receipt`, `packages/openai-guard`, `packages/langchain`, `packages/openai-agents`, `lib/commit.ts`, `lib/agent-record/core.ts`) assumes a single flat `signature: {algorithm, value}` field. This is the highest-leverage, highest-blast-radius surface in the repo for the hybrid program.

## 4. `packages/attest/`

`packages/attest/src/index.ts`:
- `verifyIdentity` — SHA-256 hash comparison only, no signature (identity pin match).
- `signWorkReceipt` — mints an `EP-RECEIPT-v1` (`AttestDocument`) binding a matched identity + work-product hash. **Algorithm:** Ed25519 (`privateKey.asymmetricKeyType !== 'ed25519'` guard). **Canonical bytes:** `canonicalize(payload)` from `packages/issue`. **Agility hook:** none. **Difficulty:** Moderate — small file, but it's a thin wrapper over `packages/issue`'s Ed25519 path, so it inherits whatever `packages/issue` becomes; do them together.

## 5. `mcp-server/` and orchestration packages — **no independent crypto**

- `mcp-server/index.ts` implements zero signing/verification primitives itself. It only imports `strictJsonGate` from `@emilia-protocol/verify/strict-json` for JSON-domain validation. The `mcp__emilia__*` tools (`ep_issue_commit`, `ep_verify_commit`, `ep_verify_receipt`, `ep_check_signoff`, `ep_verify_delegation`, `ep_verify_handshake`, etc.) delegate entirely to `lib/commit.ts`, `packages/verify`, `lib/delegation.ts`, `lib/handshake/verify.ts`. **No wiring needed here directly** — hybridizing `lib/commit.ts` / `packages/verify` propagates automatically through the MCP surface.
- Same delegation pattern (confirmed by grep with **zero** direct `crypto.sign`/`crypto.verify` hits) in: `packages/coverage-register`, `packages/checkout-evidence`, `packages/gateway-authz`, `packages/mcp-guard`, `packages/grpc-guard`, `packages/crewai`, `packages/openai-guard` (its `receipt.ts` re-exports `verifyReceipt` from `@emilia-protocol/verify`), `packages/qualify`, `packages/scan`, `packages/fire-drill`, `packages/fire-drill-mcp`, `packages/crash-test`, `packages/dtc-base`, `packages/langchain`, `packages/openai-agents` (doc-comment references to "offline Ed25519 over canonical JSON," no own crypto).
- `packages/require-receipt/src/jws.ts` — **EP-RECEIPT-JWS-PROFILE-v1**, a *parallel* RFC 7515 JWS envelope over the same receipt payload. `alg: 'EdDSA'`, `crypto.sign`/verify via Node's built-in Ed25519, canonical bytes = `canonicalizeStrictJson(payload)`. No agility hook. **Difficulty: Moderate** but it needs its own JWS `alg` negotiation story (`EdDSA` + a to-be-registered ML-DSA JOSE `alg` — IETF has draft work here (`draft-ietf-cose-dilithium`/ML-DSA JOSE registration) but it is not yet a finalized standard, so this is genuinely blocked on an external spec, not just EP code).
- `packages/require-receipt/src/index.ts` — `verifyEmiliaReceipt` composes `packages/verify`'s `verifyReceipt`; no independent crypto.
- `packages/mobile/src/*` — `verifyMobileActionIdentity`, `verifyMobileCeremony`, `verifyMobileAck`, `verifyMobileExecutionRecord`: Ed25519 over `canonicalize()`, same pattern as gate/verify. Moderate.

## 6. `lib/` (large surface — grouped)

### 6a. Core signing/verification infrastructure
| File | Role | Algorithm | Agility hook | Difficulty |
|---|---|---|---|---|
| `lib/signatures.ts` — `verifyReceiptSignature`, `resolveProvenanceTier` | legacy `identified_signed` provenance-tier signature check for receipts | Ed25519 | No | Moderate |
| `lib/commit.ts` — sign/verify (`signPayload`/`verifyPayload` equivalents), `verifyCommit` | **the "commit" artifact** (delegation/authorization commit — what `ep_issue_commit`/`ep_verify_commit` MCP tools expose) | Ed25519, via `resolveIssuerSigner()` custody boundary | No | Moderate–Hard — highest-traffic production signer in the app layer |
| `lib/key-custody.ts`, `lib/custody-signers.ts` | signer **infrastructure**, not an artifact | Ed25519-only by design; explicit callout: *"AWS KMS and GCP Cloud KMS do NOT support Ed25519 signing today... there is no honest AWS-KMS Ed25519 signer"* — only Vault Transit or a PKCS#11 HSM sign Ed25519 today | No | **Hard** — the `CustodySigner` interface (`sign(bytes)->base64url`, `publicKeySpkiB64u`) is single-key/single-signature by design. Hybrid needs a second registered signer (an ML-DSA custody path) and every call site (`lib/commit.ts`, others) to call both and assemble a combined envelope. This is the load-bearing seam for *every* production issuance path — get this interface right once and most `lib/` and `packages/gate` signers inherit it |
| `lib/envelope/envelope.ts` — `verifyEnvelope` | generic **EP-ENVELOPE-v1** wrapper | `ALLOWED_ALGS = ['Ed25519','EdDSA','ES256']` (already a small allow-list, not literally hardcoded to one alg) | No (list doesn't include ML-DSA) | Moderate — closest `lib/` surface to agility-shaped already (has an explicit alg allow-list to extend) |
| ~~`lib/quantum-safe.ts`~~ | **duplicate of `pq-hybrid.ts`**, unused outside its own test | Ed25519 + ML-DSA-65 (hybrid, both required) | **Was** a hook, but orphaned | **DELETED in wave 2**; the canonical module is `packages/verify/src/pq-hybrid.ts` |
| `lib/guard-evidence-receipt.ts` — `signEvidenceReceipt` | evidence receipt (guard) | Ed25519 | No | Moderate |
| `lib/demo-receipt.ts` — `signDemoPayload` | demo-only receipt | Ed25519 | No | N/A (demo path) |
| `lib/quorum-web.ts` — `verifyQuorum` | browser mirror of `packages/verify/src/quorum.ts` | ES256 (WebAuthn) | No | Hard — same hardware-authenticator ceiling |
| `lib/revocation/revocation.ts` — `verifyRevocation` | mirrors `packages/verify/src/revocation.ts`'s **EP-REVOCATION-v1** | Ed25519 | No | Moderate (keep in lockstep with the verify-package twin) |

### 6b. Domain/vertical artifacts (all Ed25519-over-`canonicalize()`, no agility import)
| File | Artifact | Notes |
|---|---|---|
| `lib/wysiwys/render.ts` — `verifyDisplayAttestation` | **EP-DISPLAY-ATTESTATION-v1** ("what the human actually saw") | Moderate |
| `lib/agent-record/core.ts` — `signAgentRecordObservation`, `verifyAgentRecordObservation` | **agent record observation** (`EP-AGENT-RECORD-OBSERVATION-v1`) | Moderate |
| `lib/ncpdp/rx-reliance.ts` — `signRxArtifact`, `verifyRxArtifact` | pharmacy (NCPDP) reliance artifact | Moderate |
| `lib/health/davinci-pas-consequence-control.ts`, `lib/health/proposal-to-effect-profile.ts`, `lib/health/program-integrity.ts` | healthcare consequence-control / proposal-to-effect / program-integrity packets — all EP-issued, Ed25519 | Moderate each |
| `lib/frontier/model-to-matter.ts` — `signModelToMatterEvidence`, `signModelToMatterEffect`, plus verifies | robotics/physical-effect evidence & effect artifacts | Moderate |
| `lib/authority/proof.ts` — `signAuthorityProof`, `verifyAuthorityProofSignature`/`verifyAuthorityProof` | **EP-AUTHORITY-PROOF-v1** (registry issuer signs) | Moderate |
| `lib/authority/authority-doc.ts` — sign inline, `verifyAuthorityChain`, `verifyEndorsement` | authority document chain + endorsements | Moderate |
| `lib/grace/mobile-grid.ts` — `signGraceArtifact`, `verifyGraceArtifact`, `verifyGraceMobileAuthorization`, `verifyActionStateSignedStatement` | Grace curtailment artifacts | Moderate |
| `lib/eye/eye-set.ts` — sign inline, `verifyEyeSet` | **EP-EYE-SET-v1** | Moderate |
| `lib/evidence/evidence-graph.ts` — `signRelianceResult`, `verifyRelianceResult` | **EP-AEG-v1** reliance-result signing | Moderate |
| `lib/mobile/action-continuity.ts` — sign inline, `verifyMobileProviderOutcome` | mobile action continuity / provider outcome | Moderate |
| `lib/execution/integrity.ts` — sign inline, `verifyExecutionIntegrity` | **EP-EXECUTION-INTEGRITY-v1** (executor signature) | Moderate |
| `lib/arena/refusal.ts` — `signArenaRefusal`, `verifyArenaPublicProjection` | arena public refusal record | Moderate |

### 6c. External / hardware / third-party-key surfaces inside `lib/` (flag separately, §7)
| File | What it verifies | Algorithm |
|---|---|---|
| `lib/mobile/attestation.ts` — `verifyAppleRuntimeSignals`, `verifyMobilePasskeyRegistration` | **Apple App Attest / Play Integrity** device attestation | ES256/P-256, `X509Certificate` chain — Apple/Google's format, `jose` `SignJWT` for Play Integrity assertion |
| `lib/agent-adoption/webauthn.ts` — `verifyAgentAdoptionRegistration`, `verifyAgentAdoptionAssertion` | WebAuthn agent-adoption ceremony | ES256/P-256 (WebAuthn spec-mandated) |
| `lib/release-lock/registration.ts`, `lib/release-lock/action-check.ts` | Release Lock WebAuthn credential | "Release Lock requires an ES256 P-256 credential" (hardcoded) |
| `lib/sso/session.ts` — `verifySession` | SSO session JWT | `jose.SignJWT`/`jose.jwtVerify` — algorithm is whatever `jose` negotiates (HS256/ES256 depending on config), an IdP-facing format |
| `lib/sso/state.ts` — `signState`, `verifyState` | SSO transient CSRF-style state token | **HMAC-SHA256**, symmetric — no asymmetric hybrid concept applies |
| `lib/trust-desk/hash.ts`, `lib/trust-desk/signing.ts` — `signClaim` | Trust Desk claim envelope | **HMAC-SHA256**, explicitly called out in comments as an *interim* stand-in ("HMAC today; an EP Commit receipt replaces the signature in v1.1") — should migrate to `lib/commit.ts`'s Ed25519 path before it's a hybrid candidate at all |
| `lib/adapters/github.ts`, `apps/consequence-actuator-service/src/github-app.ts`, `apps/consequence-control-service/src/github-app.ts`, `apps/gate-service/src/*` | GitHub App identity/auth | **RS256** — mandated by GitHub's own App JWT auth protocol; EP cannot change this |
| `lib/integrations/action-escrow/procore-change-order.ts` — `verifyProcoreChangeOrderEvidence` | Procore (construction) change-order evidence | SHA-256 digest match only (no asymmetric signature verified in this file) |

## 7. External-verification surfaces — explicitly out of scope for the hybrid program

These verify signatures **minted by parties EP does not control**, so EP cannot add an ML-DSA leg to them — the foreign signer decides the algorithm(s):

- **AEB adapter family** (`packages/verify/src/aeb-*-adapter.ts`, `ap2-native-adapter.ts`, `fido-ap2-bridge.ts`): APS, CCS/PyPI (HMAC), CHAP, mcgraw budget grants, OASNT (ES256), OAuth txn-challenge (ES256/EdDSA), PSEA (ES256), WAG (ES256), WIMSE/OAuth SPT (Ed25519/EdDSA), AP2 mandates, FIDO-bridged AP2. **Notable exception worth flagging positively:** `aeb-mcgraw-delegation-adapter.ts` already verifies a **foreign COSE_Sign1 signature under `cose-ml-dsa`** — i.e., one external ecosystem (`draft-mcgraw-httpapi-agent-budget`) is *already* PQ-signed on their side; EP's adapter already speaks ML-DSA for verification purposes there (worth studying as a real-world COSE/ML-DSA parsing reference even though it's not "our" hybrid work).
- **`timestamp-proof.ts`**: RFC 3161 TSA tokens — RSA/ECDSA per CMS SignedInfo, external PKI.
- **`platform-attestation.ts`**: RFC 9711 EAT/JWS device attestation — third-party attestation-service format.
- **`lib/mobile/attestation.ts`**: Apple App Attest / Google Play Integrity — vendor-owned formats.
- **WebAuthn-anchored surfaces**: `verifyWebAuthnSignoff` (in `packages/verify/src/index.ts` and its `lib/verify-web.js` browser mirror), `packages/verify/src/quorum.ts`/`lib/quorum-web.ts`, `lib/agent-adoption/webauthn.ts`, `lib/release-lock/*` — all ES256/P-256 because the signer is a FIDO2 hardware authenticator or platform passkey, not an EP-issued key. A hybrid upgrade here is gated on FIDO Alliance / W3C WebAuthn PQC extensions landing in browsers and authenticators, not on EP code.
- **`lib/adapters/github.ts` + `apps/*/github-app.ts`**: GitHub App RS256 JWTs — GitHub's own auth protocol.
- **`lib/integrations/action-escrow/procore-change-order.ts`**: Procore's evidence format.
- **`authorization-server-confirmation.ts` / `policy-decision-evidence.ts`**: quasi-external — EP ships the Ed25519 sign+verify code, but the *signer* is logically a third-party AS or policy engine (OPA/Cerbos) that adopted EP's library. Upgrading these to hybrid is technically an EP code change, but is **coordination-dependent**: every AS/policy-engine integration that vendored this signing helper needs to re-deploy with the new key material before verification can require both algorithms.
- **`lib/sso/session.ts`** (`jose` JWT session tokens) sits at the IdP boundary; algorithm is negotiated by `jose`/the IdP's OIDC configuration, not fixed by EP.

## 8. Tracked schema/version strings that would need bumps

The repo defines **several hundred** `*_VERSION`/`@version` string constants (one per artifact type, e.g. `EP-RECEIPT-v1`, `EP-AUTHORIZATION-RECEIPT-v1`, `EP-QUORUM-v1`, `EP-REVOCATION-v1`, `EP-CAPABILITY-RECEIPT-v1`, `EP-CONSENT-GRANT-v1`, `EP-GATE-COVERAGE-INVENTORY-v1`, `EP-FIELD-ORIGIN-v0.1`, `EP-GATE-ADMISSION-RECORD-v2`, `EP-ACTION-REFUSAL-STATEMENT-v1`, `EP-ATTEST-v2`, `EP-ACTION-ESCROW-STATE-v1`, etc. — full list gathered during the sweep, ~300 constants). The pattern that determines whether a bump is needed:

- Every artifact today carries a **single, flat** `signature: { algorithm: 'Ed25519', value/signature_b64u: string }` (or `signatures: [...]` for the small number of *multi-signer-role* artifacts: `breakglass.ts`, `reliance-agreement.ts`, quorum members). Adding a second signature/algorithm changes that field's **shape**, not just its content — that is a wire-format change and, per this repo's own frozen-core discipline (PIP-001) and the SemVer-ish `-v1`/`-v2` suffixes already in use elsewhere (e.g. `EP-GATE-ADMISSION-RECORD-v2`, `EP-MERKLE-v2`, `EP-COVERAGE-POPULATION-v2`), it warrants a version bump for each artifact type touched (`-v1` → `-v2`, or an additive `hybrid_signature` sibling field with its own sub-version like `EP-SIG-AGILITY-v1` uses).
- The **one exception** that does **not** need a schema bump: `EP-EVIDENCE-REATTESTATION-v1` already carries `alg: string` per entry (`'Ed25519' | 'ML-DSA-65'`) — the shape already anticipates multiple algorithms.
- `EP-SIG-AGILITY-v1` and `EP-HYBRID-SIGNATURE-v1` are themselves already-versioned, already-shaped-for-multi-algorithm envelopes — they are the schema to reuse rather than reinvent per artifact.
- `EP-ENVELOPE-v1`'s `ALLOWED_ALGS` allow-list (`Ed25519, EdDSA, ES256`) would need `ML-DSA-65` added — a small, contained change relative to the receipt-shape changes elsewhere.

---

## Hybrid-wiring priority ranking (internal surfaces only)

1. **Receipt issuance + core verification** (`packages/issue/src/index.ts` assemble/sign path + `packages/verify/src/index.ts` `verifyReceipt`/`verifyTrustReceipt`, and `lib/commit.ts`'s commit signing which shares the custody boundary) — highest leverage, everything downstream (attest, require-receipt, openai-guard, langchain, openai-agents, mobile, gate) inherits from here. **Hard-with-schema-change**, and blocked first on `lib/key-custody.ts`'s single-signer interface.
2. **Quorum / WebAuthn signoffs** (`packages/verify/src/quorum.ts`, `lib/quorum-web.ts`, `verifyWebAuthnSignoff`) — flagged next by the user's own priority order, but note this is **not** a pure code-wiring problem: it's gated on FIDO2/WebAuthn hardware PQC support, so it should be tracked as a *dependency-watch* item, not a near-term implementation task.
3. **Evidence-record family** — already done for reattestation (`EP-EVIDENCE-REATTESTATION-v1`); extend the same `pq-signature-agility` pattern to the *base* evidence-record's protected-artifact signature and to `packages/gate/src/evidence.ts`'s log (currently unsigned hash-chain — would need a signed-checkpoint addition first).
4. **Capability receipt, consent grant, coverage inventory/probe/reconciliation, field-origin evidence, admission record** (admission record needs a signed-checkpoint feature added before "hybrid" is even meaningful), **refusal statement, escrow (custodian/state/package), attestation (`packages/attest`)** — all structurally identical Ed25519-over-`canonicalize()` modules; once the `key-custody` dual-signer interface and one reference migration (e.g. `revocation.ts`, the smallest of these) are done, the rest is mechanical repetition of the same pattern across ~45 files in `packages/gate/src` and `lib/`.
5. **Remaining `lib/` domain artifacts** (health, ncpdp, frontier/model-to-matter, grace, eye-set, evidence-graph, authority proof/doc, agent-record, wysiwys) — same mechanical pattern, lower individual traffic/urgency.
6. **`lib/envelope/envelope.ts`** — small, contained, good "quick win" to add `ML-DSA-65` to the `ALLOWED_ALGS` list once a producer exists.
7. **Out of scope**: everything in §7 (external formats/foreign signers/hardware authenticators/vendor PKI), plus `packages/gate/src/zk-range-proof.ts` (different primitive family — ristretto255 ZK, not a signature) and `lib/sso/state.ts`/`lib/trust-desk/hash.ts` (symmetric HMAC, not an asymmetric-signature upgrade candidate as-is).

## Counts

- **N ≈ 70 internal signing/verification modules** identified across `packages/verify/src/` (~16 native artifact modules, excluding the 11 external AEB adapters), `packages/gate/src/` (~29 modules), `packages/issue/` (1), `packages/attest/` (1), and `lib/` (~23 native modules, excluding the 8 external/hardware-bound `lib/` files and excluding pure hash-chain/HMAC files with no asymmetric signature).
- **M = 1 already agility-ready** at sweep time: `packages/verify/src/evidence-record.ts`'s `EP-EVIDENCE-REATTESTATION-v1` (via `pq-signature-agility.ts`). One more building block existed but was **unwired to any artifact** (`pq-hybrid.ts`) — not counted in M since it did not protect a live artifact yet. Its duplicate `lib/quantum-safe.ts` was deleted in wave 2.
- **K ≈ 69 would need a schema/version bump** to carry a second signature/algorithm (essentially every internal surface except the one already-agile evidence-reattestation module) — because the wire shape today is a single flat `{algorithm, value}` object rather than an array/agile set, per §8.
---

## PATTERN: the reference hybrid migration (wave 2, workstream A)

Wave 2 landed the two things priority item 1 was blocked on plus the reference migration named in priority item 4. Everything below is code in the repository, not a plan.

**The seam (`lib/key-custody.ts`, `lib/custody-signers.ts`).** `CustodySigner` is unchanged and every existing call site is untouched. `createHybridCustodySigner({ classical, pq })` WRAPS a `CustodySigner` and returns one that still satisfies `CustodySigner` exactly (same `keyId`, `custody`, `publicKeySpkiB64u`, and a `sign()` that returns byte-identical Ed25519 bytes), plus `signSet()` for callers that opt in. `registerCustodySigner()` and `resolveIssuerSigner()` take it with no change; `isHybridCustodySigner()` is how an aware call site detects it. The post-quantum leg is `createPqCustodySigner()` (shape validation only) with the concrete backend in `softwareMldsaSigner()`.

The custody note is recorded, not smoothed over: **EP has not adopted a KMS or HSM ML-DSA-65 signing path**, so `PqCustodySigner.custody` is `'software'`, the secret key lives in process memory, and the default backend is a pure-JS FIPS 204 implementation that is not independently audited and is not a FIPS validated module. `assertProductionKeyCustody()` was deliberately NOT extended to bless it: a deployment that requires kms/hsm custody still requires it, and the PQ leg does not satisfy it.

**Corrected 2026-08-18.** An earlier revision of this paragraph said no such path existed. That was wrong, and the correction matters more than the original claim.

VERIFIED DIRECTLY (fetched and read 2026-08-18, primary sources named):
- AWS KMS supports ML-DSA key specs `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` for asymmetric KMS keys, with the `ML_DSA_SHAKE_256` signing algorithm, private key never leaving KMS unencrypted (https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html). The launch announcement is dated 2025-06-13 and states general availability, initially in US West (N. California) and Europe (Milan) (https://aws.amazon.com/about-aws/whats-new/2025/06/aws-kms-post-quantum-ml-dsa-digital-signatures/).
- CMVP certificate 4884 covers the AWS Key Management Service HSM, FIPS 140-3 Level 3, validated 2024-11-18, and its approved-algorithm list contains AES, ECDSA, HMAC-SHA, RSA, SHA, Counter DRBG, KAS-ECC, KDA, KDF and KTS-IFC, with NO ML-DSA and no FIPS 204 (https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4884).

So the honest reason EP's PQ leg is software-held is ADOPTION, not availability.

**What adopting a managed KMS would and would not change.** It would move the PQ secret key out of EP's process and let `custody` report `'kms'`. It would change EP's FIPS posture by nothing at all. Because ML-DSA is absent from certificate 4884's approved algorithms, the truthful sentence about that deployment is "executes on hardware that holds a FIPS 140-3 Level 3 module validation for other algorithms," never "runs inside a validated module." Invoking an unapproved algorithm inside a validated module is a defined condition in FIPS 140-3 terms, not a technicality.

REPORTED BUT NOT INDEPENDENTLY VERIFIED BY EP (recorded so the gap is visible, not as fact): Google Cloud KMS ML-DSA signing at a software protection level; Fortanix DSM ML-DSA object types; HashiCorp Vault Enterprise Transit `ml-dsa` as an experimental feature; Apple CryptoKit `SecureEnclave.MLDSA65` on iOS/macOS 26; ML-DSA in the firmware of self-operated HSM appliances; and the existence of any CMVP certificate whose approved-algorithm list includes ML-DSA. CMVP certificate 5450 (Luna T7, Thales Trusted Cyber Technologies, Level 3, validated 2026-07-29) was confirmed to exist, but its algorithm list is published only in a security-policy PDF that EP has not read. Do not repeat any item in this paragraph as an EP claim until someone reads the primary source. One sweep in this lane produced fabricated vendor citations that were caught and retracted, which is why this separation exists.

Two further boundaries survive any custody move: verification stays pure-JS software on the relying party's side, since no signer's custody improves a verifier, and AWS's ML-DSA signing is the hedged (randomized) FIPS 204 variant, so signature bytes are not reproducible across calls.

**The reference migration: `EP-REVOCATION-v2`** (`packages/verify/src/revocation.ts`, twinned by `lib/revocation/revocation.ts`). This is the smallest complete hybrid migration and it is the template. Copy these five moves per surface:

1. **Version bump, not a field bump.** A second signature changes the SHAPE of the proof, which is a wire-format change, so the artifact takes a new `@version` (`-v1` to `-v2`). Leave the v1 verifier alone. It then refuses a v2 artifact on the version marker BEFORE inspecting any signature, which is the required outcome: a deployed v1 verifier must never accept a hybrid artifact on the strength of the one leg it understands, and it must not crash. Captured refusal, from `verifyRevocation()` handed a real v2 statement: `valid: false`, `checks.version: false`, `errors[0] = "unsupported version: EP-REVOCATION-v2"`.
2. **Set shape.** `proof` carries `required_algorithms` plus a `signatures` array shaped exactly like `EP-SIG-AGILITY-v1`'s `AgileSignature` (`{ alg, sig, key_id? }`), one entry per algorithm in the registered order. Reuse that shape verbatim. Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw base64url public key bytes.
3. **Anti-stripping bytes.** The required algorithm SET goes INSIDE the signed bytes. Drop the ML-DSA leg and narrow `required_algorithms` and the surviving Ed25519 signature no longer verifies, because the bytes changed; leave the set intact and the missing leg is a structural refusal. This is a byte-level commitment, strictly stronger than `EP-SIG-AGILITY-v1`'s `hybrid_all` policy alone, which that module honestly documents as relying-party POLICY. Same discipline as `EP-RECEIPT-HYBRID-v1` (`packages/issue/src/hybrid-issuance.ts`). The verifier rebuilds the bytes from the REGISTERED set and from fields it recomputed itself; the presented artifact never chooses what it is checked against.
4. **v1 compatibility.** v1 artifacts keep verifying through the unchanged synchronous verifier. v2 verification is ASYNC (ML-DSA verification is async), so it is a SEPARATE entry point rather than a signature change to the v1 function, with a router (`verifyRevocationStatement`) for callers holding a mixed bag. Do not make the v1 verifier async.
5. **Named refusals.** Every failure sets a named check false and pushes a readable error; nothing throws on caller input. An absent ML-DSA backend is `pq_backend_unavailable`, never a skipped check and never a pass on the classical leg.

**Twin discipline.** Where a `lib/` twin of a `packages/verify` verifier exists, the v2 verifier is COMPOSED from the published one rather than copied (`lib/revocation/revocation.ts` re-exports it and adds only the issuer-side builder). One verification body in the repository means the twins cannot drift; the test asserts they are the same function object.

**Highest-traffic adoption: `EP-COMMIT-HYBRID-v1`** (`lib/commit-hybrid.ts`, wired into `lib/commit.ts`). Opt-in through the seam: when a `HybridCustodySigner` is registered, `issueCommit()` additionally returns a detached, set-committed proof as `hybrid_proof`, and `verifyCommit(id, { hybrid: { required, proof, keys } })` accepts it. With no hybrid signer configured, the code path does not run and issuance is byte-identical to before (pinned by a regression test that independently recomputes the canonical bytes and the exact `commits` column set). The proof is deliberately NOT a column on `commits`, so this profile needs no migration and no DB contract change.

The honest boundary is stated in the module and repeated here: inside a hybrid proof one leg alone never verifies, but the commit ROW remains a valid v1 artifact, so requiring the PQ leg is a relying-party PIN. This makes the pin available and refuses without it; it cannot make a verifier that never asks.

**What the battalion should NOT do.** Do not add an optional second signature to an existing `-v1` artifact. Do not make an existing synchronous verifier async. Do not narrow `requiredAlgorithms` to what an artifact presented. Do not treat a missing ML-DSA backend as a skipped check. Do not describe any of this as deployed, default, or certified: every hybrid profile in the repository is opt-in, and none of them is on in any deployment.

---

## MIGRATION POSTURE AND THE REMAINING SURFACES (wave 2, workstream B)

Four bounded items. Everything below is code in the repository, not a plan.

### 1. `dual`: the compatibility-preserving migration default candidate

`packages/gate/src/hybrid-receipt-profile.ts` gains a fourth `hybrid_issuance` mode between `enabled` and `required`. In `dual`, every issuance mints BOTH the `EP-RECEIPT-v1` receipt and its `EP-RECEIPT-HYBRID-v1` twin over one canonical payload, and returns `{ classical_receipt, hybrid_receipt, action_digest }` under the result marker `EP-RECEIPT-DUAL-ISSUANCE-v1`.

Why this is the migration default candidate, stated as three separate claims rather than one slogan:

- **A deployed v1 verifier keeps working.** The classical twin is a real `EP-RECEIPT-v1` receipt with the flat `signature` field v1 verifiers already read. Nothing downstream has to move on the Gate's schedule.
- **Longevity exists for everything.** The hybrid twin exists from the moment the action happened. Turning hybrid on later instead leaves a permanent window of actions with no post-quantum leg, and a receipt cannot be given one retroactively. `EP-EVIDENCE-REATTESTATION-v1` can re-anchor an old receipt's integrity, but only while the classical algorithm is still unbroken, and re-anchored evidence is not a signature the issuer made at the time.
- **Hybrid-only remains the strict end-state.** `dual` is a posture, not a destination. It still emits an artifact a quantum adversary could forge; `required` is where a deployment lands once its verifiers have moved.

The boundary, kept: two receipts over one payload is a compatibility arrangement, not a security upgrade to the classical artifact. A verifier that checks only the classical twin has gained nothing.

`EP-RECEIPT-DUAL-ISSUANCE-v1` names the RESULT PAIR and appears on neither artifact. No verifier has to learn a new envelope for a Gate to run in `dual`. The twin link is CHECKED, not asserted: `action_digest` (`sha256:<hex>` over the canonical payload) is recomputed from each returned receipt's own `payload`, and any disagreement is `dual_payload_mismatch`. The hybrid twin is minted FIRST so a dual issuance that cannot be completed refuses before the classical issuer's side effect, leaving no orphan receipt behind. Acceptance under `dual` behaves as under `enabled`: each artifact is checked on its own terms, because a relying party is handed one artifact and relies on it.

### 2. The duplicate hybrid envelope is gone

`lib/quantum-safe.ts` was deleted; `packages/verify/src/pq-hybrid.ts` is the one implementation. `tests/pq-hybrid-envelope.test.ts` replaces the old app-tier test and exercises the canonical module.

The two were never wire-compatible, so a re-export shim was not available: the duplicate's envelope was `{ type: 'EP-HYBRID-SIGNATURE-v1', payload_sha256, key_ids, signatures }` with a synchronous verifier, against the canonical `{ alg: 'EP-HYBRID-v1', signature_algos, sigs }` with an asynchronous one. Not one exported name matched in both signature and semantics. Deleting and repointing was therefore the lower-churn path AND the honest one; a shim would have silently changed the meaning of every exported name.

**The note worth carrying forward, stated precisely.** The adversarial-review pass that hardened the classical leg (curve pin plus exact signature and public-key length pins) touched `packages/verify/src/pq-hybrid.ts` and `packages/verify/src/pq-signature-agility.ts`. It did not touch `lib/quantum-safe.ts`. Reading the deleted file directly, its own equivalent pins were present, so no exploitable hole was found in it: it curve-checked KeyObject and PEM inputs, accepted raw public keys only at 32 bytes, and length-pinned both signatures. The danger was structural rather than realised. A security fix landed on one copy of a verification primitive and not the other, and nothing in the build would have caught it if the copy had been weaker. That is the argument for consolidation, and it does not depend on the duplicate having been broken.

### 3. `EP-ENVELOPE-v1` proofs: `ML-DSA-65` with a verification path

`lib/envelope/envelope.ts` adds `ML-DSA-65` to `ALLOWED_ALGS`, with a check behind it rather than a bare list entry. An algorithm a verifier lets through but cannot evaluate is worse than one it refuses, because the refusal is visible and the pass is not.

- `verifyEnvelope` stays synchronous and unchanged for existing callers, and gains one structural pin: an `ML-DSA-65` proof signature must decode from strict base64url to exactly the FIPS 204 length, or `proof_signature_wellformed` fails with the agility module's own `malformed_signature` reason.
- `verifyEnvelopeProofs` (async) routes `Ed25519` and `ML-DSA-65` to `verifyAgileSignature` over `envelopeProofBytes(env)`, a domain-separated canonical form of the envelope's signed members (`proofs`, `anchor`, `meta` are outside it). The closed registry, the key pin, the exact length pin, and the "no backend is a refusal" rule all stay in `packages/verify/src/pq-signature-agility.ts`; none is reimplemented.
- `EdDSA` and `ES256` remain structurally allow-listed for wrapped legacy profiles whose inner verifier owns the signature, and are reported `verified: false` with `alg_not_verifiable_here`. An unchecked proof never counts toward a pass.
- `verifyEnvelopeWithProofs` ANDs the two verdicts, so the proof check can only ADD a rejection. A genuine signature cannot rescue a structurally invalid envelope.

### 4. `EP-EVIDENCE-RECORD-v1` base records go agile

`packages/verify/src/evidence-record.ts` adds `verifyEvidenceRecordAgile`. `verifyEvidenceRecord` is unchanged and still routes every archive timestamp through the Ed25519-only `verifyTimeAttestation`. The two share one chain walk (`walkEvidenceRecord`) with the per-attestation signature verdict injected, so they cannot drift on version, protected-hash binding, hash linkage, or monotonic time; the tests assert identical `checks` and `errors` for v1 records under both entry points.

The agile path differs in exactly one place. A v1-shaped proof takes the unchanged v1 path. A proof declaring `algorithm: 'ML-DSA-65'` goes to `verifyAgileSignature` over the SAME bytes, which are now produced by one exported helper (`timeAttestationSignedBytes`) rather than a second definition. A pin may name several algorithm-tagged keys for one authority (`keys: [{ alg, public_key }]`), which is what a chain that renews across an algorithm transition actually needs.

**Never one leg of a set.** A SET-SHAPED proof (`proof.signatures: [...]`) goes to `verifyAgileSignatureSet` under policy `hybrid_all` with `requiredAlgorithms` defaulting to the FULL registry. One valid Ed25519 leg inside a set-shaped proof is a refusal (`missing_required_algorithm`), not a pass. A relying party may narrow the required set, and narrowing is then a decision written at its call site; the default never narrows itself to whatever happened to be presented.

The v1 boundary is unchanged and still applies: a verified chain proves the artifact was continuously time-anchored by pinned authorities under algorithms the relying party accepts. It does not prove the artifact was correct, and it cannot prove a renewal happened before its predecessor algorithm actually broke.

---

## MIGRATION STATUS (2026-08-17, battalion waves complete)

Every internally signed EP artifact surface in `packages/verify`, `packages/gate`, `packages/issue`, `packages/attest`, and `lib/` now carries a hybrid Ed25519 + ML-DSA-65 profile on the EP-REVOCATION-v2 pattern (version bump, AgileSignature set shape, anti-stripping byte commitment, separate async entry point, named refusals), with these named exceptions, each a boundary rather than a backlog item:

- **WebAuthn/FIDO surfaces** (quorum signoffs, Class A approver signatures, agent adoption, release locks): the signer is a hardware authenticator or platform passkey EP does not control. Gated on FIDO Alliance / W3C PQC support, tracked as a dependency watch.
- **Browser verifier twins** (`packages/verify/src/web.ts`, `lib/verify-web.js`): Web Crypto has no ML-DSA-65. The twins refuse hybrid artifacts by version marker (pinned by test in both copies) rather than shipping a verifier that could only pass on the classical leg.
- **DSSE / in-toto (gate qualification)**: DSSE signatures carry no algorithm identifier and the PAE leaves no signed location for a required-algorithm set. Registration-gated; refuses `alg_registration_pending`.
- **MEMORY-PROJECTION-RECORD-v1**: joint I-D wire (draft-ferro-schrock) is byte-for-byte unchanged; a detached EP-side co-signature (`EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1`) exists, and the -01 requirements for a native set-shaped proof are recorded in the module header. Coordination-gated.
- **`lib/approval-acquisition/evidence.ts`, `lib/demo-receipt.ts`, fixture generators** (eg1, grace reference scenarios): mint or consume the frozen v1 core or demo fixtures only; adoption sites for the core hybrid issuance entry points, not independent signing surfaces.
- **Symmetric/HMAC and ZK modules**: different primitive families, out of scope as before.

Verification parity exists in three languages: the JS verifiers, a Python port (`conformance/py`, refusal strings byte-identical, 26 of 27 reachable), and a Go port (`packages/go-verify` structural + `conformance/go` live backend via CIRCL). Cross-implementation ML-DSA-65 agreement: OpenSSL (via `cryptography`), `dilithium-py`, and CIRCL all verify the `@noble/post-quantum` vectors. This is cross-implementation agreement on signature verification, not an independent implementation of EP.

The posture words are unchanged by completion: every hybrid profile is OPT-IN, none is a deployment default, the software ML-DSA leg does not satisfy kms/hsm custody, and nothing here is FIPS validated. The earned sentence is "hybrid post-quantum signatures available across every internally signed EP evidence surface, verified in JS, Python, and Go, with the named boundaries above." Dual-issuance default flip preconditions: dual-signer custody (done), multi-language verification (done, this wave), FIPS 204 errata settled (external), relying parties on record (open).
