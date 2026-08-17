# PQ Hybrid Program: Signature Surface Inventory

(Generated 2026-08-17 by read-only sweep; the targeting map for staged hybrid wiring. Wave order and boundary rules in the final sections. This inventory describes public code; it contains no strategy or key material.)

# EMILIA Protocol — Signature Surface Inventory (PQ hybrid program)

Scope swept: `packages/verify/src/`, `packages/gate/src/`, `packages/issue/`, `packages/attest/`, `lib/` (all subtrees), `mcp-server/`, plus every other package that imports `crypto.sign`/`crypto.verify`/Ed25519/ECDSA/HMAC (`packages/require-receipt`, `packages/mobile`, `packages/openai-guard`, `packages/langchain`, `packages/openai-agents`, `apps/*-service`, `caid/`, and the AEB adapter family). Findings below are grouped by package. Every row was confirmed against source, not inferred.

**Headline finding:** two generic post-quantum building blocks already exist and are production code, but only **one** artifact type is actually wired to them today:

- `packages/verify/src/pq-signature-agility.ts` (**EP-SIG-AGILITY-v1**) — closed registry `{Ed25519, ML-DSA-65}`, `signAgile`/`verifyAgileSignature`/`verifyAgileSignatureSet`, fail-closed, backend = `@noble/post-quantum` ML-DSA-65. **Consumed by exactly one caller: `packages/verify/src/evidence-record.ts`'s `EP-EVIDENCE-REATTESTATION-v1`** (`createReattestation`/`verifyReattestationChain`). It is also re-exported wholesale from `packages/verify/src/index.ts`, but `verifyReceipt`/`verifyTrustReceipt` themselves remain **hardcoded to Ed25519** (index.ts:397-407 explicitly rejects any `asymmetricKeyType !== 'ed25519'`).
- `packages/verify/src/pq-hybrid.ts` (**EP-HYBRID-SIGNATURE-v1**) — `signHybrid`/`verifyHybrid`, requires *both* Ed25519 and ML-DSA-65 to verify (anti-stripping, unlike agility's policy-only binding). **Not imported by any artifact module** — it's a standalone envelope with its own test file only.
- `lib/quantum-safe.ts` is a **near-duplicate** of `pq-hybrid.ts` (same `EP-HYBRID-SIGNATURE-v1` type tag, same code shape) living in `lib/` instead of `packages/verify/src/`. Its only consumer is `tests/quantum-safe-signatures.test.ts` — **dead code / unwired**, and worth flagging to consolidate with `pq-hybrid.ts` regardless of the hybrid program.

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
| `lib/quantum-safe.ts` | **duplicate of `pq-hybrid.ts`**, unused outside its own test | Ed25519 + ML-DSA-65 (hybrid, both required) | **Is** a hook, but orphaned | n/a — recommend deleting/merging into `packages/verify/src/pq-hybrid.ts` rather than wiring it up in place |
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
- **M = 1 already agility-ready**: `packages/verify/src/evidence-record.ts`'s `EP-EVIDENCE-REATTESTATION-v1` (via `pq-signature-agility.ts`). Two more building blocks exist but are **unwired to any artifact** (`pq-hybrid.ts`, and its unused duplicate `lib/quantum-safe.ts`) — not counted in M since they don't protect a live artifact yet.
- **K ≈ 69 would need a schema/version bump** to carry a second signature/algorithm (essentially every internal surface except the one already-agile evidence-reattestation module) — because the wire shape today is a single flat `{algorithm, value}` object rather than an array/agile set, per §8.