/**
 * @emilia-protocol/verify — Zero-Dependency Trust Verification
 *
 * Verify EP trust receipts, Merkle anchors, and commitment proofs
 * using ONLY Node.js built-in crypto. No EP infrastructure required.
 *
 * This is the core primitive that makes EP a protocol, not an API.
 * Anyone can verify. No account. No API key. Just math.
 *
 * @license Apache-2.0
 */
type Obj = Record<string, any>;
export { AGENTROA_DRAFT, verifyAgentROA } from './agentroa.js';
export { OUTCOME_ATTESTATION_VERSION, OUTCOME_ATTESTATION_DOMAIN, OUTCOME_BINDING_VERSION, OUTCOME_BINDING_OUTCOMES, buildOutcomeAttestation, verifyOutcomeAttestation, observedEffectsDigest, trustReceiptDigest, } from './outcome-binding.js';
export { ORPRG_JSON_JCS_PROFILE, ORPRG_ACTION_PROFILE, computeOrprgActionDigest, verifyOrprgJsonJcsPermit, verifyOrprgJsonJcsPermitAsync, createOrprgAecVerifier, } from './orprg.js';
declare function canonicalize(value: any): string;
/**
 * EP canonicalization profile (RFC 8785 / JCS over an I-JSON profile).
 *
 * canonicalize() is byte-identical to RFC 8785 JCS for the value subset EP signs:
 * strings, booleans, null, arrays, objects, and SAFE INTEGERS. It deliberately
 * does NOT support non-integer reals: ECMAScript and Python/Go serialize floats
 * differently (e.g. 2400000.0 -> "2400000" vs "2400000.0"), so a raw JSON float
 * in signed material would canonicalize to different bytes across implementations
 * and break cross-language verification. EP therefore requires non-integer
 * quantities to be STRING-encoded (financial amounts already are), eliminating the
 * floating-point canonicalization hazard entirely.
 *
 * isCanonicalizable() lets an issuer assert a value is within the profile BEFORE
 * signing. It is a pure predicate (no throw), so it is safe to call anywhere.
 * Returns true iff every scalar is a string, boolean, null, or safe integer.
 */
export declare function isCanonicalizable(value: any): boolean;
/**
 * EP-QUORUM-v1 ordered-chain hash: the hex SHA-256 of the canonical signoff
 * context. Used to cryptographically link each ordered signoff to its
 * predecessor (context.prev_context_hash), so approval ORDER is proven by the
 * signatures themselves rather than by operator-asserted timestamps. Exported
 * for the quorum verifier; uses the same canonicalize()/sha256() as every other
 * signed-material computation in this file.
 */
export declare function contextChainHash(context: any): string;
export { canonicalize };
export { verifyRevocation, isRevoked, REVOCATION_VERSION } from './revocation.js';
export { verifyProvenanceOffline, PROVENANCE_VERSION } from './provenance.js';
export { verifyTimeAttestation, TIME_ATTESTATION_VERSION } from './time-attestation.js';
export { verifyEvidenceRecord, EVIDENCE_RECORD_VERSION } from './evidence-record.js';
export { verifyCheckpointConsistency, CONSISTENCY_ALG } from './consistency.js';
export { verifyWitnessCosignature, requireWitnessQuorum, witnessSigningDigest, WITNESS_VERSION, WITNESS_DOMAIN_TAG, } from './witness.js';
export { verifyTimestampProof, TIMESTAMP_PROOF_ALG } from './timestamp-proof.js';
export { evaluateCurrency, CURRENCY_VERSION, CURRENCY_STATUS, CURRENCY_REASON, } from './currency.js';
export { verifyConsumptionProof, ReferenceConsumptionTree, CONSUMPTION_PROFILE, CONSUMPTION_LEAF_DOMAIN, SMT_DEPTH, } from './consumption-proof.js';
export { validateInitiatorAttestation, neutralizeStatement, normalizeDigest, bindInto as bindInitiatorAttestation, INITIATOR_ATTESTATION_VERSION, INITIATOR_ATTESTATION_FIELD, INITIATOR_STATEMENT_MAX, } from './initiator-attestation.js';
export { validateSurfaceBinding, bindSurfaceInto, receiptSurfaceBinding, verifySurfaceBinding, normalizeSurfaceDigest, SURFACE_BINDING_VERSION, SURFACE_BINDING_FIELD, } from './surface-binding.js';
export declare const MERKLE_V2_ALG = "EP-MERKLE-v2";
/**
 * Verify an EP receipt document.
 *
 * Performs up to three independent checks:
 *   1. Version — document format is EP-RECEIPT-v1
 *   2. Signature — Ed25519 over the canonical payload
 *   3. Anchor (if present) — Merkle proof reconstructs the claimed root
 *
 * @param {object} doc - EP receipt document (EP-RECEIPT-v1)
 * @param {string} publicKeyBase64url - Signer's Ed25519 public key (base64url SPKI DER)
 * @returns {{ valid: boolean, checks: { version: boolean, signature: boolean, anchor: boolean|null }, error?: string }}
 */
export declare function verifyReceipt(doc: any, publicKeyBase64url: string, opts?: any): Obj;
/**
 * Verify a Merkle inclusion proof.
 *
 * @param {string} leafHash - hex SHA-256 of the receipt
 * @param {Array<{hash: string, position: 'left'|'right'}>} proof - proof steps
 * @param {string} expectedRoot - hex expected Merkle root
 * @returns {boolean}
 */
export declare function verifyMerkleAnchor(leafHash: string, proof: any[], expectedRoot: string, opts?: any): boolean;
/**
 * Verify a Class A (approver-held key) signoff fully offline.
 *
 * What this proves with pure math, no network, no EP server:
 *   - the WebAuthn challenge the device signed equals
 *     SHA-256(JCS(context)) for the EXACT context in the signoff — which
 *     binds the action hash, decision, nonce, approver, and validity window;
 *   - the signature verifies against the approver's enrolled P-256 key;
 *   - the authenticator asserted user presence AND user verification
 *     (a human with the biometric/PIN was there);
 *   - (if rpId supplied) the assertion was scoped to the expected relying
 *     party.
 *
 * What it does NOT prove (EP draft §6.3): that the key wasn't revoked
 * after commit time, or what the human SAW when they signed (§11.3).
 *
 * @param {object} signoff - {
 *   context: object,            // the canonical Authorization Context
 *   webauthn: {
 *     authenticator_data: string,  // b64u
 *     client_data_json: string,    // b64u
 *     signature: string,           // b64u (DER ECDSA)
 *   }
 * }
 * @param {string} approverPublicKeySpkiB64u - enrolled P-256 key, SPKI DER b64u
 * @param {{ rpId?: string, allowedOrigins?: string[] }} [opts]
 * @returns {{ valid: boolean, checks: object, error?: string }}
 */
export declare function verifyWebAuthnSignoff(signoff: any, approverPublicKeySpkiB64u: string, opts?: any): Obj;
/**
 * Verify an EP commitment proof.
 *
 * @param {object} proof - EP commitment proof document (EP-PROOF-v1)
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @param {{ allowUnsigned?: boolean }} options - Set allowUnsigned only for structure/expiry checks.
 * @returns {{ valid: boolean, claim: object, error?: string }}
 */
export declare function verifyCommitmentProof(proof: any, publicKeyBase64url: string | null | undefined, options?: any): Obj;
/**
 * Verify an EP receipt bundle.
 *
 * @param {object} bundle - EP-BUNDLE-v1 format
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @returns {{ valid: boolean, total: number, verified: number, failed: string[] }}
 */
export declare function verifyReceiptBundle(bundle: any, publicKeyBase64url: string): Obj;
/**
 * Verify a Trust Receipt (I-D Section 6.2) fully offline — the Section 6.3
 * algorithm. All six steps; fails closed on any missing input.
 *
 * @param {object} receipt - Section 6.2 Trust Receipt
 * @param {object} opts
 * @param {Record<string, {approver_id:string, public_key:string, key_class?:string, valid_from?:string, valid_to?:string}>} [opts.approverKeys]
 *   - pinned approver key entries by approver_key_id (or a directory extract).
 *   Required for a meaningful result; the body defaults a missing/empty opts to
 *   {} and fails closed rather than throwing.
 * @param {string} [opts.logPublicKey] - trusted log Ed25519 key (base64url SPKI DER)
 * @param {boolean} [opts.strict=false] - require deployment-grade strict checks
 * @param {string} [opts.rpId] - expected WebAuthn RP ID when strict mode sees Class-A signoffs
 * @param {string} [opts.expectedPolicyHash] - expected policy hash when strict mode is enabled
 * @param {boolean} [opts.allowLegacyMerkle] - DORMANT opt-in: verify pre-v2
 *   (sorted-pair, undomain-separated) Merkle inclusion. Never the default; never
 *   used by production gates.
 * @param {boolean} [opts.allowLegacyTrustReceiptMerkle] - alias of allowLegacyMerkle
 * @param {{tree_size:number, root_hash:string, consistency_proof:string[]}} [opts.priorCheckpoint]
 *   OPT-IN append-only check: a checkpoint head this verifier previously
 *   OBSERVED and pinned, plus the RFC 6962 consistency proof from that head to
 *   the receipt's checkpoint (obtained from the log; EP-MERKLE-v2 branch
 *   hashing). When set, verification adds a fail-closed `checks.consistency`
 *   gate. NOTE (honesty): this proves append-only consistency between two
 *   observed heads only; it does NOT establish currency or split-view honesty
 *   by itself (that needs independent witnesses).
 *
 * The five options below are ADDITIVE, OPT-IN knobs. Each runs ONLY when its
 * option is supplied, adds exactly one member to `checks`, and folds into
 * `valid` by conjunction. With none supplied, `checks` keeps its frozen seven
 * members and the result is byte-for-byte unchanged. Each fails closed.
 *
 * @param {{cosignatures:object[], pinnedWitnessKeys:Array<{witness_id:string,public_key:string}>, k:number}} [opts.witnessQuorum]
 *   OPT-IN (EP-WITNESS-v1): require >= k DISTINCT pinned witnesses to have
 *   validly cosigned the receipt's checkpoint head. Adds fail-closed
 *   `checks.witness_quorum` and surfaces the full quorum report as
 *   result.witness_quorum. HONESTY: proves k trusted witnesses attested to ONE
 *   head (local single-view); it does NOT prove no different head was shown
 *   elsewhere (that cross-view gossip is the deployment's responsibility).
 *   Fail-closed: missing receipt checkpoint, bad k, or < k distinct valid
 *   cosignatures each refuse.
 * @param {{token:(string|Buffer), expectedDigest:(string|Buffer), pinnedTsaKeys:(string|string[]|object)}} [opts.timestampProof]
 *   OPT-IN (RFC 3161): verify a TSA timestamp token over a caller-chosen
 *   `expectedDigest` (e.g. the checkpoint root or action digest) against a
 *   PINNED TSA key. Adds fail-closed `checks.timestamp_proof` and surfaces
 *   result.timestamp_proof (tsa_key_id, gen_time, reason). HONESTY: proves a
 *   TSA asserted the digest existed at gen_time; it does NOT prove the action
 *   was correct/authorized and is authentic-as-of-token only (says nothing
 *   about current TSA-cert validity).
 * @param {{now?:(number|string|Date), maxStalenessSeconds?:number, freshHead?:object, freshHeadRequired?:boolean, authentic_as_of_commit?:boolean}} [opts.currency]
 *   OPT-IN (EP-CURRENCY-v1): evaluate currency-at-T. Adds `checks.currency`,
 *   which passes ONLY when a supplied recent non-revoking signed head proves
 *   status `fresh`; BOTH `stale` and the honest offline default `unknown` fail
 *   this opted-in gate (fail-closed: absence of proof of freshness does not
 *   pass). The full two-axis result is surfaced as result.currency. HONESTY:
 *   offline verification can NEVER prove currency; `authentic_as_of_commit` is a
 *   separate axis from `currency_at_T`.
 * @param {object} [opts.consumptionProof]
 *   OPT-IN (EP-SMT-CONSUME-v1): a third-party bundle proving a one-time nonce
 *   went absent -> present exactly once across two append-only-linked heads.
 *   Adds fail-closed `checks.consumption` and surfaces result.consumption.
 *   HONESTY: proves the tree-shaped consumption facts only; checkpoint
 *   SIGNATURES are the caller's responsibility and it does NOT establish
 *   currency of the later head.
 * @param {boolean} [opts.requireInitiatorAttestation]
 *   OPT-IN (EP-INITIATOR-ATTESTATION-v1): when true, structurally validate the
 *   self-asserted initiating-software attestation at
 *   receipt.action.initiator_software. Adds fail-closed
 *   `checks.initiator_attestation` (absent or malformed => false) and surfaces
 *   result.initiator_attestation. HONESTY: says WHICH software asked; it does
 *   NOT prove the software behaved (labels are self-asserted).
 * @returns {{ valid:boolean, checks:object, errors:string[], attestation:{ present:boolean, consistent:boolean, issues:string[] }, strict:{ enabled:boolean, valid:boolean, checks:object, errors:string[] }, witness_quorum?:object, timestamp_proof?:object, currency?:object, consumption?:object, initiator_attestation?:object }}
 *   `attestation` is the PIP-007 §2 ADVISORY report. It never affects `valid` or
 *   any member of `checks`: a receipt with a malformed or inconsistent
 *   attestation still verifies (or fails) on its cryptographic checks alone.
 *   The opt-in `witness_quorum` / `timestamp_proof` / `currency` / `consumption`
 *   / `initiator_attestation` result members are present ONLY when their
 *   respective option was supplied.
 */
export declare function verifyTrustReceipt(receipt: any, opts?: Obj): Obj;
/**
 * Verify a signed Outcome Attestation against the exact, fully verified Trust
 * Receipt whose signed Action Object carries predicted_effects.
 */
export declare function verifyOutcomeBinding(receipt: any, attestation: any, opts?: Obj): Obj;
/**
 * Surface the external agent-identity / delegation evidence (L4) that a
 * decision (L7 PDP) relied on, and OPTIONALLY enforce its freshness.
 *
 * EP does NOT resolve or trust the L4 identity — `agent_binding` is a signed
 * CLAIM (PIP-008). This lets a Policy Decision Point RECORD which upstream
 * evidence backed a human authorization and detect a stale or absent upstream
 * attestation after the fact — the L4->L7 failure mode (a decision enforced
 * correctly against an unconstrained or expired upstream claim). Call it with
 * a context whose signature has ALREADY been verified.
 *
 * @param {object} context  a signature-verified ep.signoff.v1 Authorization Context
 * @param {object} [opts]
 * @param {number} [opts.maxAgeSec]  if set, delegation.observed_at must be within this window (fail-closed)
 * @param {string} [opts.at]  reference time (ISO-8601); defaults to now
 * @returns {{present:boolean, agent_id?:string, delegation?:object|null,
 *   evidence_hash?:string|null, observed_at?:string|null,
 *   fresh:(boolean|null), age_seconds:(number|null), reason:string}}
 */
export declare function evaluateAgentBinding(context: any, opts?: Obj): Obj;
export { resolveOperatorKeys, verifyFederatedReceiptOffline, verifyFederatedReceipt, } from './federation.js';
export { verifyQuorum } from './quorum.js';
//# sourceMappingURL=index.d.ts.map