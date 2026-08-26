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
import crypto from 'crypto';
import { canonicalizeStrictJson, isStrictCanonicalJson, strictJsonGate, } from './strict-json.js';
import { verifyAgileSignatureSync, mldsaRawPublicKeyFromSpki, } from './pq-signature-agility.js';
import { verifyRevocation as verifyRevocationStatement } from './revocation.js';
import { verifyOutcomeBindingCore, verifyOutcomeBindingSetCore } from './outcome-binding.js';
export { AGENTROA_DRAFT, verifyAgentROA } from './agentroa.js';
export { AUTHORITY_PROGRAM_VERSION, AUTHORITY_PROGRAM_DOMAIN, AUTHORITY_STAGE_RECEIPT_VERSION, AUTHORITY_STAGE_RECEIPT_DOMAIN, AUTHORITY_PROGRAM_RESULT_VERSION, authorityProgramDigest, authorityStageReceiptDigest, deriveAuthorityProgramPredecessors, verifyAuthorityProgram, } from './authority-program.js';
export * from './aeb-adapter-contract.js';
export * from './aeb-acceptance-profile.js';
export * from './aeb-execution-conditions.js';
export * from './aeb-aps-adapter.js';
export * from './aeb-consequence-conformance.js';
export * from './aeb-mcgraw-delegation-adapter.js';
export * from './aeb-oauth-transaction-challenge-adapter.js';
export * from './aeb-discovery-permit-adapter.js';
export * from './aeb-wimse-oauth-adapter.js';
export * from './authorization-server-confirmation.js';
export * from './authorization-bundle.js';
export * from './oauth-rar-authorization-binding.js';
export * from './aadp-authorization-artifact.js';
export * from './policy-decision-evidence.js';
export * from './aeb-native-adapters.js';
export * from './aeb-oasnt-adapter.js';
export * from './aeb-chap-adapter.js';
export * from './aeb-psea-adapter.js';
export * from './fido-ap2-bridge.js';
export * from './a2a-receipt-binding.js';
export * from './ap2-native-adapter.js';
export * from './a2a-evidence-challenge.js';
export * from './memory-projection.js';
export * from './portable-state-handoff.js';
export * from './soma-cogobj-profile.js';
export * from './agent-edge-continuity.js';
export * from './discovery-permit-contract.js';
// EP-COSE-ENCODING-v0.1: encoding-equivalence profile — deterministic
// CBOR/COSE_Sign1 transport envelope for receipts; the CAID join survives
// re-encoding. Named exports (not export *) because this module's RFC 8949
// codec shares helper names with the McGraw adapter's codec (both now RFC 8949
// Section 4.2.1 bytewise-ordered); the distinct export names avoid a collision.
export { COSE_ENCODING_PROFILE, CBOR_DETERMINISTIC_ORDER, COSE_RECEIPT_CONTENT_TYPE, COSE_ALG_EDDSA, COSE_HEADER_EP_CAID, encodeDeterministicCbor8949, decodeDeterministicCbor8949, receiptToCborBytes, receiptFromCborBytes, receiptActionCaid, buildReceiptCoseSign1, verifyReceiptCoseSign1, } from './receipt-cose-encoding.js';
// EP-SCITT-STATEMENT-v1: SCITT Signed Statement profile (RFC 9943 CWT Claims
// over the COSE transport). VERIFIED is not REGISTERED: no Transparency
// Service has accepted these statements; registration is a separate gated step.
export * from './scitt-statement.js';
// EP-FIPS-MODE-v1: deployment crypto-posture reporting and policy. Enables
// "FIPS-based algorithms, with a validated-provider deployment mode"; it does
// not make any deployment FIPS validated.
export * from './fips-mode.js';
export * from './status.js';
export * from './gate-qualification.js';
export * from './gate-qualification-promptfoo.js';
export * from './claim-assurance.js';
export { OUTCOME_ATTESTATION_VERSION, OUTCOME_ATTESTATION_DOMAIN, OUTCOME_BINDING_VERSION, OUTCOME_BINDING_RESULT_VERSION, OUTCOME_OBSERVATION_VERSION, OUTCOME_OBSERVATION_DOMAIN, OUTCOME_BINDING_SET_VERSION, OUTCOME_BINDING_SET_RESULT_VERSION, OUTCOME_BINDING_OUTCOMES, buildOutcomeAttestation, buildOutcomeObservation, verifyOutcomeAttestation, verifyOutcomeObservation, verifyOutcomeObservationSet, observedEffectsDigest, outcomeBindingResultCore, outcomeBindingResultDigest, outcomeBindingSetResultDigest, trustReceiptDigest, verifyOutcomeBindingResultDigest, } from './outcome-binding.js';
// EP-SD-v1: selective-disclosure presentation of disclosure-ready receipts
// (salted path-bound commitments inside the signed body; SD-JWT-style, no new
// signature scheme; audience/nonce presentation binding).
export { EP_SD_VERSION, EP_SD_PRESENTATION_VERSION, EP_SD_COMMIT_DOMAIN, EP_SD_BINDING_DOMAIN, EP_SD_COMMIT_MARKER_PREFIX, EP_SD_MIN_SALT_BYTES, NON_REDACTABLE_PATHS, sdCommitmentDigest, sdPresentationBindingDigest, prepareSelectiveDisclosure, createSelectiveDisclosurePresentation, verifySelectiveDisclosurePresentation, } from './receipt-selective-disclosure.js';
export { ORPRG_JSON_JCS_PROFILE, ORPRG_ACTION_PROFILE, computeOrprgActionDigest, verifyOrprgJsonJcsPermit, verifyOrprgJsonJcsPermitAsync, createOrprgAecVerifier, } from './orprg.js';
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
function decodeBase64url(value) {
    if (typeof value !== 'string' || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
        throw new Error('value is not canonical base64url');
    }
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value)
        throw new Error('value is not canonical base64url');
    return decoded;
}
// =============================================================================
// CONSTANTS
// =============================================================================
const SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'];
const SUPPORTED_PROOF_VERSIONS = ['EP-PROOF-v1'];
// =============================================================================
// PRIMITIVES
// =============================================================================
function sha256(input) {
    return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
const canonicalize = canonicalizeStrictJson;
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
export function isCanonicalizable(value) {
    return isStrictCanonicalJson(value);
}
/**
 * EP-QUORUM-v1 ordered-chain hash: the hex SHA-256 of the canonical signoff
 * context. Used to cryptographically link each ordered signoff to its
 * predecessor (context.prev_context_hash), so approval ORDER is proven by the
 * signatures themselves rather than by operator-asserted timestamps. Exported
 * for the quorum verifier; uses the same canonicalize()/sha256() as every other
 * signed-material computation in this file.
 */
export function contextChainHash(context) {
    return sha256(canonicalize(context));
}
// Exported so the portable revocation verifier (revocation.js) signs/recomputes
// over byte-identical canonical material — the single canonicalization source of
// truth for the whole offline package.
export { canonicalize };
// Portable EP-REVOCATION-v1 offline check, re-exported so the published verifier
// can answer "has this authorization been revoked by a statement I hold?".
export { verifyRevocation, isRevoked, REVOCATION_VERSION } from './revocation.js';
// EP-PROVENANCE-CHAIN-v1: the human-authority root for downstream machine
// delegation/execution — composes verifyTrustReceipt + scope-containment checks.
export { verifyProvenanceOffline, PROVENANCE_VERSION } from './provenance.js';
// EP-TIME-ATTESTATION-v1: independent, pinned, offline-verifiable proof of WHEN
// (trusted-time anchor; complements the strong ordered chain's proof of order).
export { verifyTimeAttestation, TIME_ATTESTATION_VERSION } from './time-attestation.js';
// EP-EVIDENCE-RECORD-v1: long-term, crypto-agile preservation (RFC 4998-style
// renewal chain) so a receipt's cryptographic attribution survives algorithm aging.
export { verifyEvidenceRecord, verifyEvidenceRecordAgile, EVIDENCE_RECORD_VERSION } from './evidence-record.js';
// EP-SIG-AGILITY-v1: per-artifact signature-algorithm agility (Ed25519 and
// ML-DSA-65 over the SAME canonical bytes) so evidence outlives algorithms.
export { SIGNATURE_AGILITY_VERSION, AGILE_SIGNATURE_ALGORITHMS, AGILITY_REASONS, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, loadDefaultAgilityMldsaBackend, signAgile, signAgileSet, verifyAgileSignature, verifyAgileSignatureSet } from './pq-signature-agility.js';
// EP-EVIDENCE-REATTESTATION-v1: RFC 4998-style signature re-anchoring so
// evidence signed under an aging algorithm is re-committed under a current one.
export { REATTESTATION_VERSION, createReattestation, verifyReattestationChain } from './evidence-record.js';
// EP-RECEIPT-HYBRID-v1 / EP-LOG-CHECKPOINT-HYBRID-v1: the relying-party half of
// the hybrid receipt spine. Both are OPT-IN profiles requiring BOTH an Ed25519
// and an ML-DSA-65 signature over bytes that commit to the algorithm set, so a
// stripped leg cannot be covered up by narrowing the set. verifyReceipt() above
// is untouched and still refuses either profile on the version marker.
export { HYBRID_RECEIPT_PROFILE, HYBRID_RECEIPT_REQUIRED_ALGORITHMS, HYBRID_RECEIPT_REASONS, hybridReceiptSignedMaterial, hybridReceiptSignedBytes, verifyHybridReceipt, verifyReceiptOfAnyProfile, LOG_CHECKPOINT_HYBRID_PROFILE, LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS, LOG_CHECKPOINT_HYBRID_REASONS, LOG_CHECKPOINT_HYBRID_MERKLE_ALG, logCheckpointSignedFields, logCheckpointHybridSignedMaterial, logCheckpointHybridSignedBytes, verifyLogCheckpointHybridProof, } from './receipt-hybrid.js';
// RFC 6962 §2.1.2 checkpoint consistency over EP-MERKLE-v2 branch hashing.
// Used by verifyTrustReceipt when the caller pins a prior checkpoint head
// (opts.priorCheckpoint), and re-exported for log tooling and witnesses.
import { verifyCheckpointConsistency } from './consistency.js';
export { verifyCheckpointConsistency, CONSISTENCY_ALG } from './consistency.js';
// ── Additive transparency/currency checks wired into verifyTrustReceipt ──────
// Each module below is an independent, additive check. When active, it adds one
// key to result.checks and folds into `valid` by conjunction. With none active,
// the cryptographic `checks` object keeps its frozen seven members. The
// top-level decision_scope is always present to distinguish authenticity from
// admission and replay prevention.
// EP-WITNESS-v1: k-of-n independent witness cosignatures over ONE checkpoint
// head. Proves k distinct trusted witnesses attested to that head (the local,
// single-view half of equivocation detection); does NOT by itself prove no
// split view was shown elsewhere (needs gossip).
import { requireWitnessQuorum } from './witness.js';
export { verifyWitnessCosignature, requireWitnessQuorum, witnessSigningDigest, WITNESS_VERSION, WITNESS_DOMAIN_TAG, } from './witness.js';
// RFC 3161 timestamp token verification against a PINNED TSA key. Proves a TSA
// asserted a digest existed at gen_time (the bytes predate gen_time); does NOT
// prove the action was correct/authorized, and is authentic-as-of-token only.
import { verifyTimestampProof } from './timestamp-proof.js';
export { verifyTimestampProof, TIMESTAMP_PROOF_ALG } from './timestamp-proof.js';
// EP-CURRENCY-v1: the two-axis authenticity-vs-currency evaluation. `unknown`
// is the honest offline default: offline verification can NEVER prove currency.
// Only a supplied, recent, non-revoking signed head reaches `fresh`.
import { evaluateCurrency } from './currency.js';
export { evaluateCurrency, CURRENCY_VERSION, CURRENCY_STATUS, CURRENCY_REASON, } from './currency.js';
// EP-SMT-CONSUME-v1: third-party proof that a one-time nonce transitioned
// absent -> present exactly once across two append-only-linked heads. Proves
// the tree-shaped consumption facts only; checkpoint SIGNATURES are the
// caller's responsibility, and it does NOT establish currency of h2.
import { verifyConsumptionProof } from './consumption-proof.js';
export { verifyConsumptionProof, ReferenceConsumptionTree, CONSUMPTION_PROFILE, CONSUMPTION_LEAF_DOMAIN, SMT_DEPTH, } from './consumption-proof.js';
// EP-INITIATOR-ATTESTATION-v1: fail-closed structural validation of the
// self-asserted initiating-software attestation (model_id / model_version /
// tool_chain_digest / neutralized statement). It says WHICH software asked; it
// does NOT prove the software behaved (labels are self-asserted).
import { validateInitiatorAttestation } from './initiator-attestation.js';
export { validateInitiatorAttestation, neutralizeStatement, normalizeDigest, bindInto as bindInitiatorAttestation, INITIATOR_ATTESTATION_VERSION, INITIATOR_ATTESTATION_FIELD, INITIATOR_STATEMENT_MAX, } from './initiator-attestation.js';
// Shared presentation-attack codepoint classification. One implementation for
// every surface that puts attacker-influenced bytes in front of a human: the
// free-text initiator statement escapes them, action fields refuse them.
export { BIDI_CODEPOINTS, INVISIBLE_CODEPOINTS, isControlCodepoint, isHostileCodepoint, escapeCodepoint, scanHostileText, hasHostileText, scanHostileDeep, formatCodepoints, } from './hostile-text.js';
// EP-SURFACE-BINDING-v1: the possession-row join. The signed action object
// references the approval-surface evidence (condition-bounded credential
// presentation, platform attestation) as an opaque digest, so the possession
// row and the authorization row join by digest equality, each verified in its
// own trust boundary. EP never verifies the possession-row evidence itself,
// and possession evidence never substitutes for the authorization signature.
export { validateSurfaceBinding, bindSurfaceInto, receiptSurfaceBinding, verifySurfaceBinding, normalizeSurfaceDigest, SURFACE_BINDING_VERSION, SURFACE_BINDING_FIELD, } from './surface-binding.js';
// EP-MERKLE-v1 (legacy): sorted-pair, no domain separation. Kept verifying
// forever for already-anchored receipts. Do NOT use for new anchors.
function hashPair(a, b) {
    const sorted = [a, b].sort();
    return sha256(sorted[0] + sorted[1]);
}
// EP-MERKLE-v2: domain-separated + positional (not sorted). A leaf can never
// collide with a branch (distinct 0x00 / 0x01 prefixes), closing the leaf/branch
// second-preimage class. The leaf is bound to the receipt payload (self-check in
// verifyReceipt). New issuance defaults to v2; selected per-anchor via
// `anchor.alg === 'EP-MERKLE-v2'`.
export const MERKLE_V2_ALG = 'EP-MERKLE-v2';
/** Leaf = SHA-256(0x00 || canonicalJSON(payload)) -> hex. */
function leafHashV2(canonicalPayload) {
    return crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalPayload, 'utf8')]))
        .digest('hex');
}
/** Branch = SHA-256(0x01 || leftHex || rightHex) -> hex. Positional, not sorted. */
function hashPairV2(left, right) {
    return crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
        .digest('hex');
}
// =============================================================================
// RECEIPT VERIFICATION
// =============================================================================
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
export function verifyReceipt(doc, publicKeyBase64url, opts = {}) {
    /** @type {{ version: boolean, signature: boolean, anchor: boolean|null }} */
    const checks = { version: false, signature: false, anchor: null };
    // Inspect the complete caller-supplied object before reading any member.
    // Besides rejecting values that disappear from JSON, the strict predicate
    // catches hostile Proxy traps and turns them into a closed verifier result.
    if (!isCanonicalizable(doc)) {
        return {
            valid: false,
            checks,
            error: 'Receipt is outside the EP canonicalization profile; only plain JSON data is accepted',
        };
    }
    if (!doc?.['@version'] || !SUPPORTED_VERSIONS.includes(doc['@version'])) {
        return { valid: false, checks, error: `Unsupported version: ${doc?.['@version']}` };
    }
    checks.version = true;
    if (!doc.payload || !doc.signature?.value || !doc.signature?.algorithm) {
        return { valid: false, checks, error: 'Missing payload or signature' };
    }
    if (!isCanonicalizable(doc.payload)) {
        return {
            valid: false,
            checks,
            error: 'Payload is outside the EP canonicalization profile; use strings or safe integers in signed material',
        };
    }
    try {
        const payloadBytes = Buffer.from(canonicalize(doc.payload), 'utf8');
        const publicKeyDer = decodeBase64url(publicKeyBase64url);
        const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
        // EP-RECEIPT-v1 is Ed25519 over JCS. crypto.verify(null, ...) dispatches on the
        // key type, so without this guard a non-Ed25519 pinned key (EC/RSA) would be
        // verified under a different algorithm than the receipt declares. Pin the curve
        // here to match the hardcoded Ed25519 of the web verifier (verify-web.js) and
        // reject any other key type fail-closed.
        if (keyObject.asymmetricKeyType !== 'ed25519') {
            return { valid: false, checks, error: `Unsupported issuer key type '${keyObject.asymmetricKeyType}'; EP-RECEIPT-v1 requires Ed25519` };
        }
        const sigBytes = decodeBase64url(doc.signature.value);
        checks.signature = crypto.verify(null, payloadBytes, keyObject, sigBytes);
    }
    catch (e) {
        return { valid: false, checks, error: `Signature verification failed: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (doc.anchor?.merkle_proof && doc.anchor?.leaf_hash && doc.anchor?.merkle_root) {
        const isV2 = doc.anchor.alg === MERKLE_V2_ALG;
        if (isV2) {
            // v2 REQUIRES the anchor leaf to be bound to THIS receipt's payload — the
            // anchor can't be lifted from another receipt or forged via leaf/branch
            // confusion. Self-check first, then verify the domain-separated proof.
            const expectedLeaf = leafHashV2(canonicalize(doc.payload));
            checks.anchor = doc.anchor.leaf_hash === expectedLeaf
                && verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root, { v2: true });
        }
        else if (opts.allowLegacyMerkle === true) {
            // Dormant legacy path: pre-v2 (sorted-pair, unbound) anchors verify ONLY
            // when a caller explicitly opts in — old artifacts and compatibility tests.
            // Never the default, never used by production gates. Preserves the
            // "receipts verify forever" promise without carrying live v1 risk.
            checks.anchor = verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
        }
        else {
            // Default (and every production gate): require EP-MERKLE-v2. A legacy v1
            // anchor is refused unless the caller passes { allowLegacyMerkle: true }.
            checks.anchor = false;
        }
    }
    const valid = checks.version && checks.signature && (checks.anchor === null || checks.anchor === true);
    return { valid, checks };
}
// =============================================================================
// MERKLE ANCHOR VERIFICATION
// =============================================================================
/**
 * Verify a Merkle inclusion proof.
 *
 * @param {string} leafHash - hex SHA-256 of the receipt
 * @param {Array<{hash: string, position: 'left'|'right'}>} proof - proof steps
 * @param {string} expectedRoot - hex expected Merkle root
 * @returns {boolean}
 */
export function verifyMerkleAnchor(leafHash, proof, expectedRoot, opts = {}) {
    if (typeof leafHash !== 'string' || !leafHash)
        return false;
    if (typeof expectedRoot !== 'string' || !expectedRoot)
        return false;
    if (!Array.isArray(proof))
        return false;
    if (proof.length > 20)
        return false;
    const pair = opts.v2 === true ? hashPairV2 : hashPair;
    let current = leafHash;
    for (const step of proof) {
        if (!step || typeof step.hash !== 'string')
            return false;
        if (step.position !== 'left' && step.position !== 'right')
            return false;
        current = step.position === 'left' ? pair(step.hash, current) : pair(current, step.hash);
    }
    return current === expectedRoot;
}
// =============================================================================
// CLASS A SIGNOFF VERIFICATION (WebAuthn, offline)
// =============================================================================
// authenticatorData layout (WebAuthn L2 §6.1): rpIdHash(32) | flags(1) |
// signCount(4) | ... Flags bit 0 = UP (user present), bit 2 = UV (user
// verified — biometric/PIN).
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
function webauthnAuthenticatorMetadata(authData, opts) {
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);
    const previous = opts.previousSignCount;
    let counterStatus = 'untracked';
    if (signCount === 0) {
        counterStatus = 'unsupported';
    }
    else if (previous !== undefined) {
        counterStatus = signCount > previous ? 'advanced' : 'not_advanced';
    }
    return {
        sign_count: signCount,
        backup_eligible: (flags & FLAG_BE) === FLAG_BE,
        backup_state: (flags & FLAG_BS) === FLAG_BS,
        counter_status: counterStatus,
    };
}
function webauthnCounterPolicyError(metadata, opts) {
    if (opts.previousSignCount !== undefined
        && (!Number.isInteger(opts.previousSignCount)
            || opts.previousSignCount < 0
            || opts.previousSignCount > 0xffffffff)) {
        return 'previousSignCount must be a 32-bit unsigned integer';
    }
    if (opts.counterPolicy !== undefined
        && opts.counterPolicy !== 'observe'
        && opts.counterPolicy !== 'enforce') {
        return 'counterPolicy must be "observe" or "enforce"';
    }
    if (metadata.backup_state && !metadata.backup_eligible) {
        return 'WebAuthn backup state is set while backup eligibility is not set';
    }
    if (opts.counterPolicy === 'enforce' && metadata.counter_status === 'not_advanced') {
        return 'WebAuthn signCount did not advance; possible clone, malfunction, or reordered assertion';
    }
    return null;
}
// ---------------------------------------------------------------------------
// Class A signature-algorithm dispatch
//
// EP DOES NOT SUPPORT POST-QUANTUM WEBAUTHN TODAY, and cannot: no browser,
// no platform passkey provider, and no certified authenticator produces an
// ML-DSA WebAuthn assertion, and the FIDO Registry (v2.3, the current
// published revision) carries no ALG_SIGN constant for ML-DSA, so a certified
// authenticator cannot even declare the capability. What follows is the
// RELYING-PARTY half, which was never FIDO-gated: it is EP's own verification
// code, and it is ready so that the day a real PQ assertion exists EP verifies
// it instead of shipping a change under time pressure. Until then every
// ML-DSA path here refuses by name.
//
// The IANA COSE registry already assigns ML-DSA-65 = -49 (RFC 9964) and
// WebAuthn L3 section 5.8.5 says algorithm identifiers SHOULD come from that
// registry, so -49 is a legal `pubKeyCredParams` entry today -- legal to ask
// for is not the same as available to receive.
// ---------------------------------------------------------------------------
/** The Class A signature algorithms this verifier can dispatch on. */
export const WEBAUTHN_SIGNATURE_ALGORITHMS = Object.freeze(['ES256', 'ML-DSA-65']);
/**
 * Name the signature algorithm an enrolled Class A credential is for, read
 * from the KEY itself (SPKI DER, base64url) rather than from any caller- or
 * document-supplied label. Returns null for anything outside the closed set,
 * which every caller must treat as a refusal.
 */
export function webauthnSignatureAlgorithm(approverPublicKeySpkiB64u) {
    try {
        if (typeof approverPublicKeySpkiB64u !== 'string' || approverPublicKeySpkiB64u.length === 0)
            return null;
        const der = decodeBase64url(approverPublicKeySpkiB64u);
        const keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (keyObject.asymmetricKeyType === 'ml-dsa-65')
            return 'ML-DSA-65';
        // Every EC key stays on the byte-identical legacy path. Class A enrollment
        // has always pinned EC2/ES256/P-256 (lib/webauthn.ts), so this is the same
        // key population the digest-hardcoded verifier handled before dispatch.
        if (keyObject.asymmetricKeyType === 'ec')
            return 'ES256';
        return null;
    }
    catch {
        return null;
    }
}
/**
 * Verify a Class A (approver-held key) signoff fully offline.
 *
 * What this proves with pure math, no network, no EP server:
 *   - the WebAuthn challenge the device signed equals
 *     SHA-256(JCS(context)) for the EXACT context in the signoff — which
 *     binds the action hash, decision, nonce, approver, and validity window;
 *   - the signature verifies against the approver's enrolled key, under the
 *     algorithm that key is for (ES256 today; ML-DSA-65 is implemented and
 *     refuses cleanly until an authenticator that can produce one exists);
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
 * `opts.mode` selects the verification posture:
 *   - 'relying-party': an authoritative relying-party check. `rpId` AND
 *     `allowedOrigins` are REQUIRED; omitting either fails the verdict with
 *     'rp_pins_required' and `checks.rp_id_hash === false`. This makes it
 *     impossible for a caller that intends an authoritative check to silently
 *     skip origin/rp scoping by forgetting the pins.
 *   - 'offline-integrity' (default): today's portable integrity check —
 *     challenge/action/nonce binding, ceremony type, UP/UV flags, and the
 *     device signature are verified; origin is asserted only when the caller
 *     supplies pins, and `checks.rp_id_hash` stays null when unpinned.
 *
 * `opts.alg` optionally PINS the expected signature algorithm ('ES256' or
 * 'ML-DSA-65'). Omitted, the algorithm is read from the enrolled key. Supplied
 * and contradicted by the key, the verdict is a named refusal
 * ('signature_algorithm_mismatch') -- the pin is never narrowed to whatever
 * was presented.
 *
 * `opts.agility` is passed through to EP-SIG-AGILITY-v1 for the ML-DSA-65
 * path only (e.g. an injected `mldsaBackend`). It has no effect on ES256.
 *
 * @param {string} approverPublicKeySpkiB64u - enrolled key, SPKI DER b64u
 * @param {{ rpId?: string, allowedOrigins?: string[], mode?: 'relying-party'|'offline-integrity', alg?: 'ES256'|'ML-DSA-65', agility?: object }} [opts]
 * @returns {{ valid: boolean, checks: object, error?: string }}
 */
export function verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, opts = {}) {
    /** @type {{ challenge_binding: boolean, client_data_type: boolean, user_present: boolean, user_verified: boolean, rp_id_hash: boolean|null, signature: boolean }} */
    const checks = {
        challenge_binding: false,
        client_data_type: false,
        user_present: false,
        user_verified: false,
        rp_id_hash: null,
        signature: false,
    };
    let authenticator = null;
    if (opts.mode !== undefined && opts.mode !== 'relying-party' && opts.mode !== 'offline-integrity') {
        return { valid: false, checks, authenticator, error: 'mode must be "relying-party" or "offline-integrity"' };
    }
    if (opts.mode === 'relying-party') {
        const rpIdPinned = typeof opts.rpId === 'string' && opts.rpId.length > 0;
        const originsPinned = Array.isArray(opts.allowedOrigins)
            && opts.allowedOrigins.length > 0
            && opts.allowedOrigins.every((origin) => typeof origin === 'string' && origin.length > 0);
        if (!rpIdPinned || !originsPinned) {
            // An authoritative origin check was requested but cannot be performed.
            // rp_id_hash is false (not null): the pin requirement itself failed.
            checks.rp_id_hash = false;
            return { valid: false, checks, authenticator, error: 'rp_pins_required' };
        }
    }
    try {
        if (!signoff?.context || !signoff?.webauthn) {
            return { valid: false, checks, authenticator, error: 'Missing context or webauthn evidence' };
        }
        const { authenticator_data, client_data_json, signature } = signoff.webauthn;
        if (!authenticator_data || !client_data_json || !signature) {
            return { valid: false, checks, authenticator, error: 'Missing webauthn fields' };
        }
        // 1. Challenge binding: clientDataJSON.challenge must equal
        //    b64u(SHA-256(canonical(context))). The context is re-canonicalized
        //    here — tamper any field (amount, approver, nonce) and this fails.
        const clientDataBytes = decodeBase64url(client_data_json);
        const clientDataText = FATAL_UTF8.decode(clientDataBytes);
        const clientDataGate = strictJsonGate(clientDataText);
        if (!clientDataGate.ok) {
            return { valid: false, checks, authenticator, error: `Invalid clientDataJSON: ${clientDataGate.reason}` };
        }
        const clientData = JSON.parse(clientDataText);
        const expectedChallenge = crypto
            .createHash('sha256')
            .update(canonicalize(signoff.context), 'utf8')
            .digest()
            .toString('base64url');
        checks.challenge_binding = clientData.challenge === expectedChallenge;
        // 2. Ceremony type must be an assertion, not a registration.
        checks.client_data_type = clientData.type === 'webauthn.get';
        if (Array.isArray(opts.allowedOrigins)) {
            if (opts.allowedOrigins.length === 0
                || !opts.allowedOrigins.includes(clientData.origin)
                || clientData.crossOrigin === true) {
                return { valid: false, checks, authenticator, error: 'WebAuthn origin is not allowed' };
            }
        }
        // 3. Authenticator flags: user present + user verified.
        const authData = decodeBase64url(authenticator_data);
        if (authData.length < 37) {
            return { valid: false, checks, authenticator, error: 'authenticator_data too short' };
        }
        const flags = authData[32];
        checks.user_present = (flags & FLAG_UP) === FLAG_UP;
        checks.user_verified = (flags & FLAG_UV) === FLAG_UV;
        authenticator = webauthnAuthenticatorMetadata(authData, opts);
        const policyError = webauthnCounterPolicyError(authenticator, opts);
        if (policyError) {
            return { valid: false, checks, authenticator, error: policyError };
        }
        // 4. Optional rpId scope check.
        if (opts.rpId) {
            const expectedRpIdHash = crypto.createHash('sha256').update(opts.rpId, 'utf8').digest();
            checks.rp_id_hash = expectedRpIdHash.equals(authData.subarray(0, 32));
        }
        // 5. Signature over authData || SHA-256(clientDataJSON), dispatched on the
        //    algorithm of the ENROLLED KEY. The signed bytes are identical for
        //    every algorithm; only the verification primitive differs.
        const signedData = Buffer.concat([
            authData,
            crypto.createHash('sha256').update(clientDataBytes).digest(),
        ]);
        const keyObject = crypto.createPublicKey({
            key: decodeBase64url(approverPublicKeySpkiB64u),
            format: 'der',
            type: 'spki',
        });
        const alg = webauthnSignatureAlgorithm(approverPublicKeySpkiB64u);
        // An `alg` pin is relying-party policy. A pin outside the closed set, or a
        // pin the enrolled key contradicts, is a NAMED refusal -- never a throw,
        // never a silent fall-through to whatever the key happens to be.
        if (opts.alg !== undefined) {
            if (!WEBAUTHN_SIGNATURE_ALGORITHMS.includes(opts.alg)) {
                return { valid: false, checks, authenticator, error: `unsupported_signature_algorithm: ${String(opts.alg)}` };
            }
            if (opts.alg !== alg) {
                return {
                    valid: false,
                    checks,
                    authenticator,
                    error: `signature_algorithm_mismatch: pinned ${String(opts.alg)}, enrolled key is ${alg ?? 'unsupported'}`,
                };
            }
        }
        if (alg === 'ES256') {
            // Unchanged from the pre-dispatch verifier, byte for byte: ECDSA over
            // SHA-256. crypto.verify('sha256', ...) is correct for ES256 and ONLY
            // for ES256; on an ML-DSA key it throws ERR_OSSL_INVALID_DIGEST, which
            // is exactly why this branch is now guarded instead of unconditional.
            checks.signature = crypto.verify('sha256', signedData, keyObject, decodeBase64url(signature));
        }
        else if (alg === 'ML-DSA-65') {
            // Verified through EP-SIG-AGILITY-v1, not a second implementation: the
            // same closed registry, the same length pinning, the same fail-closed
            // reasons the receipt path already uses. FIPS 204 pure ML-DSA takes no
            // pre-hash, so the agility module's node-native backend calls
            // crypto.verify(null, ...).
            const rawPublicKey = mldsaRawPublicKeyFromSpki(decodeBase64url(approverPublicKeySpkiB64u));
            if (!rawPublicKey) {
                return { valid: false, checks, authenticator, error: 'malformed_ml_dsa_65_public_key' };
            }
            const agile = verifyAgileSignatureSync(new Uint8Array(signedData), { alg: 'ML-DSA-65', sig: Buffer.from(decodeBase64url(signature)).toString('base64url') }, { alg: 'ML-DSA-65', public_key: rawPublicKey }, (opts.agility ?? {}));
            if (agile.verified !== true) {
                // Named refusal, carried through verbatim (malformed_signature,
                // pq_backend_unavailable, signature_invalid, ...). Never a throw.
                return { valid: false, checks, authenticator, error: `ml_dsa_65_${agile.reason ?? 'refused'}` };
            }
            checks.signature = true;
        }
        else {
            // Unknown or unsupported algorithm: refuse by name. INDETERMINATE never
            // authorizes, and it must never reach a digest-hardcoded verify() that
            // would throw a raw OpenSSL error instead of returning a verdict.
            return { valid: false, checks, authenticator, error: 'unsupported_signature_algorithm' };
        }
    }
    catch (e) {
        return { valid: false, checks, authenticator, error: `WebAuthn verification failed: ${e instanceof Error ? e.message : String(e)}` };
    }
    const valid = checks.challenge_binding
        && checks.client_data_type
        && checks.user_present
        && checks.user_verified
        && checks.signature
        && (checks.rp_id_hash === null || checks.rp_id_hash === true);
    return { valid, checks, authenticator };
}
// =============================================================================
// COMMITMENT PROOF VERIFICATION
// =============================================================================
/**
 * Verify an EP commitment proof.
 *
 * @param {object} proof - EP commitment proof document (EP-PROOF-v1)
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @param {{ allowUnsigned?: boolean }} options - Set allowUnsigned only for structure/expiry checks.
 * @returns {{ valid: boolean, claim: object, error?: string }}
 */
export function verifyCommitmentProof(proof, publicKeyBase64url = null, options = {}) {
    if (!proof?.['@version'] || !SUPPORTED_PROOF_VERSIONS.includes(proof['@version'])) {
        return { valid: false, claim: null, error: `Unsupported version: ${proof?.['@version']}` };
    }
    if (proof.expires_at && new Date(proof.expires_at) < new Date()) {
        return { valid: false, claim: proof.claim, error: 'Proof has expired' };
    }
    const hasPublicKey = !!publicKeyBase64url;
    const hasSignature = !!proof.signature?.value;
    if (!hasPublicKey || !hasSignature) {
        if (options.allowUnsigned === true && !hasPublicKey && !hasSignature) {
            return { valid: true, claim: proof.claim };
        }
        const error = !hasPublicKey && !hasSignature
            ? 'Signature and public key are required'
            : !hasPublicKey
                ? 'Public key is required to verify signature'
                : 'Signature is required';
        return { valid: false, claim: proof.claim, error };
    }
    try {
        const commitmentBytes = Buffer.from(canonicalize(proof.commitment), 'utf8');
        const publicKeyDer = decodeBase64url(publicKeyBase64url);
        const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
        const sigBytes = decodeBase64url(proof.signature.value);
        if (!crypto.verify(null, commitmentBytes, keyObject, sigBytes)) {
            return { valid: false, claim: proof.claim, error: 'Invalid signature' };
        }
    }
    catch (e) {
        return { valid: false, claim: proof.claim, error: `Signature check failed: ${e instanceof Error ? e.message : String(e)}` };
    }
    return { valid: true, claim: proof.claim };
}
// =============================================================================
// BUNDLE VERIFICATION
// =============================================================================
/**
 * Verify an EP receipt bundle.
 *
 * @param {object} bundle - EP-BUNDLE-v1 format
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @returns {{ valid: boolean, total: number, verified: number, failed: string[] }}
 */
export function verifyReceiptBundle(bundle, publicKeyBase64url) {
    if (bundle?.['@version'] !== 'EP-BUNDLE-v1') {
        return { valid: false, total: 0, verified: 0, failed: ['Invalid bundle version'] };
    }
    // A bundle with the right version but no document array is malformed input,
    // not an exceptional condition. Refuse it without dereferencing attacker-
    // controlled shape so callers cannot be crashed with a TypeError.
    if (!Array.isArray(bundle.documents)) {
        return { valid: false, total: 0, verified: 0, failed: ['Bundle documents must be an array'] };
    }
    const failed = [];
    let verified = 0;
    for (let i = 0; i < bundle.documents.length; i++) {
        const result = verifyReceipt(bundle.documents[i], publicKeyBase64url);
        if (result.valid)
            verified++;
        else
            failed.push(`doc[${i}]: ${result.error || 'verification failed'}`);
    }
    return { valid: failed.length === 0, total: bundle.documents.length, verified, failed };
}
// =============================================================================
// TRUST RECEIPT — FULL OFFLINE VERIFICATION (I-D Section 6.3)
// =============================================================================
// draft-schrock-ep-authorization-receipts Section 6.3: a verifier with
// (receipt, trusted log public key, pinned approver keys) and NO network access
// MUST be able to establish six properties. verifyTrustReceipt() is that
// algorithm — the reference profile for the byte-level choices the I-D leaves
// to the implementation:
//   - Hashes are "sha256:<hex>" strings; comparisons strip the prefix.
//   - Canonicalization is the recursive sorted-key JSON above (JCS-equivalent
//     for these value shapes).
//   - The signed material for a Class B/C signoff is the raw 32-byte SHA-256
//     context digest. For Class A, the WebAuthn challenge is base64url(digest).
//   - The receipt leaf is SHA-256 of the canonical receipt WITHOUT log_proof
//     and approver_key_proofs (a leaf cannot contain its own inclusion proof).
//   - inclusion_path is positioned steps [{hash, position:'left'|'right'}].
//   - The checkpoint signature is Ed25519 over the canonical checkpoint
//     WITHOUT log_signature (i.e. {log_key_id, root_hash, tree_size}).
const HASH_PREFIX = /^sha256:/;
function hexOf(h) {
    return String(h || '').replace(HASH_PREFIX, '').toLowerCase();
}
function sha256Bytes(input) {
    return crypto.createHash('sha256').update(input, 'utf8').digest();
}
function usdMinorUnits(value) {
    if (typeof value !== 'string' || !/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(value))
        return null;
    const [whole, fraction = ''] = value.split('.');
    return BigInt(whole) * 100n + BigInt(fraction.padEnd(2, '0'));
}
function isHighValueFinancialAction(action) {
    const actionType = typeof action?.action_type === 'string' ? action.action_type.toLowerCase() : '';
    const financial = /(?:^|[._-])(wire|payment|transfer|disbursement|purchase|refund|financial)(?:$|[._-])/.test(actionType);
    const currency = action?.parameters?.currency;
    const amount = usdMinorUnits(action?.parameters?.amount);
    return financial && currency === 'USD' && amount !== null && amount >= 10000000n;
}
/**
 * Audit an approver-directory update before it is installed.
 *
 * A retroactive `valid_to` narrowing is not equivalent to compromise: historical
 * verification deliberately evaluates the key at the claimed issuance time.
 * Operators therefore MUST mark a stolen or suspect key with `compromised_at`.
 * This transition guard makes that easy-to-miss distinction executable.
 *
 * `now` is mandatory so the audit never consults an ambient process clock.
 * Planned future expiry changes are allowed. A past-dated narrowing without
 * `compromised_at` fails unless the caller explicitly records the exceptional
 * `allowRetroactiveExpiryWithoutCompromise` override.
 */
export function auditApproverKeyDirectoryTransition(previousApproverKeys, nextApproverKeys, opts = {}) {
    const errors = [];
    const transitions = [];
    const now = parseInstant(opts.now);
    if (Number.isNaN(now)) {
        return {
            valid: false,
            errors: ['approver-key transition audit requires a parseable opts.now'],
            transitions,
        };
    }
    if (!previousApproverKeys || typeof previousApproverKeys !== 'object' || Array.isArray(previousApproverKeys)
        || !nextApproverKeys || typeof nextApproverKeys !== 'object' || Array.isArray(nextApproverKeys)) {
        return {
            valid: false,
            errors: ['previousApproverKeys and nextApproverKeys must be key-directory objects'],
            transitions,
        };
    }
    for (const [keyId, nextEntry] of Object.entries(nextApproverKeys)) {
        const previousEntry = previousApproverKeys[keyId];
        if (!previousEntry || typeof previousEntry !== 'object'
            || !nextEntry || typeof nextEntry !== 'object')
            continue;
        if (nextEntry.compromised_at !== undefined && nextEntry.compromised_at !== null) {
            const compromisedAt = parseInstant(nextEntry.compromised_at);
            if (Number.isNaN(compromisedAt)) {
                errors.push(`${keyId}: compromised_at is not a parseable instant`);
            }
        }
        if (nextEntry.valid_to === undefined || nextEntry.valid_to === null)
            continue;
        const nextValidTo = parseInstant(nextEntry.valid_to);
        if (Number.isNaN(nextValidTo)) {
            errors.push(`${keyId}: next valid_to is not a parseable instant`);
            continue;
        }
        const previousValidTo = previousEntry.valid_to === undefined || previousEntry.valid_to === null
            ? Number.POSITIVE_INFINITY
            : parseInstant(previousEntry.valid_to);
        if (Number.isNaN(previousValidTo)) {
            errors.push(`${keyId}: previous valid_to is not a parseable instant`);
            continue;
        }
        if (nextValidTo < previousValidTo) {
            const retroactive = nextValidTo < now;
            const compromiseRecorded = nextEntry.compromised_at !== undefined
                && nextEntry.compromised_at !== null;
            const allowedByException = opts.allowRetroactiveExpiryWithoutCompromise === true;
            transitions.push({
                approver_key_id: keyId,
                kind: retroactive ? 'retroactive_valid_to_narrowing' : 'future_valid_to_narrowing',
                previous_valid_to: previousEntry.valid_to ?? null,
                next_valid_to: nextEntry.valid_to,
                compromised_at: nextEntry.compromised_at ?? null,
                exception_recorded: allowedByException,
            });
            if (retroactive && !compromiseRecorded && !allowedByException) {
                errors.push(`${keyId}: retroactive valid_to narrowing requires compromised_at `
                    + 'or an explicit allowRetroactiveExpiryWithoutCompromise exception');
            }
        }
    }
    return { valid: errors.length === 0, errors, transitions };
}
// Canonical EP timestamp profile: RFC 3339 with an explicit UTC offset ("Z" or
// ±hh:mm). No-timezone ("2026-07-01T12:00:00") and date-only ("2026-07-01")
// forms are REJECTED — they are ambiguous (UTC vs local) and must never satisfy
// a validity window. This is the single profile JS, Python, and Go all parse
// identically and reject identically (fail-closed). Returns epoch ms or NaN.
const RFC3339_OFFSET = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;
function parseInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_OFFSET);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function withinWindow(t, from, to) {
    const ts = parseInstant(t);
    if (Number.isNaN(ts))
        return false;
    if (from) {
        const f = parseInstant(from);
        if (Number.isNaN(f) || ts < f)
            return false;
    }
    if (to) {
        const g = parseInstant(to);
        if (Number.isNaN(g) || ts > g)
            return false;
    }
    return true;
}
function parseClassAAssertion(webauthn) {
    try {
        const clientDataBytes = decodeBase64url(webauthn.client_data_json);
        const clientDataText = FATAL_UTF8.decode(clientDataBytes);
        if (!strictJsonGate(clientDataText).ok)
            return null;
        const clientData = JSON.parse(clientDataText);
        const authData = decodeBase64url(webauthn.authenticator_data);
        if (authData.length < 37)
            return null;
        return { authData, clientData, clientDataBytes };
    }
    catch {
        return null;
    }
}
// WebAuthn Class-A assertion bound to a context digest (challenge = b64u(digest)).
function verifyClassAOverDigest(webauthn, digestBytes, publicKeySpkiB64u, opts = {}) {
    try {
        const parsed = parseClassAAssertion(webauthn);
        if (!parsed)
            return { valid: false, authenticator: null, error: 'invalid WebAuthn assertion' };
        const { authData, clientData, clientDataBytes } = parsed;
        const authenticator = webauthnAuthenticatorMetadata(authData, opts);
        const policyError = webauthnCounterPolicyError(authenticator, opts);
        if (policyError)
            return { valid: false, authenticator, error: policyError };
        if (clientData.type !== 'webauthn.get')
            return { valid: false, authenticator };
        if (clientData.challenge !== Buffer.from(digestBytes).toString('base64url'))
            return { valid: false, authenticator };
        if (opts.rpId) {
            const expectedRpIdHash = crypto.createHash('sha256').update(opts.rpId, 'utf8').digest();
            if (!expectedRpIdHash.equals(authData.subarray(0, 32)))
                return { valid: false, authenticator };
        }
        if (Array.isArray(opts.allowedOrigins)) {
            if (opts.allowedOrigins.length === 0
                || !opts.allowedOrigins.includes(clientData.origin)
                || clientData.crossOrigin === true)
                return { valid: false, authenticator };
        }
        if ((authData[32] & FLAG_UP) !== FLAG_UP)
            return { valid: false, authenticator }; // human presence required
        if ((authData[32] & FLAG_UV) !== FLAG_UV)
            return { valid: false, authenticator }; // biometric/PIN verification required
        const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataBytes).digest()]);
        const keyObject = crypto.createPublicKey({
            key: decodeBase64url(publicKeySpkiB64u), format: 'der', type: 'spki',
        });
        return {
            valid: crypto.verify('sha256', signedData, keyObject, decodeBase64url(webauthn.signature)),
            authenticator,
        };
    }
    catch {
        return { valid: false, authenticator: null, error: 'WebAuthn verification failed' };
    }
}
function verifyEd25519OverDigest(signatureB64u, digestBytes, publicKeySpkiB64u) {
    try {
        const keyObject = crypto.createPublicKey({
            key: decodeBase64url(publicKeySpkiB64u), format: 'der', type: 'spki',
        });
        return crypto.verify(null, digestBytes, keyObject, decodeBase64url(signatureB64u));
    }
    catch {
        return false;
    }
}
const STRICT_CHECK_NAMES = [
    'pinned_keys',
    'rp_id',
    'origin',
    'user_presence',
    'user_verification',
    'key_windows',
    'policy_hash',
    'no_unsigned',
];
function createStrictReport(enabled) {
    return {
        enabled,
        valid: !enabled,
        checks: enabled ? Object.fromEntries(STRICT_CHECK_NAMES.map((name) => [name, false])) : {},
        errors: [],
    };
}
function parseableTimestamp(value) {
    return typeof value === 'string' && !Number.isNaN(parseInstant(value));
}
// Canonical required_approvals coercion (fail-closed, shared semantics with the
// Python and Go verifiers): the threshold MUST be an integer-typed JSON number.
// A string ("2"), a float (2.5), or any non-integer is treated as malformed and
// forces the whole receipt to fail — a lower/under-approval must never satisfy a
// higher threshold because the type was coerced away. Returns an integer >= 1,
// or null if malformed.
function coerceRequiredApprovals(value) {
    if (value === undefined || value === null)
        return 1;
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1)
        return null;
    return value;
}
function markStrict(report, name, ok, message) {
    report.checks[name] = Boolean(ok);
    if (!ok && message)
        report.errors.push(message);
}
function evaluateTrustReceiptStrict(report, receipt, contexts, signoffs, contextByHash, approverKeys, logPublicKey, opts) {
    const classASignoffs = [];
    let pinnedKeysOk = Boolean(logPublicKey);
    if (!logPublicKey) {
        report.errors.push('strict pinned_keys requires a trusted logPublicKey');
    }
    for (const s of signoffs) {
        if (!s?.approver_key_id) {
            pinnedKeysOk = false;
            report.errors.push('strict pinned_keys requires every signoff to name approver_key_id');
            continue;
        }
        const keyEntry = approverKeys[s.approver_key_id];
        if (!keyEntry?.public_key) {
            pinnedKeysOk = false;
            report.errors.push(`strict pinned_keys has no pinned public key for ${s.approver_key_id}`);
        }
        // Pinned key class is authoritative (see default path): a pinned Class-A key
        // is always evaluated as Class-A even if the signoff declares key_class:'B',
        // so its WebAuthn UP/UV checks below cannot be downgraded away.
        // Classification is a relying-party directory fact. An omitted class is
        // Class B; the presented signoff can never promote its own key to Class A.
        const keyClass = keyEntry?.key_class === 'A' ? 'A' : 'B';
        if (keyClass === 'A')
            classASignoffs.push({ signoff: s, keyEntry });
    }
    markStrict(report, 'pinned_keys', pinnedKeysOk);
    let rpOk = true;
    if (classASignoffs.length > 0 && !opts.rpId) {
        rpOk = false;
        report.errors.push('strict rp_id requires opts.rpId for Class-A WebAuthn signoffs');
    }
    for (const { signoff } of classASignoffs) {
        const parsed = parseClassAAssertion(signoff.webauthn);
        if (!parsed) {
            rpOk = false;
            report.errors.push('strict rp_id could not parse Class-A WebAuthn authenticator data');
            continue;
        }
        if (opts.rpId) {
            const expectedRpHash = sha256Bytes(opts.rpId);
            if (!parsed.authData.subarray(0, 32).equals(expectedRpHash)) {
                rpOk = false;
                report.errors.push('strict rp_id WebAuthn rpIdHash does not match opts.rpId');
            }
        }
    }
    markStrict(report, 'rp_id', rpOk);
    let originOk = true;
    if (classASignoffs.length > 0
        && (!Array.isArray(opts.allowedOrigins) || opts.allowedOrigins.length === 0)) {
        originOk = false;
        report.errors.push('strict origin requires a non-empty opts.allowedOrigins for Class-A WebAuthn signoffs');
    }
    for (const { signoff } of classASignoffs) {
        const parsed = parseClassAAssertion(signoff.webauthn);
        if (!parsed
            || !opts.allowedOrigins?.includes(parsed.clientData.origin)
            || parsed.clientData.crossOrigin === true) {
            originOk = false;
            report.errors.push('strict origin rejects the Class-A WebAuthn origin');
        }
    }
    markStrict(report, 'origin', originOk);
    let upOk = true;
    let uvOk = true;
    for (const { signoff } of classASignoffs) {
        const parsed = parseClassAAssertion(signoff.webauthn);
        const flags = parsed?.authData?.[32] || 0;
        if (!parsed || (flags & FLAG_UP) !== FLAG_UP) {
            upOk = false;
            report.errors.push('strict user_presence requires Class-A WebAuthn UP');
        }
        if (!parsed || (flags & FLAG_UV) !== FLAG_UV) {
            uvOk = false;
            report.errors.push('strict user_verification requires Class-A WebAuthn UV');
        }
    }
    markStrict(report, 'user_presence', upOk);
    markStrict(report, 'user_verification', uvOk);
    let keyWindowsOk = true;
    for (const s of signoffs) {
        const digestHex = hexOf(s?.context_hash);
        const ctx = contextByHash.get(digestHex);
        const keyEntry = approverKeys[s?.approver_key_id];
        if (!ctx || !keyEntry?.public_key) {
            keyWindowsOk = false;
            report.errors.push('strict key_windows cannot bind a signoff to both context and pinned key');
            continue;
        }
        if (!parseableTimestamp(keyEntry.valid_from) || !parseableTimestamp(keyEntry.valid_to)) {
            keyWindowsOk = false;
            report.errors.push(`strict key_windows requires valid_from and valid_to for ${s.approver_key_id}`);
            continue;
        }
        if (!withinWindow(ctx.issued_at, keyEntry.valid_from, keyEntry.valid_to)) {
            keyWindowsOk = false;
            report.errors.push(`strict key_windows rejects ${s.approver_key_id} at context issued_at`);
        }
    }
    markStrict(report, 'key_windows', keyWindowsOk);
    let policyHashOk = true;
    const expectedPolicyHash = opts.expectedPolicyHash ? hexOf(opts.expectedPolicyHash) : null;
    if (!expectedPolicyHash) {
        policyHashOk = false;
        report.errors.push('strict policy_hash requires opts.expectedPolicyHash');
    }
    for (const ctx of contexts) {
        if (!ctx?.policy_hash) {
            policyHashOk = false;
            report.errors.push('strict policy_hash requires every context to carry policy_hash');
            continue;
        }
        if (expectedPolicyHash && hexOf(ctx.policy_hash) !== expectedPolicyHash) {
            policyHashOk = false;
            report.errors.push('strict policy_hash context policy_hash does not match opts.expectedPolicyHash');
        }
    }
    markStrict(report, 'policy_hash', policyHashOk);
    let noUnsignedOk = true;
    const requireField = (value, message) => {
        if (value === undefined || value === null || value === '') {
            noUnsignedOk = false;
            report.errors.push(message);
        }
    };
    requireField(receipt.action_hash, 'strict no_unsigned requires action_hash');
    requireField(receipt.consumption?.committed_at, 'strict no_unsigned requires consumption.committed_at');
    requireField(receipt.log_proof?.checkpoint?.log_signature, 'strict no_unsigned requires checkpoint.log_signature');
    if (!Array.isArray(receipt.log_proof?.inclusion_path)) {
        noUnsignedOk = false;
        report.errors.push('strict no_unsigned requires log_proof.inclusion_path');
    }
    for (const ctx of contexts) {
        requireField(ctx?.action_hash, 'strict no_unsigned requires every context to carry action_hash');
        requireField(ctx?.policy_hash, 'strict no_unsigned requires every context to carry policy_hash');
        requireField(ctx?.approver, 'strict no_unsigned requires every context to name approver');
        requireField(ctx?.issued_at, 'strict no_unsigned requires every context to carry issued_at');
        requireField(ctx?.expires_at, 'strict no_unsigned requires every context to carry expires_at');
    }
    for (const s of signoffs) {
        requireField(s?.context_hash, 'strict no_unsigned requires every signoff to carry context_hash');
        requireField(s?.approver_key_id, 'strict no_unsigned requires every signoff to carry approver_key_id');
        requireField(s?.key_class, 'strict no_unsigned requires every signoff to carry key_class');
        requireField(s?.signed_at, 'strict no_unsigned requires every signoff to carry signed_at');
        // Pinned key class is authoritative: a pinned Class-A key must carry a full
        // WebAuthn assertion; the attacker cannot declare key_class:'B' to reduce the
        // no_unsigned requirement to a bare Ed25519 signature.
        const keyClass = approverKeys[s?.approver_key_id]?.key_class === 'A' ? 'A' : 'B';
        if (keyClass === 'A') {
            requireField(s?.webauthn?.authenticator_data, 'strict no_unsigned requires Class-A authenticator_data');
            requireField(s?.webauthn?.client_data_json, 'strict no_unsigned requires Class-A client_data_json');
            requireField(s?.webauthn?.signature, 'strict no_unsigned requires Class-A WebAuthn signature');
        }
        else {
            requireField(s?.signature, 'strict no_unsigned requires Ed25519 signoff signature');
        }
    }
    markStrict(report, 'no_unsigned', noUnsignedOk);
    report.valid = STRICT_CHECK_NAMES.every((name) => report.checks[name] === true);
}
// ── Initiator escalation attestation (PIP-007) — ADVISORY only ────────────────
//
// PIP-007 §2: "None of these checks affects signature validity." This report is
// advisory: it never sets result.valid or any check in the frozen checks object.
// verifyTrustReceipt() surfaces it as result.attestation so consumers can act on
// it (or ignore it). A verifier that predates this PIP verifies the same receipt
// cryptographically unchanged — the attestation is just additional context.
const ATTESTATION_TRIGGERS = new Set([
    'irreversibility', 'magnitude', 'uncertainty', 'novelty', 'authority_gap', 'policy_rule',
]);
const ATTESTATION_MEMBERS = new Set(['escalation_trigger', 'policy_basis', 'statement']);
const ATTESTATION_STATEMENT_MAX = 280;
/**
 * Build the advisory attestation report (PIP-007 §2) for a receipt's contexts.
 * Returns { present, consistent, issues } and NEVER influences signature
 * validity:
 *   - present:    any context carries an initiator_attestation.
 *   - consistent: per §1, if present in any context it is present in EVERY
 *     context AND canonicalize(attestation) is identical across all of them.
 *     MUST be flagged on mismatch (the divide-and-misinform vector, §Security
 *     Considerations (a)).
 *   - issues:     SHOULD-flagged §1 malformations — unknown members, a
 *     `statement` over 280 chars, `policy_rule` without `policy_basis`, a bad
 *     `escalation_trigger`, and the cross-context-identity violations above.
 *
 * @param {object[]} contexts
 * @returns {{ present: boolean, consistent: boolean, issues: string[] }}
 */
function buildAttestationReport(contexts) {
    const withAtt = contexts.filter((c) => c && c.initiator_attestation !== undefined);
    if (withAtt.length === 0) {
        return { present: false, consistent: true, issues: [] };
    }
    const issues = [];
    let consistent = true;
    // Cross-context identity (PIP-007 §1): present in any → present in every, and
    // identical canonical form across all.
    if (withAtt.length !== contexts.length) {
        consistent = false;
        issues.push('initiator_attestation is present in some contexts but not all (PIP-007 §1 requires it in every context)');
    }
    const canonForms = new Set(withAtt.map((c) => canonicalize(c.initiator_attestation)));
    if (canonForms.size > 1) {
        consistent = false;
        issues.push('initiator_attestation differs across contexts (PIP-007 §1 requires an identical canonical form in every context)');
    }
    // Per-attestation §1 malformations (SHOULD-flag).
    for (const ctx of withAtt) {
        const att = ctx.initiator_attestation;
        const who = ctx.approver || 'unknown approver';
        if (!att || typeof att !== 'object' || Array.isArray(att)) {
            issues.push(`initiator_attestation for ${who} is not an object`);
            continue;
        }
        for (const key of Object.keys(att)) {
            if (!ATTESTATION_MEMBERS.has(key)) {
                issues.push(`initiator_attestation for ${who} has an unknown member "${key}" (PIP-007 §1 allows only escalation_trigger, policy_basis, statement)`);
            }
        }
        if (!ATTESTATION_TRIGGERS.has(att.escalation_trigger)) {
            issues.push(`initiator_attestation for ${who} has an invalid escalation_trigger "${att.escalation_trigger}"`);
        }
        if (att.escalation_trigger === 'policy_rule' && !att.policy_basis) {
            issues.push(`initiator_attestation for ${who} uses escalation_trigger "policy_rule" without policy_basis (PIP-007 §1)`);
        }
        if (typeof att.statement === 'string' && att.statement.length > ATTESTATION_STATEMENT_MAX) {
            issues.push(`initiator_attestation statement for ${who} exceeds the ${ATTESTATION_STATEMENT_MAX}-character cap (PIP-007 §1)`);
        }
    }
    return { present: true, consistent, issues };
}
function trustReceiptCanonicalProfileError(receipt) {
    try {
        // Validate the complete envelope first. Validating only shallow copies can
        // erase non-enumerable or symbol members before they reach the strict gate.
        if (!isCanonicalizable(receipt))
            return 'Trust Receipt body';
        const leafContent = { ...receipt };
        delete leafContent.log_proof;
        delete leafContent.approver_key_proofs;
        if (!isCanonicalizable(leafContent))
            return 'Trust Receipt body';
        const checkpoint = receipt?.log_proof?.checkpoint;
        if (checkpoint && typeof checkpoint === 'object') {
            const signedCheckpoint = { ...checkpoint };
            delete signedCheckpoint.log_signature;
            if (!isCanonicalizable(signedCheckpoint))
                return 'Trust Receipt checkpoint';
        }
        return null;
    }
    catch {
        return 'Trust Receipt body';
    }
}
/**
 * Verify a Trust Receipt (I-D Section 6.2) fully offline — the Section 6.3
 * algorithm. All six steps; fails closed on any missing input.
 *
 * @param {object} receipt - Section 6.2 Trust Receipt
 * @param {object} opts
 * @param {Record<string, {approver_id:string, public_key:string, key_class?:string, valid_from?:string, valid_to?:string, compromised_at?:string|null}>} [opts.approverKeys]
 *   - pinned approver key entries by approver_key_id (or a directory extract).
 * @param {Record<string, object>} [opts.previousApproverKeys]
 *   OPT-IN directory-transition guard. When supplied, verification fails closed
 *   if an already-pinned key's `valid_to` was narrowed into the past without a
 *   `compromised_at` marker. Requires `opts.now`. Planned future rotations pass.
 * @param {boolean} [opts.allowRetroactiveExpiryWithoutCompromise=false]
 *   Explicit exceptional override for a relying party that has independently
 *   established that a retroactive directory correction was not a compromise.
 * @param {string} [opts.now] - optional relying-party clock used to reject
 *   presenter-claimed issuance, signoff, or consumption after the decision time; evaluate
 *   current-mode key status, audit directory transitions, and validate dated
 *   revocation evidence. Required when `verificationMode` is `current`.
 * @param {'historical'|'current'} [opts.verificationMode='historical']
 *   Historical mode verifies authenticity at claimed issuance time. Current
 *   mode additionally requires every signing key to remain current at
 *   `opts.now`; it is the minimum mode for a current reliance decision.
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
 * The evidence options below are additive and fail closed. Each active check
 * adds one member to `checks` and folds into `valid` by conjunction. The
 * always-present `decision_scope` is deliberately separate: it prevents an
 * offline authenticity verdict from being misread as current admission or
 * replay prevention.
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
 * @param {boolean} [opts.requireTimestampProof=false]
 *   Require trusted-time evidence regardless of action type. Current-mode
 *   financial actions at or above USD 100,000 require it automatically.
 * @param {object[]} [opts.revocationStatements]
 *   Exact-target EP revocation statements. A valid statement refuses; an
 *   invalid exact-target statement is indeterminate and also refuses. Absence
 *   leaves current revocation status unknown.
 * @param {object} [opts.revokerKeys]
 *   Pinned revoker keys used for `revocationStatements`.
 * @param {Record<string, number>} [opts.webauthnSignCounts]
 *   Previously stored counters keyed by approver key ID.
 * @param {'observe'|'enforce'} [opts.webauthnCounterPolicy='observe']
 *   Observe or fail closed on a non-advancing, nonzero WebAuthn counter.
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
 * @returns {{ valid:boolean, checks:object, errors:string[], decision_scope:object, attestation:{ present:boolean, consistent:boolean, issues:string[] }, strict:{ enabled:boolean, valid:boolean, checks:object, errors:string[] }, witness_quorum?:object, timestamp_proof?:object, revocation?:object, currency?:object, consumption?:object, initiator_attestation?:object }}
 *   `attestation` is the PIP-007 §2 ADVISORY report. It never affects `valid` or
 *   any member of `checks`: a receipt with a malformed or inconsistent
 *   attestation still verifies (or fails) on its cryptographic checks alone.
 *   `decision_scope` is always present and states that this function establishes
 *   authenticity, not current admission or atomic replay prevention. Optional
 *   evidence results are present only when their respective inputs are supplied.
 */
export function verifyTrustReceipt(receipt, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const checks = {
        action_hash: false, // step 1
        context_commitments: false, // step 2
        signoff_signatures: false, // step 3
        sod: false, // step 4
        inclusion: false, // step 5a
        checkpoint_signature: false, // step 5b
        windows: false, // step 6
    };
    const errors = [];
    const optionalResults = {};
    const decisionScope = {
        authenticity_only: true,
        admission_authorized: false,
        replay_status: 'not_evaluated',
        revocation_status: 'unknown',
        quorum_ordering: {
            presented: false,
            evaluated: false,
            verifier: 'verifyQuorum',
        },
        warning: 'AUTHENTICITY IS NOT ADMISSION OR REPLAY PREVENTION',
    };
    const verificationMode = opts.verificationMode ?? 'historical';
    if (verificationMode !== 'historical' && verificationMode !== 'current') {
        return {
            valid: false,
            checks,
            errors: ['verificationMode must be "historical" or "current"'],
            decision_scope: decisionScope,
        };
    }
    // Optional relying-party clock. Absent, verification behaves exactly as
    // before; supplied, a claimed issuance in the future is refused. Left opt-in
    // because offline verification of an old receipt is a supported use.
    const verifierNow = opts.now === undefined || opts.now === null
        ? null
        : parseInstant(opts.now);
    if (verifierNow !== null && Number.isNaN(verifierNow)) {
        return {
            valid: false,
            checks,
            errors: ['opts.now is not a parseable instant'],
            decision_scope: decisionScope,
        };
    }
    if (verificationMode === 'current' && verifierNow === null) {
        return {
            valid: false,
            checks,
            errors: ['verificationMode "current" requires opts.now from the relying-party clock'],
            decision_scope: decisionScope,
        };
    }
    const strict = createStrictReport(opts.strict === true);
    let attestation = { present: false, consistent: true, issues: [] };
    const fail = (msg) => {
        errors.push(msg);
        return {
            valid: false,
            checks,
            errors,
            attestation,
            strict,
            decision_scope: decisionScope,
            ...optionalResults,
        };
    };
    if (!receipt || typeof receipt !== 'object')
        return fail('Missing receipt');
    const profileError = trustReceiptCanonicalProfileError(receipt);
    if (profileError) {
        return fail(`${profileError} is outside the EP canonicalization profile; only plain JSON data is accepted`);
    }
    // PIP-007 §2 advisory report — built only after the complete envelope passed
    // strict inspection, so accessors and hostile Proxy traps cannot execute here.
    const attestationContexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
    attestation = buildAttestationReport(attestationContexts);
    const { approverKeys = {}, logPublicKey } = opts;
    const contexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
    const signoffs = Array.isArray(receipt.signoffs) ? receipt.signoffs : [];
    decisionScope.quorum_ordering.presented = contexts.some((context) => context && typeof context === 'object' && Object.hasOwn(context, 'prev_context_hash'));
    if (!receipt.action || !receipt.action_hash)
        return fail('Missing action or action_hash');
    if (contexts.length === 0 || signoffs.length === 0)
        return fail('Missing contexts or signoffs');
    // I-JSON canonicalization gate (fail-closed) — identical guard to verifyReceipt.
    // Every field folded into a signed digest below (action, contexts, leaf content)
    // is re-canonicalized; a value outside the profile (e.g. 1e-7, 1e20, unsafe int)
    // canonicalizes differently across JS/Py/Go, so it is rejected here rather than
    // silently disagreeing. The signature/proof fields are excluded from the check.
    const { signoffs: _s, log_proof: _lp, approver_key_proofs: _akp, ...canonicalScope } = receipt;
    if (!isCanonicalizable(canonicalScope)) {
        return fail('Receipt contains a value outside the EP canonicalization profile; use strings or safe integers in signed material');
    }
    if (opts.previousApproverKeys !== undefined) {
        checks.key_directory_transition = false;
        const transition = auditApproverKeyDirectoryTransition(opts.previousApproverKeys, approverKeys, {
            now: opts.now,
            allowRetroactiveExpiryWithoutCompromise: opts.allowRetroactiveExpiryWithoutCompromise === true,
        });
        optionalResults.key_directory_transition = transition;
        checks.key_directory_transition = transition.valid === true;
        if (!checks.key_directory_transition) {
            errors.push(...transition.errors.map((error) => `approver-key directory: ${error}`));
        }
    }
    // ── Step 1: recompute the action hash from the canonical Action Object ────
    const actionHashHex = sha256(canonicalize(receipt.action));
    checks.action_hash = actionHashHex === hexOf(receipt.action_hash);
    if (!checks.action_hash)
        errors.push('action_hash does not match the canonical Action Object');
    // ── Step 2: per context — recompute the context hash; confirm commitments ─
    const contextByHash = new Map(); // hex digest -> context
    let commitmentsOk = true;
    const policyHashes = new Set();
    for (const ctx of contexts) {
        const digestHex = sha256(canonicalize(ctx));
        contextByHash.set(digestHex, ctx);
        if (hexOf(ctx.action_hash) !== actionHashHex) {
            commitmentsOk = false;
            errors.push(`context for ${ctx.approver || 'unknown approver'} does not commit to the action hash`);
        }
        if (!ctx.policy_hash) {
            commitmentsOk = false;
            errors.push('context is missing policy_hash');
        }
        else {
            policyHashes.add(hexOf(ctx.policy_hash));
        }
        if (!ctx.approver) {
            commitmentsOk = false;
            errors.push('context is missing approver');
        }
    }
    // All contexts in one receipt must commit to the same evaluated policy.
    if (policyHashes.size > 1) {
        commitmentsOk = false;
        errors.push('contexts commit to different policy hashes');
    }
    checks.context_commitments = commitmentsOk;
    // ── Step 3: per signoff — signature over the context hash vs approver key ─
    const validSignoffs = []; // cryptographically valid signed decisions, including denials
    const validApprovals = []; // validSignoffs whose signed decision authorizes the action
    const webauthnSignoffs = [];
    let signaturesOk = signoffs.length > 0;
    for (const s of signoffs) {
        const digestHex = hexOf(s.context_hash);
        const ctx = contextByHash.get(digestHex);
        if (!ctx) {
            signaturesOk = false;
            errors.push('signoff references a context hash not present in this receipt');
            continue;
        }
        const keyEntry = approverKeys[s.approver_key_id];
        if (!keyEntry?.public_key) {
            signaturesOk = false;
            errors.push(`no pinned key entry for ${s.approver_key_id}`);
            continue;
        }
        // A pinned key proves a principal only when the directory entry names that
        // principal. Without this join, any pinned low-privilege key can sign a
        // context that self-asserts a CFO/clinician/admin approver and the receipt
        // falsely reports that the named human approved. The Approver Directory
        // contract requires approver_id; missing or mismatched identity is a hard
        // signature failure, not advisory metadata.
        if (typeof keyEntry.approver_id !== 'string' || keyEntry.approver_id.length === 0) {
            signaturesOk = false;
            errors.push(`pinned key ${s.approver_key_id} is missing approver_id`);
            continue;
        }
        if (keyEntry.approver_id !== ctx.approver) {
            signaturesOk = false;
            errors.push(`pinned key ${s.approver_key_id} belongs to ${keyEntry.approver_id}, not context approver ${ctx.approver}`);
            continue;
        }
        // Key compromise is TERMINAL and RETROACTIVE, and is deliberately not a
        // window edge. `valid_to` answers "when did this key expire", and it is
        // compared against ctx.issued_at, which the presenter signs with this very
        // key. A holder of a stolen key can therefore mint a receipt after the key
        // is revoked and backdate issued_at into the window, and every window check
        // still passes. Expiry-driven rotation can live with that; compromise
        // cannot. `compromised_at` refuses the key outright, whatever time the
        // presenter claims, matching the rule docs/AUTHORITY-GOVERNANCE.md §4.4
        // already states for authority changes: compromise can be backdated in its
        // effect window, so a revocation at t1 < t0 taints the whole span.
        if (keyEntry.compromised_at !== undefined && keyEntry.compromised_at !== null) {
            const compromisedAt = parseInstant(keyEntry.compromised_at);
            if (Number.isNaN(compromisedAt)) {
                signaturesOk = false;
                errors.push(`pinned key ${s.approver_key_id} has an unparseable compromised_at`);
                continue;
            }
            signaturesOk = false;
            errors.push(`approver key ${s.approver_key_id} is marked compromised; no claimed issued_at can clear it`);
            continue;
        }
        // Key validity window must contain the context's issued_at (Section 5.2).
        if (!withinWindow(ctx.issued_at, keyEntry.valid_from, keyEntry.valid_to)) {
            signaturesOk = false;
            errors.push(`approver key ${s.approver_key_id} was not valid at issued_at`);
            continue;
        }
        if (verificationMode === 'current') {
            const currentFrom = parseInstant(keyEntry.valid_from);
            const currentTo = parseInstant(keyEntry.valid_to);
            if (Number.isNaN(currentFrom) || Number.isNaN(currentTo)
                || verifierNow < currentFrom || verifierNow > currentTo) {
                signaturesOk = false;
                errors.push(`approver key ${s.approver_key_id} is not current at the verifier decision time`);
                continue;
            }
        }
        // The window above is only as honest as ctx.issued_at, which the presenter
        // asserts. When the relying party supplies its own clock, refuse a claimed
        // issuance in the future: a receipt cannot have been approved after the
        // moment it is being verified. This does not bound backdating on its own
        // (see compromised_at above, and opts.timestampProof for a trusted anchor).
        if (verifierNow !== null && parseInstant(ctx.issued_at) > verifierNow) {
            signaturesOk = false;
            errors.push(`issued_at for ${s.approver_key_id} is in the future relative to the verifier clock`);
            continue;
        }
        if (verifierNow !== null && parseInstant(s.signed_at) > verifierNow) {
            signaturesOk = false;
            errors.push(`signed_at for ${s.approver_key_id} is in the future relative to the verifier clock`);
            continue;
        }
        const digestBytes = Buffer.from(digestHex, 'hex');
        // The PINNED key entry's class is authoritative and takes precedence over the
        // attacker-controlled signoff's declared key_class. Otherwise an attacker
        // pins a Class-A (WebAuthn, user-presence/user-verification) approver but
        // declares key_class:'B' and supplies a bare ECDSA/Ed25519 signature over the
        // digest, downgrading to raw-signature verification with NO WebAuthn proof.
        // A pinned Class-A key MUST be satisfied by a real WebAuthn assertion and is
        // rejected if it only carries a raw signature.
        const keyClass = keyEntry.key_class === 'A' ? 'A' : 'B';
        let sigOk;
        if (keyClass === 'A') {
            const counterOptions = {
                ...opts,
                previousSignCount: opts.webauthnSignCounts?.[s.approver_key_id],
                counterPolicy: opts.webauthnCounterPolicy ?? 'observe',
            };
            const webauthnResult = Boolean(s.webauthn)
                ? verifyClassAOverDigest(s.webauthn, digestBytes, keyEntry.public_key, counterOptions)
                : { valid: false, authenticator: null, error: 'missing WebAuthn assertion' };
            webauthnSignoffs.push({
                approver_key_id: s.approver_key_id,
                approver: ctx.approver,
                authenticator: webauthnResult.authenticator,
                counter_policy: counterOptions.counterPolicy,
                valid: webauthnResult.valid === true,
                ...(webauthnResult.error ? { error: webauthnResult.error } : {}),
            });
            sigOk = webauthnResult.valid === true;
        }
        else {
            sigOk = verifyEd25519OverDigest(s.signature, digestBytes, keyEntry.public_key);
        }
        if (!sigOk) {
            signaturesOk = false;
            errors.push(`signoff by ${ctx.approver} does not verify`);
            continue;
        }
        const verifiedSignoff = { approver: ctx.approver, signedAt: s.signed_at, ctx };
        validSignoffs.push(verifiedSignoff);
        // Pre-decision Authorization Contexts remain compatible as implicit
        // approvals. Once a decision is present, only the typed `approved` outcome
        // can satisfy authorization; a valid signature over `denied` remains useful
        // decision evidence but cannot be counted as an approval.
        if (ctx.decision === undefined || ctx.decision === 'approved') {
            validApprovals.push(verifiedSignoff);
        }
        else if (ctx.decision === 'denied') {
            errors.push(`signed denial by ${ctx.approver} does not authorize the action`);
        }
        else {
            errors.push(`signed decision by ${ctx.approver} is not a recognized approval outcome`);
        }
    }
    checks.signoff_signatures = signaturesOk;
    if (webauthnSignoffs.length > 0)
        optionalResults.webauthn_signoffs = webauthnSignoffs;
    // ── Step 4: separation of duties ──────────────────────────────────────────
    const initiator = receipt.action.initiator;
    const approvers = validApprovals.map((a) => a.approver);
    const coerced = contexts.map((c) => coerceRequiredApprovals(c.required_approvals));
    let sodOk = true;
    if (coerced.some((n) => n === null)) {
        sodOk = false;
        errors.push('required_approvals must be an integer >= 1 (fail-closed on non-integer)');
    }
    const requiredApprovals = Math.max(1, ...coerced.map((n) => n ?? 1));
    if (initiator && approvers.includes(initiator)) {
        sodOk = false;
        errors.push('initiator appears in an approver slot (SoD violation)');
    }
    if (new Set(approvers).size !== approvers.length) {
        sodOk = false;
        errors.push('approvers are not pairwise distinct');
    }
    if (validApprovals.length < requiredApprovals) {
        sodOk = false;
        errors.push(`approval count ${validApprovals.length} < required_approvals ${requiredApprovals}`);
    }
    checks.sod = sodOk;
    // ── Step 5: inclusion proof + checkpoint signature ────────────────────────
    const lp = receipt.log_proof;
    if (lp?.checkpoint && Array.isArray(lp.inclusion_path)) {
        const leafContent = { ...receipt };
        delete leafContent.log_proof;
        delete leafContent.approver_key_proofs;
        const canonicalLeaf = canonicalize(leafContent);
        const merkleAlg = lp.alg || lp.checkpoint?.merkle_alg || null;
        // Degenerate empty-path rule (fail-closed): with an empty inclusion_path the
        // Merkle fold collapses to leafHash === root_hash, which is only a true
        // inclusion statement for a SINGLE-LEAF tree. Without this gate, a forged
        // checkpoint whose root_hash simply repeats the leaf hash would "include"
        // the receipt at ANY claimed tree_size. An empty path is therefore accepted
        // ONLY when the checkpoint's tree_size is exactly the integer 1 (and, since
        // this shape carries an index, leaf_index — when present — is 0). Any other
        // tree size (including a missing or non-integer tree_size) refuses with a
        // distinct reason. Applies to v2 AND opt-in legacy folds; mirrored by the
        // Python and Go ports.
        let emptyPathRefusal = null;
        if (lp.inclusion_path.length === 0) {
            if (lp.checkpoint.tree_size !== 1) {
                emptyPathRefusal = 'empty inclusion_path requires checkpoint tree_size 1 (single-leaf tree)';
            }
            else if (lp.leaf_index !== undefined && lp.leaf_index !== 0) {
                emptyPathRefusal = 'empty inclusion_path requires leaf_index 0 in a single-leaf tree';
            }
        }
        if (emptyPathRefusal) {
            checks.inclusion = false;
            errors.push(emptyPathRefusal);
        }
        else if (merkleAlg === MERKLE_V2_ALG) {
            // EP-MERKLE-v2 (default): leaf is domain-separated (0x00) and bound to the
            // canonical receipt payload; the proof folds with positional, domain-
            // separated (0x01) branch hashing. Closes leaf/branch second-preimage
            // confusion and root equivocation. When log_proof carries an explicit
            // leaf_hash, it must bind THIS receipt's canonical payload.
            const leafHash = leafHashV2(canonicalLeaf);
            const presentedLeaf = lp.leaf_hash ? hexOf(lp.leaf_hash) : leafHash;
            checks.inclusion = presentedLeaf === leafHash
                && verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash), { v2: true });
            if (presentedLeaf !== leafHash)
                errors.push('Trust Receipt log_proof leaf_hash does not bind this receipt');
            else if (!checks.inclusion)
                errors.push('EP-MERKLE-v2 inclusion proof does not reconstruct the checkpoint root');
        }
        else if (opts.allowLegacyMerkle === true || opts.allowLegacyTrustReceiptMerkle === true) {
            // Dormant legacy path: pre-v2 (sorted-pair, undomain-separated) inclusion
            // verifies ONLY when the caller explicitly opts in. Never the default,
            // never used by production gates.
            const leafHash = sha256(canonicalLeaf);
            checks.inclusion = verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash));
            if (!checks.inclusion)
                errors.push('legacy EP-MERKLE-v1 inclusion proof does not reconstruct the checkpoint root');
        }
        else {
            // Default (and every production gate): require EP-MERKLE-v2. A legacy v1
            // proof is refused unless the caller passes { allowLegacyMerkle: true }.
            checks.inclusion = false;
            errors.push('log_proof is not EP-MERKLE-v2 (legacy v1 refused unless allowLegacyMerkle is set)');
        }
        if (logPublicKey && lp.checkpoint.log_signature) {
            const signedCheckpoint = { ...lp.checkpoint };
            delete signedCheckpoint.log_signature;
            checks.checkpoint_signature = verifyEd25519OverDigest(String(lp.checkpoint.log_signature).replace(/^b64u:/, ''), sha256Bytes(canonicalize(signedCheckpoint)), logPublicKey);
            if (!checks.checkpoint_signature)
                errors.push('checkpoint signature does not verify against the log key');
        }
        else {
            errors.push('missing log public key or checkpoint signature');
        }
    }
    else {
        errors.push('missing log_proof (inclusion path + checkpoint)');
    }
    // ── Step 5c (OPT-IN): append-only consistency from a pinned prior head ────
    // When the caller pins a previously-OBSERVED checkpoint head
    // (opts.priorCheckpoint = { tree_size, root_hash, consistency_proof }), the
    // receipt's checkpoint MUST additionally be proven an append-only extension
    // of that head via an RFC 6962 §2.1.2 consistency proof over EP-MERKLE-v2
    // branch hashing (consistency.js). The proof travels IN THE OPTION, not
    // inside the receipt's log_proof: a consistency proof is relative to
    // whichever head THIS verifier pinned, so the issuer cannot embed one at
    // issuance (no such field exists in the Section 6.2 artifact shape); the
    // verifier obtains it from the log alongside the receipt and supplies it
    // here. An EMPTY array is a legitimate proof only for equal heads (same
    // tree_size, same root_hash); a missing/non-array proof always refuses.
    //
    // HONESTY: this proves append-only consistency between two OBSERVED heads.
    // It does NOT establish currency (that the receipt's head is the log's
    // latest) and does NOT by itself detect split-view equivocation (a log
    // showing different histories to different verifiers) — that requires
    // independent witnesses/gossip. See docs/security/TRANSPARENCY-LAYER-DESIGN.md.
    //
    // Fail-closed: option set + malformed pin, unusable receipt checkpoint,
    // missing proof, or invalid proof each refuse with a distinct reason and
    // fail the receipt via checks.consistency. Option NOT set: this block never
    // runs and checks keeps its frozen seven members.
    if (opts.priorCheckpoint !== undefined) {
        checks.consistency = false;
        const prior = opts.priorCheckpoint;
        const priorSize = prior?.tree_size;
        const priorRoot = hexOf(prior?.root_hash);
        const headSize = lp?.checkpoint?.tree_size;
        const headRoot = hexOf(lp?.checkpoint?.root_hash);
        if (!prior || typeof prior !== 'object' || !Number.isInteger(priorSize) || priorSize < 1 || !priorRoot) {
            errors.push('priorCheckpoint requires integer tree_size >= 1 and root_hash');
        }
        else if (!Number.isInteger(headSize) || !headRoot) {
            errors.push('priorCheckpoint is pinned but the receipt checkpoint is missing tree_size or root_hash');
        }
        else if (!Array.isArray(prior.consistency_proof)) {
            errors.push('priorCheckpoint is pinned but consistency_proof is missing');
        }
        else if (verifyCheckpointConsistency(priorRoot, priorSize, headRoot, headSize, prior.consistency_proof)) {
            checks.consistency = true;
        }
        else {
            errors.push('consistency_proof does not prove an append-only extension from the pinned prior checkpoint');
        }
    }
    // ── Step 5d..5h (OPT-IN transparency/currency knobs) ──────────────────────
    // Each block below is additive and mirrors the priorCheckpoint pattern: it
    // runs ONLY when its option is present, sets ONE new `checks` member to false
    // first (fail-closed default) then flips it true only on a clean pass, and
    // surfaces its full module result under a dedicated, option-gated member of
    // `optionalResults`. When no evidence option is supplied, `checks` keeps
    // exactly its frozen seven members and `optionalResults` stays empty.
    // ── Step 5d (OPT-IN): k-of-n witness cosignatures (EP-WITNESS-v1) ─────────
    // Require >= k DISTINCT pinned witnesses to have validly cosigned the
    // receipt's checkpoint head. HONESTY: this proves k trusted witnesses saw ONE
    // head (the local, single-view half of equivocation detection); it does NOT
    // prove no different head was shown to someone else (needs gossip). Fail
    // closed: a receipt with no usable checkpoint, or fewer than k distinct valid
    // cosignatures, refuses via checks.witness_quorum. The module already returns
    // ok:false for a bad k or non-array inputs.
    if (opts.witnessQuorum !== undefined) {
        checks.witness_quorum = false;
        const wq = opts.witnessQuorum;
        const checkpoint = lp?.checkpoint;
        if (!checkpoint || typeof checkpoint !== 'object') {
            optionalResults.witness_quorum = {
                ok: false, met: 0, required: 0, witness_ids: [],
                reasons: ['receipt has no checkpoint for witnesses to cosign'],
            };
            errors.push('witnessQuorum is set but the receipt checkpoint is missing');
        }
        else if (!wq || typeof wq !== 'object') {
            optionalResults.witness_quorum = {
                ok: false, met: 0, required: 0, witness_ids: [],
                reasons: ['witnessQuorum must be an object { cosignatures, pinnedWitnessKeys, k }'],
            };
            errors.push('witnessQuorum must be an object with cosignatures, pinnedWitnessKeys, and k');
        }
        else {
            const res = requireWitnessQuorum(checkpoint, wq.cosignatures, wq.pinnedWitnessKeys, wq.k);
            optionalResults.witness_quorum = res;
            checks.witness_quorum = res.ok === true;
            if (!checks.witness_quorum) {
                errors.push(`witness quorum not met: ${res.met}/${res.required} distinct pinned witnesses cosigned this head`);
            }
        }
    }
    // ── Step 5e (OPT-IN): RFC 3161 trusted-time proof (TIMESTAMP_PROOF_ALG) ────
    // Verify a TSA timestamp token over a caller-chosen digest against a PINNED
    // TSA key. HONESTY: proves a TSA asserted the digest existed at gen_time; it
    // does NOT prove the action was correct/authorized and is authentic-as-of-
    // token only. Fail closed: the module refuses (verified:false + reason) on
    // missing token, missing/malformed digest, an unpinned TSA, or a bad
    // signature; a refusal fails checks.timestamp_proof.
    const timestampRequiredByPolicy = opts.requireTimestampProof === true;
    const timestampRequiredByFinancialProfile = verificationMode === 'current' && isHighValueFinancialAction(receipt.action);
    const timestampRequired = timestampRequiredByPolicy || timestampRequiredByFinancialProfile;
    if (timestampRequired && opts.timestampProof === undefined) {
        const reason = timestampRequiredByFinancialProfile
            ? 'high-value financial action requires timestampProof in current-evidence mode'
            : 'relying-party policy requires timestampProof';
        checks.timestamp_proof = false;
        optionalResults.timestamp_proof = {
            verified: false,
            tsa_key_id: null,
            gen_time: null,
            reason,
        };
        errors.push(reason);
    }
    else if (opts.timestampProof !== undefined) {
        checks.timestamp_proof = false;
        const tp = opts.timestampProof;
        if (!tp || typeof tp !== 'object') {
            optionalResults.timestamp_proof = {
                verified: false, tsa_key_id: null, gen_time: null,
                reason: 'timestampProof must be an object { token, expectedDigest, pinnedTsaKeys }',
            };
            errors.push('timestampProof must be an object with token, expectedDigest, and pinnedTsaKeys');
        }
        else {
            const res = verifyTimestampProof(tp.token, tp.expectedDigest, tp.pinnedTsaKeys);
            optionalResults.timestamp_proof = res;
            checks.timestamp_proof = res.verified === true;
            if (!checks.timestamp_proof) {
                errors.push(`timestamp proof did not verify: ${res.reason}`);
            }
        }
    }
    // ── Step 5e.1 (OPT-IN): presented exact-target revocation statements ──────
    // Absence is never called "not revoked": without a current authenticated
    // status source the default remains `unknown`. A valid exact-target terminal
    // revocation refuses. A malformed exact-target statement is
    // `indeterminate` and also refuses rather than being ignored.
    if (opts.revocationStatements !== undefined) {
        checks.revocation = false;
        const statements = opts.revocationStatements;
        const target = {
            target_type: 'receipt',
            target_id: receipt.receipt_id,
            action_hash: receipt.action_hash,
        };
        const reports = [];
        let exactPresented = false;
        let revoked = false;
        let indeterminate = false;
        if (!Array.isArray(statements)) {
            indeterminate = true;
            errors.push('revocationStatements must be an array');
        }
        else {
            for (const statement of statements) {
                const exact = statement?.target_type === target.target_type
                    && statement?.target_id === target.target_id
                    && hexOf(statement?.action_hash) === hexOf(target.action_hash);
                if (!exact)
                    continue;
                exactPresented = true;
                const report = verifyRevocationStatement(target, statement, {
                    revokerKeys: opts.revokerKeys,
                    now: opts.now,
                });
                reports.push(report);
                if (report.valid)
                    revoked = true;
                else
                    indeterminate = true;
            }
        }
        const status = revoked
            ? 'revoked'
            : indeterminate
                ? 'indeterminate'
                : exactPresented
                    ? 'indeterminate'
                    : 'not_found_in_presented_set';
        optionalResults.revocation = {
            status,
            exact_target_statements: reports.length,
            reports,
            warning: status === 'not_found_in_presented_set'
                ? 'absence from the presented set is not proof of current non-revocation'
                : null,
        };
        decisionScope.revocation_status = status;
        checks.revocation = status === 'not_found_in_presented_set';
        if (status === 'revoked')
            errors.push('receipt is revoked by an authentic exact-target statement');
        else if (status === 'indeterminate')
            errors.push('exact-target revocation status is indeterminate');
    }
    // ── Step 5f (OPT-IN): currency-at-T (EP-CURRENCY-v1) ──────────────────────
    // Two-axis evaluation. `checks.currency` GATES validity and passes ONLY on a
    // proven `fresh` status. Both `stale` and the honest offline default
    // `unknown` FAIL this opted-in gate: opting in means the caller REQUIRES
    // demonstrated freshness, and offline verification can NEVER prove currency,
    // so absence of proof does not pass (fail-closed). The full two-axis result
    // (authentic_as_of_commit + currency_at_T{status,evaluated_at,reason}) is
    // surfaced so the caller can distinguish `unknown` from `stale`.
    if (opts.currency !== undefined) {
        checks.currency = false;
        const c = (opts.currency && typeof opts.currency === 'object') ? opts.currency : {};
        // authentic_as_of_commit is a SEPARATE axis (offline authenticity), passed
        // through verbatim and fail-safe to false. It does NOT influence the
        // currency status gate below, which is driven solely by freshHead recency
        // and revocation. The caller supplies it (typically this same call's overall
        // `valid`); if omitted it records false rather than guessing an in-progress
        // partial verdict.
        const res = evaluateCurrency({
            receipt,
            authentic_as_of_commit: c.authentic_as_of_commit === true,
            now: c.now,
            maxStalenessSeconds: c.maxStalenessSeconds,
            freshHead: c.freshHead,
            freshHeadRequired: c.freshHeadRequired,
        });
        optionalResults.currency = res;
        checks.currency = res.currency_at_T.status === 'fresh';
        if (!checks.currency) {
            errors.push(`currency gate not satisfied: status "${res.currency_at_T.status}" (${res.currency_at_T.reason}); only "fresh" passes`);
        }
    }
    // ── Step 5g (OPT-IN): third-party consumption proof (EP-SMT-CONSUME-v1) ────
    // Prove a one-time nonce transitioned absent -> present exactly once between
    // two append-only-linked heads. HONESTY: proves the tree-shaped consumption
    // facts only; checkpoint SIGNATURES are the caller's responsibility and it
    // does NOT establish currency of the later head. Fail closed: the module
    // refuses with a distinct reason on any missing/malformed/invalid sub-proof;
    // a refusal fails checks.consumption.
    if (opts.consumptionProof !== undefined) {
        checks.consumption = false;
        const res = verifyConsumptionProof(opts.consumptionProof);
        optionalResults.consumption = res;
        checks.consumption = res.valid === true;
        if (!checks.consumption) {
            errors.push(`consumption proof did not verify: ${res.reason}`);
        }
        else {
            decisionScope.replay_status = 'presented_consumption_proof_verified_not_atomic_admission';
        }
    }
    // ── Step 5h (OPT-IN): initiating-software attestation (EP-INITIATOR-...) ───
    // Structurally validate the self-asserted initiating-software attestation at
    // receipt.action.initiator_software. HONESTY: says WHICH software asked; it
    // does NOT prove the software behaved (labels are self-asserted). Fail
    // closed: when required, an absent or malformed attestation fails
    // checks.initiator_attestation (the module never repairs a malformed one).
    if (opts.requireInitiatorAttestation === true) {
        checks.initiator_attestation = false;
        const att = (receipt.action && typeof receipt.action === 'object')
            ? receipt.action.initiator_software
            : undefined;
        if (att === undefined) {
            optionalResults.initiator_attestation = {
                ok: false, normalized: null,
                errors: ['requireInitiatorAttestation is set but action.initiator_software is absent'],
                statement_report: null,
            };
            errors.push('requireInitiatorAttestation is set but action.initiator_software is absent');
        }
        else {
            const res = validateInitiatorAttestation(att);
            optionalResults.initiator_attestation = res;
            checks.initiator_attestation = res.ok === true;
            if (!checks.initiator_attestation) {
                errors.push(`initiator_software attestation is invalid: ${res.errors.join('; ')}`);
            }
        }
    }
    // ── Step 6: temporal windows ──────────────────────────────────────────────
    let windowsOk = validSignoffs.length > 0;
    for (const a of validSignoffs) {
        if (!withinWindow(a.signedAt, a.ctx.issued_at, a.ctx.expires_at)) {
            windowsOk = false;
            errors.push(`signed_at for ${a.approver} falls outside [issued_at, expires_at]`);
        }
    }
    const committedAt = receipt.consumption?.committed_at;
    if (!committedAt) {
        windowsOk = false;
        errors.push('missing consumption.committed_at');
    }
    else {
        if (verifierNow !== null && parseInstant(committedAt) > verifierNow) {
            windowsOk = false;
            errors.push('committed_at is in the future relative to the verifier clock');
        }
        for (const ctx of contexts) {
            if (!withinWindow(committedAt, ctx.issued_at, ctx.expires_at)) {
                windowsOk = false;
                errors.push('committed_at falls outside a context validity window');
                break;
            }
        }
    }
    checks.windows = windowsOk;
    // `attestation` is advisory (PIP-007 §2): it is deliberately excluded from the
    // `valid` computation. `strict` is opt-in: default verification remains exactly
    // the conjunction of the frozen Section 6.3 `checks`; strict mode adds a second
    // deployment-grade gate without renaming or reinterpreting those checks.
    if (strict.enabled) {
        evaluateTrustReceiptStrict(strict, receipt, contexts, signoffs, contextByHash, approverKeys, logPublicKey, opts);
        if (!strict.valid) {
            errors.push(...strict.errors);
        }
    }
    const valid = Object.values(checks).every(Boolean) && strict.valid;
    // Spread optional evidence reports last. decision_scope remains unconditional
    // so no caller can silently equate authenticity with executable authority.
    return {
        valid,
        checks,
        errors,
        attestation,
        strict,
        decision_scope: decisionScope,
        ...optionalResults,
    };
}
/**
 * Verify a signed Outcome Attestation against the exact, fully verified Trust
 * Receipt whose signed Action Object carries predicted_effects.
 */
export function verifyOutcomeBinding(receipt, attestation, opts = {}) {
    return verifyOutcomeBindingCore(receipt, attestation, opts, verifyTrustReceipt);
}
/** Verify a Trust Receipt against all required signed outcome sources. */
export function verifyOutcomeBindingSet(receipt, observations, opts = {}) {
    return verifyOutcomeBindingSetCore(receipt, observations, opts, verifyTrustReceipt);
}
// =============================================================================
// PIP-008 — L4 -> L7 binding: record relied-on agent identity + freshness
// =============================================================================
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
export function evaluateAgentBinding(context, opts = {}) {
    const binding = (context && typeof context === 'object') ? context.agent_binding : null;
    if (!binding || typeof binding !== 'object') {
        return { present: false, fresh: null, age_seconds: null, reason: 'no_agent_binding' };
    }
    const d = (binding.delegation && typeof binding.delegation === 'object') ? binding.delegation : null;
    /** @type {{present: boolean, agent_id?: string, delegation?: object|null,
     *   evidence_hash?: string|null, observed_at?: string|null,
     *   fresh: boolean|null, age_seconds: number|null, reason: string}} */
    const out = {
        present: true,
        agent_id: binding.agent_id,
        delegation: d
            ? {
                scheme: d.scheme,
                ref: d.ref,
                ...(d.hash ? { hash: d.hash } : {}),
                ...(d.observed_at ? { observed_at: d.observed_at } : {}),
            }
            : null,
        evidence_hash: (d && d.hash) || null,
        observed_at: (d && d.observed_at) || null,
        fresh: null,
        age_seconds: null,
        reason: 'recorded',
    };
    const { maxAgeSec, at } = opts;
    if (Object.hasOwn(opts, 'maxAgeSec')) {
        if (typeof maxAgeSec !== 'number' || !Number.isFinite(maxAgeSec) || maxAgeSec < 0) {
            out.fresh = false;
            out.reason = 'freshness_profile_invalid';
            return out;
        }
        if (!out.observed_at) {
            out.fresh = false;
            out.reason = 'freshness_required_but_no_observed_at';
            return out;
        }
        const obs = parseInstant(out.observed_at);
        if (!Number.isFinite(obs)) {
            out.fresh = false;
            out.reason = 'unparseable_observed_at';
            return out;
        }
        const ref = at === undefined ? Date.now() : parseInstant(at);
        if (!Number.isFinite(ref)) {
            out.fresh = false;
            out.reason = 'freshness_reference_time_invalid';
            return out;
        }
        const ageSec = (ref - obs) / 1000;
        out.age_seconds = Math.round(ageSec);
        if (ageSec < -60) { // observed in the future (allow 60s clock skew)
            out.fresh = false;
            out.reason = 'observed_at_in_future';
        }
        else if (ageSec > maxAgeSec) {
            out.fresh = false;
            out.reason = `stale: L4 evidence observed ${out.age_seconds}s ago (max ${maxAgeSec}s)`;
        }
        else {
            out.fresh = true;
            out.reason = 'fresh';
        }
    }
    return out;
}
// =============================================================================
// FEDERATION (PIP-006)
// =============================================================================
// Operator-B cross-operator verification. Re-exported from the main entry so a
// relying party can `import { verifyFederatedReceipt } from '@emilia-protocol/verify'`
// alongside the single-operator primitives above. See ./federation.js.
export { resolveOperatorKeys, verifyFederatedReceiptOffline, verifyFederatedReceipt, } from './federation.js';
// EP-QUORUM-v1 — multi-party (M-of-N / ordered) approval, additive over EP-SIGNOFF-v1.
export { verifyQuorum } from './quorum.js';
// EP-AEB-CROSSING-RECORD-v1 — carrier-neutral evidence that one exact action
// crossed one relying-party boundary under one verified native authority
// instance. Verification is evidence-only and never authorizes another entry.
export { AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS, AEB_CROSSING_RECORD_VERSION, BCR_CROSSING_ADAPTER, BCR_CROSSING_MAPPING_PROFILE, WIMSE_OAUTH_CROSSING_ADAPTER, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE, crossingRecordContractDigest, crossingRecordDigest, crossingRecordSignedBytes, issueAebCrossingRecord, mapBcrCrossingAuthority, mapWimseOAuthCrossingAuthority, verifyAebCrossingRecord, } from './aeb-crossing-record.js';
// Native AIC crossing mappings preserve the pure-JSON RFC 7638 JKT and
// X.509 SPKI cases as separate authority systems. The JWT-SVID helper emits a
// new-signature-required identity projection and never authorizes an action.
export { AIC_JWT_JKT_CROSSING_MAPPING_PROFILE, AIC_JWT_SVID_PROJECTION_VERSION, AIC_X509_SPKI_CROSSING_MAPPING_PROFILE, mapAicJwtJktCrossingAuthority, mapAicX509SpkiCrossingAuthority, projectAicJwtToStrictJwtSvid, } from './aeb-aic-crossing-adapter.js';
// EP-AEC-v1 is available through the explicit `./evidence-chain` package subpath.
// It is not re-exported here because evidence-chain.js composes this module and a
// main-entry re-export would create a circular initialization path.
//# sourceMappingURL=index.js.map