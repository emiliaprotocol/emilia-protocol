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

// Recursive canonical JSON — depth-first key sort at every level.
//
// The previous implementation
//
//   JSON.stringify(obj, Object.keys(obj).sort())
//
// was a SHALLOW canonicalization. The second argument to JSON.stringify
// in array form is a property allowlist filter, NOT a sort order, and it
// does NOT recurse into nested objects to enforce key order at depth.
// Worse, it filters nested keys to only those names present in the
// top-level allowlist.
//
// Net effect of the shallow pattern: a verifier and a signer that both
// "sort keys before signing" could compute different canonical bytes for
// the same logical document, producing a false-negative signature
// failure. And nested fields (e.g. claim.context.risk_signals or
// claim.context.change.after_bank_hash) were not deterministically
// included in the signed material under the shallow algorithm.
//
// The fix below is the same recursive canonicalize() used by
// lib/guard-policies.js (hashCanonicalAction) on the server side, so
// signer and verifier produce byte-identical canonical material for any
// arbitrarily-nested object.
//
// Bug history: shipped in 1.0.0, fixed in 1.0.1. See package.json.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

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
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value) && Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(isCanonicalizable);
  if (typeof value === 'object') return Object.values(value).every(isCanonicalizable);
  return false; // undefined, bigint, symbol, function — out of profile
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
// renewal chain) so a receipt's non-repudiation survives algorithm aging.
export { verifyEvidenceRecord, EVIDENCE_RECORD_VERSION } from './evidence-record.js';

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
  const checks = { version: false, signature: false, anchor: null };

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
    const publicKeyDer = Buffer.from(publicKeyBase64url, 'base64url');
    const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const sigBytes = Buffer.from(doc.signature.value, 'base64url');
    checks.signature = crypto.verify(null, payloadBytes, keyObject, sigBytes);
  } catch (e) {
    return { valid: false, checks, error: `Signature verification failed: ${e.message}` };
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
    } else if (opts.allowLegacyMerkle === true) {
      // Dormant legacy path: pre-v2 (sorted-pair, unbound) anchors verify ONLY
      // when a caller explicitly opts in — old artifacts and compatibility tests.
      // Never the default, never used by production gates. Preserves the
      // "receipts verify forever" promise without carrying live v1 risk.
      checks.anchor = verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
    } else {
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
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 20) return false;

  const pair = opts.v2 === true ? hashPairV2 : hashPair;
  let current = leafHash;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string') return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
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

/**
 * Verify a Class A (approver-held key) signoff fully offline.
 *
 * What this proves with pure math, no network, no EP server:
 *   - the WebAuthn challenge the device signed equals
 *     SHA-256(JCS(context)) for the EXACT context in the signoff — which
 *     binds the action hash, nonce, approver, and validity window;
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
 * @param {{ rpId?: string }} [opts]
 * @returns {{ valid: boolean, checks: object, error?: string }}
 */
export function verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, opts = {}) {
  const checks = {
    challenge_binding: false,
    client_data_type: false,
    user_present: false,
    user_verified: false,
    rp_id_hash: null,
    signature: false,
  };

  try {
    if (!signoff?.context || !signoff?.webauthn) {
      return { valid: false, checks, error: 'Missing context or webauthn evidence' };
    }
    const { authenticator_data, client_data_json, signature } = signoff.webauthn;
    if (!authenticator_data || !client_data_json || !signature) {
      return { valid: false, checks, error: 'Missing webauthn fields' };
    }

    // 1. Challenge binding: clientDataJSON.challenge must equal
    //    b64u(SHA-256(canonical(context))). The context is re-canonicalized
    //    here — tamper any field (amount, approver, nonce) and this fails.
    const clientDataBytes = Buffer.from(client_data_json, 'base64url');
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const expectedChallenge = crypto
      .createHash('sha256')
      .update(canonicalize(signoff.context), 'utf8')
      .digest()
      .toString('base64url');
    checks.challenge_binding = clientData.challenge === expectedChallenge;

    // 2. Ceremony type must be an assertion, not a registration.
    checks.client_data_type = clientData.type === 'webauthn.get';

    // 3. Authenticator flags: user present + user verified.
    const authData = Buffer.from(authenticator_data, 'base64url');
    if (authData.length < 37) {
      return { valid: false, checks, error: 'authenticator_data too short' };
    }
    const flags = authData[32];
    checks.user_present = (flags & FLAG_UP) === FLAG_UP;
    checks.user_verified = (flags & FLAG_UV) === FLAG_UV;

    // 4. Optional rpId scope check.
    if (opts.rpId) {
      const expectedRpIdHash = crypto.createHash('sha256').update(opts.rpId, 'utf8').digest();
      checks.rp_id_hash = expectedRpIdHash.equals(authData.subarray(0, 32));
    }

    // 5. Signature: ECDSA P-256/SHA-256 over authData || SHA-256(clientDataJSON).
    const signedData = Buffer.concat([
      authData,
      crypto.createHash('sha256').update(clientDataBytes).digest(),
    ]);
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(approverPublicKeySpkiB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    checks.signature = crypto.verify(
      'sha256',
      signedData,
      keyObject,
      Buffer.from(signature, 'base64url'),
    );
  } catch (e) {
    return { valid: false, checks, error: `WebAuthn verification failed: ${e.message}` };
  }

  const valid = checks.challenge_binding
    && checks.client_data_type
    && checks.user_present
    && checks.user_verified
    && checks.signature
    && (checks.rp_id_hash === null || checks.rp_id_hash === true);
  return { valid, checks };
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
export function verifyCommitmentProof(proof, publicKeyBase64url, options = {}) {
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
    const publicKeyDer = Buffer.from(publicKeyBase64url, 'base64url');
    const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const sigBytes = Buffer.from(proof.signature.value, 'base64url');
    if (!crypto.verify(null, commitmentBytes, keyObject, sigBytes)) {
      return { valid: false, claim: proof.claim, error: 'Invalid signature' };
    }
  } catch (e) {
    return { valid: false, claim: proof.claim, error: `Signature check failed: ${e.message}` };
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

  const failed = [];
  let verified = 0;

  for (let i = 0; i < bundle.documents.length; i++) {
    const result = verifyReceipt(bundle.documents[i], publicKeyBase64url);
    if (result.valid) verified++;
    else failed.push(`doc[${i}]: ${result.error || 'verification failed'}`);
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

function withinWindow(t, from, to) {
  const ts = Date.parse(t);
  if (Number.isNaN(ts)) return false;
  if (from && ts < Date.parse(from)) return false;
  if (to && ts > Date.parse(to)) return false;
  return true;
}

function parseClassAAssertion(webauthn) {
  try {
    const clientDataBytes = Buffer.from(webauthn.client_data_json, 'base64url');
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const authData = Buffer.from(webauthn.authenticator_data, 'base64url');
    if (authData.length < 37) return null;
    return { authData, clientData, clientDataBytes };
  } catch {
    return null;
  }
}

// WebAuthn Class-A assertion bound to a context digest (challenge = b64u(digest)).
function verifyClassAOverDigest(webauthn, digestBytes, publicKeySpkiB64u) {
  try {
    const parsed = parseClassAAssertion(webauthn);
    if (!parsed) return false;
    const { authData, clientData, clientDataBytes } = parsed;
    if (clientData.type !== 'webauthn.get') return false;
    if (clientData.challenge !== Buffer.from(digestBytes).toString('base64url')) return false;

    if ((authData[32] & FLAG_UP) !== FLAG_UP) return false; // human presence required
    if ((authData[32] & FLAG_UV) !== FLAG_UV) return false; // biometric/PIN verification required

    const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataBytes).digest()]);
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki',
    });
    return crypto.verify('sha256', signedData, keyObject, Buffer.from(webauthn.signature, 'base64url'));
  } catch {
    return false;
  }
}

function verifyEd25519OverDigest(signatureB64u, digestBytes, publicKeySpkiB64u) {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki',
    });
    return crypto.verify(null, digestBytes, keyObject, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

const STRICT_CHECK_NAMES = [
  'pinned_keys',
  'rp_id',
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
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function markStrict(report, name, ok, message) {
  report.checks[name] = Boolean(ok);
  if (!ok && message) report.errors.push(message);
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
    const keyClass = s.key_class || keyEntry?.key_class || 'B';
    if (keyClass === 'A') classASignoffs.push({ signoff: s, keyEntry });
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
    const keyClass = s?.key_class || approverKeys[s?.approver_key_id]?.key_class || 'B';
    if (keyClass === 'A') {
      requireField(s?.webauthn?.authenticator_data, 'strict no_unsigned requires Class-A authenticator_data');
      requireField(s?.webauthn?.client_data_json, 'strict no_unsigned requires Class-A client_data_json');
      requireField(s?.webauthn?.signature, 'strict no_unsigned requires Class-A WebAuthn signature');
    } else {
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
  const leafContent = { ...receipt };
  delete leafContent.log_proof;
  delete leafContent.approver_key_proofs;
  if (!isCanonicalizable(leafContent)) return 'Trust Receipt body';

  const checkpoint = receipt?.log_proof?.checkpoint;
  if (checkpoint && typeof checkpoint === 'object') {
    const signedCheckpoint = { ...checkpoint };
    delete signedCheckpoint.log_signature;
    if (!isCanonicalizable(signedCheckpoint)) return 'Trust Receipt checkpoint';
  }
  return null;
}

/**
 * Verify a Trust Receipt (I-D Section 6.2) fully offline — the Section 6.3
 * algorithm. All six steps; fails closed on any missing input.
 *
 * @param {object} receipt - Section 6.2 Trust Receipt
 * @param {object} opts
 * @param {Record<string, {public_key:string, key_class?:string, valid_from?:string, valid_to?:string}>} opts.approverKeys
 *   - pinned approver key entries by approver_key_id (or a directory extract)
 * @param {string} opts.logPublicKey - trusted log Ed25519 key (base64url SPKI DER)
 * @param {boolean} [opts.strict=false] - require deployment-grade strict checks
 * @param {string} [opts.rpId] - expected WebAuthn RP ID when strict mode sees Class-A signoffs
 * @param {string} [opts.expectedPolicyHash] - expected policy hash when strict mode is enabled
 * @returns {{ valid:boolean, checks:object, errors:string[], attestation:{ present:boolean, consistent:boolean, issues:string[] }, strict:{ enabled:boolean, valid:boolean, checks:object, errors:string[] } }}
 *   `attestation` is the PIP-007 §2 ADVISORY report. It never affects `valid` or
 *   any member of `checks`: a receipt with a malformed or inconsistent
 *   attestation still verifies (or fails) on its cryptographic checks alone.
 */
export function verifyTrustReceipt(receipt, opts = {}) {
  const checks = {
    action_hash: false,        // step 1
    context_commitments: false, // step 2
    signoff_signatures: false, // step 3
    sod: false,                // step 4
    inclusion: false,          // step 5a
    checkpoint_signature: false, // step 5b
    windows: false,            // step 6
  };
  const errors = [];
  // PIP-007 §2 advisory report — built from contexts as presented, independent
  // of every cryptographic check. fail() carries it through early returns too.
  const attestationContexts = Array.isArray(receipt?.contexts) ? receipt.contexts : [];
  const attestation = buildAttestationReport(attestationContexts);
  const strict = createStrictReport(opts.strict === true);
  const fail = (msg) => { errors.push(msg); return { valid: false, checks, errors, attestation, strict }; };

  if (!receipt || typeof receipt !== 'object') return fail('Missing receipt');
  const { approverKeys = {}, logPublicKey } = opts;
  const contexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
  const signoffs = Array.isArray(receipt.signoffs) ? receipt.signoffs : [];
  if (!receipt.action || !receipt.action_hash) return fail('Missing action or action_hash');
  if (contexts.length === 0 || signoffs.length === 0) return fail('Missing contexts or signoffs');
  const profileError = trustReceiptCanonicalProfileError(receipt);
  if (profileError) {
    return fail(`${profileError} is outside the EP canonicalization profile; encode non-integer quantities as strings`);
  }

  // ── Step 1: recompute the action hash from the canonical Action Object ────
  const actionHashHex = sha256(canonicalize(receipt.action));
  checks.action_hash = actionHashHex === hexOf(receipt.action_hash);
  if (!checks.action_hash) errors.push('action_hash does not match the canonical Action Object');

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
    } else {
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
  const validApprovals = []; // { approver, signedAt, ctx }
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
    // Key validity window must contain the context's issued_at (Section 5.2).
    if (!withinWindow(ctx.issued_at, keyEntry.valid_from, keyEntry.valid_to)) {
      signaturesOk = false;
      errors.push(`approver key ${s.approver_key_id} was not valid at issued_at`);
      continue;
    }
    const digestBytes = Buffer.from(digestHex, 'hex');
    const keyClass = s.key_class || keyEntry.key_class || 'B';
    const sigOk = keyClass === 'A'
      ? Boolean(s.webauthn) && verifyClassAOverDigest(s.webauthn, digestBytes, keyEntry.public_key)
      : verifyEd25519OverDigest(s.signature, digestBytes, keyEntry.public_key);
    if (!sigOk) {
      signaturesOk = false;
      errors.push(`signoff by ${ctx.approver} does not verify`);
      continue;
    }
    validApprovals.push({ approver: ctx.approver, signedAt: s.signed_at, ctx });
  }
  checks.signoff_signatures = signaturesOk;

  // ── Step 4: separation of duties ──────────────────────────────────────────
  const initiator = receipt.action.initiator;
  const approvers = validApprovals.map((a) => a.approver);
  const requiredApprovals = Math.max(1, ...contexts.map((c) => Number(c.required_approvals) || 1));
  let sodOk = true;
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
    const merkleAlg = lp.alg || lp.checkpoint?.merkle_alg || null;
    if (merkleAlg === MERKLE_V2_ALG) {
      const leafHash = leafHashV2(canonicalize(leafContent));
      const presentedLeaf = lp.leaf_hash ? hexOf(lp.leaf_hash) : '';
      checks.inclusion = presentedLeaf === leafHash
        && verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash), { v2: true });
      if (presentedLeaf !== leafHash) errors.push('Trust Receipt log_proof leaf_hash does not bind this receipt');
    } else if (opts.allowLegacyMerkle === true || opts.allowLegacyTrustReceiptMerkle === true) {
      const leafHash = sha256(canonicalize(leafContent));
      checks.inclusion = verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash));
    } else {
      checks.inclusion = false;
      errors.push('Trust Receipt log_proof must use EP-MERKLE-v2');
    }
    if (!checks.inclusion) errors.push('Merkle inclusion proof does not reconstruct the checkpoint root');

    if (logPublicKey && lp.checkpoint.log_signature) {
      const signedCheckpoint = { ...lp.checkpoint };
      delete signedCheckpoint.log_signature;
      checks.checkpoint_signature = verifyEd25519OverDigest(
        String(lp.checkpoint.log_signature).replace(/^b64u:/, ''),
        sha256Bytes(canonicalize(signedCheckpoint)),
        logPublicKey,
      );
      if (!checks.checkpoint_signature) errors.push('checkpoint signature does not verify against the log key');
    } else {
      errors.push('missing log public key or checkpoint signature');
    }
  } else {
    errors.push('missing log_proof (inclusion path + checkpoint)');
  }

  // ── Step 6: temporal windows ──────────────────────────────────────────────
  let windowsOk = validApprovals.length > 0;
  for (const a of validApprovals) {
    if (!withinWindow(a.signedAt, a.ctx.issued_at, a.ctx.expires_at)) {
      windowsOk = false;
      errors.push(`signed_at for ${a.approver} falls outside [issued_at, expires_at]`);
    }
  }
  const committedAt = receipt.consumption?.committed_at;
  if (!committedAt) {
    windowsOk = false;
    errors.push('missing consumption.committed_at');
  } else {
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
  return { valid, checks, errors, attestation, strict };
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
  if (typeof maxAgeSec === 'number' && maxAgeSec >= 0) {
    if (!out.observed_at) {
      out.fresh = false;
      out.reason = 'freshness_required_but_no_observed_at';
      return out;
    }
    const obs = Date.parse(out.observed_at);
    const ref = at ? Date.parse(at) : Date.now();
    if (Number.isNaN(obs) || Number.isNaN(ref)) {
      out.fresh = false;
      out.reason = 'unparseable_observed_at';
      return out;
    }
    const ageSec = (ref - obs) / 1000;
    out.age_seconds = Math.round(ageSec);
    if (ageSec < -60) {                       // observed in the future (allow 60s clock skew)
      out.fresh = false;
      out.reason = 'observed_at_in_future';
    } else if (ageSec > maxAgeSec) {
      out.fresh = false;
      out.reason = `stale: L4 evidence observed ${out.age_seconds}s ago (max ${maxAgeSec}s)`;
    } else {
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
export {
  resolveOperatorKeys,
  verifyFederatedReceiptOffline,
  verifyFederatedReceipt,
} from './federation.js';

// EP-QUORUM-v1 — multi-party (M-of-N / ordered) approval, additive over EP-SIGNOFF-v1.
export { verifyQuorum } from './quorum.js';

// EP-AEC-v1 (Authorization Evidence Chain) is an EXPERIMENTAL reference verifier in
// ./evidence-chain.js. It is intentionally NOT re-exported here and NOT in package
// "files" — it must not ship in the published SDK until its draft is posted. Import
// it directly from './evidence-chain.js' for local/reference use.
