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

function hashPair(a, b) {
  const sorted = [a, b].sort();
  return sha256(sorted[0] + sorted[1]);
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
export function verifyReceipt(doc, publicKeyBase64url) {
  const checks = { version: false, signature: false, anchor: null };

  if (!doc?.['@version'] || !SUPPORTED_VERSIONS.includes(doc['@version'])) {
    return { valid: false, checks, error: `Unsupported version: ${doc?.['@version']}` };
  }
  checks.version = true;

  if (!doc.payload || !doc.signature?.value || !doc.signature?.algorithm) {
    return { valid: false, checks, error: 'Missing payload or signature' };
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
    checks.anchor = verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
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
export function verifyMerkleAnchor(leafHash, proof, expectedRoot) {
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 20) return false;

  let current = leafHash;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string') return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
    current = step.position === 'left' ? hashPair(step.hash, current) : hashPair(current, step.hash);
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
 * @returns {{ valid: boolean, claim: object, error?: string }}
 */
export function verifyCommitmentProof(proof, publicKeyBase64url) {
  if (!proof?.['@version'] || !SUPPORTED_PROOF_VERSIONS.includes(proof['@version'])) {
    return { valid: false, claim: null, error: `Unsupported version: ${proof?.['@version']}` };
  }

  if (proof.expires_at && new Date(proof.expires_at) < new Date()) {
    return { valid: false, claim: proof.claim, error: 'Proof has expired' };
  }

  if (publicKeyBase64url && proof.signature) {
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

// WebAuthn Class-A assertion bound to a context digest (challenge = b64u(digest)).
function verifyClassAOverDigest(webauthn, digestBytes, publicKeySpkiB64u) {
  try {
    const clientDataBytes = Buffer.from(webauthn.client_data_json, 'base64url');
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    if (clientData.type !== 'webauthn.get') return false;
    if (clientData.challenge !== Buffer.from(digestBytes).toString('base64url')) return false;

    const authData = Buffer.from(webauthn.authenticator_data, 'base64url');
    if (authData.length < 37) return false;
    if ((authData[32] & FLAG_UV) !== FLAG_UV) return false; // user verification required

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

/**
 * Verify a Trust Receipt (I-D Section 6.2) fully offline — the Section 6.3
 * algorithm. All six steps; fails closed on any missing input.
 *
 * @param {object} receipt - Section 6.2 Trust Receipt
 * @param {object} opts
 * @param {Record<string, {public_key:string, key_class?:string, valid_from?:string, valid_to?:string}>} opts.approverKeys
 *   - pinned approver key entries by approver_key_id (or a directory extract)
 * @param {string} opts.logPublicKey - trusted log Ed25519 key (base64url SPKI DER)
 * @returns {{ valid:boolean, checks:object, errors:string[], attestation:{ present:boolean, consistent:boolean, issues:string[] } }}
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
  const fail = (msg) => { errors.push(msg); return { valid: false, checks, errors, attestation }; };

  if (!receipt || typeof receipt !== 'object') return fail('Missing receipt');
  const { approverKeys = {}, logPublicKey } = opts;
  const contexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
  const signoffs = Array.isArray(receipt.signoffs) ? receipt.signoffs : [];
  if (!receipt.action || !receipt.action_hash) return fail('Missing action or action_hash');
  if (contexts.length === 0 || signoffs.length === 0) return fail('Missing contexts or signoffs');

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
    const leafHash = sha256(canonicalize(leafContent));
    checks.inclusion = verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash));
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
  // `valid` computation, which remains exactly the conjunction of `checks`.
  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, attestation };
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
