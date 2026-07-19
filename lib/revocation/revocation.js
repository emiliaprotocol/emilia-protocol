/**
 * EMILIA Protocol — Portable, offline-verifiable revocation statement
 * (EP-REVOCATION-v1)
 *
 * @license Apache-2.0
 *
 * REFERENCE IMPLEMENTATION of an ADDITIVE signed claim + fail-closed verifier
 * check over EP-RECEIPT-v1. Spec: docs/EP-REVOCATION-SPEC.md. Conformance
 * vectors: conformance/vectors/revocation.v1.json. EXPERIMENTAL — governed by an
 * Extension PIP; not a production or customer claim; reports no metrics.
 *
 *   target the relying party HOLDS { target_type, target_id, action_hash }
 *     -> a SIGNED revocation statement that BINDS that exact (target_id, action_hash)
 *       -> verify under the key the verifier PINNED for revoker_id (not self-asserted)
 *         -> fail closed on any: version / binding / pin / effective-time / signature gap
 *
 * THE GAP THIS FILLS. Revocation in EP today is SERVER-STATE only:
 * revokeCommit() (lib/commit.js) flips a commit to status:'revoked', and
 * revokeAttestation()/revokeChallenge() (lib/signoff/revoke.js) do the same for
 * signoff records — all live datastore queries. There is NO portable artifact a
 * relying party can be HANDED to prove, offline and with no call back to the
 * issuer, that a previously-valid authorization is now revoked. This profile
 * defines that artifact: a detached, signed revocation statement over a target,
 * carrying revoker_id + revoked_at + reason, and a verifier that accepts it only
 * when it is AUTHENTIC and BINDS the exact target.
 *
 * EXPLICIT TRUST INPUT. The relying party selects a revoker key out of band;
 * the statement then proves that key signed the exact terminal fact. The
 * revoker is a party EP IDENTIFIES BUT NEVER TRUSTS merely because it appears;
 * its signature ATTRIBUTES the revocation claim to a named, PINNED key — a self-
 * asserted, unpinned key confers NOTHING (anyone can mint a keypair and sign "X
 * is revoked"). This mirrors executor_key_pinned (lib/execution/integrity.js) and
 * signer_key_unpinned (lib/wysiwys/render.js).
 *
 * FROZEN CORE (PIP-001). This file does NOT modify the EP-RECEIPT-v1 wire
 * format, canonicalization, or signature, and it does NOT touch packages/verify
 * or packages/issue, nor the existing server-state revocation. It imports the
 * frozen canonicalize() as the single canonicalization source of truth (same
 * relative-import convention as lib/provenance/chain.js, lib/execution/integrity.js,
 * and lib/wysiwys/render.js) and re-implements nothing of Core's receipt path.
 *
 * FAIL CLOSED: verifyRevocation() returns { valid:false } whenever the @version
 * is wrong, whenever the statement does not bind the EXACT (target_type,
 * target_id, action_hash) the verifier holds (revoking A must never revoke B),
 * whenever revoker_id is unpinned or the proof key differs from the pinned key,
 * whenever revoked_at is absent/malformed, whenever the proof is forged or signs
 * bytes other than the verifier-recomputed SIGNED_FIELDS, and whenever the
 * revocation has not taken effect by the verifier's decision time.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST BOUNDARY — READ THIS. Offline verification proves the revocation
 * statement is AUTHENTIC and BINDS the target. It does NOT prove you hold the
 * LATEST revocation state. "Has this authorization been revoked by a statement I
 * do NOT hold?" is a freshness / liveness / transparency problem — exactly the
 * gap OCSP and CRLs exist to fill — and is OUT OF SCOPE of this offline check. A
 * relying party that needs liveness MUST consult a revocation feed / transparency
 * log, or rely on a short receipt TTL; the offline artifact answers "is THIS
 * revocation real and for THIS target", NOT "is the absence of a revocation
 * trustworthy". Treating absence-of-statement as proof-of-not-revoked is a
 * relying-party error this profile CANNOT prevent. Freshness belongs to a
 * separate authenticated status checkpoint; a terminal revocation itself
 * never ages out.
 * ──────────────────────────────────────────────────────────────────────────
 */

import crypto from 'node:crypto';

// Compose the FROZEN v1 issuer's canonicalizer as the single source of
// canonicalization truth. Relative import to the in-repo package source mirrors
// lib/provenance/chain.js and lib/execution/integrity.js, so the signed bytes
// are identical to the published @emilia-protocol/issue by construction.
import { canonicalize } from '../../packages/issue/index.js';

export const REVOCATION_VERSION = 'EP-REVOCATION-v1';

// The set of target_type values this profile recognizes.
const TARGET_TYPES = Object.freeze(['receipt', 'commit', 'delegation']);
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

// ── small helpers ────────────────────────────────────────────────────────────

/** Normalize a valid SHA-256 digest; malformed input becomes empty. */
const hexOf = (h) => {
  const value = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(value) ? value : '';
};

/** Strict RFC 3339 instant => epoch ms, else NaN (never throws). */
function instantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s, , oh, om] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) return NaN;
  if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59)) return NaN;
  return Date.parse(value);
}

function decisionTimeMs(value) {
  if (value === undefined) return Date.now();
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  return instantMs(value);
}

/**
 * The canonical bytes the REVOKER signature is bound to — the fixed SIGNED_FIELDS
 * set. The verifier INDEPENDENTLY recomputes these from the PRESENTED statement
 * fields, so a producer cannot present one set of fields while claiming a
 * signature over another (revoked_at / reason / target cannot be swapped after
 * signing). Field order is irrelevant — canonicalize() sorts keys.
 *
 * Mirrors EP-REVOCATION-SPEC §3.3: canonicalize({ @version, target_type,
 * target_id, action_hash, revoker_id, revoked_at, reason }).
 */
function revocationSignedPayload(stmt) {
  return Buffer.from(
    canonicalize({
      '@version': REVOCATION_VERSION,
      action_hash: stmt.action_hash ?? null,
      reason: stmt.reason ?? null,
      revoked_at: stmt.revoked_at ?? null,
      revoker_id: stmt.revoker_id ?? null,
      target_id: stmt.target_id ?? null,
      target_type: stmt.target_type ?? null,
    }),
    'utf8',
  );
}

/**
 * Verify a detached Ed25519 signature over `bytes` under a base64url SPKI-DER
 * public key. Returns true/false; never throws. This is the ONLY signature
 * primitive added here, and it grants NO trust by itself — the caller gates on it
 * AND on the key being pinned (identified-but-not-trusted).
 */
function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, bytes, key, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

/** A base64url string that decodes to a plausible Ed25519 signature length (64 bytes). */
function isWellFormedSignature(sigB64u) {
  try { return Buffer.from(String(sigB64u ?? ''), 'base64url').length === 64; }
  catch { return false; }
}

// ── assembly (revoker / issuer side) ──────────────────────────────────────────

/**
 * buildRevocation — produce an EP-REVOCATION-v1 statement binding the exact
 * target, signed by the revoker (detached `proof` block keyed by revoker_key_id).
 *
 * HONESTY GATE: this refuses to mint a statement that does not bind a COMPLETE
 * target (target_type + target_id + action_hash) or that lacks a revoked_at
 * anchor. A signed claim asserts a fact that was structurally well-formed at
 * signing time. (Negative tests bypass this gate by re-signing tampered/partial
 * bytes directly, to exercise the verifier's independent fail-closed checks.)
 *
 * @param {object} args
 * @param {{ target_type:string, target_id:string, action_hash:string }} args.target
 *   - the thing being revoked; both target_id AND action_hash are part of the binding.
 * @param {string} args.revoker_id - the party asserting the revocation (pinned by the verifier).
 * @param {string} [args.revoked_at] - RFC 3339 instant the revocation took effect (defaults to now).
 * @param {string} [args.reason] - human-readable cause (covered by the signature).
 * @param {{ revoker_key_id?:string, privateKey:import('crypto').KeyObject,
 *           publicKeyB64u:string, algorithm?:string }} args.signer - the revoker's signer.
 * @returns {object} an EP-REVOCATION-v1 statement (with a `proof` block).
 */
export function buildRevocation({
  target,
  revoker_id: revokerId,
  revoked_at: revokedAt = new Date().toISOString(),
  reason,
  signer,
} = {}) {
  if (!target || typeof target !== 'object') {
    throw new Error('buildRevocation requires target {target_type,target_id,action_hash}');
  }
  if (!TARGET_TYPES.includes(target.target_type)
    || typeof target.target_id !== 'string' || target.target_id.length === 0
    || !hexOf(target.action_hash)) {
    throw new Error('buildRevocation: target must bind target_type, target_id, and action_hash (fail-closed honesty gate)');
  }
  if (typeof revokerId !== 'string' || revokerId.length === 0) throw new Error('buildRevocation requires revoker_id');
  if (!Number.isFinite(instantMs(revokedAt))) throw new Error('buildRevocation requires a strict RFC 3339 revoked_at anchor');
  if (reason !== undefined && reason !== null && typeof reason !== 'string') {
    throw new Error('buildRevocation reason must be a string or null');
  }
  if (!signer || !signer.privateKey || !signer.publicKeyB64u) {
    throw new Error('buildRevocation requires signer.{privateKey,publicKeyB64u}');
  }
  if (signer.algorithm !== undefined && signer.algorithm !== 'Ed25519') {
    throw new Error('buildRevocation supports Ed25519 only');
  }

  const stmt = {
    '@version': REVOCATION_VERSION,
    target_type: target.target_type,
    target_id: target.target_id,
    action_hash: target.action_hash,
    revoker_id: revokerId,
    revoked_at: revokedAt,
    reason: reason ?? null,
  };

  const payload = revocationSignedPayload(stmt);
  stmt.proof = {
    algorithm: signer.algorithm || 'Ed25519',
    revoker_key_id: signer.revoker_key_id || revokerId,
    signed_payload_b64u: payload.toString('base64url'),
    signature_b64u: crypto.sign(null, payload, signer.privateKey).toString('base64url'),
    public_key: signer.publicKeyB64u,
  };
  // EVIDENCE that a named revoker attested this; never proof you hold the LATEST
  // revocation state. See the HONEST BOUNDARY block above and SPEC §7.
  stmt.scope_note =
    'Revoker is identified but not trusted: this attributes the revocation claim to a named, pinned key. '
    + 'Offline verification proves THIS revocation is real and binds THIS target; it does NOT prove the '
    + 'absence of a revocation is trustworthy (freshness/transparency is a layer above — SPEC §7).';
  return stmt;
}

// ── verification (verifier side) ──────────────────────────────────────────────

/**
 * verifyRevocation(target, statement, opts) — FAIL-CLOSED revocation check.
 *
 * Given the TARGET the relying party HOLDS (derived from the receipt/commit it
 * has, never from the statement) and a candidate statement, evaluates the gating
 * checks below. Any one false ⇒ valid:false. valid = AND(all gating checks).
 *
 * Rejects (valid:false) on ANY of:
 *   - version: @version is not EP-REVOCATION-v1 (vector f);
 *   - target_bound: the statement does not bind the EXACT (target_type,
 *     target_id, action_hash) the verifier holds — a statement for a different
 *     target_id (vector d) or a different action_hash (vector e, revoke-A-for-B)
 *     is rejected; revoking A must never revoke B;
 *   - revoker_key_pinned: revoker_id is not pinned by the verifier (vector b,
 *     self-asserted key), or the proof key differs from the pinned key (vector c,
 *     key substitution) — never falls back to the proof's own public_key;
 *   - revoked_at_present: revoked_at is absent or malformed (vector h);
 *   - revoker_signature_valid + signature_binds_statement: the proof is forged
 *     (vector a) or signs bytes other than the verifier-recomputed SIGNED_FIELDS
 *     (vector g, tampered-after-signing);
 *   - effective_at_or_before_T: revoked_at is in the future relative to
 *     opts.now (or opts.now itself is unusable).
 *
 * @param {{ target_type:string, target_id:string, action_hash:string }} target
 *   - the thing the relying party is reasoning about (NOT taken from the statement).
 * @param {object|null} statement - an EP-REVOCATION-v1 statement, or null/absent.
 * @param {object} [opts]
 * @param {Record<string,{public_key:string}>} [opts.revokerKeys] - pinned key per
 *   revoker_id. A revoker with no pin, or a proof whose key differs, is rejected.
 * @param {number} [opts.maxAgeSeconds] - DEPRECATED and ignored. Terminal
 *   revocations never age out; freshness belongs to separate status evidence.
 * @param {number|string|Date} [opts.now] - decision time (default: now).
 * @returns {{ valid:boolean, checks:object, errors:string[] }}
 */
export function verifyRevocation(target, statement, opts = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const revokerKeys = opts.revokerKeys || {};

  const checks = {
    version: true,                  // @version matches
    target_bound: true,             // binds the EXACT (target_type, target_id, action_hash)
    revoker_key_pinned: true,       // revoker_id maps to a pinned key == the proof key
    revoked_at_present: true,       // revoked_at present and well-formed
    effective_at_or_before_T: true, // revocation has taken effect by decision time
    revoker_signature_valid: true,  // signature verifies under the pinned key
    signature_binds_statement: true,// signature is over the recomputed presented bytes
  };
  const errors = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };

  // A missing statement confers nothing — fail closed (an absent statement is not
  // proof of anything; it is the relying party's job to obtain one).
  if (!statement || typeof statement !== 'object' || Array.isArray(statement)) {
    fail('signature_binds_statement', 'no revocation statement presented (fail-closed)');
    fail('revoker_signature_valid', 'no revocation statement presented (fail-closed)');
    return { valid: false, checks, errors };
  }

  // ── 1. version ────────────────────────────────────────────────────────────
  if (statement['@version'] !== REVOCATION_VERSION) {
    fail('version', `unsupported version: ${statement['@version']}`);
  }

  // ── 2. target binding (BOTH target_id AND action_hash; never just an id) ────
  if (!target || typeof target !== 'object' || Array.isArray(target)) {
    fail('target_bound', 'no target handed to the verifier (fail-closed)');
  } else {
    const heldHash = hexOf(target.action_hash);
    const statementHash = hexOf(statement.action_hash);
    if (!TARGET_TYPES.includes(target.target_type)
      || typeof target.target_id !== 'string' || target.target_id.length === 0
      || !heldHash) {
      fail('target_bound', 'handed target is incomplete or malformed');
    }
    if (!TARGET_TYPES.includes(statement.target_type)
      || typeof statement.target_id !== 'string' || statement.target_id.length === 0
      || !statementHash) {
      fail('target_bound', 'revocation statement target is incomplete or malformed');
    } else if (statement.target_type !== target.target_type) {
      fail('target_bound',
        `statement target_type "${statement.target_type}" != handed target_type "${target.target_type}"`);
    } else if (statement.target_id !== target.target_id) {
      fail('target_bound',
        `statement target_id "${statement.target_id}" != handed target_id "${target.target_id}"`);
    } else if (statementHash !== heldHash) {
      // target_id matched but action_hash did not — the revoke-A-presented-for-B
      // case (vector e). Revoking A must never revoke B.
      fail('target_bound',
        `statement action_hash ${hexOf(statement.action_hash)} != handed action_hash ${hexOf(target.action_hash)} `
        + '(revoke-A-presented-for-B)');
    }
  }

  // ── 3. revoker key pinned (identified-but-not-trusted) ─────────────────────
  // revoker_id MUST resolve to a key the verifier PINNED, and the proof's key
  // MUST equal that pinned key. No pin ⇒ reject (vector b). Different key ⇒
  // reject (vector c). NEVER fall back to the proof's self-asserted public_key.
  const proof = statement.proof || null;
  const revokerId = statement.revoker_id;
  const pinned = revokerKeys[revokerId]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) {
    fail('revoker_key_pinned',
      `no pinned key for revoker "${revokerId}" (identified but not trusted)`);
  } else if (presentedKey && pinned !== presentedKey) {
    fail('revoker_key_pinned',
      `presented revoker key does not match the pinned key for "${revokerId}" (key substitution)`);
  }
  if (proof?.algorithm !== 'Ed25519') {
    fail('revoker_signature_valid', 'revocation proof algorithm must be Ed25519');
  }
  if (statement.reason !== undefined && statement.reason !== null && typeof statement.reason !== 'string') {
    fail('signature_binds_statement', 'reason must be a string or null');
  }

  // ── 4. revoked_at present + well-formed (the effective-time anchor) ────────
  const revokedAtMs = instantMs(statement.revoked_at);
  if (!Number.isFinite(revokedAtMs)) {
    fail('revoked_at_present', 'revoked_at is absent or not a well-formed RFC 3339 instant');
  }

  const nowMs = decisionTimeMs(opts.now);
  if (!Number.isFinite(revokedAtMs) || !Number.isFinite(nowMs) || revokedAtMs > nowMs) {
    fail('effective_at_or_before_T',
      'revoked_at must be a valid instant at or before the verifier decision time');
  }

  // ── 5. signature: valid AND bound to the recomputed presented bytes ────────
  // Verify under the PINNED key (never a producer-supplied key), over bytes the
  // verifier recomputes from the presented statement fields. FAIL CLOSED, never
  // throw: a non-canonicalizable field yields null bytes, against which no
  // signature can verify.
  let recomputedBytes = null;
  try {
    recomputedBytes = revocationSignedPayload(statement);
  } catch {
    recomputedBytes = null;
  }
  const signatureB64u = proof?.signature_b64u ?? null;
  const sigBindsPinned = pinned && recomputedBytes && verifyEd25519(recomputedBytes, pinned, signatureB64u);
  if (!sigBindsPinned) {
    // Diagnose against whichever key we have so the forensic cause is precise,
    // but the VERDICT only ever honors the pinned key (set in check 3 above).
    const verifyKey = pinned || presentedKey;
    const sigOverRecomputed = verifyKey && recomputedBytes && verifyEd25519(recomputedBytes, verifyKey, signatureB64u);
    if (!signatureB64u || !verifyKey) {
      fail('revoker_signature_valid', 'revocation proof signature or key missing');
    } else if (!sigOverRecomputed && isWellFormedSignature(signatureB64u)) {
      // Well-formed signature that does not verify over the recomputed bytes:
      // either forged (verifies nowhere — vector a) or valid over OTHER (tampered)
      // bytes (vector g). Without the original bytes we cannot tell which, so we
      // flag BOTH the math and the binding to keep fail-closed and forensic.
      fail('signature_binds_statement',
        'revoker signature does not bind the presented statement bytes (recomputed payload mismatch)');
      fail('revoker_signature_valid',
        'revoker signature does not verify under the pinned revoker key over the recomputed bytes');
    } else if (!sigOverRecomputed) {
      fail('revoker_signature_valid',
        'revoker signature does not verify under the pinned revoker key');
    }
    // (If sigOverRecomputed is true here, the only reason sigBindsPinned was
    // false is that no key is pinned — already failed in check 3, fail-closed.)
  }

  // maxAgeSeconds is intentionally ignored. Revocation is a terminal negative
  // fact: once effective, passage of time can never turn it into acceptance.
  // Recency applies only to separately authenticated non-revocation/status
  // evidence (for example a Token Status List checkpoint).

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

/**
 * isRevoked(target, statements, opts) — aggregate convenience over a BAG of
 * statements a relying party may have collected. Returns true IFF at least one
 * statement returns valid:true from verifyRevocation(target, statement, opts).
 *
 * It does NOT require the matching statement to be first or alone (vector z2):
 * a valid binding statement sitting among unrelated (validly-signed-but-for-
 * other-targets) statements still yields true, and the unrelated ones are
 * ignored. It is NOT a completeness oracle: a `false` means "no VALID binding
 * statement is present IN THIS BAG", never "this target was never revoked
 * anywhere" — the absence-of-statement gap (SPEC §7) is out of scope.
 *
 * @param {{ target_type:string, target_id:string, action_hash:string }} target
 * @param {Array<object>} statements
 * @param {object} [opts] - same opts as verifyRevocation.
 * @returns {boolean}
 */
export function isRevoked(target, statements, opts = {}) {
  if (!Array.isArray(statements)) return false;
  return statements.some((s) => verifyRevocation(target, s, opts).valid);
}

const revocation = {
  buildRevocation,
  verifyRevocation,
  isRevoked,
  REVOCATION_VERSION,
};
export default revocation;
