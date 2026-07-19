/**
 * EMILIA Protocol — Eye continuous-eval as a Security Event Token (EP-EYE-SET-v1)
 *
 * @license Apache-2.0
 *
 * REFERENCE IMPLEMENTATION of an ADDITIVE emission over Eye's advisory path.
 * Spec: docs/EP-EYE-SET-SPEC.md. Conformance: conformance/vectors/eye-set.v1.json.
 * EXPERIMENTAL — governed by an Extension PIP; not a production or customer
 * claim; reports no metrics. It MUST be ratified by a PIP before it can be
 * called part of the protocol.
 *
 *   computed Eye advisory (status / reason_codes / recommended_policy_action /
 *     scope_binding_hash / advisory_hash / expires_at — docs/EMILIA-EYE-ADVISORY-SPEC.md)
 *       -> carried as an RFC 8417 Security Event Token (CAEP-style), JWS-COMPACT
 *         -> header { alg:'EdDSA', typ:'secevent+jwt', kid }, EdDSA over the
 *            JWS signing input (RFC 7515 §5.1) via node:crypto
 *           -> verified offline under a key PINNED for the kid/iss (fail closed)
 *             -> returns the advisory POSTURE for a relying party to ACT on
 *
 * WHAT THIS ADDS. The Eye advisory (EMILIA-EYE-ADVISORY-SPEC §9) is itself
 * UNSIGNED in v1 — its authenticity rests on the authenticated channel and its
 * durable verifiable record is the EP receipt. §9.1 names a forward-compatible
 * path: carry the advisory as a SET (RFC 8417) JWS, CAEP-style, supplying the
 * verifiable scope-binding and the "never the sole gate" invariant that SSF/CAEP
 * deliberately leave undefined. This module builds exactly that emission +
 * verifier, additively, without touching the frozen Core.
 *
 * NEVER A GATE. verifyEyeSet() returns an advisory POSTURE (status, reason_codes,
 * recommended_policy_action) for a relying party to combine TIGHTEN-ONLY with its
 * own base decision. It NEVER returns allow/deny and NEVER authorizes — there is
 * no decision vocabulary in its output. The never-sole-gate invariant is carried
 * IN-BAND (events[...].never_sole_gate:true, re-checked here) and enforced
 * STRUCTURALLY (this verifier exposes no allow/deny path). A 'clear' status is
 * the default-path no-change posture (Eye spec §6) and is NOT a posture-CHANGE
 * event: buildEyeSet refuses to emit it and verifyEyeSet rejects it, so a
 * replayed/forged 'clear' can never be read as an affirmative "authorized" signal.
 *
 * REDACTION POSTURE (reused from lib/eye/webhook-notify.js#redactAdvisory).
 * The SET's subject identifier sub_id is the re-derivable scope_binding_hash —
 * NEVER a raw subject_ref / actor_ref / target_ref / issuer_ref. The event member
 * carries only non-attributable facts (status, reason_codes,
 * recommended_policy_action, advisory_hash, expires_at, never_sole_gate). A
 * relying party that knows the scope can re-derive sub_id; the SET leaks nothing
 * attributable on its own.
 *
 * FROZEN CORE (PIP-001). This file does NOT modify the EP-RECEIPT-v1 wire
 * format, canonicalization, or signature, and it does NOT touch packages/verify
 * or packages/issue. It imports the frozen canonicalize() READ-ONLY (the same
 * relative-import convention as lib/provenance/chain.js and
 * lib/execution/integrity.js) wherever canonical bytes are needed, and
 * re-implements NOTHING cryptographic of the receipt path. The only added
 * primitive is a small detached-EdDSA/JWS over node:crypto — no new dependency.
 *
 * FAIL CLOSED. verifyEyeSet() returns { valid:false } on ANY of: a non-EdDSA alg
 * (incl. 'none'); a wrong typ; an unpinned or substituted emitter key; a forged
 * signature or a payload tampered after signing (e.g. a status downgrade);
 * missing/ill-typed required claims; an audience mismatch when opts.audience is
 * set; staleness (exp past / iat too old) when freshness is required; a
 * non-actionable ('clear'/unknown) status; or a missing/non-true never_sole_gate
 * marker. Each gate is checked before it can matter; the alg gate runs first so
 * an unsecured token is never treated as signed.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST BOUNDARY (state this plainly). SET (RFC 8417), JWS (RFC 7515), and
 * OpenID SSF/CAEP — including continuous evaluation AND the posture that a signal
 * "is never the sole authorization gate" — are PRIOR ART. This profile does NOT
 * claim continuous-eval, the SET envelope, or the never-sole-gate invariant
 * itself as novel; they are documented prior art (Eye spec §8, §9.1, §11). The
 * only contribution is the verifiable, scope-bound SET that carries the invariant
 * IN-BAND together with the redaction posture (sub_id = scope_binding_hash). An
 * Eye SET INFORMS; it is never the sole gate and never authorizes.
 *
 * HONEST RESIDUAL — out of scope. A FULLY COMPROMISED EMITTER is out of scope:
 * an Eye operator holding the pinned signing key can emit a truthful-looking SET
 * for a posture it did not actually compute (over- or, bounded by never-sole-gate,
 * under-tightening). Pinning bounds this to a NAMED key whose claims are
 * attributable; it does not make a compromised emitter's claims true — that is
 * addressed only by emitter host/TEE attestation and key-management hygiene, a
 * layer ABOVE this envelope, not its mathematics. SOLE-GATE MISUSE by a relying
 * party that reads the posture as authorization defeats the invariant; this
 * envelope cannot prevent that integration error by cryptography. A WITHHELD or
 * STALE SET is treated as "no posture change" (fail-open as an INPUT, never a
 * relax of the base gate); staleness never relaxes; absence never relaxes. Read
 * valid:true as "a pinned, named emitter made this fresh, scope-bound, in-band
 * never-sole-gate posture claim, untampered since signing" — NOT "allow," and NOT
 * "the posture is objectively correct."
 * ──────────────────────────────────────────────────────────────────────────
 */

import crypto from 'node:crypto';

// Compose the FROZEN v1 issuer's canonicalizer. Imported READ-ONLY by relative
// path to the in-repo package source — the SAME convention as
// lib/provenance/chain.js and lib/execution/integrity.js — so this file uses the
// identical bytes as the published @emilia-protocol/issue by construction. We
// re-implement nothing cryptographic of the receipt path.
import { canonicalize } from '../../packages/issue/index.js';
import { strictJsonGate } from '../strict-json.js';

export const EYE_SET_VERSION = 'EP-EYE-SET-v1';

/** RFC 8417 token type for a Security Event Token in JWS-COMPACT serialization. */
export const EYE_SET_TYP = 'secevent+jwt';

/** The single CAEP-style event URI that keys the SET's `events` map. */
export const EYE_ADVISORY_EVENT_URI =
  'https://schemas.emiliaprotocol.ai/secevent/eye-advisory';

// Status that is the default-path, no-change posture. NEVER emitted as a
// posture-change event; rejected by the verifier as non-actionable (Eye spec §6).
const CLEAR_STATUS = 'clear';

// The actionable posture-change statuses. A SET event MUST carry one of these.
// (Mirrors EYE_STATUSES minus 'clear' — webhook-notify.js STATUS_RANK 1..3.)
const ACTIONABLE_STATUSES = Object.freeze(['caution', 'elevated', 'review_required']);

// ── small helpers ─────────────────────────────────────────────────────────────

/** base64url WITHOUT padding (RFC 7515 §2). */
function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

/** Decode a base64url segment to a Buffer; never throws (returns null on junk). */
function b64uDecode(seg, maxBytes = 1024 * 1024) {
  try {
    if (typeof seg !== 'string' || seg.length === 0) return null;
    // Reject anything that is not strict base64url so a malformed segment fails
    // closed rather than silently decoding to lossy bytes.
    if (!/^[A-Za-z0-9_-]+$/.test(seg) || seg.length % 4 === 1) return null;
    const bytes = Buffer.from(seg, 'base64url');
    if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== seg) return null;
    return bytes;
  } catch {
    return null;
  }
}

/** Parse a base64url JSON segment into an object; null on any failure. */
function decodeJsonSegment(seg, maxBytes) {
  const buf = b64uDecode(seg, maxBytes);
  if (!buf) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
    if (!strictJsonGate(text).ok) return null;
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
  } catch {
    return null;
  }
}

/** A non-empty string. */
const isStr = (v) => typeof v === 'string' && v.length > 0;

/** A non-empty array of non-empty strings. */
function isStrArray(v) {
  return Array.isArray(v) && v.length > 0 && v.every(isStr);
}

/** Whole, finite, non-negative seconds-since-epoch. */
function isEpochSeconds(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && Number.isInteger(v);
}

/**
 * Resolve the pinned Ed25519 public key for an emitter. A self-asserted kid/iss
 * confers nothing: the key is looked up ONLY in the verifier-supplied pinned map,
 * keyed by kid first then iss. Returns the base64url SPKI-DER string or null.
 * (Mirrors execution-integrity's executorKeys[keyId].public_key resolution.)
 */
function resolvePinnedKey(pinnedKeys, kid, iss) {
  if (!pinnedKeys || typeof pinnedKeys !== 'object') return null;
  const entry =
    (isStr(kid) ? pinnedKeys[kid] : undefined) ??
    (isStr(iss) ? pinnedKeys[iss] : undefined);
  if (!entry) return null;
  // Accept either { public_key } (the pinned-key convention used across
  // lib/execution + lib/provenance) or a bare base64url string.
  if (typeof entry === 'string') return entry.length > 0 ? entry : null;
  return isStr(entry.public_key) ? entry.public_key : null;
}

/**
 * Verify a detached Ed25519 signature over `signingInput` (ASCII bytes) under a
 * base64url SPKI-DER public key. Returns true/false; never throws. This is the
 * ONLY signature primitive added here and it grants NO trust by itself — the
 * caller gates on it AND on the key being pinned (identified-but-not-trusted).
 * Mirrors verifyEd25519 in lib/execution/integrity.js.
 */
function verifyEd25519(signingInput, publicKeyB64u, signatureB64u) {
  try {
    if (!publicKeyB64u || !signatureB64u) return false;
    const sig = b64uDecode(signatureB64u, 64);
    if (!sig || sig.length !== 64) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, Buffer.from(signingInput, 'ascii'), key, sig);
  } catch {
    return false;
  }
}

/**
 * Pull the single advisory event member out of a SET payload. Returns the member
 * object or null when there is not exactly one event under the expected URI (the
 * profile fixes exactly one CAEP-style event).
 */
function singleEvent(payload) {
  const events = payload?.events;
  if (!events || typeof events !== 'object' || Array.isArray(events)) return null;
  const keys = Object.keys(events);
  if (keys.length !== 1) return null;
  if (keys[0] !== EYE_ADVISORY_EVENT_URI) return null;
  const member = events[keys[0]];
  return member && typeof member === 'object' && !Array.isArray(member) ? member : null;
}

// ── emission (Eye emitter side) ───────────────────────────────────────────────

/**
 * buildEyeSet — emit an Eye advisory as an RFC 8417 Security Event Token in
 * JWS-COMPACT serialization (`<b64u(header)>.<b64u(payload)>.<b64u(signature)>`),
 * signed EdDSA over the JWS signing input via node:crypto. No new dependency.
 *
 * REFUSES 'clear' (and any non-actionable status): a `clear` status is the
 * default-path, no-change posture (Eye spec §6) and emitting it as a signed
 * posture-change event would let a replayed/forged `clear` be read as an
 * affirmative "authorized" signal — the exact sole-gate misuse the profile
 * refuses (spec §3.4 / vector j_clear_status_emitted_as_event).
 *
 * The subject id (sub_id) is the re-derivable scope_binding_hash, NEVER a raw
 * subject/actor/target/issuer reference (redaction posture of
 * lib/eye/webhook-notify.js#redactAdvisory). The event member carries only
 * non-attributable advisory facts plus the in-band never_sole_gate:true marker.
 *
 * @param {object} advisory - an eye-advisory-v1-shaped object. MUST carry a
 *   non-empty scope_binding_hash, an actionable status, non-empty reason_codes,
 *   a recommended_policy_action (or the spec's recommended_action), advisory_hash,
 *   and expires_at.
 * @param {object} [args]
 * @param {{ kid:string, iss?:string, privateKey:import('crypto').KeyObject,
 *           sign?:(input:string)=>string }} [args.signer]
 *   - the emitter's signing material. `kid` names the pinned emitter key. A raw
 *     Ed25519 `privateKey` KeyObject is signed with node:crypto; alternatively a
 *     `sign(signingInput)->b64u` callback may be supplied (EP never needs to hold
 *     the key). `iss` defaults to `kid`.
 * @param {string} [args.audience] - the intended relying-party id, placed in `aud`.
 * @param {string} [args.jti] - unique token id (defaults to a random UUID).
 * @param {number} [args.iat] - issued-at seconds (defaults to now).
 * @param {number} [args.exp] - optional JWT exp seconds (a top-level expiry in
 *   addition to the event's expires_at).
 * @returns {string} the compact SET.
 */
export function buildEyeSet(advisory, { signer, audience, jti, iat, exp } = {}) {
  if (!advisory || typeof advisory !== 'object') {
    throw new Error('buildEyeSet requires an advisory object');
  }
  if (!signer || !isStr(signer.kid)) {
    throw new Error('buildEyeSet requires signer.{kid}');
  }
  const hasSignCb = typeof signer.sign === 'function';
  if (!hasSignCb && !signer.privateKey) {
    throw new Error('buildEyeSet requires signer.privateKey or signer.sign');
  }

  const status = advisory.status;
  // clear (and any non-actionable status) is a build-time rejection (§3.4).
  if (status === CLEAR_STATUS) {
    throw new Error(
      "buildEyeSet: 'clear' is the default-path no-change posture and MUST NOT be "
      + 'emitted as a posture-change event (fail-closed; see vector j_clear_status_emitted_as_event)',
    );
  }
  if (!ACTIONABLE_STATUSES.includes(status)) {
    throw new Error(
      `buildEyeSet: status "${status}" is not an actionable posture-change status `
      + `(expected one of ${ACTIONABLE_STATUSES.join(' | ')})`,
    );
  }

  const scopeBindingHash = advisory.scope_binding_hash;
  if (!isStr(scopeBindingHash)) {
    throw new Error('buildEyeSet requires advisory.scope_binding_hash (the scope-bound sub_id; never a raw ref)');
  }
  const reasonCodes = advisory.reason_codes;
  if (!isStrArray(reasonCodes)) {
    throw new Error('buildEyeSet requires non-empty advisory.reason_codes for an actionable status');
  }
  // The SET wire uses recommended_policy_action; accept the advisory spec's
  // recommended_action as the source field too (EMILIA-EYE-ADVISORY-SPEC §3.1).
  const recommendedPolicyAction =
    advisory.recommended_policy_action ?? advisory.recommended_action;
  if (!isStr(recommendedPolicyAction)) {
    throw new Error('buildEyeSet requires advisory.recommended_policy_action (or recommended_action)');
  }
  if (!isStr(advisory.advisory_hash)) {
    throw new Error('buildEyeSet requires advisory.advisory_hash');
  }
  if (!isStr(advisory.expires_at)) {
    throw new Error('buildEyeSet requires advisory.expires_at');
  }

  const header = {
    alg: 'EdDSA',
    typ: EYE_SET_TYP,
    kid: signer.kid,
  };

  const payload = {
    iss: isStr(signer.iss) ? signer.iss : signer.kid,
    iat: isEpochSeconds(iat) ? iat : Math.floor(Date.now() / 1000),
    jti: isStr(jti) ? jti : crypto.randomUUID(),
    // sub_id is the re-derivable scope_binding_hash — NEVER a raw identifier.
    sub_id: scopeBindingHash,
    events: {
      [EYE_ADVISORY_EVENT_URI]: {
        status,
        reason_codes: [...reasonCodes],
        recommended_policy_action: recommendedPolicyAction,
        advisory_hash: advisory.advisory_hash,
        expires_at: advisory.expires_at,
        // The in-band invariant, re-checked by verifyEyeSet. An Eye SET INFORMS;
        // it is never the sole gate and never authorizes.
        never_sole_gate: true,
      },
    },
  };
  if (isStr(audience)) payload.aud = audience;
  if (isEpochSeconds(exp)) payload.exp = exp;

  // JWS-COMPACT signing input: b64u(header) + '.' + b64u(payload) (RFC 7515 §5.1).
  // canonicalize() (frozen, sorted-key JSON) is used for the serialized segments
  // so the bytes are deterministic and re-derivable by the verifier.
  const headerSeg = b64uEncode(Buffer.from(canonicalize(header), 'utf8'));
  const payloadSeg = b64uEncode(Buffer.from(canonicalize(payload), 'utf8'));
  const signingInput = `${headerSeg}.${payloadSeg}`;

  const signatureB64u = hasSignCb
    ? signer.sign(signingInput)
    : crypto.sign(null, Buffer.from(signingInput, 'ascii'), signer.privateKey).toString('base64url');

  return `${signingInput}.${signatureB64u}`;
}

// ── verification (relying-party side) — FAIL CLOSED ───────────────────────────

/**
 * verifyEyeSet — FAIL-CLOSED verification of an Eye SET. NEVER returns allow/deny
 * and NEVER authorizes: on valid:true it returns the advisory POSTURE for a
 * relying party to combine TIGHTEN-ONLY with its own base decision (Eye spec §7.4).
 *
 * Steps (each fail-closed; the alg gate runs FIRST so an unsecured token is never
 * treated as signed):
 *   1. parse + alg gate     — REJECT any alg != 'EdDSA' (incl. 'none')   alg_is_eddsa
 *   2. typ gate             — typ MUST be 'secevent+jwt'                  typ_ok
 *   3. pin the emitter key  — resolve from opts.pinnedKeys (kid/iss);
 *                             an unpinned/self-asserted kid is rejected   emitter_key_pinned
 *   4. verify JWS signature — recompute the signing input from the
 *                             PRESENTED header.payload and verify under the
 *                             PINNED key only (forge/substitute/tamper fail) jws_signature_valid
 *   5. required claims       — iss, iat, jti, aud, sub_id + exactly one
 *                              event member with the required fields        claims_present
 *   6. audience              — payload.aud == opts.audience when set        audience_match
 *   7. freshness             — exp/expires_at not past AND iat not older
 *                              than maxAgeSec, when required                fresh
 *   8. actionable status     — status in {caution,elevated,review_required} status_is_actionable
 *   9. never-sole-gate       — event member carries never_sole_gate:true    never_sole_gate_present
 *
 * @param {string} setCompact - the compact SET `header.payload.signature`.
 * @param {object} [opts]
 * @param {Record<string,{public_key:string}|string>} [opts.pinnedKeys] - REQUIRED.
 *   Map from (kid and/or iss) -> the pinned Ed25519 public key (base64url SPKI-DER,
 *   as { public_key } or a bare string). An emitter absent here is UNPINNED and
 *   rejected — a self-asserted kid confers nothing.
 * @param {string} [opts.audience] - when set, payload.aud MUST equal it; when
 *   unset, audience is not gated.
 * @param {boolean} [opts.requireFresh] - when set, iat/exp freshness is enforced.
 * @param {number} [opts.maxAgeSec] - maximum iat age (seconds) when fresh is required.
 * @param {number} [opts.now] - injectable clock (seconds) for deterministic tests.
 * @returns {{ valid:boolean, checks:object, errors:string[], posture:object|null }}
 *   `posture` is present ONLY on valid:true and is NEVER allow/deny.
 */
export function verifyEyeSet(setCompact, opts = {}) {
  const checks = {
    alg_is_eddsa: false,
    typ_ok: false,
    emitter_key_pinned: false,
    jws_signature_valid: false,
    claims_present: false,
    audience_match: true, // vacuously true until/unless opts.audience is set
    fresh: true,          // vacuously true until/unless freshness is required
    status_is_actionable: false,
    never_sole_gate_present: false,
  };
  const errors = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
  const done = () => ({ valid: false, checks, errors, posture: null });

  // ── parse the compact serialization ──────────────────────────────────────
  if (typeof setCompact !== 'string' || setCompact.length === 0 || setCompact.length > 2 * 1024 * 1024) {
    fail('alg_is_eddsa', 'SET is not a non-empty compact string');
    return done();
  }
  const parts = setCompact.split('.');
  if (parts.length !== 3) {
    fail('alg_is_eddsa', `compact SET must have exactly 3 segments, got ${parts.length}`);
    return done();
  }
  const [headerSeg, payloadSeg, signatureSeg] = parts;
  const header = decodeJsonSegment(headerSeg, 4096);
  const payload = decodeJsonSegment(payloadSeg, 1024 * 1024);
  if (!header) {
    fail('alg_is_eddsa', 'JOSE header is not decodable JSON');
    return done();
  }
  if (Object.keys(header).some((name) => !['alg', 'typ', 'kid'].includes(name))
      || !isStr(header.kid) || header.kid.length > 256) {
    fail('alg_is_eddsa', 'JOSE header is outside the EP Eye SET profile');
    return done();
  }

  // ── 1. alg gate (FIRST — never treat an unsecured token as signed) ────────
  // REJECT any alg other than EdDSA, including 'none' and any non-EdDSA value,
  // BEFORE any verification. A verifier that branched on the attacker-controlled
  // alg would accept an unsigned token (vector d_alg_none_confusion).
  if (header.alg !== 'EdDSA') {
    fail('alg_is_eddsa', `alg "${header.alg}" is not the pinned EdDSA (unsecured/confusion rejected)`);
    return done();
  }
  checks.alg_is_eddsa = true;

  // ── 2. typ gate ──────────────────────────────────────────────────────────
  if (header.typ !== EYE_SET_TYP) {
    fail('typ_ok', `typ "${header.typ}" is not "${EYE_SET_TYP}"`);
    return done();
  }
  checks.typ_ok = true;

  // The payload must decode before we can pin on iss / verify / read claims.
  if (!payload) {
    fail('claims_present', 'SET payload is not decodable JSON');
    return done();
  }

  // ── 3. pin the emitter key (self-asserted kid confers nothing) ────────────
  const pinnedKey = resolvePinnedKey(opts.pinnedKeys, header.kid, payload.iss);
  if (!pinnedKey) {
    fail('emitter_key_pinned',
      `no pinned key for emitter kid "${header.kid}" / iss "${payload.iss}" (unpinned — fail closed)`);
    return done();
  }
  checks.emitter_key_pinned = true;

  // ── 4. verify the JWS signature under the PINNED key ──────────────────────
  // Recompute the signing input from the PRESENTED header.payload segments and
  // verify ONLY under the pinned key (never a producer-supplied key). A forged
  // signature, a substituted key, or a payload tampered after signing (e.g. a
  // status downgrade) all fail here (vectors a / c / e).
  const signingInput = `${headerSeg}.${payloadSeg}`;
  if (!verifyEd25519(signingInput, pinnedKey, signatureSeg)) {
    fail('jws_signature_valid',
      'JWS signature does not verify under the pinned emitter key over the presented signing input');
    return done();
  }
  checks.jws_signature_valid = true;

  // ── 5. required claims ────────────────────────────────────────────────────
  const event = singleEvent(payload);
  const claimProblems = [];
  if (!isStr(payload.iss)) claimProblems.push('iss');
  if (!isEpochSeconds(payload.iat)) claimProblems.push('iat');
  if (!isStr(payload.jti)) claimProblems.push('jti');
  if (!isStr(payload.aud)) claimProblems.push('aud');
  if (!isStr(payload.sub_id)) claimProblems.push('sub_id');
  if (!event) {
    claimProblems.push('events (exactly one advisory event member required)');
  } else {
    if (!isStr(event.status)) claimProblems.push('events.status');
    if (!isStrArray(event.reason_codes)) claimProblems.push('events.reason_codes');
    if (!isStr(event.recommended_policy_action)) claimProblems.push('events.recommended_policy_action');
    if (!isStr(event.advisory_hash)) claimProblems.push('events.advisory_hash');
    if (!isStr(event.expires_at)) claimProblems.push('events.expires_at');
  }
  if (claimProblems.length > 0) {
    fail('claims_present', `missing/ill-typed required claims: ${claimProblems.join(', ')}`);
    return done();
  }
  checks.claims_present = true;

  // ── 6. audience (gated only when opts.audience is set) ────────────────────
  if (isStr(opts.audience)) {
    if (payload.aud !== opts.audience) {
      fail('audience_match', `aud "${payload.aud}" != expected audience "${opts.audience}"`);
    }
  }

  // ── 7. freshness (enforced only when required) ────────────────────────────
  // A stale SET is rejected, never used to tighten OR relax. Freshness is
  // enforced on BOTH exp/expires_at and iat age (vectors g / h).
  if (opts.requireFresh === true) {
    const now = isEpochSeconds(opts.now)
      ? opts.now
      : Math.floor(Date.now() / 1000);

    // exp: prefer the JWT exp if present; always also enforce the event expires_at.
    if (isEpochSeconds(payload.exp) && payload.exp <= now) {
      fail('fresh', `SET exp ${payload.exp} is not after now ${now} (expired)`);
    }
    const expiresAtMs = Date.parse(event.expires_at);
    if (Number.isNaN(expiresAtMs)) {
      fail('fresh', `events.expires_at "${event.expires_at}" is not a parseable timestamp`);
    } else if (Math.floor(expiresAtMs / 1000) <= now) {
      fail('fresh', `events.expires_at "${event.expires_at}" is in the past (stale)`);
    }

    // iat age: an ancient issuance is stale even if exp parsing alone might pass.
    if (isEpochSeconds(opts.maxAgeSec)) {
      const age = now - payload.iat;
      if (age > opts.maxAgeSec) {
        fail('fresh', `iat age ${age}s exceeds maxAgeSec ${opts.maxAgeSec}s (stale issuance)`);
      }
    }
  }

  // ── 8. actionable status (a signed 'clear' event is REJECTED) ─────────────
  // 'clear' is the default-path no-change posture (Eye spec §6); permitting a
  // signed 'clear' event would let a replayed/forged 'clear' be read as an
  // affirmative "authorized" signal (vector j_clear_status_emitted_as_event).
  if (ACTIONABLE_STATUSES.includes(event.status)) {
    checks.status_is_actionable = true;
  } else {
    fail('status_is_actionable',
      `event status "${event.status}" is not an actionable posture-change status `
      + `(a 'clear' or unknown status is not a posture event)`);
  }

  // ── 9. never-sole-gate marker (load-bearing, in-band) ─────────────────────
  // The in-band invariant is load-bearing: a posture-change event that does not
  // carry never_sole_gate:true is malformed for this profile and MUST be rejected
  // (vector i_missing_never_sole_gate_marker).
  if (event.never_sole_gate === true) {
    checks.never_sole_gate_present = true;
  } else {
    fail('never_sole_gate_present',
      'event member does not carry never_sole_gate:true (the in-band invariant is required)');
  }

  const valid = Object.values(checks).every(Boolean);

  // The returned POSTURE is advice, not a command, and is NEVER allow/deny. The
  // relying party MUST recompute scope_binding_hash against the action it is
  // gating (Eye spec §7.3) and apply the posture TIGHTEN-ONLY. There is no
  // decision vocabulary here by construction.
  const posture = valid
    ? {
        status: event.status,
        reason_codes: [...event.reason_codes],
        recommended_policy_action: event.recommended_policy_action,
        scope_binding_hash: payload.sub_id,
        advisory_hash: event.advisory_hash,
        expires_at: event.expires_at,
        never_sole_gate: true,
      }
    : null;

  return { valid, checks, errors, posture };
}

const eyeSet = {
  buildEyeSet,
  verifyEyeSet,
  EYE_SET_VERSION,
  EYE_SET_TYP,
  EYE_ADVISORY_EVENT_URI,
};
export default eyeSet;
