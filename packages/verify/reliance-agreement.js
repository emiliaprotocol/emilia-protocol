// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-AGREEMENT-v1 / EP-RELIANCE-EVENT-v1 — machine-readable, signed
 * reliance agreements and per-action reliance events.
 *
 * THE OBJECT
 * ----------
 * The reliance kernel (EP-RELIANCE-KERNEL-v1) answers "may I rely on this
 * evidence packet under MY pinned profile?" This module carries the layer the
 * insurance market writes in prose today: a signed, portable object in which
 * named parties condition a liability transfer or an indemnity on
 * authorization-evidence sufficiency — "if the presented evidence satisfies
 * reliance profile P, terms T (mode, caps, currency) apply between us." The
 * agreement references the evidence condition by DIGEST of a reliance profile
 * (EP-RELIANCE-PROFILE-v1); it never reinvents evidence policy. The per-action
 * RELIANCE EVENT then binds ONE action's reliance verdict to the agreement,
 * making both the commitment and the act of reliance non-repudiable.
 *
 * WHAT VERIFICATION PROVES — AND DOES NOT
 * ---------------------------------------
 * verifyRelianceAgreement proves WHO agreed to WHAT terms over WHICH evidence
 * conditions: every signature required by the agreement's own required_signers
 * verifies under a key the verifier pinned out of band, over the JCS-canonical
 * agreement payload, inside the agreement's own validity window. It does NOT
 * prove enforceability (a jurisdiction question), does NOT escrow the cap
 * amounts (they are claims about intent), and CANNOT prevent a party from
 * dishonoring the commitment — it makes dishonor attributable and the record
 * portable to a dispute forum. The object is designed to be incorporated by
 * reference into a prose master agreement; it is the interoperable expression
 * of the agreement, not a substitute for contract law.
 *
 * PURE. OFFLINE. FAIL-CLOSED. No deps beyond node:crypto. Monetary amounts are
 * decimal STRINGS, never JSON numbers (floating-point representation of money
 * is a refusal, not a warning). All vocabularies are closed.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const RELIANCE_AGREEMENT_VERSION = 'EP-RELIANCE-AGREEMENT-v1';
export const RELIANCE_EVENT_VERSION = 'EP-RELIANCE-EVENT-v1';
export const RELIANCE_AGREEMENT_DOMAIN = 'EP-RELIANCE-AGREEMENT-v1\0';
export const RELIANCE_EVENT_DOMAIN = 'EP-RELIANCE-EVENT-v1\0';

/** The CLOSED set of agreement term modes. */
export const AGREEMENT_MODES = Object.freeze(['liability_shift', 'indemnity']);
/** The CLOSED set of party roles. */
export const AGREEMENT_ROLES = Object.freeze(['issuer', 'relying_party', 'underwriter']);
/** Profile-local closed vocabulary; not a shared protocol assurance taxonomy. */
const ASSURANCE_CLASSES = Object.freeze(['S', 'H', 'V', 'Q']);

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
/** Decimal money string: no sign, no exponent, no leading zeros, optional fraction. */
const AMOUNT_RE = /^(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;

const sha256hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function toMs(t) {
  if (t == null) return Date.now();
  if (typeof t === 'number') return t;
  if (t instanceof Date) return t.getTime();
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? Date.now() : ms;
}

/** Strict timestamp parse for fields inside signed objects: NaN on anything malformed. */
function parseTs(t) {
  if (typeof t !== 'string' || t === '') return NaN;
  return Date.parse(t);
}

function pubKeyB64u(ref) {
  if (typeof ref === 'string') return ref;
  if (ref && typeof ref.public_key === 'string') return ref.public_key;
  return null;
}

function importPinnedKey(b64u) {
  try {
    return crypto.createPublicKey({ key: Buffer.from(b64u, 'base64url'), type: 'spki', format: 'der' });
  } catch {
    return null;
  }
}

function stripSignatures(agreement) {
  const { signatures: _sigs, ...body } = agreement;
  return body;
}
function stripSignature(event) {
  const { signature: _sig, ...body } = event;
  return body;
}

function agreementSigningBytes(unsignedBody) {
  return Buffer.from(RELIANCE_AGREEMENT_DOMAIN + canonicalize(unsignedBody), 'utf8');
}
function eventSigningBytes(unsignedBody) {
  return Buffer.from(RELIANCE_EVENT_DOMAIN + canonicalize(unsignedBody), 'utf8');
}

/** Digest of the agreement body (domain-separated, signature envelope excluded). */
export function relianceAgreementDigest(agreement) {
  return `sha256:${sha256hex(agreementSigningBytes(stripSignatures(agreement)))}`;
}

/** Digest of the event body (domain-separated, signature envelope excluded). */
export function relianceEventDigest(event) {
  return `sha256:${sha256hex(eventSigningBytes(stripSignature(event)))}`;
}

/** Content digest of a reliance result record (plain JCS, no signing domain). */
export function relianceResultDigest(result) {
  return `sha256:${sha256hex(Buffer.from(canonicalize(result), 'utf8'))}`;
}

/**
 * Sign an agreement payload as one or more parties. Test/issuance convenience;
 * verification never trusts the carried public keys, only pinned ones.
 * @param {object} payload  the agreement WITHOUT signatures
 * @param {Array<{party:string, privateKey:import('node:crypto').KeyObject}>} signers
 * @returns {object} the agreement with a signatures[] envelope appended
 */
export function signRelianceAgreement(payload, signers) {
  const body = stripSignatures(payload);
  const bytes = agreementSigningBytes(body);
  const signatures = (signers || []).map(({ party, privateKey }) => {
    // @types/node omits KeyObject from createPublicKey's param union though the
    // runtime derives a public key from a private KeyObject (see its own docs).
    const publicKey = crypto.createPublicKey(/** @type {any} */ (privateKey)).export({ type: 'spki', format: 'der' }).toString('base64url');
    return {
      party,
      algorithm: 'Ed25519',
      key_id: body.parties?.[party]?.key_id ?? null,
      public_key: publicKey,
      signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
    };
  });
  return { ...body, signatures };
}

/**
 * Sign a reliance event payload as the relying party.
 * @param {object} payload  the event WITHOUT signature
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {object} the event with a signature envelope appended
 */
export function signRelianceEvent(payload, privateKey) {
  const body = stripSignature(payload);
  const bytes = eventSigningBytes(body);
  // @types/node omits KeyObject from createPublicKey's param union though the
  // runtime derives a public key from a private KeyObject (see its own docs).
  const publicKey = crypto.createPublicKey(/** @type {any} */ (privateKey)).export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    ...body,
    signature: {
      party: 'relying_party',
      algorithm: 'Ed25519',
      public_key: publicKey,
      signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
    },
  };
}

/** Validate one money field. Returns a reason string on refusal, null when fine. */
function checkAmount(terms, field, required) {
  const v = terms[field];
  if (v === undefined || v === null) {
    return required ? `terms.${field} is required` : null;
  }
  if (typeof v === 'number') {
    return `terms.${field} must be a decimal string, not a JSON number (floating point cannot represent money exactly)`;
  }
  if (typeof v !== 'string' || !AMOUNT_RE.test(v)) {
    return `terms.${field} must be a decimal amount string`;
  }
  return null;
}

/**
 * Verify an EP-RELIANCE-AGREEMENT-v1 against pinned party keys.
 *
 * Proves: well-formed closed-vocabulary payload; the agreement is inside its
 * own validity window at `now`; every party named by the agreement's OWN
 * required_signers[] has exactly one Ed25519 signature that verifies under the
 * key pinned (out of band) for that party's key_id; any additional signature
 * present also verifies. Fail-closed: any missing pin, missing signature,
 * unknown vocabulary value, or amount-as-number is a refusal with a reason.
 *
 * @param {object} agreement
 * @param {object} [opts]
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]  key_id -> pinned base64url SPKI Ed25519 key
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], digest?:string, required_signers?:string[]}}
 */
export function verifyRelianceAgreement(agreement, opts = {}) {
  const reasons = [];
  const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
  const now = toMs(opts.now);
  const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};

  // ── 1. STRUCTURE — closed vocabularies, fail-closed ────────────────────────
  if (!agreement || typeof agreement !== 'object' || Array.isArray(agreement)) return fail('agreement is not an object');
  if (agreement.version !== RELIANCE_AGREEMENT_VERSION) return fail(`version must be ${RELIANCE_AGREEMENT_VERSION}`);
  if (typeof agreement.agreement_id !== 'string' || agreement.agreement_id === '') return fail('agreement_id must be a non-empty string');

  const parties = agreement.parties;
  if (!parties || typeof parties !== 'object' || Array.isArray(parties)) return fail('parties must be an object');
  for (const role of Object.keys(parties)) {
    if (!AGREEMENT_ROLES.includes(role)) return fail(`unknown party role '${role}' (closed set: ${AGREEMENT_ROLES.join(', ')})`);
  }
  for (const role of ['issuer', 'relying_party']) {
    const p = parties[role];
    if (!p || typeof p !== 'object') return fail(`parties.${role} is required`);
    if (typeof p.id !== 'string' || p.id === '') return fail(`parties.${role}.id must be a non-empty string`);
    if (typeof p.key_id !== 'string' || p.key_id === '') return fail(`parties.${role}.key_id must be a non-empty string`);
  }
  if (parties.underwriter !== undefined) {
    const u = parties.underwriter;
    if (!u || typeof u !== 'object' || typeof u.id !== 'string' || u.id === '' || typeof u.key_id !== 'string' || u.key_id === '') {
      return fail('parties.underwriter, when present, must carry a non-empty id and key_id');
    }
  }

  const required = agreement.required_signers;
  if (!Array.isArray(required) || required.length === 0) return fail('required_signers must be a non-empty array');
  if (new Set(required).size !== required.length) return fail('required_signers must not contain duplicates');
  for (const role of required) {
    if (!AGREEMENT_ROLES.includes(role)) return fail(`required_signers contains unknown role '${role}'`);
    if (!parties[role]) return fail(`required_signers names '${role}' but the agreement declares no such party`);
  }
  if (!required.includes('issuer') || !required.includes('relying_party')) {
    return fail('required_signers must include both issuer and relying_party (an agreement neither issued nor accepted is not an agreement)');
  }

  const scope = agreement.scope;
  if (!scope || typeof scope !== 'object') return fail('scope is required');
  if (!Array.isArray(scope.action_families) || scope.action_families.length === 0
    || !scope.action_families.every((f) => typeof f === 'string' && f !== '')) {
    return fail('scope.action_families must be a non-empty array of non-empty strings');
  }
  if (scope.jurisdictions !== undefined
    && (!Array.isArray(scope.jurisdictions) || !scope.jurisdictions.every((j) => typeof j === 'string' && j !== ''))) {
    return fail('scope.jurisdictions, when present, must be an array of non-empty strings');
  }
  const validity = scope.validity;
  if (!validity || typeof validity !== 'object') return fail('scope.validity is required');
  const notBefore = parseTs(validity.not_before);
  const notAfter = parseTs(validity.not_after);
  if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) return fail('scope.validity.not_before and not_after must be parseable timestamps');
  if (notBefore >= notAfter) return fail('scope.validity.not_before must precede not_after');

  const condition = agreement.condition;
  if (!condition || typeof condition !== 'object') return fail('condition is required');
  if (typeof condition.reliance_profile_digest !== 'string' || !SHA256_RE.test(condition.reliance_profile_digest)) {
    return fail('condition.reliance_profile_digest must be a sha256:<64 hex> digest of the pinned reliance profile');
  }
  if (condition.min_assurance_class !== undefined && !ASSURANCE_CLASSES.includes(condition.min_assurance_class)) {
    return fail(`condition.min_assurance_class must be one of ${ASSURANCE_CLASSES.join(', ')}`);
  }
  if (condition.max_staleness_sec !== undefined
    && !(Number.isFinite(condition.max_staleness_sec) && condition.max_staleness_sec >= 0)) {
    return fail('condition.max_staleness_sec must be a non-negative finite number');
  }

  const terms = agreement.terms;
  if (!terms || typeof terms !== 'object') return fail('terms is required');
  if (!AGREEMENT_MODES.includes(terms.mode)) {
    return fail(`terms.mode '${String(terms.mode)}' is not in the closed set (${AGREEMENT_MODES.join(', ')})`);
  }
  for (const [field, req] of [['cap_amount', true], ['per_action_cap', false], ['aggregate_cap', false], ['deductible', false]]) {
    const r = checkAmount(terms, field, req);
    if (r) return fail(r);
  }
  if (typeof terms.currency !== 'string' || !CURRENCY_RE.test(terms.currency)) {
    return fail('terms.currency must be a three-letter uppercase currency code');
  }
  if (agreement.recourse_ref !== undefined && (typeof agreement.recourse_ref !== 'string' || agreement.recourse_ref === '')) {
    return fail('recourse_ref, when present, must be a non-empty string');
  }

  // ── 2. CANONICAL FORM — the exact bytes every signature covers ─────────────
  let bytes;
  try { bytes = agreementSigningBytes(stripSignatures(agreement)); } catch { return fail('agreement is not JCS-canonicalizable'); }
  const digest = `sha256:${sha256hex(bytes)}`;

  // ── 3. VALIDITY WINDOW ──────────────────────────────────────────────────────
  if (now < notBefore || now > notAfter) return fail('agreement is outside its validity window');

  // ── 4. SIGNATURES — every REQUIRED party, under PINNED keys only ────────────
  const sigs = Array.isArray(agreement.signatures) ? agreement.signatures : [];
  const byParty = new Map();
  for (const s of sigs) {
    if (!s || typeof s !== 'object' || !AGREEMENT_ROLES.includes(s.party)) return fail('a signature entry names no known party role');
    if (!parties[s.party]) return fail(`a signature is present for undeclared party '${s.party}'`);
    if (byParty.has(s.party)) return fail(`duplicate signature entries for party '${s.party}'`);
    byParty.set(s.party, s);
  }
  for (const role of required) {
    if (!byParty.has(role)) return fail(`required signature from '${role}' is missing (the agreement is not effective)`);
  }
  // Any signature PRESENT must verify — including non-required ones. A broken
  // signature on the object is never ignorable.
  for (const [role, s] of byParty) {
    if (s.algorithm !== 'Ed25519' || typeof s.signature_b64u !== 'string' || s.signature_b64u === '') {
      return fail(`signature from '${role}' is malformed (Ed25519 signature_b64u required)`);
    }
    const keyId = parties[role].key_id;
    const pinned = pubKeyB64u(trustedKeys[keyId]);
    if (!pinned) return fail(`no pinned key for '${role}' (key_id ${keyId}); an unpinned signer cannot make the agreement effective`);
    const keyObj = importPinnedKey(pinned);
    if (!keyObj) return fail(`the pinned key for '${role}' is not a valid Ed25519 SPKI key`);
    let ok = false;
    try { ok = crypto.verify(null, bytes, keyObj, Buffer.from(s.signature_b64u, 'base64url')); } catch { ok = false; }
    if (!ok) return fail(`signature from '${role}' does not verify over the canonical agreement payload`);
  }

  reasons.push('all required signatures verify under pinned keys and the agreement is inside its validity window');
  return { valid: true, reasons, digest, required_signers: [...required] };
}

/**
 * Verify an EP-RELIANCE-EVENT-v1: the per-action claim instrument binding one
 * action's reliance verdict to a reliance agreement.
 *
 * Proves: the referenced agreement verifies (all required signatures, pinned
 * keys) and was inside its validity window AT relied_at; the event's
 * agreement_digest matches the supplied agreement; the event's action_digest
 * is the action the supplied reliance result attests; the result digest
 * matches the supplied result byte-for-byte (JCS); the result's action family
 * is inside the agreement scope; when the result names the profile it was
 * evaluated under, it is the profile the agreement conditions on; and the
 * event is signed by the agreement's relying_party under its pinned key.
 *
 * Does NOT re-evaluate the evidence: whether the verdict inside the result is
 * honest is established by replaying the reliance kernel over the evidence,
 * not by this binding check.
 *
 * @param {object} event
 * @param {object} [opts]
 * @param {object} [opts.agreement]       the EP-RELIANCE-AGREEMENT-v1 relied on
 * @param {object} [opts.relianceResult]  the reliance result record the event binds
 *                                      (must carry action_digest and action_family;
 *                                      may carry profile_digest and verdict)
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], agreement_digest?:string, event_digest?:string}}
 */
export function verifyRelianceEvent(event, opts = {}) {
  const reasons = [];
  const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
  const now = toMs(opts.now);
  const { agreement, relianceResult } = opts;

  // ── 1. EVENT STRUCTURE ──────────────────────────────────────────────────────
  if (!event || typeof event !== 'object' || Array.isArray(event)) return fail('event is not an object');
  if (event.version !== RELIANCE_EVENT_VERSION) return fail(`version must be ${RELIANCE_EVENT_VERSION}`);
  if (typeof event.event_id !== 'string' || event.event_id === '') return fail('event_id must be a non-empty string');
  for (const f of ['agreement_digest', 'action_digest', 'reliance_result_digest']) {
    if (typeof event[f] !== 'string' || !SHA256_RE.test(event[f])) return fail(`${f} must be a sha256:<64 hex> digest`);
  }
  const reliedAt = parseTs(event.relied_at);
  if (Number.isNaN(reliedAt)) return fail('relied_at must be a parseable timestamp');
  if (reliedAt > now) return fail('relied_at is in the future relative to verification time');

  // ── 2. THE AGREEMENT — must verify, and must have been effective AT relied_at
  if (!agreement || typeof agreement !== 'object') return fail('no agreement supplied to bind the event against');
  const ag = verifyRelianceAgreement(agreement, { trustedKeys: opts.trustedKeys, now: reliedAt });
  if (!ag.valid) return fail(`the referenced agreement does not verify at relied_at: ${ag.reasons.join('; ')}`);
  if (event.agreement_digest !== ag.digest) {
    return fail('the event is bound to a different agreement (agreement_digest mismatch)');
  }

  // ── 3. THE RELIANCE RESULT — the verdict this event claims under ────────────
  if (!relianceResult || typeof relianceResult !== 'object' || Array.isArray(relianceResult)) {
    return fail('no reliance result supplied to bind the event against');
  }
  if (typeof relianceResult.action_digest !== 'string' || !SHA256_RE.test(relianceResult.action_digest)) {
    return fail('the reliance result carries no sha256 action_digest');
  }
  if (event.action_digest !== relianceResult.action_digest) {
    return fail('the reliance result attests a different action than the event claims (action_digest mismatch)');
  }
  let resultDigest;
  try { resultDigest = relianceResultDigest(relianceResult); } catch { return fail('the reliance result is not JCS-canonicalizable'); }
  if (event.reliance_result_digest !== resultDigest) {
    return fail('reliance_result_digest does not match the supplied reliance result (the result was substituted or altered)');
  }

  // ── 4. SCOPE AND CONDITION BINDING ──────────────────────────────────────────
  const families = agreement.scope.action_families;
  if (typeof relianceResult.action_family !== 'string' || relianceResult.action_family === '') {
    return fail('the reliance result names no action_family; scope cannot be established');
  }
  if (!families.includes(relianceResult.action_family)) {
    return fail(`action family '${relianceResult.action_family}' is outside the agreement scope`);
  }
  if (relianceResult.profile_digest !== undefined
    && relianceResult.profile_digest !== agreement.condition.reliance_profile_digest) {
    return fail('the reliance result was evaluated under a different reliance profile than the agreement conditions on');
  }

  // ── 5. SIGNATURE — the RELYING PARTY, under its pinned key, or nothing ──────
  const sig = event.signature;
  if (!sig || typeof sig !== 'object' || sig.algorithm !== 'Ed25519' || typeof sig.signature_b64u !== 'string' || sig.signature_b64u === '') {
    return fail('event signature is missing or malformed (Ed25519 signature_b64u required)');
  }
  const rpKeyId = agreement.parties.relying_party.key_id;
  const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};
  const pinned = pubKeyB64u(trustedKeys[rpKeyId]);
  if (!pinned) return fail(`no pinned key for the agreement relying_party (key_id ${rpKeyId})`);
  const keyObj = importPinnedKey(pinned);
  if (!keyObj) return fail('the pinned relying_party key is not a valid Ed25519 SPKI key');
  let bytes;
  try { bytes = eventSigningBytes(stripSignature(event)); } catch { return fail('event is not JCS-canonicalizable'); }
  let ok = false;
  try { ok = crypto.verify(null, bytes, keyObj, Buffer.from(sig.signature_b64u, 'base64url')); } catch { ok = false; }
  if (!ok) return fail('event signature does not verify under the agreement relying_party pinned key');

  reasons.push('the event binds this action, this reliance result, and this agreement, signed by the relying party at a time the agreement was effective');
  return { valid: true, reasons, agreement_digest: ag.digest, event_digest: `sha256:${sha256hex(bytes)}` };
}
