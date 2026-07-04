// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — break-glass as EVIDENCE, never a bypass (EP-GATE-BREAKGLASS-v1).
 *
 * An emergency override is a FIRST-CLASS SIGNED ARTIFACT, not a config flag.
 * There is no "disable the gate" switch anywhere in this module: to act outside
 * the normal receipt path, operators mint a break-glass authorization — an
 * M-of-N Ed25519 multi-signature over canonical JSON (sorted keys, same idiom
 * as receipts/entitlements/evidence) of ONE shared grant:
 *
 *   { grant_id, scope: { action_types[] }, window: { not_before, expires_at },
 *     reason, incident_ref, threshold }
 *
 * Every signer signs the SAME payload, so the artifact proves that `threshold`
 * DISTINCT pinned principals authorized exactly this scope, for exactly this
 * window, for exactly this incident. The grant is:
 *   - SCOPED     — valid only for the listed action_types; anything else refuses;
 *   - BOUNDED    — valid only inside [not_before, expires_at];
 *   - ATTRIBUTED — reason + incident_ref are REQUIRED; an override with no
 *                  stated cause is refused, not logged-and-allowed;
 *   - SINGLE-USE — consumed through the same consumption-store contract as
 *                  receipts (store.js); consumption is committed BEFORE use, so
 *                  a crash mid-override burns the grant instead of leaving it
 *                  replayable (fail direction: unusable, never reusable);
 *   - LOGGED     — `buildBreakGlassEvidence` shapes a kind:'breakglass' entry
 *                  for the tamper-evident evidence log.
 *
 * THE MODULE'S CONTRACT: NO EVIDENCE ENTRY, NO OVERRIDE. Callers MUST append
 * the break-glass evidence entry via a strict evidence log
 * (createEvidenceLog({ strict: true })) and see record() succeed BEFORE
 * executing the overridden action. If the entry cannot be durably recorded,
 * the override MUST NOT run — the whole point of break-glass-as-evidence is
 * that an unaccounted emergency action is indistinguishable from an attack.
 *
 * Verification FAILS CLOSED with machine-readable reasons: threshold unmet,
 * non-distinct signer kids, expired, not-yet-valid, out-of-scope action_type,
 * tampered payload, unknown kid, malformed anything → { valid:false, reason }.
 * A grant carrying ANY signature that does not verify is refused outright —
 * we never "count the good ones" past a bad one.
 *
 * Pure functions: inputs in, verdict out. Time is injected (`now`), never read
 * from the wall clock implicitly, so verification is deterministic.
 */
import crypto from 'node:crypto';

export const BREAKGLASS_VERSION = 'EP-GATE-BREAKGLASS-v1';
export const BREAKGLASS_EVIDENCE_KIND = 'breakglass';

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/** Canonical JSON (recursive sorted keys) — matches @emilia-protocol/verify. */
function canonical(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function toMs(t) {
  if (t == null) return null;
  const ms = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}

/** Every refusal shape is identical and machine-readable. Fail closed. */
function refuse(reason, extra = {}) {
  return { valid: false, reason, ...extra };
}

function isNonEmptyString(s) {
  return typeof s === 'string' && s.length > 0;
}

function isActionTypeList(a) {
  return Array.isArray(a) && a.length > 0 && a.every(isNonEmptyString);
}

/**
 * Mint a break-glass authorization: every signer signs the canonical JSON of
 * the SAME grant payload. Throws on invalid fields — a malformed grant must
 * never be issued, only refused. Signer kids must already be distinct at mint
 * time: one principal can never pre-fill two threshold slots.
 *
 * grant_id is CONTENT-DERIVED (sha-256 of the canonical grant fields), so the
 * id is deterministic and re-minting the identical grant yields the identical
 * single-use consumption key — the same emergency authorization cannot be
 * "refreshed" into extra uses by minting it twice.
 *
 * @param {Array<{ privateKey: crypto.KeyObject, kid: string }>} signers
 * @param {object} fields { scope: { action_types: string[] }, window: { not_before, expires_at }, reason, incident_ref, threshold }
 * @returns {{ '@version': string, payload: object, signatures: Array<{ kid: string, algorithm: 'Ed25519', value: string }> }}
 */
export function mintBreakGlassAuthorization(signers, {
  scope, window: win, reason, incident_ref, threshold,
} = {}) {
  if (!Array.isArray(signers) || signers.length === 0) {
    throw new Error('breakglass: signers must be a non-empty array of { privateKey, kid }');
  }
  for (const s of signers) {
    if (!s || !s.privateKey || !isNonEmptyString(s.kid)) {
      throw new Error('breakglass: each signer needs a privateKey and a kid');
    }
  }
  const kids = signers.map((s) => s.kid);
  if (new Set(kids).size !== kids.length) {
    throw new Error('breakglass: signer kids must be distinct — one principal cannot fill two threshold slots');
  }
  if (!scope || !isActionTypeList(scope.action_types)) {
    throw new Error('breakglass: scope.action_types must be a non-empty array of action-type strings');
  }
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new Error('breakglass: threshold must be an integer >= 1');
  }
  if (threshold > signers.length) {
    throw new Error(`breakglass: threshold ${threshold} exceeds signer count ${signers.length} — the grant could never verify`);
  }
  const nbf = toMs(win?.not_before);
  const exp = toMs(win?.expires_at);
  if (nbf == null || exp == null) {
    throw new Error('breakglass: window.not_before and window.expires_at are required (ISO or ms)');
  }
  if (exp <= nbf) throw new Error('breakglass: window.expires_at must be after window.not_before');
  // An override with no stated cause must never exist — attribution is the deal.
  if (!isNonEmptyString(reason)) throw new Error('breakglass: reason is required');
  if (!isNonEmptyString(incident_ref)) throw new Error('breakglass: incident_ref is required');

  const core = {
    scope: { action_types: scope.action_types.slice() },
    window: { not_before: win.not_before, expires_at: win.expires_at },
    reason,
    incident_ref,
    threshold,
  };
  const grant_id = `bg_${sha256hex(canonical(core))}`;
  const payload = { grant_id, ...core };
  const msg = Buffer.from(canonical(payload), 'utf8');
  const signatures = signers.map(({ privateKey, kid }) => ({
    kid,
    algorithm: 'Ed25519',
    value: crypto.sign(null, msg, privateKey).toString('base64url'),
  }));
  return { '@version': BREAKGLASS_VERSION, payload, signatures };
}

/** Resolve a base64url SPKI-DER key for `kid` from a map or an entry list. */
function issuerKeyFor(issuerKeys, kid) {
  if (!issuerKeys) return null;
  if (Array.isArray(issuerKeys)) {
    const e = issuerKeys.find((x) => x && x.kid === kid && typeof x.key === 'string');
    return e ? e.key : null;
  }
  const k = issuerKeys[kid];
  return typeof k === 'string' ? k : null;
}

/**
 * Verify a break-glass grant against pinned issuer keys. NEVER throws for a
 * bad artifact — every failure resolves to { valid:false, reason } so the
 * refusal itself is loggable. FAILS CLOSED on every path:
 *   no_grant | grant_unparseable | grant_malformed | unsupported_version |
 *   unsupported_algorithm | invalid_threshold | invalid_scope |
 *   missing_reason | missing_incident_ref | duplicate_signer |
 *   threshold_unmet | unknown_kid | bad_signature |
 *   invalid_validity_window | not_yet_valid | expired |
 *   action_type_required | out_of_scope
 *
 * A grant can never nominate its own keys: every signature's kid must resolve
 * to a PINNED key, and EVERY listed signature must verify — one tampered or
 * unknown signature refuses the whole grant. The validity window is checked
 * only AFTER the signatures, so the timestamps themselves are authenticated.
 *
 * @param {object|string|null} grantJson the artifact (object or JSON string)
 * @param {object} o
 * @param {object|Array<{kid:string,key:string}>} o.issuerKeys pinned kid -> base64url SPKI-DER public key
 * @param {number|string|function} [o.now=Date.now] injected clock (ms, ISO, or () => ms)
 * @param {string} o.actionType the action the caller wants to override — REQUIRED (scope cannot be checked without it)
 * @returns {{ valid: boolean, reason: string, grant_id?: string, incident_ref?: string, scope?: object, window?: object, threshold?: number, signer_kids?: string[] }}
 */
export function verifyBreakGlass(grantJson, { issuerKeys, now = Date.now, actionType } = {}) {
  if (grantJson == null || grantJson === '') return refuse('no_grant');

  let doc = grantJson;
  if (typeof doc === 'string') {
    try { doc = JSON.parse(doc); } catch { return refuse('grant_unparseable'); }
  }
  if (!doc || typeof doc !== 'object') return refuse('grant_malformed');
  if (doc['@version'] !== BREAKGLASS_VERSION) return refuse('unsupported_version');

  const p = doc.payload;
  const sigs = doc.signatures;
  if (!p || typeof p !== 'object' || !Array.isArray(sigs) || sigs.length === 0) {
    return refuse('grant_malformed');
  }
  if (!isNonEmptyString(p.grant_id)) return refuse('grant_malformed');
  if (!Number.isInteger(p.threshold) || p.threshold < 1) return refuse('invalid_threshold');
  if (!p.scope || !isActionTypeList(p.scope.action_types)) return refuse('invalid_scope');
  // Attribution is non-optional: an anonymous or causeless override is refused.
  if (!isNonEmptyString(p.reason)) return refuse('missing_reason');
  if (!isNonEmptyString(p.incident_ref)) return refuse('missing_incident_ref');

  for (const s of sigs) {
    if (!s || typeof s !== 'object' || !isNonEmptyString(s.kid) || typeof s.value !== 'string') {
      return refuse('grant_malformed');
    }
    if (s.algorithm !== 'Ed25519') return refuse('unsupported_algorithm', { kid: s.kid });
  }

  // Distinct principals: one kid may fill exactly one threshold slot.
  const kids = sigs.map((s) => s.kid);
  if (new Set(kids).size !== kids.length) {
    const dup = kids.find((k, i) => kids.indexOf(k) !== i);
    return refuse('duplicate_signer', { kid: dup });
  }
  if (sigs.length < p.threshold) {
    return refuse('threshold_unmet', { threshold: p.threshold, signatures: sigs.length });
  }

  // Every listed signature must verify against a PINNED key. One unknown kid
  // or one bad signature refuses the whole grant — never count past a failure.
  const msg = Buffer.from(canonical(p), 'utf8');
  for (const s of sigs) {
    const keyB64 = issuerKeyFor(issuerKeys, s.kid);
    if (!keyB64) return refuse('unknown_kid', { kid: s.kid });
    let ok = false;
    try {
      const pub = crypto.createPublicKey({ key: Buffer.from(keyB64, 'base64url'), format: 'der', type: 'spki' });
      ok = crypto.verify(null, msg, pub, Buffer.from(s.value, 'base64url'));
    } catch { ok = false; }
    if (!ok) return refuse('bad_signature', { kid: s.kid });
  }

  // Validity window — checked only AFTER the signatures, so the timestamps
  // themselves are authenticated. Both bounds are required; unparseable fails closed.
  const nowMs = typeof now === 'function' ? now() : toMs(now);
  const nbf = toMs(p.window?.not_before);
  const exp = toMs(p.window?.expires_at);
  if (nbf == null || exp == null || nowMs == null) return refuse('invalid_validity_window');
  if (nowMs < nbf) return refuse('not_yet_valid', { not_before: p.window.not_before });
  if (nowMs > exp) return refuse('expired', { expires_at: p.window.expires_at });

  // Scope: without knowing the action there is nothing to authorize — refuse.
  if (!isNonEmptyString(actionType)) return refuse('action_type_required');
  if (!p.scope.action_types.includes(actionType)) {
    return refuse('out_of_scope', { action_type: actionType, scope: p.scope.action_types.slice() });
  }

  return {
    valid: true,
    reason: 'breakglass_verified',
    grant_id: p.grant_id,
    incident_ref: p.incident_ref,
    scope: { action_types: p.scope.action_types.slice() },
    window: { not_before: p.window.not_before, expires_at: p.window.expires_at },
    threshold: p.threshold,
    signer_kids: kids.slice(),
  };
}

/**
 * SINGLE-USE consumption via the consumption-store contract (store.js):
 * `consume(key)` returns true the FIRST time, false on every replay, and marks
 * the key seen BEFORE the caller acts — consumption is committed before use.
 * If the process crashes after consume() and before the override, the grant is
 * burned, not replayable: the fail direction is unusable, never reusable.
 *
 * Accepts the grant document ({ payload: { grant_id } }) or a verified result
 * ({ grant_id }). NEVER throws — a missing store, missing grant_id, or a store
 * error all refuse with a machine-readable reason.
 *
 * @param {object} grant break-glass grant document or verifyBreakGlass result
 * @param {{ consume(key: string): Promise<boolean> }} store consumption store (store.js contract)
 * @returns {Promise<{ consumed: boolean, reason: string, key?: string }>}
 */
export async function consumeBreakGlass(grant, store) {
  const grantId = grant?.payload?.grant_id ?? grant?.grant_id;
  if (!isNonEmptyString(grantId)) return { consumed: false, reason: 'missing_grant_id' };
  if (!store || typeof store.consume !== 'function') {
    return { consumed: false, reason: 'no_consumption_store' };
  }
  const key = `breakglass:${grantId}`;
  let first = false;
  try {
    first = (await store.consume(key)) === true;
  } catch {
    // The store could not commit the consumption — fail CLOSED: we cannot
    // prove single-use, so the override must not run.
    return { consumed: false, reason: 'store_error', key };
  }
  if (!first) return { consumed: false, reason: 'already_consumed', key };
  return { consumed: true, reason: 'consumed', key };
}

/**
 * Shape an evidence-log entry (kind 'breakglass') committing to the EXACT
 * grant artifact (grant_hash = sha-256 of canonical grant) and the decision
 * taken under it. Append it via the hash-chained evidence log — with
 * { strict: true } so a sink failure refuses the override.
 *
 * THE CONTRACT: NO EVIDENCE ENTRY, NO OVERRIDE. `evidence.record(entry)` must
 * SUCCEED before the overridden action executes; if it throws, refuse. This
 * function never throws, even for a malformed grant or missing decision — the
 * refusal of a bad grant must itself be loggable. A missing/indeterminate
 * decision is recorded as allow:false (fail closed).
 *
 * @param {object} grant the break-glass grant document as presented (even if invalid)
 * @param {object} decision e.g. { allow, reason, action_type } from verify/consume
 * @param {object} [o]
 * @param {number|string|function} [o.now=Date.now] injected clock for the entry timestamp
 * @returns {object} entry ready for createEvidenceLog().record()
 */
export function buildBreakGlassEvidence(grant, decision, { now = Date.now } = {}) {
  const nowMs = typeof now === 'function' ? now() : toMs(now);
  const p = (grant && typeof grant === 'object' && grant.payload && typeof grant.payload === 'object')
    ? grant.payload : null;
  const sigs = (grant && Array.isArray(grant.signatures)) ? grant.signatures : [];
  const d = (decision && typeof decision === 'object') ? decision : {};
  return {
    kind: BREAKGLASS_EVIDENCE_KIND,
    '@version': BREAKGLASS_VERSION,
    at: new Date(nowMs ?? 0).toISOString(),
    grant_id: p?.grant_id ?? null,
    incident_ref: p?.incident_ref ?? null,
    grant_reason: p?.reason ?? null,
    scope: p?.scope?.action_types?.slice?.() ?? null,
    threshold: p?.threshold ?? null,
    signer_kids: sigs.map((s) => s?.kid ?? null),
    // Commits the log entry to the exact artifact presented — a later dispute
    // can prove which grant (tampered or not) the decision was taken under.
    grant_hash: sha256hex(canonical(grant ?? null)),
    decision: {
      allow: d.allow === true, // fail closed: anything else records a refusal
      reason: isNonEmptyString(d.reason) ? d.reason : 'unspecified',
      action_type: d.action_type ?? null,
    },
  };
}

export default {
  mintBreakGlassAuthorization,
  verifyBreakGlass,
  consumeBreakGlass,
  buildBreakGlassEvidence,
  BREAKGLASS_VERSION,
  BREAKGLASS_EVIDENCE_KIND,
};
