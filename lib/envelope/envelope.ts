/**
 * EP-ENVELOPE-v1 — the narrow waist.
 *
 * @license Apache-2.0
 *
 * ONE wire object that every EP profile inhabits, ONE verifier that dispatches by
 * a registered profile URN, and ONE composition rule: a profile plugin may only
 * ADD rejections, never approvals. This is what turns N bespoke `verifyX()`
 * functions into a single family where profiles (and the actions they cover) are
 * DATA, not code — a third party can register a profile without changing the core.
 *
 *   envelope = {
 *     ep:       "EP-ENVELOPE-v1",
 *     profile:  "urn:ep:profile:<name>:v<n>",   // resolved against the registry
 *     typ?:     string,                          // optional media-type hint
 *     payload:  object,                          // the profile-specific body
 *     binding?: { action_hash?, policy_hash?, prev_hash? },  // uniform bindings
 *     proofs?:  [ { algorithm, kid?, ... } ],    // envelope-level detached proofs
 *     anchor?:  object,                          // optional transparency anchor
 *     meta?:    object
 *   }
 *
 * ## The Core Freeze is respected
 * This file does NOT modify EP-RECEIPT-v1, its canonicalization, its signature,
 * or any existing verifier. It imports the FROZEN canonicalize() read-only and
 * composes the existing profile verifiers as plugins. `migrate()` wraps a legacy
 * profile object into an envelope LOSSLESSLY (the payload IS the original object,
 * byte-stable under canonicalize) so previously-issued objects and the live I-D
 * stay valid.
 *
 * ## PluginCannotWeaken (the load-bearing invariant)
 * verifyEnvelope computes `valid = sharedOk && pluginResult.valid`. A plugin's
 * verdict is AND-ed with the shared pipeline; a plugin can therefore only turn a
 * shared `valid:true` into `false` (add a rejection) — it can NEVER turn a shared
 * `valid:false` into `true`. A malicious or buggy plugin cannot make a structurally
 * invalid envelope verify. An unknown profile fails closed.
 */

import { canonicalize } from '../../packages/issue/index.js';

export const EP_ENVELOPE_VERSION = 'EP-ENVELOPE-v1';

// Algorithms an envelope-level proof may use. 'none' and anything unlisted are
// rejected before a plugin runs. (Wrapped legacy profiles carry their own proofs
// inside payload and are verified by their inner verifier; this gate covers
// envelope-level proofs for native profiles.)
const ALLOWED_ALGS = Object.freeze(['Ed25519', 'EdDSA', 'ES256']);

// Reserved private-use namespace: anyone may ship `urn:ep:profile:x-<vendor>:*`
// today without coordination. The core never collides with it.
const VENDOR_URN = /^urn:ep:profile:x-[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9._-]*$/i;
const CORE_URN = /^urn:ep:profile:[a-z0-9][a-z0-9-]*:v\d+$/i;

/** A profile is valid IFF it matches the core or the reserved vendor namespace. */
export function isWellFormedProfileUrn(urn) {
  return typeof urn === 'string' && (CORE_URN.test(urn) || VENDOR_URN.test(urn));
}
export function isVendorProfileUrn(urn) {
  return typeof urn === 'string' && VENDOR_URN.test(urn);
}

// ── Profile registry (in-process) ────────────────────────────────────────────
// Maps a profile URN to { validateBody, descriptor }. validateBody(env, opts) ->
// { valid:boolean, checks?:object, errors?:string[] }. It receives ONLY what the
// caller supplied (incl. any pinned trust store) and MUST fail closed on its own
// (no fallback to self-asserted keys) — every shipped EP verifier already does.
const REGISTRY = new Map();

/**
 * Register a profile plugin. Idempotent re-registration with the same URN
 * replaces the prior entry (last-writer-wins is fine: registration is local
 * trust configuration, not a wire input).
 *
 * @param {string} urn
 * @param {{ validateBody?: Function, descriptor?: * }} [options]
 */
export function registerProfile(urn, { validateBody, descriptor = null } = {}) {
  if (!isWellFormedProfileUrn(urn)) {
    throw new Error(`registerProfile: malformed profile URN "${urn}" (expected urn:ep:profile:<name>:v<n> or the x-<vendor> private space)`);
  }
  if (typeof validateBody !== 'function') {
    throw new Error(`registerProfile(${urn}): validateBody must be a function`);
  }
  REGISTRY.set(urn, { validateBody, descriptor });
  return urn;
}

export function getProfile(urn) {
  return REGISTRY.get(urn) || null;
}
export function listProfiles() {
  return [...REGISTRY.keys()].sort();
}

// ── Shared pipeline (profile-agnostic; NO plugin can skip it) ─────────────────
function runSharedPipeline(env) {
  const checks = {
    envelope_version: false,   // ep == EP-ENVELOPE-v1
    profile_known: false,      // profile URN is well-formed AND registered
    payload_present: false,    // payload is a non-null object
    proof_alg_allowed: true,   // envelope-level proofs use an allowed alg (vacuous if none)
  };
  const errors = [];
  const fail = (k, m) => { checks[k] = false; errors.push(m); };

  if (!env || typeof env !== 'object' || Array.isArray(env)) {
    fail('payload_present', 'envelope is not an object');
    return { ok: false, checks, errors, plugin: null };
  }
  if (env.ep !== EP_ENVELOPE_VERSION) {
    fail('envelope_version', `unsupported envelope version: ${env.ep}`);
  } else {
    checks.envelope_version = true;
  }

  const plugin = isWellFormedProfileUrn(env.profile) ? getProfile(env.profile) : null;
  if (!isWellFormedProfileUrn(env.profile)) {
    fail('profile_known', `malformed profile URN: ${env.profile}`);
  } else if (!plugin) {
    // Unknown profile MUST fail closed — a verifier never accepts a profile it
    // cannot evaluate, even if it is well-formed.
    fail('profile_known', `unknown profile (not registered): ${env.profile}`);
  } else {
    checks.profile_known = true;
  }

  if (!env.payload || typeof env.payload !== 'object' || Array.isArray(env.payload)) {
    fail('payload_present', 'envelope.payload must be a non-null object');
  } else {
    checks.payload_present = true;
  }

  if (Array.isArray(env.proofs)) {
    for (const p of env.proofs) {
      const alg = p && (p.algorithm || p.alg);
      if (!ALLOWED_ALGS.includes(alg)) {
        fail('proof_alg_allowed', `envelope proof algorithm "${alg}" is not allowed (no 'none'/unlisted)`);
        break;
      }
    }
  }

  const ok = Object.values(checks).every(Boolean);
  return { ok, checks, errors, plugin };
}

/**
 * verifyEnvelope(env, opts) — the ONE verifier.
 *
 * Runs the shared pipeline, then dispatches to the registered profile's
 * validateBody. The final verdict is `sharedOk && body.valid` — the plugin can
 * only ADD rejections (PluginCannotWeaken). Fails closed on unknown profiles,
 * malformed envelopes, disallowed algorithms, and any thrown plugin error.
 *
 * @returns {{ valid:boolean, profile:string|null, checks:object, errors:string[] }}
 */
export function verifyEnvelope(env, opts = {}) {
  const shared = runSharedPipeline(env);
  const profile = env && typeof env === 'object' ? env.profile ?? null : null;

  // No plugin (unknown/malformed profile): the envelope is already invalid; do
  // not attempt a body check. Fail closed.
  if (!shared.plugin) {
    return { valid: false, profile, checks: shared.checks, errors: shared.errors };
  }

  // Run the plugin body check. A thrown plugin is treated as a rejection — a
  // verifier must never crash on adversarial input.
  let body;
  try {
    body = shared.plugin.validateBody(env, opts);
  } catch (e) {
    body = { valid: false, checks: {}, errors: [`plugin_threw: ${e?.message || 'error'}`] };
  }
  if (!body || typeof body !== 'object') {
    body = { valid: false, checks: {}, errors: ['plugin_returned_non_object'] };
  }

  // PluginCannotWeaken: AND the verdicts. A plugin's valid:true cannot rescue a
  // shared rejection; a plugin's valid:false always stands.
  const valid = shared.ok && body.valid === true;

  return {
    valid,
    profile,
    checks: { ...shared.checks, ...(body.checks || {}) },
    errors: [...shared.errors, ...(body.errors || [])],
  };
}

/**
 * migrate(profileObject, profileUrn, extra?) — wrap a legacy profile object into
 * an EP-ENVELOPE-v1 envelope LOSSLESSLY. The payload IS the original object, so
 * canonicalize(env.payload) === canonicalize(profileObject) byte-for-byte — no
 * re-signing, previously-issued objects and the live I-D stay valid.
 */
export function migrate(profileObject, profileUrn, extra = {}) {
  if (!isWellFormedProfileUrn(profileUrn)) {
    throw new Error(`migrate: malformed profile URN "${profileUrn}"`);
  }
  if (!profileObject || typeof profileObject !== 'object') {
    throw new Error('migrate: profileObject must be an object');
  }
  const env = { ep: EP_ENVELOPE_VERSION, profile: profileUrn, payload: profileObject };
  if (extra.binding) env.binding = extra.binding;
  if (extra.typ) env.typ = extra.typ;
  if (extra.meta) env.meta = extra.meta;
  return env;
}

/** True iff wrapping `profileObject` preserves its canonical bytes (lossless). */
export function isLosslessMigration(profileObject, env) {
  try {
    return canonicalize(env.payload) === canonicalize(profileObject);
  } catch {
    return false;
  }
}

const envelope = {
  EP_ENVELOPE_VERSION,
  registerProfile,
  getProfile,
  listProfiles,
  verifyEnvelope,
  migrate,
  isWellFormedProfileUrn,
  isVendorProfileUrn,
  isLosslessMigration,
};
export default envelope;
