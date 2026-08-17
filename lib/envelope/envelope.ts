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

import { Buffer } from 'node:buffer';

import { canonicalize } from '../../packages/issue/index.js';
import {
  AGILE_SIGNATURE_ALGORITHMS,
  AGILITY_REASONS,
  ML_DSA_65_SIGNATURE_BYTES,
  verifyAgileSignature,
} from '../../packages/verify/pq-signature-agility.js';

export const EP_ENVELOPE_VERSION = 'EP-ENVELOPE-v1';

// Algorithms an envelope-level proof may use. 'none' and anything unlisted are
// rejected before a plugin runs. (Wrapped legacy profiles carry their own proofs
// inside payload and are verified by their inner verifier; this gate covers
// envelope-level proofs for native profiles.)
//
// 'ML-DSA-65' (FIPS 204) is on the list because EP-SIG-AGILITY-v1's closed
// registry can actually CHECK it -- see verifyEnvelopeProofs below. It was
// added with a verification path rather than as a bare allow-list entry: an
// algorithm a verifier lets through but cannot evaluate is worse than one it
// refuses, because the refusal is visible and the pass is not.
const ALLOWED_ALGS = Object.freeze(['Ed25519', 'EdDSA', 'ES256', 'ML-DSA-65']);

/**
 * The subset of ALLOWED_ALGS this file can verify itself, by routing to
 * EP-SIG-AGILITY-v1's closed registry. 'EdDSA' (the JOSE spelling) and 'ES256'
 * stay structurally allowed for wrapped legacy profiles whose inner verifier
 * owns the signature, but this module does NOT check them and never reports
 * them as verified; see PROOF_REASONS.ALG_NOT_VERIFIABLE_HERE.
 */
const AGILE_PROOF_ALGS = Object.freeze([...AGILE_SIGNATURE_ALGORITHMS]);

/**
 * Domain separator for envelope-level detached proofs. Its job is to keep an
 * envelope proof from being replayed as a signature over anything else that
 * canonicalizes to the same bytes (a bare payload, a receipt body): the label
 * is inside what gets signed, so the two byte strings can never collide.
 */
export const ENVELOPE_PROOF_DOMAIN = 'emilia-protocol/envelope-proof/v1';

/** Named refusals for envelope-level proof verification. */
export const PROOF_REASONS = Object.freeze({
  MALFORMED_PROOF: 'malformed_proof',
  ALG_NOT_ALLOWED: 'alg_not_allowed',
  ALG_NOT_VERIFIABLE_HERE: 'alg_not_verifiable_here',
  MALFORMED_SIGNATURE: AGILITY_REASONS.MALFORMED_SIGNATURE,
  NO_PINNED_KEY: 'no_pinned_key',
});

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * The exact bytes an envelope-level proof covers: the domain label, then the
 * canonical form of the SIGNED members of the envelope. `proofs`, `anchor`, and
 * `meta` are deliberately outside it -- a proof cannot cover itself, and the
 * unsigned buckets keep the same role they have in EP-RECEIPT-v1's `metadata`.
 * Nothing a relying party authorizes on may live in them.
 *
 * Exported so a verifier, a conformance vector, or an independent
 * implementation can rebuild the bytes without reading this module's internals.
 */
export function envelopeProofBytes(env: any): Buffer {
  return Buffer.from(
    `${ENVELOPE_PROOF_DOMAIN}\u0000${canonicalize({
      binding: env?.binding ?? null,
      ep: env?.ep ?? null,
      payload: env?.payload ?? null,
      profile: env?.profile ?? null,
      typ: env?.typ ?? null,
    })}`,
    'utf8',
  );
}

/**
 * Structural pin on an ML-DSA-65 proof signature: strict base64url decoding to
 * EXACTLY the FIPS 204 signature length. This runs in the synchronous shared
 * pipeline, before any key is consulted, because a length pin is half of the
 * anti-masquerade control the agility module documents (the other half is the
 * key pin, which only the async path can apply). Returns a reason string when
 * the proof is malformed, or null when it is well formed.
 */
function mldsaProofStructuralReason(proof: any): string | null {
  const sig = proof?.signature ?? proof?.sig ?? proof?.signature_b64u;
  if (typeof sig !== 'string' || sig.length === 0 || !B64URL_RE.test(sig)) {
    return PROOF_REASONS.MALFORMED_SIGNATURE;
  }
  let bytes: Buffer;
  try {
    bytes = Buffer.from(sig, 'base64url');
  } catch {
    return PROOF_REASONS.MALFORMED_SIGNATURE;
  }
  if (bytes.length !== ML_DSA_65_SIGNATURE_BYTES) return PROOF_REASONS.MALFORMED_SIGNATURE;
  return null;
}

// Reserved private-use namespace: anyone may ship `urn:ep:profile:x-<vendor>:*`
// today without coordination. The core never collides with it.
const VENDOR_URN = /^urn:ep:profile:x-[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9._-]*$/i;
const CORE_URN = /^urn:ep:profile:[a-z0-9][a-z0-9-]*:v\d+$/i;

/** A profile is valid IFF it matches the core or the reserved vendor namespace. */
export function isWellFormedProfileUrn(urn: any) {
  return typeof urn === 'string' && (CORE_URN.test(urn) || VENDOR_URN.test(urn));
}
export function isVendorProfileUrn(urn: any) {
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
 */
export function registerProfile(urn: any, { validateBody, descriptor = null }: any = {}) {
  if (!isWellFormedProfileUrn(urn)) {
    throw new Error(`registerProfile: malformed profile URN "${urn}" (expected urn:ep:profile:<name>:v<n> or the x-<vendor> private space)`);
  }
  if (typeof validateBody !== 'function') {
    throw new Error(`registerProfile(${urn}): validateBody must be a function`);
  }
  REGISTRY.set(urn, { validateBody, descriptor });
  return urn;
}

export function getProfile(urn: any) {
  return REGISTRY.get(urn) || null;
}
export function listProfiles() {
  return [...REGISTRY.keys()].sort();
}

// ── Shared pipeline (profile-agnostic; NO plugin can skip it) ─────────────────
function runSharedPipeline(env: any) {
  const checks = {
    envelope_version: false,   // ep == EP-ENVELOPE-v1
    profile_known: false,      // profile URN is well-formed AND registered
    payload_present: false,    // payload is a non-null object
    proof_alg_allowed: true,   // envelope-level proofs use an allowed alg (vacuous if none)
    proof_signature_wellformed: true, // fixed-length proof signatures decode to their exact length (vacuous if none)
  };
  const errors: any[] = [];
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
      // ML-DSA-65 carries a fixed-length signature, so a wrong length is a
      // structural refusal here rather than something the async path discovers
      // later. Same discipline the hybrid envelope applies to both its legs.
      if (alg === 'ML-DSA-65') {
        const reason = mldsaProofStructuralReason(p);
        if (reason) {
          fail('proof_signature_wellformed', `envelope proof (ML-DSA-65) refused: ${reason}`);
          break;
        }
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
 */
export function verifyEnvelope(env: any, opts: any = {}) {
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
 * verifyEnvelopeProofs(env, opts): CRYPTOGRAPHICALLY check the envelope-level
 * detached proofs, routed entirely through EP-SIG-AGILITY-v1.
 *
 * This is the half `verifyEnvelope` cannot do: signature verification for
 * ML-DSA-65 is asynchronous (the FIPS 204 backend is resolved lazily and its
 * absence is a refusal), so it lives in its own async entry point rather than
 * changing the synchronous verifier every existing caller uses.
 *
 * WHAT IT CHECKS, AND WHAT IT REFUSES TO PRETEND IT CHECKED. Each proof is
 * evaluated on its own and reported on its own:
 *   - 'Ed25519' and 'ML-DSA-65' are handed to verifyAgileSignature over
 *     envelopeProofBytes(env), with the algorithm-tagged pinned key. That
 *     function owns the closed registry, the curve pin, the exact
 *     signature-length pin, and the ML-DSA backend refusal; none of it is
 *     reimplemented here.
 *   - 'EdDSA' and 'ES256' are structurally allowed but NOT checked by this
 *     module, and are reported `verified: false` with reason
 *     `alg_not_verifiable_here`. An unchecked proof never counts toward a pass.
 *
 * The overall verdict is true only when there is at least one proof and EVERY
 * proof verified. An envelope with no proofs returns valid:false with
 * `no_proofs`: this function answers "do the proofs hold", and there is no
 * honest way to answer yes about proofs that are not there.
 *
 * @param env    the EP-ENVELOPE-v1 object.
 * @param opts.proofKeys  pinned keys by `kid`: { [kid]: { alg, public_key } }.
 *   Ed25519 public keys are base64url SPKI DER or a KeyObject; ML-DSA-65 public
 *   keys are 1952 raw bytes or base64url of them. A proof whose `kid` is not
 *   pinned refuses with `no_pinned_key`; there is no self-asserted-key path.
 * @param opts.agility    passed through to EP-SIG-AGILITY-v1 (backend injection).
 */
export async function verifyEnvelopeProofs(env: any, opts: any = {}) {
  const results: any[] = [];
  const errors: any[] = [];
  const proofKeys = opts && typeof opts.proofKeys === 'object' && opts.proofKeys !== null ? opts.proofKeys : {};
  const agilityOptions = opts && typeof opts.agility === 'object' && opts.agility !== null ? opts.agility : {};

  const proofs = env && typeof env === 'object' && Array.isArray(env.proofs) ? env.proofs : null;
  if (!proofs || proofs.length === 0) {
    return { valid: false, reason: 'no_proofs', results, errors: ['envelope carries no envelope-level proofs'] };
  }

  const messageBytes = new Uint8Array(envelopeProofBytes(env));

  for (let i = 0; i < proofs.length; i++) {
    const p = proofs[i];
    const alg = p && typeof p === 'object' && !Array.isArray(p) ? (p.algorithm || p.alg) : null;
    const kid = p && typeof p.kid === 'string' ? p.kid : null;
    const report = { index: i, alg: typeof alg === 'string' ? alg : null, kid, verified: false, reason: null as string | null };
    results.push(report);

    if (!p || typeof p !== 'object' || Array.isArray(p)) {
      report.reason = PROOF_REASONS.MALFORMED_PROOF;
    } else if (!ALLOWED_ALGS.includes(alg)) {
      report.reason = PROOF_REASONS.ALG_NOT_ALLOWED;
    } else if (!AGILE_PROOF_ALGS.includes(alg)) {
      // Structurally allowed, but this module cannot evaluate it. Saying so is
      // the whole point: an unchecked leg is never reported as a checked one.
      report.reason = PROOF_REASONS.ALG_NOT_VERIFIABLE_HERE;
    } else if (kid === null || !Object.prototype.hasOwnProperty.call(proofKeys, kid)) {
      report.reason = PROOF_REASONS.NO_PINNED_KEY;
    } else {
      const pin = proofKeys[kid];
      const result = await verifyAgileSignature(
        messageBytes,
        { alg, sig: p.signature ?? p.sig ?? p.signature_b64u, key_id: kid },
        { alg: pin?.alg, public_key: pin?.public_key, key_id: kid },
        agilityOptions,
      );
      report.verified = result.verified === true;
      report.reason = result.verified === true ? null : result.reason;
    }

    if (!report.verified) errors.push(`envelope proof ${i} (${report.alg ?? 'unknown alg'}) refused: ${report.reason}`);
  }

  return { valid: errors.length === 0, reason: errors.length === 0 ? null : results.find((r) => !r.verified)?.reason ?? null, results, errors };
}

/**
 * verifyEnvelopeWithProofs(env, opts): the structural verifier AND the
 * envelope-level proof check, ANDed.
 *
 * The composition rule is the same one PluginCannotWeaken states: verdicts are
 * ANDed, so the proof check can only ADD a rejection. A valid proof can never
 * rescue a structurally invalid envelope, and a structurally valid envelope
 * with a bad proof is invalid.
 */
export async function verifyEnvelopeWithProofs(env: any, opts: any = {}) {
  const structural = verifyEnvelope(env, opts);
  const proofs = await verifyEnvelopeProofs(env, opts);
  return {
    valid: structural.valid === true && proofs.valid === true,
    profile: structural.profile,
    checks: { ...structural.checks, proofs_valid: proofs.valid === true },
    errors: [...structural.errors, ...proofs.errors],
    proofs: proofs.results,
  };
}

/**
 * migrate(profileObject, profileUrn, extra?) — wrap a legacy profile object into
 * an EP-ENVELOPE-v1 envelope LOSSLESSLY. The payload IS the original object, so
 * canonicalize(env.payload) === canonicalize(profileObject) byte-for-byte — no
 * re-signing, previously-issued objects and the live I-D stay valid.
 */
export function migrate(profileObject: any, profileUrn: any, extra: any = {}) {
  if (!isWellFormedProfileUrn(profileUrn)) {
    throw new Error(`migrate: malformed profile URN "${profileUrn}"`);
  }
  if (!profileObject || typeof profileObject !== 'object') {
    throw new Error('migrate: profileObject must be an object');
  }
  const env: { ep: any, profile: any, payload: any, binding?: any, typ?: any, meta?: any } =
    { ep: EP_ENVELOPE_VERSION, profile: profileUrn, payload: profileObject };
  if (extra.binding) env.binding = extra.binding;
  if (extra.typ) env.typ = extra.typ;
  if (extra.meta) env.meta = extra.meta;
  return env;
}

/** True iff wrapping `profileObject` preserves its canonical bytes (lossless). */
export function isLosslessMigration(profileObject: any, env: any) {
  try {
    return canonicalize(env.payload) === canonicalize(profileObject);
  } catch {
    return false;
  }
}

const envelope = {
  EP_ENVELOPE_VERSION,
  ENVELOPE_PROOF_DOMAIN,
  PROOF_REASONS,
  registerProfile,
  getProfile,
  listProfiles,
  verifyEnvelope,
  verifyEnvelopeProofs,
  verifyEnvelopeWithProofs,
  envelopeProofBytes,
  migrate,
  isWellFormedProfileUrn,
  isVendorProfileUrn,
  isLosslessMigration,
};
export default envelope;
