/**
 * EMILIA Protocol — WYSIWYS / Display-Attestation profile (EP-DISPLAY-ATTESTATION-v1)
 *
 * @license Apache-2.0
 *
 * REFERENCE IMPLEMENTATION of an ADDITIVE signed claim + verifier check over
 * EP-RECEIPT-v1. Spec: docs/EP-WYSIWYS-SPEC.md. EXPERIMENTAL — governed by an
 * Extension PIP; not a production or customer claim; reports no metrics.
 *
 *   approved action (the EXACT bytes that action_hash commits to, I-D §3)
 *     -> renderAction(): a PURE, DETERMINISTIC human-readable rendering
 *       -> displayHash = sha256(canonicalize(rendering))
 *         -> display_attestation: a signed claim "I rendered THIS"
 *
 * The EP Core (PIP-001) is frozen: this file does NOT modify the
 * EP-RECEIPT-v1 wire format, canonicalization, or signature, and it does NOT
 * touch packages/verify or packages/issue. It imports the frozen
 * canonicalize() as the single canonicalization source of truth, and reuses the
 * frozen actionHash() so the rendering binds to the very bytes the receipt
 * signed. It re-implements nothing cryptographic of the receipt path.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST RESIDUAL — READ THIS. WYSIWYS IS NOT SOLVED HERE.
 *
 *   A signature proves user presence and approval toward *whatever was
 *   rendered*. Cryptography cannot prove the signing surface displayed the
 *   action honestly. This profile REDUCES the presentation-attack surface by
 *   making the rendering a PURE FUNCTION of the signed action (so an offline
 *   verifier can re-derive it byte-for-byte and reject any rendering that is
 *   not a deterministic function of the action), and by attaching a signed
 *   claim of what was shown. It does NOT eliminate the residual: a fully
 *   compromised signing client/device can render one thing, attest another, or
 *   lie about both. That residual is OUT OF SCOPE and is addressed only by
 *   device / TEE attestation (e.g. App Attest, Play Integrity, WebAuthn device
 *   binding) — a layer below this profile, not a property of it.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * FAIL CLOSED: verifyDisplayAttestation() returns { valid:false } whenever the
 * presented rendering is not the deterministic function of the signed action
 * (the rendering says one thing, action_hash another), whenever a display
 * attestation is REQUIRED (high-stakes) but missing, and whenever a present
 * attestation's display_hash does not match the re-derived rendering or its
 * signature does not verify under the pinned signer key.
 */

import crypto from 'node:crypto';

// The FROZEN canonicalizer + action hasher are the single source of truth.
// Imported by relative path to the in-repo package source, the same convention
// lib/provenance/chain.js uses, so this file uses identical bytes to the
// published @emilia-protocol/* packages by construction.
import { canonicalize, actionHash } from '../../packages/issue/index.js';

export const DISPLAY_ATTESTATION_VERSION = 'EP-DISPLAY-ATTESTATION-v1';
export const RENDER_PROFILE = 'EP-WYSIWYS-RENDER-v1';

// ── small helpers ────────────────────────────────────────────────────────

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hexOf = (h) => String(h || '').replace(/^sha256:/, '').toLowerCase();

/**
 * The closed set of baseline action fields this profile always renders, in
 * fixed order. The renderer NEVER reads anything outside the baseline and
 * policy-rollout sets, so adding noise fields to an action cannot change the
 * readable lines. A `null` value renders the literal absence marker — it is
 * still part of the deterministic output.
 */
const RENDER_FIELDS = Object.freeze([
  ['action_type', 'Action'],
  ['target_resource_id', 'Target'],
  ['organization_id', 'Organization'],
  ['actor_id', 'Initiator'],
  ['policy_id', 'Policy'],
  ['amount', 'Amount'],
  ['currency', 'Currency'],
  ['requested_at', 'Requested'],
  ['risk_flags', 'Risk signals'],
]);

/**
 * Additive fields for canonical policy-rollout actions. They are emitted only
 * when present so actions minted before this material existed retain their
 * byte-identical EP-WYSIWYS-RENDER-v1 rendering and display_hash.
 */
const POLICY_ROLLOUT_RENDER_FIELDS = Object.freeze([
  ['executing_key_id', 'Executing key ID'],
  ['rollout_policy_id', 'Rollout policy ID'],
  ['rollout_policy_key', 'Rollout policy key'],
  ['rollout_policy_version', 'Rollout policy version'],
  ['rollout_policy_rules', 'Rollout policy rules'],
  ['rollout_policy_mode', 'Rollout policy mode'],
  ['rollout_policy_status', 'Rollout policy status'],
  ['rollout_environment', 'Rollout environment'],
  ['rollout_strategy', 'Rollout strategy'],
  ['rollout_canary_pct', 'Rollout canary percent'],
  ['rollout_metadata', 'Rollout metadata'],
  ['rollout_before_state', 'Rollout before state'],
  ['rollout_after_state', 'Rollout after state'],
]);

function renderValue(key, value) {
  if (value === null || value === undefined) return '∅';
  if (key === 'risk_flags') {
    const arr = Array.isArray(value) ? value : [value];
    return arr.length ? arr.map(String).join(' · ') : '∅';
  }
  // Structured material is rendered with the frozen recursive canonicalizer:
  // key order is stable at every depth and objects never collapse to
  // "[object Object]". Arrays outside the legacy risk_flags field use the same
  // canonical JSON representation.
  if (typeof value === 'object') return canonicalize(value);
  // Numbers and strings render via their canonical JSON scalar form so the
  // rendering is locale-INDEPENDENT and platform-INDEPENDENT. No toLocaleString:
  // a currency-formatted string is not reproducible across runtimes and would
  // break determinism. Presentation locale is a display concern layered ABOVE
  // the attested bytes, never inside them.
  if (typeof value === 'number') return JSON.stringify(value);
  return String(value);
}

/**
 * renderAction(action) — the WYSIWYS deterministic rendering.
 *
 * PURE: same action object always yields byte-identical output, on any
 * runtime, in any locale. The rendering is derived ONLY from the configured
 * render fields and binds to the frozen actionHash() of the SAME action. The
 * returned `display_hash` is sha256(canonicalize({...})) over a small,
 * key-sorted object — the JCS-style canonical bytes a verifier re-derives.
 *
 * @param {object} action - the canonical Action Object (I-D §3), i.e. the exact
 *   bytes that action_hash commits to.
 * @returns {{
 *   render_profile: string,
 *   action_hash: string,        // "sha256:<hex>" of the SAME action (frozen hasher)
 *   lines: Array<{ label: string, value: string }>,
 *   text: string,               // newline-joined human-readable rendering
 *   display_hash: string,       // "sha256:<hex>" of the canonical rendering object
 * }}
 */
export function renderAction(action) {
  if (!action || typeof action !== 'object') {
    throw new TypeError('renderAction requires the canonical Action Object');
  }

  const rolloutFields = POLICY_ROLLOUT_RENDER_FIELDS.filter(
    ([key]) => Object.prototype.hasOwnProperty.call(action, key),
  );
  const lines = [...RENDER_FIELDS, ...rolloutFields].map(([key, label]) => ({
    label,
    value: renderValue(key, action[key]),
  }));
  const text = lines.map((l) => `${l.label}: ${l.value}`).join('\n');

  const aHash = actionHash(action); // frozen — same bytes the receipt signed

  // The attested object: profile id + the action hash it renders + the rendered
  // lines. Hashing the action_hash INTO the rendering is what binds "this
  // rendering" to "this signed action": a verifier re-derives both from the
  // action and rejects on any mismatch.
  const renderingObject = {
    render_profile: RENDER_PROFILE,
    action_hash: aHash,
    lines,
  };
  const displayHash = `sha256:${sha256hex(canonicalize(renderingObject))}`;

  return { render_profile: RENDER_PROFILE, action_hash: aHash, lines, text, display_hash: displayHash };
}

/**
 * buildDisplayAttestation({ action, signer }) — produce the signed claim.
 *
 * The signing CLIENT (the surface that showed the action to the human) renders
 * deterministically and signs the display_hash, asserting "I rendered THIS
 * representation of THIS action". Optional: an unsigned attestation is a bare
 * claim that a verifier reports but never trusts as signed.
 *
 * @param {object} args
 * @param {object} args.action - the canonical Action Object that was rendered.
 * @param {{ signer_key_id: string, privateKey: import('crypto').KeyObject,
 *           publicKeyB64u?: string, algorithm?: string }} [args.signer] - optional signer.
 * @returns {object} an EP-DISPLAY-ATTESTATION-v1 object.
 */
export function buildDisplayAttestation({ action, signer } = /** @type {any} */ ({})) {
  const rendered = renderAction(action);
  const att = {
    '@version': DISPLAY_ATTESTATION_VERSION,
    render_profile: rendered.render_profile,
    action_hash: rendered.action_hash,
    display_hash: rendered.display_hash,
  };
  if (signer) {
    const payload = Buffer.from(canonicalize({
      '@version': DISPLAY_ATTESTATION_VERSION,
      render_profile: att.render_profile,
      action_hash: att.action_hash,
      display_hash: att.display_hash,
    }), 'utf8');
    att.proof = {
      algorithm: signer.algorithm || 'Ed25519',
      signer_key_id: signer.signer_key_id,
      signed_payload_b64u: payload.toString('base64url'),
      signature_b64u: crypto.sign(null, payload, signer.privateKey).toString('base64url'),
      public_key: signer.publicKeyB64u,
    };
  }
  return att;
}

function verifyDetachedEd25519(proof, expectedPayloadB64u, boundPublicKeyB64u) {
  // Reject unless the proof signs EXACTLY the bytes the verifier independently
  // recomputed (defeats sign-over-other-bytes), and the key is the one bound to
  // the named signer (defeats key substitution).
  if (!proof || proof.algorithm !== 'Ed25519') return { ok: false, reason: 'proof_algorithm' };
  if (proof.signed_payload_b64u !== expectedPayloadB64u) return { ok: false, reason: 'proof_payload_mismatch' };
  if (boundPublicKeyB64u && proof.public_key !== boundPublicKeyB64u) {
    return { ok: false, reason: 'proof_key_unbound' };
  }
  try {
    const pub = crypto.createPublicKey({
      key: Buffer.from(proof.public_key, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    const ok = crypto.verify(
      null,
      Buffer.from(proof.signed_payload_b64u, 'base64url'),
      pub,
      Buffer.from(proof.signature_b64u, 'base64url'),
    );
    return ok ? { ok: true } : { ok: false, reason: 'proof_signature' };
  } catch {
    return { ok: false, reason: 'proof_signature' };
  }
}

/**
 * verifyDisplayAttestation(action, attestation, opts) — FAIL-CLOSED check.
 *
 * Re-derives the deterministic rendering from the SIGNED action and rejects:
 *   - render_mismatch: the attested display_hash is not the re-derived hash, or
 *     the attested action_hash is not the frozen hash of `action` (the
 *     rendering says one thing, the action_hash another);
 *   - missing_required_attestation: a display attestation is REQUIRED
 *     (opts.requireDisplayAttestation, e.g. high-stakes) but absent;
 *   - proof_*: a signed attestation whose proof does not verify under the
 *     pinned signer key, or whose key is unbound, or whose payload is forged.
 *
 * @param {object} action - the canonical Action Object the receipt committed to.
 * @param {object|null} attestation - an EP-DISPLAY-ATTESTATION-v1 object or null.
 * @param {object} [opts]
 * @param {boolean} [opts.requireDisplayAttestation=false] - high-stakes gate.
 * @param {boolean} [opts.requireSignedAttestation=false] - reject unsigned.
 * @param {Object<string,{public_key:string}>} [opts.displaySignerKeys] - map of
 *   signer_key_id -> pinned key. When present, the attestation's key MUST match
 *   the pinned key for its named signer.
 * @returns {{ valid: boolean, checks: object, errors: string[], display_hash: string|null }}
 */
export function verifyDisplayAttestation(action, attestation, opts = {}) {
  /** @type {{ render_deterministic: boolean, attestation_present: boolean, display_hash_match: boolean, proof_signed: boolean|null }} */
  const checks = {
    render_deterministic: false,    // rendering is a pure fn of the signed action
    attestation_present: false,     // present iff required-or-supplied
    display_hash_match: false,      // attested hash == re-derived hash
    proof_signed: null,             // null = not required / not present
  };
  const errors = [];
  const fail = (msg) => { errors.push(msg); return { valid: false, checks, errors, display_hash: null }; };

  if (!action || typeof action !== 'object') return fail('Missing canonical action');

  // Re-derive the rendering from the signed bytes. This is the WYSIWYS anchor:
  // the verifier never trusts a producer-supplied rendering; it recomputes one.
  let rendered;
  try {
    rendered = renderAction(action);
  } catch (e) {
    return fail(`render failed: ${e.message}`);
  }
  checks.render_deterministic = true;

  const required = opts.requireDisplayAttestation === true;

  if (!attestation) {
    if (required) return fail('missing_required_attestation');
    // Not required and not present: the rendering is still a deterministic
    // function of the action (control 1), but no signed display claim exists.
    // Nothing to reject; nothing extra is proven.
    return { valid: true, checks, errors, display_hash: rendered.display_hash };
  }

  checks.attestation_present = true;

  if (attestation['@version'] !== DISPLAY_ATTESTATION_VERSION) {
    return fail('invalid_attestation_version');
  }

  // FAIL CLOSED: the attested rendering MUST be the deterministic function of
  // the signed action. Both the action_hash and the display_hash must match the
  // re-derived values, or the rendering said one thing and the signed action
  // another — exactly the presentation attack this profile rejects.
  if (hexOf(attestation.action_hash) !== hexOf(rendered.action_hash)) {
    return fail('render_mismatch: attested action_hash != frozen action hash');
  }
  if (hexOf(attestation.display_hash) !== hexOf(rendered.display_hash)) {
    return fail('render_mismatch: attested display_hash != re-derived rendering');
  }
  checks.display_hash_match = true;

  // Signature (optional unless required). The proof signs the canonical bytes of
  // {version, render_profile, action_hash, display_hash}; we recompute exactly
  // those bytes and verify under the key PINNED to the named signer.
  //
  // FAIL CLOSED on an unpinned/absent signer. A present proof is trustworthy only
  // when it verifies under a key the verifier has pinned for its signer_key_id.
  // Without a pin the signature can be checked only against the producer's OWN
  // self-asserted key, which proves nothing — anyone can mint a keypair and a
  // correct rendering — so it MUST NOT be reported as verified. This mirrors the
  // execution-integrity twin's executor_key_pinned gate (lib/execution/integrity.js)
  // and the spec's "rejects a proof under any other key" rule (EP-WYSIWYS-SPEC §4).
  if (attestation.proof) {
    const proof = attestation.proof;
    const expectedPayloadB64u = Buffer.from(canonicalize({
      '@version': DISPLAY_ATTESTATION_VERSION,
      render_profile: rendered.render_profile,
      action_hash: rendered.action_hash,
      display_hash: rendered.display_hash,
    }), 'utf8').toString('base64url');

    // Structural checks first, so the forensic reason is precise even before key
    // resolution: wrong algorithm, or a signature over bytes other than the ones
    // the verifier independently recomputed.
    if (proof.algorithm !== 'Ed25519') {
      checks.proof_signed = false;
      return fail('proof_invalid: proof_algorithm');
    }
    if (proof.signed_payload_b64u !== expectedPayloadB64u) {
      checks.proof_signed = false;
      return fail('proof_invalid: proof_payload_mismatch');
    }

    // The named signer MUST be pinned. No pin (or no registry) => no attribution
    // => fail closed. Never fall back to the self-asserted proof.public_key.
    const pinned = opts.displaySignerKeys?.[proof.signer_key_id]?.public_key;
    if (!pinned) {
      checks.proof_signed = false;
      return fail('proof_invalid: signer_key_unpinned');
    }
    if (proof.public_key !== pinned) {
      checks.proof_signed = false;
      return fail('proof_invalid: proof_key_unbound');
    }

    const res = verifyDetachedEd25519(proof, expectedPayloadB64u, pinned);
    checks.proof_signed = res.ok;
    if (!res.ok) return fail(`proof_invalid: ${res.reason}`);
  } else if (opts.requireSignedAttestation === true) {
    checks.proof_signed = false;
    return fail('missing_required_signature');
  }

  return { valid: true, checks, errors, display_hash: rendered.display_hash };
}
