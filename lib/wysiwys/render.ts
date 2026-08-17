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
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
  type AgileSignature,
  type AgileVerificationKey,
} from '../../packages/verify/pq-signature-agility.js';

export const DISPLAY_ATTESTATION_VERSION = 'EP-DISPLAY-ATTESTATION-v1';
export const RENDER_PROFILE = 'EP-WYSIWYS-RENDER-v1';

interface DisplaySigner {
  signer_key_id: string;
  privateKey: crypto.KeyObject;
  publicKeyB64u?: string;
  algorithm?: string;
}

interface DisplayAttestationProof {
  algorithm: string;
  signer_key_id: string;
  signed_payload_b64u: string;
  signature_b64u: string;
  public_key?: string;
}

interface DisplayAttestation {
  '@version': string;
  render_profile: string;
  action_hash: string;
  display_hash: string;
  proof?: DisplayAttestationProof;
}

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
export function buildDisplayAttestation({ action, signer }: { action: Record<string, any>; signer?: DisplaySigner } = {} as any): DisplayAttestation {
  const rendered = renderAction(action);
  const att: DisplayAttestation = {
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

function verifyDetachedEd25519(proof, expectedPayloadB64u) {
  // Reject unless the proof signs EXACTLY the bytes the verifier independently
  // recomputed (defeats sign-over-other-bytes). The caller resolves and pins the
  // named signer before invoking this cryptographic check.
  if (!proof || proof.algorithm !== 'Ed25519') return { ok: false, reason: 'proof_algorithm' };
  if (proof.signed_payload_b64u !== expectedPayloadB64u) return { ok: false, reason: 'proof_payload_mismatch' };
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
export function verifyDisplayAttestation(action, attestation, opts: {
  requireDisplayAttestation?: boolean;
  requireSignedAttestation?: boolean;
  displaySignerKeys?: Record<string, { public_key: string }>;
} = {}) {
  const checks: {
    render_deterministic: boolean;
    attestation_present: boolean;
    display_hash_match: boolean;
    proof_signed: boolean | null;
  } = {
    render_deterministic: false,    // rendering is a pure fn of the signed action
    attestation_present: false,     // present iff required-or-supplied
    display_hash_match: false,      // attested hash == re-derived hash
    proof_signed: null,             // null = not required / not present
  };
  const errors: string[] = [];
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

    const res = verifyDetachedEd25519(proof, expectedPayloadB64u);
    checks.proof_signed = res.ok;
    if (!res.ok) return fail(`proof_invalid: ${res.reason}`);
  } else if (opts.requireSignedAttestation === true) {
    checks.proof_signed = false;
    return fail('missing_required_signature');
  }

  return { valid: true, checks, errors, display_hash: rendered.display_hash };
}

// ===========================================================================
// EP-DISPLAY-ATTESTATION-v2 -- the hybrid (Ed25519 + ML-DSA-65) attestation
// ===========================================================================
/**
 * HYBRID MIGRATION following the reference pattern in
 * docs/protocol/pq-hybrid-program.md ("PATTERN: the reference hybrid
 * migration") and packages/verify/src/revocation.ts's EP-REVOCATION-v2. Five
 * moves, in order: (1) VERSION BUMP, not a field bump — a second signature
 * changes the SHAPE of the proof, so the attestation takes a new `@version`
 * (EP-DISPLAY-ATTESTATION-v1 -> -v2); verifyDisplayAttestation() above is
 * untouched and refuses a v2 attestation on the version marker
 * (`invalid_attestation_version`); (2) SET SHAPE — `proof.signatures` is the
 * EP-SIG-AGILITY-v1 AgileSignature array, one entry per algorithm in the
 * registered order; (3) ANTI-STRIPPING BYTES — the required algorithm set is
 * inside the signed bytes (displayAttestationV2SignedPayload), rebuilt by the
 * verifier from the REGISTERED set; (4) V1 COMPATIBILITY — the v1 sync verifier
 * is unchanged; v2 verification is ASYNC and a SEPARATE entry point;
 * (5) NAMED REFUSALS — every failure names a check, nothing throws on caller
 * input, and an absent ML-DSA backend is a refusal, never a pass on the
 * classical leg.
 *
 * The WYSIWYS anchor is unchanged: the verifier RE-DERIVES the deterministic
 * rendering from the SIGNED action and refuses any attested rendering that is
 * not that pure function; the signing client is pinned out of band per
 * signer_key_id, now with BOTH its Ed25519 and ML-DSA-65 halves.
 *
 * HONEST RESIDUAL is exactly the v1 residual (a fully compromised signing
 * client can render one thing and attest another; that is addressed by
 * device/TEE attestation, a layer below). The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module; v2 does not retroactively protect v1
 * attestations.
 */

export const DISPLAY_ATTESTATION_V2_VERSION = 'EP-DISPLAY-ATTESTATION-v2';
export const DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const DISPLAY_SIGNER_PQ_KEY_ID = /^ep:display-signer-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;

interface DisplaySignerV2 {
  signer_key_id: string;
  /** Ed25519 signing key. */
  privateKey: crypto.KeyObject;
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  pqSecretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  pqPublicKey: Uint8Array | string;
}

interface DisplayAttestationV2Proof {
  profile: string;
  required_algorithms: string[];
  signer_key_id: string;
  public_key: string;
  pq_key_id: string;
  pq_public_key: string;
  signatures: AgileSignature[];
}

interface DisplayAttestationV2 {
  '@version': string;
  render_profile: string;
  action_hash: string;
  display_hash: string;
  proof?: DisplayAttestationV2Proof;
}

interface DisplaySignerV2Pin { public_key: string; pq_public_key: string; }

interface VerifyDisplayAttestationV2Options extends AgilityOptions {
  requireDisplayAttestation?: boolean;
  requireSignedAttestation?: boolean;
  displaySignerKeys?: Record<string, DisplaySignerV2Pin>;
}

function displayAlgorithmSetMatches(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS[i]);
}

function displayEdSpkiB64u(key: crypto.KeyObject): string {
  return crypto.createPublicKey(key as unknown as crypto.PublicKeyInput)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
}

function displayPqKeyIdOf(rawB64u: string): string {
  return `ep:display-signer-key:ml-dsa-65:sha256:${crypto
    .createHash('sha256').update(Buffer.from(rawB64u, 'base64url')).digest('hex')}`;
}

function displayPqRawB64u(value: Uint8Array | string, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
  if (bytes.length !== expectedLength) {
    throw new Error(`buildDisplayAttestationV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

/**
 * The bytes BOTH legs sign: the v2 version marker, the render profile, the
 * action hash, the display hash, and the required algorithm set. Recomputed by
 * the verifier from the RE-DERIVED rendering and the REGISTERED set.
 */
export function displayAttestationV2SignedPayload(
  fields: { render_profile: string; action_hash: string; display_hash: string },
  requiredAlgorithms: readonly string[] = DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!displayAlgorithmSetMatches(requiredAlgorithms)) {
    throw new Error('displayAttestationV2SignedPayload: algorithm set is not the registered EP-DISPLAY-ATTESTATION-v2 set');
  }
  return Buffer.from(canonicalize({
    '@version': DISPLAY_ATTESTATION_V2_VERSION,
    render_profile: fields.render_profile,
    action_hash: fields.action_hash,
    display_hash: fields.display_hash,
    required_algorithms: [...requiredAlgorithms],
  }), 'utf8');
}

/**
 * buildDisplayAttestationV2({ action, signer }) — produce a hybrid signed claim.
 * THROWS on issuer-side misuse or an unavailable ML-DSA backend, so a
 * half-hybrid attestation is never produced.
 */
export async function buildDisplayAttestationV2(
  { action, signer, deterministic = false }:
  { action: Record<string, any>; signer: DisplaySignerV2; deterministic?: boolean },
): Promise<DisplayAttestationV2> {
  if (!signer || !signer.signer_key_id || !signer.privateKey || !signer.pqSecretKey || !signer.pqPublicKey) {
    throw new Error('buildDisplayAttestationV2 requires signer.{signer_key_id,privateKey,pqSecretKey,pqPublicKey}');
  }
  const rendered = renderAction(action);
  const edPublic = displayEdSpkiB64u(signer.privateKey);
  const pqPublic = displayPqRawB64u(signer.pqPublicKey, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKey');
  const pqSecret = displayPqRawB64u(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');
  const pqKeyId = displayPqKeyIdOf(pqPublic);

  const messageBytes = displayAttestationV2SignedPayload({
    render_profile: rendered.render_profile,
    action_hash: rendered.action_hash,
    display_hash: rendered.display_hash,
  }, DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(
    new Uint8Array(messageBytes),
    [
      { alg: 'Ed25519', private_key: signer.privateKey, key_id: signer.signer_key_id },
      { alg: 'ML-DSA-65', private_key: pqSecret, key_id: pqKeyId },
    ],
    deterministic === true ? { deterministic: true } : {},
  );
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered = DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS.map((alg) => {
    const s = byAlg.get(alg);
    if (!s) throw new Error(`buildDisplayAttestationV2: signing produced no ${alg} leg`);
    return s;
  });

  return {
    '@version': DISPLAY_ATTESTATION_V2_VERSION,
    render_profile: rendered.render_profile,
    action_hash: rendered.action_hash,
    display_hash: rendered.display_hash,
    proof: {
      profile: DISPLAY_ATTESTATION_V2_VERSION,
      required_algorithms: [...DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS],
      signer_key_id: signer.signer_key_id,
      public_key: edPublic,
      pq_key_id: pqKeyId,
      pq_public_key: pqPublic,
      signatures: ordered,
    },
  };
}

/**
 * verifyDisplayAttestationV2(action, attestation, opts) — FAIL-CLOSED hybrid
 * check. Never throws on caller input. A signed v2 attestation NEVER verifies on
 * one leg alone.
 */
export async function verifyDisplayAttestationV2(
  action: any,
  attestation: any,
  opts: VerifyDisplayAttestationV2Options = {},
): Promise<{ valid: boolean; checks: Record<string, boolean | null>; errors: string[]; display_hash: string | null }> {
  const checks: Record<string, boolean | null> = {
    render_deterministic: false,
    attestation_present: false,
    display_hash_match: false,
    algorithm_set: null,
    legs_present: null,
    signer_key_pinned: null,
    proof_signed: null,
  };
  const errors: string[] = [];
  const fail = (msg: string) => { errors.push(msg); return { valid: false, checks, errors, display_hash: null }; };

  opts = opts && typeof opts === 'object' ? opts : {};
  if (!action || typeof action !== 'object') return fail('Missing canonical action');

  let rendered;
  try {
    rendered = renderAction(action);
  } catch (e: any) {
    return fail(`render failed: ${e?.message}`);
  }
  checks.render_deterministic = true;

  const required = opts.requireDisplayAttestation === true;
  if (!attestation) {
    if (required) return fail('missing_required_attestation');
    return { valid: true, checks, errors, display_hash: rendered.display_hash };
  }
  checks.attestation_present = true;

  if (attestation['@version'] !== DISPLAY_ATTESTATION_V2_VERSION) {
    return fail('invalid_attestation_version');
  }

  // WYSIWYS anchor: the attested rendering MUST be the deterministic function of
  // the signed action, identical to v1.
  if (hexOf(attestation.action_hash) !== hexOf(rendered.action_hash)) {
    return fail('render_mismatch: attested action_hash != frozen action hash');
  }
  if (hexOf(attestation.display_hash) !== hexOf(rendered.display_hash)) {
    return fail('render_mismatch: attested display_hash != re-derived rendering');
  }
  checks.display_hash_match = true;

  const proof = attestation.proof;
  if (!proof) {
    if (opts.requireSignedAttestation === true) {
      checks.proof_signed = false;
      return fail('missing_required_signature');
    }
    return { valid: true, checks, errors, display_hash: rendered.display_hash };
  }

  checks.algorithm_set = true;
  checks.legs_present = true;
  checks.signer_key_pinned = true;
  checks.proof_signed = true;
  const note = (key: string, msg: string) => { checks[key] = false; errors.push(msg); };

  if (proof.profile !== DISPLAY_ATTESTATION_V2_VERSION || typeof proof.signer_key_id !== 'string') {
    note('proof_signed', 'proof must use the exact EP-DISPLAY-ATTESTATION-v2 proof schema');
  }
  if (!displayAlgorithmSetMatches(proof.required_algorithms)) {
    note('algorithm_set',
      `proof.required_algorithms must be exactly ${JSON.stringify([...DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
  }

  const signatures = Array.isArray(proof.signatures) ? proof.signatures as AgileSignature[] : null;
  if (!signatures || signatures.length === 0) {
    note('legs_present', 'proof.signatures must carry one signature per required algorithm');
  } else {
    const presented = new Set<string>();
    let malformed = false;
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        note('legs_present', 'each proof.signatures entry must be { alg, sig, key_id? }');
        malformed = true;
        break;
      }
      if (presented.has(s.alg)) {
        note('legs_present', `duplicate signature for algorithm "${s.alg}"`);
        malformed = true;
        break;
      }
      presented.add(s.alg);
    }
    if (!malformed) {
      for (const alg of DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) note('legs_present', `missing required ${alg} signature (leg stripped)`);
      }
      for (const alg of presented) {
        if (!(DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
          note('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
        }
      }
    }
  }

  // Signer pinned out of band, BOTH halves. Never fall back to the proof's own
  // self-asserted key material.
  const pin = typeof proof.signer_key_id === 'string' ? opts.displaySignerKeys?.[proof.signer_key_id] : undefined;
  const presentedEd = typeof proof.public_key === 'string' ? proof.public_key : '';
  const presentedPq = typeof proof.pq_public_key === 'string' ? proof.pq_public_key : '';
  const derivedPqKeyId = presentedPq
    && Buffer.from(presentedPq, 'base64url').length === ML_DSA_65_PUBLIC_KEY_BYTES
    && Buffer.from(presentedPq, 'base64url').toString('base64url') === presentedPq
    ? displayPqKeyIdOf(presentedPq) : '';
  if (!pin || !pin.public_key || !pin.pq_public_key) {
    note('signer_key_pinned', `signer "${proof.signer_key_id}" is not pinned with both halves (unpinned)`);
  } else {
    if (pin.public_key !== presentedEd) note('signer_key_pinned', 'presented Ed25519 signer key != pinned key (key substitution)');
    if (pin.pq_public_key !== presentedPq) note('signer_key_pinned', 'presented ML-DSA-65 signer key != pinned key (key substitution)');
  }
  if (!derivedPqKeyId || proof.pq_key_id !== derivedPqKeyId
    || !DISPLAY_SIGNER_PQ_KEY_ID.test(typeof proof.pq_key_id === 'string' ? proof.pq_key_id : '')) {
    note('signer_key_pinned', 'pq_key_id must be the full digest of the presented ML-DSA-65 key');
  }

  const recomputedBytes = displayAttestationV2SignedPayload({
    render_profile: rendered.render_profile,
    action_hash: rendered.action_hash,
    display_hash: rendered.display_hash,
  }, DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS);
  const verificationKeys: AgileVerificationKey[] = [
    { alg: 'Ed25519', public_key: pin?.public_key ?? '', key_id: typeof proof.signer_key_id === 'string' ? proof.signer_key_id : undefined },
    { alg: 'ML-DSA-65', public_key: pin?.pq_public_key ?? '', key_id: derivedPqKeyId || undefined },
  ];
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(recomputedBytes),
      signatures ?? [],
      verificationKeys,
      {
        ...displayAgilityPassthrough(opts),
        policy: 'hybrid_all',
        requiredAlgorithms: [...DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS],
      },
    );
  } catch {
    setResult = null;
  }
  if (setResult?.verified !== true) {
    note('proof_signed', `signer signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${String(setResult?.reason ?? 'signature_set_unverified')})`);
  }

  const valid = Object.values(checks).every((c) => c !== false);
  return { valid, checks, errors, display_hash: valid ? rendered.display_hash : null };
}

function displayAgilityPassthrough(opts: VerifyDisplayAttestationV2Options): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}
