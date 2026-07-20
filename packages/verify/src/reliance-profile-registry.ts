// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-PROFILE-REGISTRY-v1 — signed, pinnable regulated reliance profiles.
 *
 * The business layer above the kernel is not another verifier. It is a REGISTRY
 * of certified reliance profiles: EMILIA (or any registrar) publishes and signs
 * a named EP-RELIANCE-PROFILE-v1 for a regulated flow — NCPDP specialty prior
 * auth, CMS prior auth, Medicaid, specialty pharmacy, government benefits,
 * procurement, agentic payments — so a relying party pins ONE registry key and a
 * profile_id + epoch instead of hand-authoring the rule. The relying party then
 * feeds the resolved profile to evaluateReliance and computes the SAME reliance
 * verdict over the SAME automated action as every other party pinning that
 * profile. That is the clearinghouse: which evidence is admissible before a
 * payer, PBM, pharmacy, agency, bank, or model platform acts.
 *
 * VERIFIED ≠ ACCEPTED, kept separate as everywhere else: `verified` = the entry's
 * Ed25519 signature, entry digest, and inner profile hash all hold; `accepted` =
 * verified AND the registrar key was pinned out of band by the relying party AND
 * any profile_id / epoch freshness pins are satisfied. A signed entry under an
 * unpinned key is identified, not trusted. FAIL-CLOSED throughout.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../index.js';
import { validateRelianceProfile, RELIANCE_PROFILE_VERSION } from './reliance.js';

type Obj = Record<string, any>;

interface RegistryOptions {
  pinnedRegistryKeys?: Obj[];
  expectProfileId?: string;
  expectMinEpoch?: number;
}

export const PROFILE_REGISTRY_VERSION = 'EP-RELIANCE-PROFILE-REGISTRY-v1';
export const PROFILE_REGISTRY_DOMAIN = 'EP-RELIANCE-PROFILE-REGISTRY-v1\0';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const sha256hex = (bytes: Uint8Array): string => crypto.createHash('sha256').update(bytes).digest('hex');
const keyIdFor = (pub: string): string => `ep:reliance-registry-key:sha256:${sha256hex(Buffer.from(pub, 'base64url')).slice(0, 16)}`;

function profileHash(profile: Obj): string {
  return `sha256:${sha256hex(Buffer.from(canonicalize(profile), 'utf8'))}`;
}
function entrySigningBytes(unsignedEntry: Obj): Buffer {
  return Buffer.from(PROFILE_REGISTRY_DOMAIN + canonicalize(unsignedEntry), 'utf8');
}
function unsigned(entry: Obj): Obj {
  const { signature: _sig, ...body } = entry;
  return body;
}

/** Digest of the signed entry body, excluding the signature envelope. */
export function profileRegistryEntryDigest(entry: Obj): string {
  return `sha256:${sha256hex(entrySigningBytes(unsigned(entry)))}`;
}

/**
 * Sign a reliance profile into a registry entry. `privateKey` is a Node
 * Ed25519 KeyObject held by the REGISTRAR (never in this repo).
 * @returns {object} the signed EP-RELIANCE-PROFILE-REGISTRY-v1 entry
 */
export function signRelianceProfileEntry({ registry_id, profile_id, profile, registry_epoch, issued_at }: Obj, privateKey: any): Obj {
  const v = validateRelianceProfile(profile);
  if (!v.ok) throw new Error(`invalid inner profile: ${v.issues.join('; ')}`);
  if (typeof registry_id !== 'string' || !registry_id) throw new Error('registry_id is required');
  if (typeof profile_id !== 'string' || !profile_id) throw new Error('profile_id is required');
  // Store an immutable copy so the signed entry cannot be mutated through the
  // caller's reference to `profile` after signing (the signature/hash would then
  // silently disagree with the body a verifier canonicalizes).
  const frozenProfile = structuredClone(profile);
  const body = {
    '@type': PROFILE_REGISTRY_VERSION,
    registry_id,
    profile_id,
    registry_epoch: Number.isSafeInteger(registry_epoch) ? registry_epoch : 1,
    profile: frozenProfile,
    profile_hash: profileHash(frozenProfile),
    issued_at: issued_at ?? null,
  };
  const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  const entry_digest = `sha256:${sha256hex(entrySigningBytes(body))}`;
  const signature_b64u = crypto.sign(null, entrySigningBytes(body), privateKey).toString('base64url');
  return { ...body, signature: { algorithm: 'Ed25519', public_key: publicKey, key_id: keyIdFor(publicKey), entry_digest, signature_b64u } };
}

/**
 * Verify a registry entry against pinned registrar keys.
 * @param {object} entry
 * @param {object} [opts]
 * @param {Array<{registry_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectProfileId]
 * @param {number} [opts.expectMinEpoch]
 * @returns {{verified:boolean, accepted:boolean, profile:(object|null), checks:object, reason?:string, entry_digest?:string, key_id?:string, registry_id?:string, profile_id?:string, registry_epoch?:number}}
 */
export function verifyRelianceProfileEntry(entry: Obj, opts: RegistryOptions = {}) {
  const checks: Record<string, boolean> = { version: false, signature: false, entry_digest: false, profile_hash: false, pinned_registry_key: false, profile_id: true, epoch_fresh: true, profile_wellformed: false };
  const fail = (reason: string, extra: Obj = {}) => ({ verified: false, accepted: false, profile: null, checks: { ...checks }, reason, ...extra });

  if (!entry || typeof entry !== 'object' || entry['@type'] !== PROFILE_REGISTRY_VERSION) return fail('unsupported_version');
  checks.version = true;

  const sig = entry.signature;
  if (typeof entry.registry_id !== 'string' || !entry.registry_id) return fail('registry_id_missing_or_malformed');
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string' || typeof sig.signature_b64u !== 'string') return fail('signature_missing_or_malformed');
  if (typeof sig.entry_digest !== 'string' || !SHA256_RE.test(sig.entry_digest)) return fail('entry_digest_malformed');

  let digest;
  try { digest = profileRegistryEntryDigest(entry); } catch { return fail('entry_uncanonicalizable'); }
  if (digest !== sig.entry_digest) return fail('entry_digest_mismatch', { entry_digest: digest });
  checks.entry_digest = true;

  // The inner profile must be well-formed AND bound by profile_hash (a lying
  // profile_hash cannot substitute a different profile under the same signature).
  const pv = validateRelianceProfile(entry.profile);
  checks.profile_wellformed = pv.ok;
  if (!pv.ok) return fail('inner_profile_invalid', { entry_digest: digest });
  if (entry.profile_hash !== profileHash(entry.profile)) return fail('profile_hash_mismatch', { entry_digest: digest });
  checks.profile_hash = true;

  if (typeof opts.expectProfileId === 'string' && entry.profile_id !== opts.expectProfileId) {
    checks.profile_id = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'profile_id_mismatch', entry_digest: digest };
  }
  const minEpoch = opts.expectMinEpoch;
  if (typeof minEpoch === 'number' && Number.isSafeInteger(minEpoch) && !(Number.isSafeInteger(entry.registry_epoch) && entry.registry_epoch >= minEpoch)) {
    checks.epoch_fresh = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'stale_registry', entry_digest: digest };
  }

  // Signature must verify (regardless of pinning) so `verified` is honest.
  let sigOk = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    sigOk = crypto.verify(null, entrySigningBytes(unsigned(entry)), publicKey, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch { sigOk = false; }
  if (!sigOk) return { verified: false, accepted: false, profile: null, checks, reason: 'signature_invalid', entry_digest: digest };
  checks.signature = true;

  const derivedKeyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== derivedKeyId) {
    return { verified: false, accepted: false, profile: null, checks, reason: 'key_id_mismatch', entry_digest: digest };
  }
  const pinned = Array.isArray(opts.pinnedRegistryKeys) ? opts.pinnedRegistryKeys : [];
  const keyMatched = pinned.filter((k: Obj) => k?.public_key === sig.public_key
    && (k.key_id === undefined || k.key_id === derivedKeyId));
  const pin = keyMatched.find((k: Obj) => typeof k.registry_id === 'string' && k.registry_id === entry.registry_id);
  if (!pin) {
    // VERIFIED (signature holds) but NOT ACCEPTED (registrar key not pinned).
    return {
      verified: true,
      accepted: false,
      profile: entry.profile,
      checks,
      reason: keyMatched.length ? 'pin_missing_or_mismatched_registry_id' : 'registry_key_not_pinned',
      entry_digest: digest,
      key_id: derivedKeyId,
      registry_id: entry.registry_id,
    };
  }
  checks.pinned_registry_key = true;

  return { verified: true, accepted: true, profile: entry.profile, checks, key_id: derivedKeyId, registry_id: entry.registry_id, profile_id: entry.profile_id, registry_epoch: entry.registry_epoch, entry_digest: digest };
}

export { RELIANCE_PROFILE_VERSION };
