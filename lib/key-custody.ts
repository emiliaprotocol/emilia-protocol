// SPDX-License-Identifier: Apache-2.0
//
// Key custody abstraction for high-assurance deployments.
//
// The important government posture is not "EP has a private key in env." It is:
// signing is behind a custody boundary (KMS/HSM), the key id is auditable, and
// production refuses dev-local signing. This module gives callers that seam
// without binding the protocol to a specific cloud vendor.

import crypto from 'node:crypto';
import { getKeyCustodyConfig } from './env.js';

const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Shape of the key-custody configuration consumed throughout this module. */
export interface KeyCustodyConfig {
  mode?: string;
  keyId?: string | null;
  fipsRequired?: boolean;
  govStrict?: boolean;
  isProduction?: boolean;
}

export type KeyCustodyCheckResult =
  | { ok: true; mode: string; keyId?: string }
  | { ok: false; reason: string; detail: string };

/**
 * A registered signer with the minimal surface the issuer (lib/commit.js)
 * relies on. `custody` and `publicKeySpkiB64u` are optional because callers
 * of registerCustodySigner() may supply a minimal ad-hoc object with just
 * { keyId, sign } — see registerCustodySigner's runtime validation below.
 */
export interface CustodySigner {
  keyId: string;
  custody?: string;
  publicKeySpkiB64u?: string | (() => string | null | Promise<string | null>);
  sign(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<string>;
}

export function assertProductionKeyCustody(config: KeyCustodyConfig = getKeyCustodyConfig()): KeyCustodyCheckResult {
  const mode = config.mode || 'local-dev';
  const govStrict = config.govStrict || config.isProduction;
  if (!govStrict) return { ok: true, mode };
  if (mode === 'local-dev' || mode === 'env') {
    return {
      ok: false,
      reason: 'local_key_custody_forbidden',
      detail: 'Production/government mode requires EP_KEY_CUSTODY_MODE=kms or hsm; local/env private keys are dev-only.',
    };
  }
  if (!['kms', 'hsm'].includes(mode)) {
    return { ok: false, reason: 'unknown_key_custody_mode', detail: `Unsupported key custody mode "${mode}".` };
  }
  if (!config.keyId) {
    return { ok: false, reason: 'missing_custody_key_id', detail: 'EP_KMS_KEY_ID or EP_HSM_KEY_ID is required.' };
  }
  return { ok: true, mode, keyId: config.keyId };
}

export function privateKeyFromSeedB64(seedB64?: string | null): crypto.KeyObject {
  const seed = Buffer.from(String(seedB64 || ''), 'base64');
  if (seed.length !== 32) {
    throw new Error('Ed25519 seed must be a base64-encoded 32-byte value');
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

export function createLocalDevSigner({ keyId = 'local-dev#1', seedB64, privateKey }: {
  keyId?: string;
  seedB64?: string;
  privateKey?: crypto.KeyObject;
} = {}): CustodySigner {
  const key = privateKey || privateKeyFromSeedB64(seedB64);
  const publicKey = crypto.createPublicKey(key as any);
  return {
    keyId,
    custody: 'local-dev',
    publicKeySpkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    async sign(bytes: Uint8Array | Buffer): Promise<string> {
      return crypto.sign(null, Buffer.from(bytes), key).toString('base64url');
    },
  };
}

export function createExternalCustodySigner({ mode, keyId, sign, getPublicKey }: {
  mode: string;
  keyId: string;
  sign: (bytes: Buffer, context?: Record<string, unknown>) => Promise<string>;
  getPublicKey?: () => string | null | Promise<string | null>;
}): CustodySigner {
  if (!['kms', 'hsm'].includes(mode)) {
    throw new Error('external custody signer mode must be "kms" or "hsm"');
  }
  if (!keyId || typeof keyId !== 'string') {
    throw new Error('external custody signer requires a stable keyId');
  }
  if (typeof sign !== 'function') {
    throw new Error('external custody signer requires a sign(bytes) function');
  }
  return {
    keyId,
    custody: mode,
    async publicKeySpkiB64u(): Promise<string | null> {
      if (typeof getPublicKey !== 'function') return null;
      return getPublicKey();
    },
    async sign(bytes: Uint8Array | Buffer, context: Record<string, unknown> = {}): Promise<string> {
      return sign(Buffer.from(bytes), { keyId, mode, ...context });
    },
  };
}

// --- Dual-signer custody (EP-CUSTODY-HYBRID-v1) ------------------------------
//
// WHY THIS EXISTS. CustodySigner above is single-key by construction: one
// keyId, one sign(bytes) -> one base64url signature, one publicKeySpkiB64u.
// That is exactly right for the Ed25519 artifacts EP issues today, and it is
// the shape every production issuance path already calls. Adding a
// post-quantum leg must NOT change it. So the hybrid signer WRAPS a
// CustodySigner instead of replacing it: a HybridCustodySigner IS a
// CustodySigner (same keyId, same custody, same publicKeySpkiB64u, same
// sign() returning the same Ed25519 bytes), plus a second registered signer
// and a signSet() that aware call sites opt into. registerCustodySigner() and
// resolveIssuerSigner() take it unchanged, and a call site that has never
// heard of hybrid signing keeps getting byte-identical Ed25519 signatures.
//
// HONEST CUSTODY BOUNDARY -- READ THIS. The Ed25519 note at the top of
// lib/custody-signers.ts records the realistic external-custody options for the
// classical leg. The ML-DSA-65 leg now has two explicit paths:
//
//   - softwareMldsaSigner() keeps the secret in process memory and uses the
//     bundled pure-JS backend. It is not independently audited or FIPS validated.
//   - EP-PQ-CUSTODY-EXTERNAL-v1 accepts an operator-supplied remote signer and
//     verifies its output before use. EP-PQ-CUSTODY-AWS-KMS-v1 implements that
//     contract for AWS KMS against documented API shapes.
//
// No live AWS signing call or production key is evidence in this repository.
// The external seam also cannot observe a hardware boundary, so its custody
// label is an operator declaration with verified_by_code=false. AWS KMS improves
// key custody only: CMVP certificate 4884 does not list ML-DSA among its approved
// algorithms, so the adapter does not improve the ML-DSA FIPS claim.
//
// That asymmetry is a PROPERTY OF THE DEPLOYMENT, not a detail to hide, so
// PqCustodySigner carries an explicit `custody` field. 'software' is the safe
// default; non-software labels must come from an operator-owned external signer
// integration whose declaration is recorded rather than inferred. A gov-strict
// deployment still requires an accepted kms/hsm declaration for both legs.
//
// ANTI-STRIPPING IS NOT THIS MODULE'S JOB. signSet() returns one signature
// per required algorithm over the SAME caller-supplied bytes. Committing the
// required-algorithm SET into those bytes (so a stripped leg cannot be
// covered up by narrowing the set) belongs to the artifact profile that calls
// this, exactly as EP-RECEIPT-HYBRID-v1 does in
// packages/issue/src/hybrid-issuance.ts. See lib/commit-hybrid.ts for the
// EP-COMMIT-HYBRID-v1 instance of that discipline.

/** Profile id for a dual-signer custody configuration. */
export const HYBRID_CUSTODY_PROFILE = 'EP-CUSTODY-HYBRID-v1';

/** The fixed v1 algorithm set, in canonical order. Matches EP-SIG-AGILITY-v1. */
export const HYBRID_CUSTODY_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);
export type HybridCustodyAlgorithm = (typeof HYBRID_CUSTODY_ALGORITHMS)[number];

/** FIPS 204 ML-DSA-65 fixed sizes (bytes); mirrored from the agility module. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SECRET_KEY_BYTES = 4032;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;

/** One entry of a signature set, shaped exactly like EP-SIG-AGILITY-v1's AgileSignature. */
export interface CustodySignatureSetEntry {
  alg: HybridCustodyAlgorithm;
  /** base64url */
  sig: string;
  key_id?: string;
}

/**
 * The post-quantum leg of a dual-signer custody configuration.
 *
 * Deliberately NOT a CustodySigner: a CustodySigner's publicKeySpkiB64u is an
 * SPKI DER key and ML-DSA-65 has no SPKI encoding EP consumes, so its public
 * half is raw bytes (base64url of 1952 bytes), matching what
 * verifyAgileSignature expects. Keeping the types distinct stops an ML-DSA
 * signer from being registered where an Ed25519 signer is meant.
 */
export interface PqCustodySigner {
  keyId: string;
  algorithm: 'ML-DSA-65';
  /**
   * How the secret key is held. 'software' is the conservative default;
   * anything else is an explicit operator declaration about its deployment.
   */
  custody: string;
  /** base64url of the raw 1952-byte ML-DSA-65 public key, or a resolver for it. */
  publicKeyRawB64u?: string | (() => string | null | Promise<string | null>);
  /** Returns a base64url ML-DSA-65 signature over `bytes`. */
  sign(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<string>;
}

/**
 * A CustodySigner carrying a second, post-quantum signer alongside it.
 * ADDITIVE by construction: every CustodySigner member is present and behaves
 * identically to the wrapped classical signer.
 */
export interface HybridCustodySigner extends CustodySigner {
  hybrid: {
    profile: string;
    requiredAlgorithms: readonly HybridCustodyAlgorithm[];
    /** The Ed25519 leg this signer wraps; sign() delegates to it verbatim. */
    classical: CustodySigner;
    /** The ML-DSA-65 leg and its declared custody boundary. */
    pq: PqCustodySigner;
  };
  /**
   * Sign the SAME bytes under every required algorithm, in canonical order.
   * The caller is responsible for having committed the required-algorithm set
   * into those bytes.
   */
  signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<CustodySignatureSetEntry[]>;
}

/** Public halves of both legs, in the encodings EP-SIG-AGILITY-v1 verifies under. */
export interface HybridCustodyPublicKeys {
  ed25519KeyId: string;
  /** base64url SPKI DER. */
  ed25519PublicKeySpkiB64u: string | null;
  mldsaKeyId: string;
  /** base64url raw 1952 bytes. */
  mldsaPublicKeyRawB64u: string | null;
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Wrap an ML-DSA-65 sign callback as the PQ leg of a hybrid custody signer.
 * Mirrors createExternalCustodySigner: shape validation only, no crypto here.
 *
 * @throws when required signer metadata is absent. The default 'software' is
 *   conservative; pass a different label only as an operator attestation about
 *   custody you actually operate, preferably through EP-PQ-CUSTODY-EXTERNAL-v1.
 */
export function createPqCustodySigner({ keyId, sign, getPublicKey, custody = 'software' }: {
  keyId: string;
  sign: (bytes: Buffer, context?: Record<string, unknown>) => Promise<string>;
  getPublicKey?: () => string | null | Promise<string | null>;
  custody?: string;
}): PqCustodySigner {
  if (!keyId || typeof keyId !== 'string') {
    throw new Error('createPqCustodySigner requires a stable keyId');
  }
  if (typeof sign !== 'function') {
    throw new Error('createPqCustodySigner requires a sign(bytes) function');
  }
  if (!custody || typeof custody !== 'string') {
    throw new Error('createPqCustodySigner requires a non-empty custody label; "software" is the conservative default and external labels are operator declarations');
  }
  return {
    keyId,
    algorithm: 'ML-DSA-65',
    custody,
    async publicKeyRawB64u(): Promise<string | null> {
      if (typeof getPublicKey !== 'function') return null;
      return getPublicKey();
    },
    async sign(bytes: Uint8Array | Buffer, context: Record<string, unknown> = {}): Promise<string> {
      const sig = await sign(Buffer.from(bytes), { keyId, algorithm: 'ML-DSA-65', custody, ...context });
      if (typeof sig !== 'string' || !B64URL_RE.test(sig)) {
        throw new Error('ML-DSA-65 custody signer must return a base64url signature string');
      }
      if (Buffer.from(sig, 'base64url').length !== ML_DSA_65_SIGNATURE_BYTES) {
        throw new Error(`ML-DSA-65 custody signer returned a signature that is not ${ML_DSA_65_SIGNATURE_BYTES} bytes`);
      }
      return sig;
    },
  };
}

/**
 * Compose an existing CustodySigner (the Ed25519 leg, which may be a KMS/HSM
 * signer) with a PqCustodySigner into one registrable signer.
 *
 * The returned object satisfies CustodySigner exactly, so
 * registerCustodySigner(), resolveIssuerSigner(), and every existing call site
 * keep working with no knowledge of the PQ leg. Aware call sites detect it
 * with isHybridCustodySigner() and call signSet().
 */
export function createHybridCustodySigner({ classical, pq }: {
  classical: CustodySigner;
  pq: PqCustodySigner;
}): HybridCustodySigner {
  if (!classical || typeof classical.sign !== 'function' || !classical.keyId) {
    throw new Error('createHybridCustodySigner requires a classical signer with { keyId, async sign(bytes) }');
  }
  if (!pq || typeof pq.sign !== 'function' || !pq.keyId || pq.algorithm !== 'ML-DSA-65') {
    throw new Error('createHybridCustodySigner requires a PQ signer from createPqCustodySigner()');
  }
  if (classical.keyId === pq.keyId) {
    // Two algorithms under one key id makes the signature set unattributable.
    throw new Error('createHybridCustodySigner requires distinct keyIds for the classical and PQ legs');
  }

  const publicKeySpkiB64u = typeof classical.publicKeySpkiB64u === 'function'
    ? () => (classical.publicKeySpkiB64u as () => string | null | Promise<string | null>).call(classical)
    : classical.publicKeySpkiB64u;

  const signer: HybridCustodySigner = {
    keyId: classical.keyId,
    custody: classical.custody,
    publicKeySpkiB64u,
    // Byte-identical to the wrapped signer: unaware call sites see no change.
    sign: (bytes, context) => classical.sign(bytes, context),
    hybrid: {
      profile: HYBRID_CUSTODY_PROFILE,
      requiredAlgorithms: HYBRID_CUSTODY_ALGORITHMS,
      classical,
      pq,
    },
    async signSet(bytes, context = {}) {
      const out: CustodySignatureSetEntry[] = [];
      for (const alg of HYBRID_CUSTODY_ALGORITHMS) {
        if (alg === 'Ed25519') {
          out.push({ alg, sig: await classical.sign(bytes, context), key_id: classical.keyId });
        } else {
          out.push({ alg, sig: await pq.sign(bytes, context), key_id: pq.keyId });
        }
      }
      return out;
    },
  };
  return signer;
}

/** Is this signer a dual-signer (hybrid) custody signer? */
export function isHybridCustodySigner(signer: CustodySigner | null | undefined): signer is HybridCustodySigner {
  const s = signer as HybridCustodySigner | null | undefined;
  return !!s
    && typeof s.signSet === 'function'
    && !!s.hybrid
    && s.hybrid.profile === HYBRID_CUSTODY_PROFILE
    && !!s.hybrid.pq
    && s.hybrid.pq.algorithm === 'ML-DSA-65';
}

/**
 * Resolve both public halves so a relying party can pin them. Returns nulls
 * rather than throwing when a leg exposes no public key: an issuer that cannot
 * publish its verification key is a configuration problem the CALLER reports
 * with its own artifact vocabulary (lib/commit.ts already refuses issuance in
 * that case), not a throw from the custody seam.
 */
export async function resolveHybridPublicKeys(signer: HybridCustodySigner): Promise<HybridCustodyPublicKeys> {
  const ed = signer.publicKeySpkiB64u;
  const edValue = typeof ed === 'function' ? await ed() : ed ?? null;
  const pqPub = signer.hybrid.pq.publicKeyRawB64u;
  const pqValue = typeof pqPub === 'function' ? await pqPub() : pqPub ?? null;
  return {
    ed25519KeyId: signer.keyId,
    ed25519PublicKeySpkiB64u: edValue ?? null,
    mldsaKeyId: signer.hybrid.pq.keyId,
    mldsaPublicKeyRawB64u: pqValue ?? null,
  };
}

export function requireConfiguredCustody(config: KeyCustodyConfig = getKeyCustodyConfig()): Extract<KeyCustodyCheckResult, { ok: true }> {
  const result = assertProductionKeyCustody(config);
  if (!result.ok) {
    const err: Error & { code?: string } = new Error(result.detail);
    err.code = result.reason;
    throw err;
  }
  return result;
}

// ── Issuer signer resolution (KMS/HSM custody, wired into signing) ────────────
//
// An operator registers their KMS/HSM signer ONCE at boot (an AWS KMS, GCP KMS,
// or PKCS#11/HSM `sign(bytes)` callback wrapped via createExternalCustodySigner).
// resolveIssuerSigner() then returns that signer when custody mode is kms/hsm,
// throws if kms/hsm is configured but no signer was registered (fail closed),
// and returns null for local-dev/env to mean "use the built-in env-key path"
// (which itself fails closed under gov-strict). This is the seam the issuer
// (lib/commit.js) calls so signing goes through the custody boundary without
// binding EP to any one cloud vendor.

let _registeredCustodySigner: CustodySigner | null = null;

/** Register the process-wide KMS/HSM custody signer (call once at boot). */
export function registerCustodySigner(signer: CustodySigner): CustodySigner {
  if (!signer || typeof signer.sign !== 'function' || !signer.keyId) {
    throw new Error('registerCustodySigner requires a signer with { keyId, async sign(bytes) } (see createExternalCustodySigner)');
  }
  _registeredCustodySigner = signer;
  return signer;
}

export function getRegisteredCustodySigner(): CustodySigner | null {
  return _registeredCustodySigner;
}

/** Test/ops hook: clear the registered signer. */
export function clearCustodySigner(): void {
  _registeredCustodySigner = null;
}

/**
 * Resolve the signer the issuer should use.
 * @returns {object|null} the custody signer for kms/hsm, or null to use the
 *   built-in env-key path (local-dev/env). Throws if kms/hsm is configured
 *   without a registered signer, or if local custody is forbidden (gov-strict).
 */
export function resolveIssuerSigner(config: KeyCustodyConfig = getKeyCustodyConfig()): CustodySigner | null {
  const mode = config.mode || 'local-dev';
  if (mode === 'kms' || mode === 'hsm') {
    requireConfiguredCustody(config); // throws on missing keyId / unknown mode
    if (!_registeredCustodySigner) {
      const err: Error & { code?: string } = new Error(
        `EP_KEY_CUSTODY_MODE=${mode} but no custody signer is registered. `
        + 'Register one at boot: registerCustodySigner(createExternalCustodySigner({ mode, keyId, sign, getPublicKey })) '
        + 'backed by your KMS/HSM. Refusing to fall back to a local key (fail closed).',
      );
      err.code = 'custody_signer_not_registered';
      throw err;
    }
    return _registeredCustodySigner;
  }
  // local-dev / env: use the built-in env-key signer (null). KMS/HSM is OPT-IN —
  // forcing it here would break the supported env-key production path
  // (EP_COMMIT_SIGNING_KEY), whose own production requirement is enforced by the
  // issuer. The gov-strict "no local keys" posture is surfaced by
  // assertProductionKeyCustody / gov:check, not by hard-failing issuance here.
  return null;
}

// --- Custody-resolved issuance posture ---------------------------------------
//
// WHY THIS EXISTS. Most hybrid profiles in this repository are opt-in. The
// receipt profile can resolve to dual issuance by default only when an accepted
// hybrid custody signer is registered. A deployment that does nothing still
// gets no post-quantum leg, and a receipt cannot be given one afterwards:
// re-attestation
// (EP-EVIDENCE-REATTESTATION-v1) can re-anchor an old receipt's integrity while
// the classical algorithm is still unbroken, but that is re-anchored evidence,
// not a signature the issuer made at the time. The fix is NOT a blanket flip.
// It is a posture resolved from CUSTODY, and this function is the custody half
// of it: may this deployment mint an ML-DSA-65 leg at all, and if not, under
// which named reason?
//
// THE REFUSAL THAT MATTERS IS pq_custody_not_permitted. A software-backed PQ
// signer does not satisfy kms/hsm custody. An external signer may declare kms or
// hsm custody, but this function records that declaration; it does not verify
// hardware confinement. A deployment under gov-strict (or production) still
// requires an accepted kms/hsm declaration, and a changed default must never
// quietly hand it a software-held PQ key. Below gov-strict the software leg is
// permitted.
//
// SCOPE. This decides CUSTODY only. It does not know the issuance-mode
// vocabulary (disabled/enabled/dual/required); packages/gate's
// hybrid-receipt-profile.ts maps this posture onto that vocabulary, so lib/ and
// packages/gate stay independent of one another. Nothing here is a security
// upgrade to any classical artifact: permitting a PQ leg means a second
// artifact can EXIST for the same action, not that the Ed25519 one got stronger.

/** Named reasons a custody posture refuses the post-quantum leg. */
export const HYBRID_CUSTODY_POSTURE_REASONS = Object.freeze({
  /** No dual-signer custody signer is registered, so there is no PQ leg to mint. */
  HYBRID_SIGNER_ABSENT: 'hybrid_signer_absent',
  /** The PQ leg is not behind a custody boundary this deployment accepts. */
  PQ_CUSTODY_NOT_PERMITTED: 'pq_custody_not_permitted',
  /** The deployment's own custody policy is not satisfied (see `detail`). */
  CUSTODY_POLICY_NOT_SATISFIED: 'custody_policy_not_satisfied',
});

/** Custody labels that satisfy a gov-strict deployment's boundary requirement. */
export const CUSTODY_BOUNDARY_LABELS = Object.freeze(['kms', 'hsm'] as const);

export interface HybridCustodyPosture {
  /** Is a dual-signer (hybrid) custody signer registered? */
  hybrid_signer_present: boolean;
  /** May this deployment mint the ML-DSA-65 leg? */
  pq_leg_permitted: boolean;
  /** The PQ leg's own custody label ('software' today), or null when absent. */
  pq_custody: string | null;
  /** The classical leg's custody label, or null when unknown. */
  classical_custody: string | null;
  /** Is this deployment gov-strict (EP_GOV_STRICT) or production? */
  gov_strict: boolean;
  /** Named reason, non-null EXACTLY when pq_leg_permitted is false. */
  reason: string | null;
  /** Which specific condition produced the reason; null when permitted. */
  detail: string | null;
}

function boundaryLabel(custody: string | null | undefined): boolean {
  return typeof custody === 'string' && (CUSTODY_BOUNDARY_LABELS as readonly string[]).includes(custody);
}

/**
 * Describe whether this deployment's custody permits a post-quantum leg.
 *
 * @param signer  the signer to assess. Omit to read the process-wide registered
 *   signer; pass null explicitly to assess "no signer registered".
 * @param config  the custody configuration; defaults to the environment's.
 *
 * Never throws: an unregistered, malformed, or non-hybrid signer is a named
 * refusal, because a caller resolving a DEFAULT must get an answer rather than
 * an exception it would be tempted to catch and treat as permission.
 */
export function describeHybridCustodyPosture({ signer, config }: {
  signer?: CustodySigner | null;
  config?: KeyCustodyConfig;
} = {}): HybridCustodyPosture {
  const resolved = signer === undefined ? getRegisteredCustodySigner() : signer;
  const cfg = config ?? getKeyCustodyConfig();
  const govStrict = !!(cfg.govStrict || cfg.isProduction);

  if (!isHybridCustodySigner(resolved)) {
    return Object.freeze({
      hybrid_signer_present: false,
      pq_leg_permitted: false,
      pq_custody: null,
      classical_custody: resolved?.custody ?? null,
      gov_strict: govStrict,
      reason: HYBRID_CUSTODY_POSTURE_REASONS.HYBRID_SIGNER_ABSENT,
      detail: null,
    });
  }

  const pqCustody = resolved.hybrid.pq.custody ?? null;
  const classicalCustody = resolved.hybrid.classical.custody ?? resolved.custody ?? null;
  const base = {
    hybrid_signer_present: true,
    pq_custody: pqCustody,
    classical_custody: classicalCustody,
    gov_strict: govStrict,
  };

  // Below gov-strict, a software-held PQ leg remains a permitted arrangement.
  if (!govStrict) {
    return Object.freeze({ ...base, pq_leg_permitted: true, reason: null, detail: null });
  }

  // Gov-strict. The deployment's declared custody policy must hold first: a PQ
  // leg cannot rescue a classical leg that is not behind the boundary.
  const declared = assertProductionKeyCustody(cfg);
  if (!declared.ok) {
    return Object.freeze({
      ...base,
      pq_leg_permitted: false,
      reason: HYBRID_CUSTODY_POSTURE_REASONS.CUSTODY_POLICY_NOT_SATISFIED,
      detail: declared.reason,
    });
  }
  // And the registered classical signer must actually be the boundary the
  // config claims. This can only refuse more than the config check, never less.
  if (!boundaryLabel(classicalCustody)) {
    return Object.freeze({
      ...base,
      pq_leg_permitted: false,
      reason: HYBRID_CUSTODY_POSTURE_REASONS.CUSTODY_POLICY_NOT_SATISFIED,
      detail: `classical_leg_custody:${classicalCustody ?? 'unknown'}`,
    });
  }
  // The case this whole function exists for. 'software' is the only honest
  // value a PQ leg carries today, and gov-strict does not accept it.
  if (!boundaryLabel(pqCustody)) {
    return Object.freeze({
      ...base,
      pq_leg_permitted: false,
      reason: HYBRID_CUSTODY_POSTURE_REASONS.PQ_CUSTODY_NOT_PERMITTED,
      detail: `pq_leg_custody:${pqCustody ?? 'unknown'}`,
    });
  }
  return Object.freeze({ ...base, pq_leg_permitted: true, reason: null, detail: null });
}
