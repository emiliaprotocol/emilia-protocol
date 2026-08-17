// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RECEIPT-HYBRID-v1 -- the Gate-side deployment profile for hybrid
 * classical + post-quantum authorization receipts.
 *
 * WHAT THIS IS. packages/issue/src/hybrid-issuance.ts can MINT a receipt
 * carrying both an Ed25519 and an ML-DSA-65 (FIPS 204) signature over one set
 * of canonical bytes, and can verify one. This module is the operator-facing
 * switch that decides whether a given Gate deployment does that, and what it
 * accepts. It is deliberately a thin, fail-closed policy layer: it makes no
 * cryptographic decisions of its own and never reimplements a check.
 *
 * OPT-IN, AND OFF BY DEFAULT. `disabled` is the default mode. EP-RECEIPT-v1
 * remains the Gate's receipt format unless an operator turns this on. Nothing
 * in this repository ships with hybrid issuance enabled.
 *
 * THE THREE MODES
 *   disabled  (default) The Gate issues and accepts EP-RECEIPT-v1 only. A
 *             request for a hybrid receipt is REFUSED (hybrid_issuance_disabled)
 *             rather than quietly answered with a classical receipt, and a
 *             hybrid receipt presented for acceptance is REFUSED
 *             (hybrid_receipt_not_accepted) rather than partially checked. A
 *             deployment that cannot check an ML-DSA leg must not pretend it
 *             checked one.
 *   enabled   Hybrid is available per request. A request that asks for it gets
 *             a hybrid receipt; everything else stays EP-RECEIPT-v1. Both
 *             profiles are accepted on the verification side.
 *   required  Every receipt this Gate issues is hybrid, and only hybrid
 *             receipts are accepted. A classical-only request or a classical
 *             receipt presented for acceptance is REFUSED
 *             (hybrid_required). This is the mode with teeth: there is no
 *             configuration in which `required` silently produces or accepts a
 *             single-signature receipt.
 *
 * NO SILENT DOWNGRADE, ANYWHERE. Every path where hybrid could not be produced
 * or could not be checked (missing keys, missing ML-DSA backend, missing
 * issuance module) is a refusal with a named reason. There is no fallback edge
 * in this file that turns a hybrid intent into a classical artifact.
 *
 * HONEST BOUNDARIES
 *   - This is an opt-in profile, not the default receipt format, and it is not
 *     enabled in any deployment shipped from this repository.
 *   - The ML-DSA implementation reached through EP-SIG-AGILITY-v1 is
 *     @noble/post-quantum, a pure-JS FIPS 204 implementation that is not a
 *     FIPS-validated module. Turning this profile on is not a certification.
 *   - `action-control-manifest.ts` still pins `authorization_receipt.profile`
 *     to EP-RECEIPT-v1. A relying party who wants hybrid receipts named in a
 *     manifest needs that contract extended; this module does not change it.
 *
 * @license Apache-2.0
 */

type AnyRecord = Record<string, any>;

export const HYBRID_RECEIPT_PROFILE_ID = 'EP-RECEIPT-HYBRID-v1';
export const CLASSICAL_RECEIPT_PROFILE_ID = 'EP-RECEIPT-v1';

/** Config values for the `hybrid_issuance` flag, in increasing strictness. */
export const HYBRID_ISSUANCE_MODES = Object.freeze(['disabled', 'enabled', 'required'] as const);
export type HybridIssuanceMode = (typeof HYBRID_ISSUANCE_MODES)[number];

export const HYBRID_PROFILE_REASONS = Object.freeze({
  HYBRID_ISSUANCE_DISABLED: 'hybrid_issuance_disabled',
  HYBRID_REQUIRED: 'hybrid_required',
  HYBRID_RECEIPT_NOT_ACCEPTED: 'hybrid_receipt_not_accepted',
  HYBRID_KEYS_MISSING: 'hybrid_keys_missing',
  HYBRID_ISSUANCE_UNAVAILABLE: 'hybrid_issuance_unavailable',
  CLASSICAL_ISSUER_MISSING: 'classical_issuer_missing',
  CLASSICAL_VERIFIER_MISSING: 'classical_verifier_missing',
  UNKNOWN_RECEIPT_PROFILE: 'unknown_receipt_profile',
});

/**
 * The issuance/verification surface this module drives, structurally typed so
 * packages/gate gains no build-time dependency on packages/issue.
 */
export interface HybridIssuanceModule {
  createHybridReceipt: (args: AnyRecord) => Promise<AnyRecord>;
  verifyHybridReceipt: (doc: unknown, keys: unknown, options?: AnyRecord) => Promise<{
    verified: boolean;
    reason: string | null;
    failed_algorithm: string | null;
    checks: AnyRecord;
  }>;
}

export interface HybridReceiptProfile {
  profile_id: typeof HYBRID_RECEIPT_PROFILE_ID;
  mode: HybridIssuanceMode;
  /** True when the Gate may mint a hybrid receipt at all. */
  issues_hybrid: boolean;
  /** True when a hybrid receipt is the ONLY acceptable receipt. */
  requires_hybrid: boolean;
}

export interface HybridProfileRefusal {
  ok: false;
  reason: string;
  /** Present when the refusal came from the underlying verifier. */
  detail?: AnyRecord | null;
}

export type HybridIssueOutcome =
  | { ok: true; profile: typeof HYBRID_RECEIPT_PROFILE_ID; receipt: AnyRecord }
  | { ok: true; profile: typeof CLASSICAL_RECEIPT_PROFILE_ID; receipt: AnyRecord }
  | HybridProfileRefusal;

export type HybridAcceptOutcome =
  | { ok: true; profile: string; detail?: AnyRecord | null }
  | HybridProfileRefusal;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * Normalize a Gate deployment's `hybrid_issuance` setting into a frozen
 * profile. An unrecognized value THROWS: a misconfigured security flag must
 * stop a deployment, not be rounded down to the permissive default.
 *
 * Accepts either the flag itself or a config object carrying it:
 *   resolveHybridReceiptProfile('required')
 *   resolveHybridReceiptProfile({ hybrid_issuance: 'required' })
 *   resolveHybridReceiptProfile(undefined)            -> disabled
 */
export function resolveHybridReceiptProfile(config?: unknown): HybridReceiptProfile {
  let value: unknown = config;
  if (config && typeof config === 'object' && !Array.isArray(config)) {
    value = (config as AnyRecord).hybrid_issuance;
  }
  if (value === undefined || value === null) value = 'disabled';
  // `true`/`false` are accepted because operators reach for booleans on a flag
  // named like this one; they map onto the two unambiguous modes, never onto
  // `required` (which nobody would spell as `true`).
  if (value === true) value = 'enabled';
  if (value === false) value = 'disabled';
  if (typeof value !== 'string' || !(HYBRID_ISSUANCE_MODES as readonly string[]).includes(value)) {
    throw new Error(
      `hybrid_issuance must be one of ${HYBRID_ISSUANCE_MODES.join(', ')}; got ${JSON.stringify(value)}`,
    );
  }
  const mode = value as HybridIssuanceMode;
  return Object.freeze({
    profile_id: HYBRID_RECEIPT_PROFILE_ID,
    mode,
    issues_hybrid: mode !== 'disabled',
    requires_hybrid: mode === 'required',
  });
}

// ---------------------------------------------------------------------------
// Issuance module resolution (lazy, fail-closed)
// ---------------------------------------------------------------------------

// Non-literal specifiers on purpose, matching trust-program-adapters.ts:
// packages/gate must not gain a hard dependency on packages/issue, and neither
// tsc nor a bundler should try to resolve these.
const ISSUE_PACKAGE_SPECIFIER = '@emilia-protocol/issue/hybrid-issuance';
const ISSUE_LOCAL_SPECIFIER = '../../issue/dist/hybrid-issuance.js';

let cachedIssuance: HybridIssuanceModule | null | undefined;

function isIssuanceModule(value: unknown): value is HybridIssuanceModule {
  const m = value as Partial<HybridIssuanceModule> | null;
  return !!m && typeof m.createHybridReceipt === 'function' && typeof m.verifyHybridReceipt === 'function';
}

/** Resolve the hybrid issuance module. Returns null rather than throwing. */
export async function loadHybridIssuanceModule(): Promise<HybridIssuanceModule | null> {
  if (cachedIssuance !== undefined) return cachedIssuance;
  for (const specifier of [ISSUE_PACKAGE_SPECIFIER, ISSUE_LOCAL_SPECIFIER]) {
    try {
      const mod = await import(specifier);
      if (isIssuanceModule(mod)) {
        cachedIssuance = mod;
        return cachedIssuance;
      }
    } catch {
      // try the next specifier; absence is a refusal, never a crash
    }
  }
  cachedIssuance = null;
  return null;
}

async function resolveIssuance(injected?: HybridIssuanceModule | null): Promise<HybridIssuanceModule | null> {
  if (injected !== undefined && injected !== null) {
    return isIssuanceModule(injected) ? injected : null;
  }
  return loadHybridIssuanceModule();
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

export interface HybridIssueArgs {
  profile: HybridReceiptProfile;
  payload: AnyRecord;
  metadata?: AnyRecord;
  /** Hybrid signing keys (see signingKeysFromHybridBundle in @emilia-protocol/issue). */
  hybridKeys?: AnyRecord | null;
  /** Did this request ask for a hybrid receipt? Ignored in `required` mode. */
  requestHybrid?: boolean;
  /** The Gate's existing EP-RECEIPT-v1 issuance, called for classical requests. */
  issueClassical?: (args: { payload: AnyRecord; metadata?: AnyRecord }) => Promise<AnyRecord> | AnyRecord;
  /** Inject the issuance module instead of resolving it. */
  issuance?: HybridIssuanceModule | null;
  /** Passed through to EP-SIG-AGILITY-v1 (backend injection, deterministic mode). */
  agilityOptions?: AnyRecord;
}

/**
 * The wrapper a Gate's receipt-issuing call site adopts. One line at the call
 * site replaces a direct call to the classical issuer:
 *
 *   const outcome = await issueUnderHybridProfile({
 *     profile: resolveHybridReceiptProfile(config),
 *     payload, metadata, hybridKeys, requestHybrid,
 *     issueClassical: ({ payload, metadata }) => existingIssueReceipt(payload, metadata),
 *   });
 *   if (!outcome.ok) return refuse(outcome.reason);
 *
 * Every failure is a named refusal returned to the caller. This function never
 * substitutes a classical receipt for a hybrid one that could not be minted.
 */
export async function issueUnderHybridProfile(args: HybridIssueArgs): Promise<HybridIssueOutcome> {
  const { profile, payload, metadata, hybridKeys, requestHybrid, issueClassical, issuance, agilityOptions } = args;
  if (!profile || profile.profile_id !== HYBRID_RECEIPT_PROFILE_ID) {
    throw new TypeError('issueUnderHybridProfile: profile must come from resolveHybridReceiptProfile()');
  }
  const refuse = (reason: string): HybridProfileRefusal => ({ ok: false, reason });

  // An explicit ask for a classical receipt under `required` is refused, not
  // silently upgraded: the caller learns the deployment's rule instead of
  // receiving a different artifact than the one it asked for. An unspecified
  // request under `required` gets the hybrid receipt the mode demands.
  if (profile.requires_hybrid && requestHybrid === false) {
    return refuse(HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
  }
  const wantsHybrid = profile.requires_hybrid || requestHybrid === true;

  if (!wantsHybrid) {
    if (typeof issueClassical !== 'function') return refuse(HYBRID_PROFILE_REASONS.CLASSICAL_ISSUER_MISSING);
    const receipt = await issueClassical({ payload, ...(metadata !== undefined ? { metadata } : {}) });
    return { ok: true, profile: CLASSICAL_RECEIPT_PROFILE_ID, receipt };
  }

  // From here the caller asked for (or the deployment demands) a hybrid
  // receipt. Anything that stops us producing one is a refusal.
  if (!profile.issues_hybrid) return refuse(HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_DISABLED);
  if (!hybridKeys || typeof hybridKeys !== 'object') return refuse(HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);

  const module = await resolveIssuance(issuance);
  if (!module) return refuse(HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);

  let receipt: AnyRecord;
  try {
    receipt = await module.createHybridReceipt({
      payload,
      keys: hybridKeys,
      ...(metadata !== undefined ? { metadata } : {}),
      ...(agilityOptions ?? {}),
    });
  } catch (error) {
    // createHybridReceipt throws on issuer-side misuse and on an unavailable
    // ML-DSA backend. Either way the Gate refuses; it does not fall back.
    return { ok: false, reason: HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE, detail: { error: String((error as Error)?.message ?? error) } };
  }
  return { ok: true, profile: HYBRID_RECEIPT_PROFILE_ID, receipt };
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

export interface HybridAcceptArgs {
  profile: HybridReceiptProfile;
  receipt: unknown;
  /** Hybrid verification keys (see verificationKeysFromHybridBundle). */
  hybridKeys?: AnyRecord | null;
  /** The Gate's existing EP-RECEIPT-v1 verification, for classical receipts. */
  verifyClassical?: (receipt: unknown) => Promise<AnyRecord> | AnyRecord;
  issuance?: HybridIssuanceModule | null;
  agilityOptions?: AnyRecord;
}

/**
 * The acceptance-side companion. Routes by the presented `@version`, enforces
 * the deployment's mode, and delegates the cryptography.
 *
 * The two enforcement points that matter:
 *   - `required` refuses a classical receipt (hybrid_required). A Gate that
 *     demands post-quantum evidence must not accept evidence that has none.
 *   - `disabled` refuses a hybrid receipt (hybrid_receipt_not_accepted)
 *     instead of handing it to a classical verifier, which would either refuse
 *     on the version anyway or, worse, check one leg of two.
 */
export async function acceptUnderHybridProfile(args: HybridAcceptArgs): Promise<HybridAcceptOutcome> {
  const { profile, receipt, hybridKeys, verifyClassical, issuance, agilityOptions } = args;
  if (!profile || profile.profile_id !== HYBRID_RECEIPT_PROFILE_ID) {
    throw new TypeError('acceptUnderHybridProfile: profile must come from resolveHybridReceiptProfile()');
  }
  const refuse = (reason: string, detail: AnyRecord | null = null): HybridProfileRefusal => ({ ok: false, reason, detail });

  const version = (receipt && typeof receipt === 'object' && !Array.isArray(receipt))
    ? (receipt as AnyRecord)['@version']
    : undefined;

  if (version === HYBRID_RECEIPT_PROFILE_ID) {
    if (!profile.issues_hybrid) return refuse(HYBRID_PROFILE_REASONS.HYBRID_RECEIPT_NOT_ACCEPTED);
    if (!hybridKeys || typeof hybridKeys !== 'object') return refuse(HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);
    const module = await resolveIssuance(issuance);
    if (!module) return refuse(HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);
    const result = await module.verifyHybridReceipt(receipt, hybridKeys, agilityOptions ?? {});
    if (result?.verified !== true) return refuse(String(result?.reason ?? 'signature_invalid'), result ?? null);
    return { ok: true, profile: HYBRID_RECEIPT_PROFILE_ID, detail: result };
  }

  if (version === CLASSICAL_RECEIPT_PROFILE_ID) {
    if (profile.requires_hybrid) return refuse(HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
    if (typeof verifyClassical !== 'function') return refuse(HYBRID_PROFILE_REASONS.CLASSICAL_VERIFIER_MISSING);
    const result = await verifyClassical(receipt);
    if (result?.valid !== true) return refuse(String(result?.error ?? 'signature_invalid'), result ?? null);
    return { ok: true, profile: CLASSICAL_RECEIPT_PROFILE_ID, detail: result };
  }

  return refuse(HYBRID_PROFILE_REASONS.UNKNOWN_RECEIPT_PROFILE);
}
