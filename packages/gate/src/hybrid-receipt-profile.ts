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
 * THE DEFAULT IS RESOLVED FROM CUSTODY, NOT HARDCODED OFF. An operator setting
 * always decides the mode when there is one. When there is not,
 * resolveHybridIssuancePosture() reads the deployment's custody posture (see
 * describeHybridCustodyPosture() in lib/key-custody.ts) and resolves:
 *
 *   - a dual-signer custody signer is registered AND custody permits the
 *     post-quantum leg  ->  `dual`
 *   - no dual-signer custody signer                            ->  `disabled`
 *                                                                  (hybrid_signer_absent)
 *   - a dual signer, but custody REFUSES its declared PQ leg   ->  `disabled`
 *                                                                  (pq_custody_not_permitted)
 *
 * The refusal is the half worth stating loudly. EP now has a provider-neutral
 * external ML-DSA-65 signer contract and an AWS KMS adapter, but no code here
 * registers either at boot and the repository has not made a live AWS signing
 * call. Custody remains an operator declaration rather than a fact this module
 * can observe. A gov-strict deployment is therefore NOT quietly handed a
 * software PQ key because a default changed: it stays classical-only unless a
 * registered signer declares an accepted kms/hsm boundary, and the resolved
 * posture carries the named reason otherwise. There is no silent downgrade
 * here and no silent upgrade either.
 *
 * WHAT THIS REPOSITORY STILL DOES NOT DO. No code here registers a custody
 * signer at boot, hybrid or otherwise, and no Gate call site in this repository
 * issues receipts through issueUnderHybridProfile() yet. So nothing shipped
 * from this repository mints a hybrid receipt on its own; the default resolves
 * to `dual` only for a deployment that registered a dual signer whose custody
 * its own policy accepts. That is a changed default, not a deployed one.
 *
 * THE FOUR MODES
 *   disabled  The Gate issues and accepts EP-RECEIPT-v1 only. A
 *             request for a hybrid receipt is REFUSED (hybrid_issuance_disabled)
 *             rather than quietly answered with a classical receipt, and a
 *             hybrid receipt presented for acceptance is REFUSED
 *             (hybrid_receipt_not_accepted) rather than partially checked. A
 *             deployment that cannot check an ML-DSA leg must not pretend it
 *             checked one.
 *   enabled   Hybrid is available per request. A request that asks for it gets
 *             a hybrid receipt; everything else stays EP-RECEIPT-v1. Both
 *             profiles are accepted on the verification side.
 *   dual      Every issuance mints BOTH artifacts over the same canonical
 *             payload: an EP-RECEIPT-v1 receipt AND its EP-RECEIPT-HYBRID-v1
 *             twin. See the DUAL ISSUANCE note below. Acceptance behaves as in
 *             `enabled`: either profile is checked on its own terms.
 *   required  Every receipt this Gate issues is hybrid, and only hybrid
 *             receipts are accepted. A classical-only request or a classical
 *             receipt presented for acceptance is REFUSED
 *             (hybrid_required). This is the mode with teeth: there is no
 *             configuration in which `required` silently produces or accepts a
 *             single-signature receipt.
 *
 * --- DUAL ISSUANCE: THE MIGRATION DEFAULT CANDIDATE -------------------------
 *
 * `dual` is the mode this profile puts forward as the compatibility-preserving
 * default for a migration, and the reasoning is worth stating rather than
 * implying:
 *
 *   - A DEPLOYED v1 VERIFIER KEEPS WORKING. Every action still produces a
 *     real EP-RECEIPT-v1 receipt with the flat `signature` field v1 verifiers
 *     already read. Nothing downstream has to move on the Gate's schedule, and
 *     no relying party is asked to learn a new envelope before it is ready.
 *   - LONGEVITY EXISTS FOR EVERYTHING. Every action ALSO produces the hybrid
 *     twin, so the post-quantum evidence for that action exists from the moment
 *     the action happened. That matters because the alternative -- turn hybrid
 *     on later -- leaves a permanent window of actions with no PQ leg, and a
 *     receipt cannot be retroactively given one. Re-attestation
 *     (EP-EVIDENCE-REATTESTATION-v1) can re-anchor an old receipt's integrity,
 *     but only while the classical algorithm is still unbroken, and it is
 *     re-anchored evidence rather than a signature the issuer made at the time.
 *   - HYBRID-ONLY REMAINS THE STRICT END-STATE. `dual` is a migration posture,
 *     not a destination: it still emits an artifact an adversary with a
 *     quantum computer could forge, so a relying party that wants post-quantum
 *     evidence must not treat the classical twin as interchangeable. `required`
 *     is where a deployment ends up once its verifiers have moved.
 *
 * BOUNDARY, STATED PLAINLY: two receipts over one payload is a compatibility
 * arrangement, not a security upgrade to the classical artifact. The EP-RECEIPT-v1
 * twin is exactly as strong as it was alone. What dual mode buys is that the
 * hybrid twin EXISTS for the same action, so a relying party can choose which
 * evidence to rely on. It does not make the classical receipt harder to forge,
 * and a verifier that checks only the classical twin has gained nothing.
 *
 * THE TWIN LINK IS CHECKED, NOT ASSERTED. The dual outcome names an
 * `action_digest`, and this module recomputes that digest from EACH returned
 * receipt's own `payload` before returning. Two artifacts that do not commit to
 * identical canonical bytes are a REFUSAL (dual_payload_mismatch), never a pair
 * labelled as twins on the strength of having been minted in the same call.
 *
 * NO SILENT DOWNGRADE, ANYWHERE. Every path where hybrid could not be produced
 * or could not be checked (missing keys, missing ML-DSA backend, missing
 * issuance module) is a refusal with a named reason. There is no fallback edge
 * in this file that turns a hybrid intent into a classical artifact.
 *
 * HONEST BOUNDARIES
 *   - EP-RECEIPT-v1 is still the Gate's receipt format; `dual` adds a twin
 *     alongside it, and no deployment shipped from this repository issues
 *     either through this module yet.
 *   - The ML-DSA implementation reached through EP-SIG-AGILITY-v1 is
 *     @noble/post-quantum, a pure-JS FIPS 204 implementation that is not a
 *     FIPS-validated module. Turning this profile on is not a certification.
 *   - `action-control-manifest.ts` still pins `authorization_receipt.profile`
 *     to EP-RECEIPT-v1. A relying party who wants hybrid receipts named in a
 *     manifest needs that contract extended; this module does not change it.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';

import { canonicalizeStrictJson } from './strict-json.js';

type AnyRecord = Record<string, any>;

export const HYBRID_RECEIPT_PROFILE_ID = 'EP-RECEIPT-HYBRID-v1';
export const CLASSICAL_RECEIPT_PROFILE_ID = 'EP-RECEIPT-v1';

/**
 * The marker on a dual-issuance OUTCOME. It names the RESULT PAIR returned to
 * the caller; it is deliberately NOT a third receipt format. Neither artifact
 * carries this string on the wire: the classical twin stays EP-RECEIPT-v1 and
 * the hybrid twin stays EP-RECEIPT-HYBRID-v1, so no verifier has to learn a new
 * envelope in order for a Gate to run in dual mode.
 */
export const DUAL_ISSUANCE_RESULT_ID = 'EP-RECEIPT-DUAL-ISSUANCE-v1';

/** Config values for the `hybrid_issuance` flag, in increasing strictness. */
export const HYBRID_ISSUANCE_MODES = Object.freeze(['disabled', 'enabled', 'dual', 'required'] as const);
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
  /** dual mode: the caller asked for a single-profile receipt. */
  DUAL_REQUIRED: 'dual_required',
  /** dual mode: the classical issuer did not return an EP-RECEIPT-v1 document. */
  CLASSICAL_RECEIPT_MALFORMED: 'classical_receipt_malformed',
  /** dual mode: the two artifacts do not commit to identical canonical bytes. */
  DUAL_PAYLOAD_MISMATCH: 'dual_payload_mismatch',
  /** default resolution: no dual-signer custody signer is registered. */
  HYBRID_SIGNER_ABSENT: 'hybrid_signer_absent',
  /** default resolution: custody refuses the registered ML-DSA-65 leg. */
  PQ_CUSTODY_NOT_PERMITTED: 'pq_custody_not_permitted',
  /** default resolution: the deployment's own custody policy is not satisfied. */
  CUSTODY_POLICY_NOT_SATISFIED: 'custody_policy_not_satisfied',
  /** default resolution: an explicit operator setting pinned classical-only. */
  OPERATOR_PINNED_CLASSICAL: 'operator_pinned_classical',
  /** the issuance module does not expose the custody-signer issuance entry point. */
  HYBRID_SIGNER_ISSUANCE_UNSUPPORTED: 'hybrid_signer_issuance_unsupported',
});

/**
 * The issuance/verification surface this module drives, structurally typed so
 * packages/gate gains no build-time dependency on packages/issue.
 */
export interface HybridIssuanceModule {
  createHybridReceipt: (args: AnyRecord) => Promise<AnyRecord>;
  /**
   * Mint from a dual-signer's signSet(bytes) instead of raw key material.
   * OPTIONAL so an older @emilia-protocol/issue is a named refusal
   * (hybrid_signer_issuance_unsupported) rather than a crash.
   */
  createHybridReceiptFromSignSet?: (args: AnyRecord) => Promise<AnyRecord>;
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
  /** True when every issuance mints BOTH the classical and the hybrid twin. */
  issues_dual: boolean;
}

export interface HybridProfileRefusal {
  ok: false;
  reason: string;
  /** Present when the refusal came from the underlying verifier. */
  detail?: AnyRecord | null;
}

/**
 * The dual-issuance outcome: BOTH artifacts plus the digest that links them.
 *
 * `action_digest` is `sha256:<hex>` over `canonicalizeStrictJson(payload)` --
 * the canonical action bytes BOTH receipts commit to, in the repository's
 * `<alg>:<hex>` digest idiom. It is recomputed here from each returned
 * receipt's own `payload`, so a relying party handed either artifact alone can
 * recompute the same value and confirm it is looking at the twin of the other.
 * A relying party may verify either artifact, or both; verifying one says
 * nothing about the other beyond the shared digest.
 */
export interface DualIssueResult {
  ok: true;
  profile: typeof DUAL_ISSUANCE_RESULT_ID;
  /** The EP-RECEIPT-v1 artifact a deployed v1 verifier reads unchanged. */
  classical_receipt: AnyRecord;
  /** The EP-RECEIPT-HYBRID-v1 twin over the same canonical payload. */
  hybrid_receipt: AnyRecord;
  /** `sha256:<hex>` over the canonical payload both artifacts commit to. */
  action_digest: string;
}

export type HybridIssueOutcome =
  | { ok: true; profile: typeof HYBRID_RECEIPT_PROFILE_ID; receipt: AnyRecord }
  | { ok: true; profile: typeof CLASSICAL_RECEIPT_PROFILE_ID; receipt: AnyRecord }
  | DualIssueResult
  | HybridProfileRefusal;

export type HybridAcceptOutcome =
  | { ok: true; profile: string; detail?: AnyRecord | null }
  | HybridProfileRefusal;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * The custody posture this module resolves a DEFAULT from, structurally typed
 * so packages/gate gains no dependency on lib/. Produce it with
 * describeHybridCustodyPosture() in lib/key-custody.ts, or hand-build the two
 * fields that matter for a Gate that manages its own signers.
 */
export interface HybridCustodyPostureInput {
  /** Is a dual-signer (hybrid) custody signer registered? */
  hybrid_signer_present?: boolean;
  /** May this deployment mint the ML-DSA-65 leg under its own custody policy? */
  pq_leg_permitted?: boolean;
  /** The PQ leg's operator-declared custody label. */
  pq_custody?: string | null;
  /** The custody layer's named refusal, when it refused. */
  reason?: string | null;
  detail?: string | null;
}

/** Where a resolved mode came from. */
export type HybridPostureSource = 'operator' | 'custody_default';

/**
 * A resolved posture: the profile plus WHY it is that profile.
 *
 * `reason` is non-null exactly when this posture mints no post-quantum leg, and
 * it is always one of HYBRID_PROFILE_REASONS. That is the observability
 * requirement: a deployment that ends up classical-only can read the named
 * cause (`pq_custody_not_permitted`, `hybrid_signer_absent`,
 * `custody_policy_not_satisfied`, `operator_pinned_classical`) instead of
 * discovering a silent downgrade later.
 *
 * `custody` is recorded even when an operator setting won, so a deployment that
 * explicitly turned hybrid on over a refusing custody policy can still see the
 * declared custody boundary. An explicit setting is an operator attestation
 * about their own deployment; this module records it rather than second-guesses
 * it, and it never lets a DEFAULT make that attestation on their behalf.
 */
export interface ResolvedHybridPosture {
  profile: HybridReceiptProfile;
  source: HybridPostureSource;
  reason: string | null;
  custody: {
    hybrid_signer_present: boolean;
    pq_leg_permitted: boolean;
    pq_custody: string | null;
    reason: string | null;
  };
}

const CUSTODY_REASONS: Record<string, string> = Object.freeze({
  hybrid_signer_absent: HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ABSENT,
  pq_custody_not_permitted: HYBRID_PROFILE_REASONS.PQ_CUSTODY_NOT_PERMITTED,
  custody_policy_not_satisfied: HYBRID_PROFILE_REASONS.CUSTODY_POLICY_NOT_SATISFIED,
});

function freezeProfile(mode: HybridIssuanceMode): HybridReceiptProfile {
  return Object.freeze({
    profile_id: HYBRID_RECEIPT_PROFILE_ID,
    mode,
    issues_hybrid: mode !== 'disabled',
    requires_hybrid: mode === 'required',
    issues_dual: mode === 'dual',
  });
}

/**
 * Normalize an explicit `hybrid_issuance` setting, or return undefined when the
 * operator set none. An unrecognized value THROWS: a misconfigured security
 * flag must stop a deployment, not be rounded down to a permissive default.
 */
function normalizeOperatorMode(config?: unknown): HybridIssuanceMode | undefined {
  let value: unknown = config;
  if (config && typeof config === 'object' && !Array.isArray(config)) {
    value = (config as AnyRecord).hybrid_issuance;
  }
  if (value === undefined || value === null) return undefined;
  // `true`/`false` are accepted because operators reach for booleans on a flag
  // named like this one; they map onto the two unambiguous modes, never onto
  // `required` (which nobody would spell as `true`). `false` is a real
  // operator decision to stay classical-only, and it wins over any default.
  if (value === true) value = 'enabled';
  if (value === false) value = 'disabled';
  if (typeof value !== 'string' || !(HYBRID_ISSUANCE_MODES as readonly string[]).includes(value)) {
    throw new Error(
      `hybrid_issuance must be one of ${HYBRID_ISSUANCE_MODES.join(', ')}; got ${JSON.stringify(value)}`,
    );
  }
  return value as HybridIssuanceMode;
}

/**
 * Resolve the deployment's posture from its operator setting and its custody.
 *
 * THE RULE, IN ONE PLACE:
 *   1. An explicit `hybrid_issuance` setting WINS, in both directions. It can
 *      turn hybrid on where custody would have refused (an operator attestation
 *      about custody they operate), and it can pin classical-only where the
 *      default would have resolved `dual`.
 *   2. With no explicit setting, the default is `dual` when a dual-signer
 *      custody signer is registered AND custody permits the post-quantum leg.
 *   3. Otherwise the default is `disabled`, carrying the custody layer's named
 *      reason. Refusal is never rounded up to permission: an unrecognized or
 *      missing custody verdict resolves classical-only, not dual.
 *
 * `required` semantics are untouched by any of this: it is only ever reached
 * through an explicit setting, and it still refuses every classical-only path.
 */
export function resolveHybridIssuancePosture({ config, custody }: {
  config?: unknown;
  custody?: HybridCustodyPostureInput | null;
} = {}): ResolvedHybridPosture {
  const signerPresent = custody?.hybrid_signer_present === true;
  const rawReason = typeof custody?.reason === 'string' && custody.reason.length > 0 ? custody.reason : null;
  // Fail closed on a contradictory verdict: permission requires BOTH the
  // affirmative flag and no stated refusal, so a posture that says "permitted"
  // while naming a reason is treated as the refusal it names.
  const pqPermitted = custody?.pq_leg_permitted === true && signerPresent && rawReason === null;
  const custodyReason = pqPermitted
    ? null
    : rawReason === null
      ? (signerPresent
        ? HYBRID_PROFILE_REASONS.CUSTODY_POLICY_NOT_SATISFIED
        : HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ABSENT)
      : CUSTODY_REASONS[rawReason] ?? rawReason;
  const custodyRecord = Object.freeze({
    hybrid_signer_present: signerPresent,
    pq_leg_permitted: pqPermitted,
    pq_custody: custody?.pq_custody ?? null,
    reason: custodyReason,
  });

  const operatorMode = normalizeOperatorMode(config);
  if (operatorMode !== undefined) {
    return Object.freeze({
      profile: freezeProfile(operatorMode),
      source: 'operator',
      reason: operatorMode === 'disabled' ? HYBRID_PROFILE_REASONS.OPERATOR_PINNED_CLASSICAL : null,
      custody: custodyRecord,
    });
  }

  if (pqPermitted) {
    return Object.freeze({
      profile: freezeProfile('dual'),
      source: 'custody_default',
      reason: null,
      custody: custodyRecord,
    });
  }
  return Object.freeze({
    profile: freezeProfile('disabled'),
    source: 'custody_default',
    reason: custodyRecord.reason,
    custody: custodyRecord,
  });
}

/**
 * Normalize a Gate deployment's `hybrid_issuance` setting into a frozen
 * profile, resolving the DEFAULT from custody when the operator set none.
 * An unrecognized value THROWS.
 *
 *   resolveHybridReceiptProfile('required')                     -> required
 *   resolveHybridReceiptProfile({ hybrid_issuance: 'required' }) -> required
 *   resolveHybridReceiptProfile(undefined)                       -> disabled
 *   resolveHybridReceiptProfile(undefined, custodyPosture)       -> dual, when
 *     a dual signer is registered and custody permits its PQ leg
 *
 * Call resolveHybridIssuancePosture() instead when the deployment needs the
 * named reason for a classical-only default rather than just the profile.
 */
export function resolveHybridReceiptProfile(
  config?: unknown,
  custody?: HybridCustodyPostureInput | null,
): HybridReceiptProfile {
  return resolveHybridIssuancePosture({ config, custody }).profile;
}

// ---------------------------------------------------------------------------
// The twin link (dual mode)
// ---------------------------------------------------------------------------

/**
 * `sha256:<hex>` over the canonical bytes of a receipt payload. Returns null
 * when the value is outside the EP canonicalization profile, so the caller
 * refuses instead of comparing a digest of something it could not canonicalize.
 */
function canonicalPayloadDigest(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  try {
    const canonical = canonicalizeStrictJson(payload);
    return `sha256:${crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex')}`;
  } catch {
    return null;
  }
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
  /**
   * A registered dual-signer instead of raw key material: anything with a
   * signSet(bytes, context) returning one signature per required algorithm
   * (HybridCustodySigner from lib/key-custody.ts is exactly this shape). This
   * is the path a deployment whose classical leg is behind a KMS/HSM boundary
   * must use, because it has no secret bytes to hand over. Preferred over
   * `hybridKeys` when both are supplied.
   */
  hybridSigner?: { signSet: (bytes: Uint8Array | Buffer, context?: AnyRecord) => Promise<any> } | null;
  /**
   * Did this request ask for a hybrid receipt? Ignored in `required` mode, and
   * refused in `dual` mode (which always answers with both artifacts).
   */
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
 *     profile: resolveHybridReceiptProfile(config, custodyPosture),
 *     payload, metadata, requestHybrid,
 *     hybridSigner,   // or hybridKeys, for an issuer holding its own key bytes
 *     issueClassical: ({ payload, metadata }) => existingIssueReceipt(payload, metadata),
 *   });
 *   if (!outcome.ok) return refuse(outcome.reason);
 *
 * Every failure is a named refusal returned to the caller. This function never
 * substitutes a classical receipt for a hybrid one that could not be minted.
 */
export async function issueUnderHybridProfile(args: HybridIssueArgs): Promise<HybridIssueOutcome> {
  const { profile, payload, metadata, requestHybrid, issueClassical, issuance } = args;
  if (!profile || profile.profile_id !== HYBRID_RECEIPT_PROFILE_ID) {
    throw new TypeError('issueUnderHybridProfile: profile must come from resolveHybridReceiptProfile()');
  }
  const refuse = (reason: string, detail: AnyRecord | null = null): HybridProfileRefusal => (
    detail === null ? { ok: false, reason } : { ok: false, reason, detail }
  );

  // An explicit ask for a classical receipt under `required` is refused, not
  // silently upgraded: the caller learns the deployment's rule instead of
  // receiving a different artifact than the one it asked for. An unspecified
  // request under `required` gets the hybrid receipt the mode demands.
  if (profile.requires_hybrid && requestHybrid === false) {
    return refuse(HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
  }

  // dual mode answers with BOTH artifacts, so it never reads `requestHybrid` as
  // a choice between them. An explicit single-profile ask is refused with its
  // own reason rather than answered with a result shape the caller did not ask
  // for: a call site reading `outcome.receipt` would otherwise read undefined
  // and see nothing wrong. Reversal path: run `enabled` if a call site needs to
  // choose per request.
  if (profile.issues_dual) {
    if (typeof requestHybrid === 'boolean') return refuse(HYBRID_PROFILE_REASONS.DUAL_REQUIRED);
    return issueDual(args);
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
  if (!hasSigningMaterial(args)) return refuse(HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);

  const module = await resolveIssuance(issuance);
  if (!module) return refuse(HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);

  const minted = await mintHybrid(module, args);
  if (!minted.ok) return minted;
  return { ok: true, profile: HYBRID_RECEIPT_PROFILE_ID, receipt: minted.receipt };
}

/**
 * Mint the EP-RECEIPT-HYBRID-v1 twin, from a custody signer when one is given
 * and from raw key material otherwise. One function so the single-artifact and
 * dual paths cannot drift on which signing surface they use or on how they
 * refuse.
 *
 * Every failure is a named refusal. The underlying issuance THROWS on
 * issuer-side misuse and on an unavailable ML-DSA backend (`pq_backend_unavailable`
 * reaches us in the error text); either way the Gate refuses and never falls
 * back to a classical artifact.
 */
async function mintHybrid(
  module: HybridIssuanceModule,
  args: HybridIssueArgs,
): Promise<{ ok: true; receipt: AnyRecord } | HybridProfileRefusal> {
  const { payload, metadata, hybridKeys, hybridSigner, agilityOptions } = args;
  const useSigner = !!hybridSigner && typeof hybridSigner.signSet === 'function';
  if (!useSigner && (!hybridKeys || typeof hybridKeys !== 'object')) {
    return { ok: false, reason: HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING };
  }
  if (useSigner && typeof module.createHybridReceiptFromSignSet !== 'function') {
    return { ok: false, reason: HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ISSUANCE_UNSUPPORTED };
  }
  try {
    const receipt = useSigner
      ? await module.createHybridReceiptFromSignSet!({
        payload,
        signSet: (bytes: Uint8Array | Buffer, context?: AnyRecord) => hybridSigner!.signSet(bytes, context),
        ...(metadata !== undefined ? { metadata } : {}),
      })
      : await module.createHybridReceipt({
        payload,
        keys: hybridKeys,
        ...(metadata !== undefined ? { metadata } : {}),
        ...(agilityOptions ?? {}),
      });
    return { ok: true, receipt };
  } catch (error) {
    return {
      ok: false,
      reason: HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE,
      detail: { error: String((error as Error)?.message ?? error) },
    };
  }
}

/**
 * dual mode: mint both artifacts over one payload and return them with the
 * digest that links them.
 *
 * ORDER MATTERS, AND IT IS DELIBERATE. The hybrid twin is minted FIRST. It is
 * the leg that can fail for cryptographic reasons (no ML-DSA backend, no
 * issuance module, bad key material), while `issueClassical` is a deployment's
 * real receipt-issuing path and may persist, log, or anchor what it mints.
 * Minting hybrid first means a dual issuance that cannot be completed refuses
 * BEFORE the classical side effect happens, so a refused dual issuance does not
 * leave an orphan classical receipt behind that a relying party could later
 * mistake for a complete one.
 *
 * Every failure is a named refusal. There is no path here that returns one
 * artifact when two were promised.
 */
async function issueDual(args: HybridIssueArgs): Promise<HybridIssueOutcome> {
  const { payload, metadata, issueClassical, issuance } = args;
  const refuse = (reason: string, detail: AnyRecord | null = null): HybridProfileRefusal => (
    detail === null ? { ok: false, reason } : { ok: false, reason, detail }
  );

  if (typeof issueClassical !== 'function') return refuse(HYBRID_PROFILE_REASONS.CLASSICAL_ISSUER_MISSING);
  if (!hasSigningMaterial(args)) return refuse(HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);

  // The digest of what the caller asked to have signed. Both artifacts are
  // checked against THIS, never against each other alone: two receipts that
  // agree with one another but not with the requested payload are still wrong.
  const expectedDigest = canonicalPayloadDigest(payload);
  if (expectedDigest === null) {
    return refuse(HYBRID_PROFILE_REASONS.DUAL_PAYLOAD_MISMATCH, { payload: 'outside the EP canonicalization profile' });
  }

  const module = await resolveIssuance(issuance);
  if (!module) return refuse(HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);

  const minted = await mintHybrid(module, args);
  if (!minted.ok) return minted;
  const hybridReceipt = minted.receipt;

  const classicalReceipt = await issueClassical({ payload, ...(metadata !== undefined ? { metadata } : {}) });

  // The twin link, recomputed rather than asserted. A classical issuer that
  // returns something other than an EP-RECEIPT-v1 document, or either artifact
  // committing to different canonical bytes, is a refusal.
  if (!classicalReceipt || typeof classicalReceipt !== 'object' || Array.isArray(classicalReceipt)
      || (classicalReceipt as AnyRecord)['@version'] !== CLASSICAL_RECEIPT_PROFILE_ID) {
    return refuse(HYBRID_PROFILE_REASONS.CLASSICAL_RECEIPT_MALFORMED);
  }
  const classicalDigest = canonicalPayloadDigest((classicalReceipt as AnyRecord).payload);
  const hybridDigest = canonicalPayloadDigest(hybridReceipt?.payload);
  if (classicalDigest !== expectedDigest || hybridDigest !== expectedDigest) {
    return refuse(HYBRID_PROFILE_REASONS.DUAL_PAYLOAD_MISMATCH, {
      expected: expectedDigest,
      classical: classicalDigest,
      hybrid: hybridDigest,
    });
  }

  return {
    ok: true,
    profile: DUAL_ISSUANCE_RESULT_ID,
    classical_receipt: classicalReceipt as AnyRecord,
    hybrid_receipt: hybridReceipt,
    action_digest: expectedDigest,
  };
}

/** Does this call carry something that can sign the PQ leg? */
function hasSigningMaterial(args: HybridIssueArgs): boolean {
  if (args.hybridSigner && typeof args.hybridSigner.signSet === 'function') return true;
  return !!args.hybridKeys && typeof args.hybridKeys === 'object';
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
 *
 * `dual` accepts on the same terms as `enabled`: each presented artifact is
 * checked under its own profile, one at a time. Acceptance is deliberately NOT
 * given a "both twins" mode, because a relying party is handed one artifact and
 * relies on it; a verdict that quietly depended on the other artifact being
 * present would be a different claim than the one the caller made.
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
