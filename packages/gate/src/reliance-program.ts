// SPDX-License-Identifier: Apache-2.0
/**
 * Customer-owned Reliance Program source and deterministic compiler.
 *
 * The signed source is the relying party's policy artifact. Compilation emits
 * the existing Gate Trust Program wire format; it does not create another
 * authorization engine or let a presenter select the acceptance bar.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  TRUST_PROGRAM_VERSION,
  TRUST_PROGRAM_V2_VERSION,
  trustProgramDigest,
  trustProgramV2Digest,
  validateTrustProgram,
  validateTrustProgramV2,
} from './trust-program.js';
import { createPinnedEvidenceAdapter } from './trust-program-adapters.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSigningKey,
  type AgileSignature,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';

export const RELIANCE_PROGRAM_SOURCE_VERSION = 'EP-RELIANCE-PROGRAM-SOURCE-v1';
export const RELIANCE_PROGRAM_VERSION = 'EP-RELIANCE-PROGRAM-v1';
export const RELIANCE_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519';
export const RELIANCE_PROGRAM_ADMISSIBILITY_EVIDENCE = 'ep-admissibility-evaluation';
export const RELIANCE_PROGRAM_ADMISSIBILITY_VERIFIER = 'ep-admissibility-profile:v1';

const DOMAIN = `${RELIANCE_PROGRAM_VERSION}\0`;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const TRUST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const SOURCE_KEYS = new Set([
  '@version', 'program_id', 'version', 'relying_party', 'root_caid',
  'action_digest', 'valid_from', 'expires_at', 'stages', 'execution',
]);
const RELYING_PARTY_KEYS = new Set(['id', 'key_id']);
const STAGE_KEYS = new Set(['stage_id', 'depends_on', 'rule', 'profiles']);
const PROFILE_REF_KEYS = new Set([
  'profile_id', 'profile_hash', 'evaluation_max_age_sec', 'revocation_required',
]);
const EXECUTION_KEYS = new Set([
  'depends_on', 'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
]);
const ENVELOPE_KEYS = new Set(['@version', 'source', 'source_digest', 'signature']);
const SIGNATURE_KEYS = new Set(['algorithm', 'key_id', 'value']);
const TRUSTED_SIGNER_KEYS = new Set(['relying_party_id', 'public_key']);
const MAX_STAGES = 64;
const MAX_PROFILES_PER_STAGE = 64;
const MAX_PROFILE_CATALOG = 1024;
const MAX_PROFILE_BYTES = 262_144;

type JsonRecord = Record<string, any>;

export interface CompiledRelianceProgram {
  version: typeof RELIANCE_PROGRAM_VERSION;
  source_digest: string;
  relying_party_id: string;
  program: JsonRecord;
  program_digest: string;
  trace: Array<{
    stage_id: string;
    requirement_id: string;
    profile_id: string;
    profile_hash: string;
  }>;
  claim_boundary: string;
}

export interface AdmissibilityProfileTrustAdapterOptions {
  profile: JsonRecord;
  evaluate: (profile: JsonRecord, bundle: unknown, context: {
    now?: string | number;
    expectedProfileHash: string;
  }) => any | Promise<any>;
  project: (input: {
    evaluation: Readonly<JsonRecord>;
    bundle: unknown;
  }) => {
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at?: string | null;
  } | Promise<{
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at?: string | null;
  }>;
  now?: string | number | (() => string | number);
}

export class RelianceProgramValidationError extends TypeError {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'RelianceProgramValidationError';
    this.code = code;
  }
}

function refuse(code: string, message: string): never {
  throw new RelianceProgramValidationError(code, message);
}

function isRecord(value: unknown): value is JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is JsonRecord {
  return isRecord(value) && Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exact(value: unknown, keys: Set<string>): value is JsonRecord {
  return isDataRecord(value)
    && Reflect.ownKeys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonicalize(value));
}

function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as JsonRecord)) deepFreeze(child);
  return value;
}

function digest(value: unknown): string {
  return `sha256:${hashCanonical(value)}`;
}

function strictInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function exactIdentifiers(value: unknown, maximum = MAX_STAGES): value is string[] {
  return Array.isArray(value) && value.length <= maximum
    && value.every((entry) => typeof entry === 'string' && TRUST_ID.test(entry))
    && new Set(value).size === value.length;
}

function validateRule(rule: unknown, profileCount: number): boolean {
  if (!isDataRecord(rule) || !['all', 'any', 'threshold'].includes(rule.mode)) return false;
  const keys = rule.mode === 'threshold'
    ? new Set(['mode', 'required', 'distinct_subjects', 'distinct_keys'])
    : new Set(['mode', 'distinct_subjects', 'distinct_keys']);
  if (!exact(rule, keys)
      || typeof rule.distinct_subjects !== 'boolean'
      || typeof rule.distinct_keys !== 'boolean') return false;
  if (rule.mode !== 'threshold') return true;
  return Number.isSafeInteger(rule.required) && rule.required >= 1 && rule.required <= profileCount;
}

function validateSource(value: unknown): asserts value is JsonRecord {
  validateSourceUnder(value, RELIANCE_PROGRAM_SOURCE_VERSION);
}

/**
 * ONE source-validation body for both versions. validateSource (v1) and the v2
 * path differ ONLY in the `@version` marker they accept, so the closed schema,
 * bindings, time window, stage rules, and consequence-owner rules cannot drift.
 */
function validateSourceUnder(value: unknown, expectedVersion: string): asserts value is JsonRecord {
  try { canonicalize(value); } catch {
    refuse('source_not_canonical', 'reliance program source is not canonicalizable JSON');
  }
  if (!exact(value, SOURCE_KEYS) || value['@version'] !== expectedVersion
      || !exact(value.relying_party, RELYING_PARTY_KEYS)) {
    refuse('source_schema_invalid', 'reliance program source is not a closed v1 object');
  }
  if (typeof value.program_id !== 'string' || !TRUST_ID.test(value.program_id)
      || !Number.isSafeInteger(value.version) || value.version < 1
      || typeof value.relying_party.id !== 'string' || !ID.test(value.relying_party.id)
      || typeof value.relying_party.key_id !== 'string' || !TRUST_ID.test(value.relying_party.key_id)
      || typeof value.root_caid !== 'string' || !CAID.test(value.root_caid)
      || typeof value.action_digest !== 'string' || !DIGEST.test(value.action_digest)) {
    refuse('source_binding_invalid', 'relying party, CAID, or action binding is invalid');
  }
  const validFrom = strictInstant(value.valid_from);
  const expiresAt = strictInstant(value.expires_at);
  if (!Number.isFinite(validFrom) || !Number.isFinite(expiresAt) || expiresAt <= validFrom) {
    refuse('source_time_window_invalid', 'reliance program validity window is invalid');
  }
  if (!Array.isArray(value.stages) || value.stages.length < 1 || value.stages.length > MAX_STAGES) {
    refuse('source_stage_count_invalid', 'reliance program stage count is invalid');
  }
  const stageIds = new Set<string>();
  for (const stage of value.stages) {
    if (!exact(stage, STAGE_KEYS) || typeof stage.stage_id !== 'string'
        || !TRUST_ID.test(stage.stage_id) || stageIds.has(stage.stage_id)
        || !exactIdentifiers(stage.depends_on)
        || !Array.isArray(stage.profiles) || stage.profiles.length < 1
        || stage.profiles.length > MAX_PROFILES_PER_STAGE
        || !validateRule(stage.rule, stage.profiles.length)) {
      refuse('source_stage_invalid', 'reliance program stage is invalid');
    }
    stageIds.add(stage.stage_id);
    const profileIds = new Set<string>();
    for (const reference of stage.profiles) {
      if (!exact(reference, PROFILE_REF_KEYS)
          || typeof reference.profile_id !== 'string' || !ID.test(reference.profile_id)
          || profileIds.has(reference.profile_id)
          || typeof reference.profile_hash !== 'string' || !DIGEST.test(reference.profile_hash)
          || !Number.isSafeInteger(reference.evaluation_max_age_sec)
          || reference.evaluation_max_age_sec < 1 || reference.evaluation_max_age_sec > 31_536_000
          || typeof reference.revocation_required !== 'boolean') {
        refuse('source_profile_reference_invalid', 'admissibility profile reference is invalid');
      }
      profileIds.add(reference.profile_id);
    }
  }
  if (!exact(value.execution, EXECUTION_KEYS)
      || !exactIdentifiers(value.execution.depends_on)
      || value.execution.depends_on.length < 1
      || !['receipt-program', 'action-escrow'].includes(value.execution.consequence_mode)
      || (value.execution.consequence_mode === 'receipt-program'
        && (!DIGEST.test(value.execution.capability_template_digest)
          || value.execution.escrow_profile_digest !== null))
      || (value.execution.consequence_mode === 'action-escrow'
        && (!DIGEST.test(value.execution.escrow_profile_digest)
          || value.execution.capability_template_digest !== null))) {
    refuse('source_execution_invalid', 'reliance program consequence owner is invalid');
  }
}

function signingBytes(source: JsonRecord): Buffer {
  return Buffer.concat([
    Buffer.from(DOMAIN, 'utf8'),
    Buffer.from(canonicalize(source), 'utf8'),
  ]);
}

function publicKey(value: unknown): crypto.KeyObject | null {
  try {
    if (value instanceof crypto.KeyObject) {
      const key = value.type === 'public' ? value : crypto.createPublicKey(value as any);
      return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch { return null; }
}

export function relianceProgramSourceDigest(source: unknown): string {
  validateSource(source);
  return digest(source);
}

export function signRelianceProgram(source: unknown, privateKey: crypto.KeyLike): JsonRecord {
  validateSource(source);
  const key = privateKey instanceof crypto.KeyObject
    ? privateKey : crypto.createPrivateKey(privateKey as any);
  if (key.asymmetricKeyType !== 'ed25519') {
    refuse('signing_key_invalid', 'reliance program signing key must be Ed25519');
  }
  const frozenSource = canonicalCopy(source);
  const signature = crypto.sign(null, signingBytes(frozenSource), key).toString('base64url');
  return deepFreeze({
    '@version': RELIANCE_PROGRAM_VERSION,
    source: frozenSource,
    source_digest: digest(frozenSource),
    signature: {
      algorithm: RELIANCE_PROGRAM_SIGNATURE_ALGORITHM,
      key_id: frozenSource.relying_party.key_id,
      value: signature,
    },
  });
}

export function verifyRelianceProgram(
  envelope: unknown,
  { trustedKeys = {} }: { trustedKeys?: Record<string, unknown> } = {},
): JsonRecord {
  if (!exact(envelope, ENVELOPE_KEYS) || envelope['@version'] !== RELIANCE_PROGRAM_VERSION
      || !exact(envelope.signature, SIGNATURE_KEYS)
      || envelope.signature.algorithm !== RELIANCE_PROGRAM_SIGNATURE_ALGORITHM
      || typeof envelope.source_digest !== 'string' || !DIGEST.test(envelope.source_digest)
      || typeof envelope.signature.key_id !== 'string'
      || typeof envelope.signature.value !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(envelope.signature.value)
      || Buffer.from(envelope.signature.value, 'base64url').length !== 64
      || Buffer.from(envelope.signature.value, 'base64url').toString('base64url') !== envelope.signature.value) {
    return { valid: false, reason: 'envelope_schema_invalid', source_digest: null };
  }
  try { validateSource(envelope.source); } catch (error) {
    return { valid: false, reason: error instanceof RelianceProgramValidationError
      ? error.code : 'source_schema_invalid', source_digest: null };
  }
  if (envelope.signature.key_id !== envelope.source.relying_party.key_id) {
    return { valid: false, reason: 'signature_key_mismatch', source_digest: envelope.source_digest };
  }
  const computed = digest(envelope.source);
  if (computed !== envelope.source_digest) {
    return { valid: false, reason: 'source_digest_mismatch', source_digest: computed };
  }
  if (!isRecord(trustedKeys) || !Object.hasOwn(trustedKeys, envelope.signature.key_id)) {
    return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
  }
  const signer = trustedKeys[envelope.signature.key_id];
  if (!exact(signer, TRUSTED_SIGNER_KEYS)
      || signer.relying_party_id !== envelope.source.relying_party.id) {
    return { valid: false, reason: 'relying_party_identity_mismatch', source_digest: computed };
  }
  const key = publicKey(signer.public_key);
  if (!key) {
    return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
  }
  const valid = crypto.verify(
    null,
    signingBytes(envelope.source),
    key,
    Buffer.from(envelope.signature.value, 'base64url'),
  );
  if (!valid) return { valid: false, reason: 'signature_invalid', source_digest: computed };
  return {
    valid: true,
    reason: null,
    source_digest: computed,
    relying_party_id: envelope.source.relying_party.id,
    key_id: envelope.signature.key_id,
  };
}

function profileMap(profiles: unknown): Map<string, JsonRecord> {
  if (!Array.isArray(profiles) || profiles.length > MAX_PROFILE_CATALOG) {
    refuse('profile_catalog_invalid', 'profile catalog must be a bounded array');
  }
  const result = new Map<string, JsonRecord>();
  for (const profile of profiles) {
    if (!isDataRecord(profile) || typeof profile.id !== 'string' || !ID.test(profile.id)
        || typeof profile.profile_hash !== 'string' || !DIGEST.test(profile.profile_hash)
        || result.has(profile.id)) {
      refuse('profile_catalog_invalid', 'profile catalog contains an invalid or duplicate entry');
    }
    const { profile_hash: profileHash, ...profileBody } = profile;
    let computed: string;
    try {
      const canonical = canonicalize(profileBody);
      if (Buffer.byteLength(canonical, 'utf8') > MAX_PROFILE_BYTES) {
        refuse('profile_catalog_invalid', `profile ${profile.id} exceeds the size limit`);
      }
      computed = `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
    } catch (error) {
      if (error instanceof RelianceProgramValidationError) throw error;
      refuse('profile_integrity_invalid', `profile ${profile.id} is not canonicalizable`);
    }
    if (computed !== profileHash) {
      refuse('profile_integrity_invalid', `profile ${profile.id} self-hash does not match its content`);
    }
    result.set(profile.id, profile);
  }
  return result;
}

function verifiedProfile(profile: unknown): JsonRecord {
  const catalog = profileMap([profile]);
  return catalog.values().next().value as JsonRecord;
}

/**
 * Adapt the existing Admissibility Profile evaluator into one constructor-
 * pinned Trust Program verifier. The runtime artifact supplies evidence only;
 * the profile, evaluator, projection, and clock are all relying-party owned.
 */
export function createAdmissibilityProfileTrustAdapter({
  profile,
  evaluate,
  project,
  now,
}: AdmissibilityProfileTrustAdapterOptions) {
  const pinnedProfile = canonicalCopy(verifiedProfile(profile));
  if (typeof evaluate !== 'function' || typeof project !== 'function') {
    refuse('admissibility_adapter_invalid', 'admissibility evaluator and projection are required');
  }
  const profileHash = pinnedProfile.profile_hash;
  return createPinnedEvidenceAdapter({
    policyDigest: profileHash,
    trustedConfiguration: {
      profile_id: pinnedProfile.id,
      profile_hash: profileHash,
    },
    verify: async (evidence, context) => {
      if (!exact(evidence, new Set(['bundle']))) {
        return { valid: false, reason: 'admissibility_evidence_schema_invalid' };
      }
      const evaluationTime = typeof now === 'function' ? now() : now;
      let evaluation: any;
      try {
        evaluation = await evaluate(pinnedProfile, evidence.bundle, {
          ...(evaluationTime === undefined ? {} : { now: evaluationTime }),
          expectedProfileHash: profileHash,
        });
      } catch {
        return { valid: false, reason: 'admissibility_evaluation_failed' };
      }
      if (!isDataRecord(evaluation)
          || evaluation.profile_hash !== profileHash
          || evaluation.verdict !== 'admissible') {
        const verdict = typeof evaluation?.verdict === 'string'
          && /^[a-z_]{1,64}$/.test(evaluation.verdict)
          ? evaluation.verdict : 'unverifiable';
        return { valid: false, reason: `admissibility_${verdict}` };
      }
      let projection: any;
      try {
        projection = await project({
          evaluation: Object.freeze(canonicalCopy(evaluation)),
          bundle: evidence.bundle,
        });
      } catch {
        return { valid: false, reason: 'admissibility_projection_failed' };
      }
      if (!isDataRecord(projection)) {
        return { valid: false, reason: 'admissibility_projection_invalid' };
      }
      return {
        valid: true,
        binding_digest: context.expectedBindingDigest,
        policy_digest: profileHash,
        subjects: projection.subjects,
        key_fingerprints: projection.key_fingerprints,
        issued_at: projection.issued_at,
        expires_at: projection.expires_at,
        revocation_checked_at: projection.revocation_checked_at ?? null,
      };
    },
  });
}

export function compileRelianceProgram(
  envelope: unknown,
  { trustedKeys = {}, profiles = [] }: {
    trustedKeys?: Record<string, unknown>;
    profiles?: unknown[];
  } = {},
): CompiledRelianceProgram {
  const verified = verifyRelianceProgram(envelope, { trustedKeys });
  if (verified.valid !== true) {
    refuse(verified.reason ?? 'source_unverified', 'reliance program source did not verify');
  }
  return compileVerifiedSource(envelope as JsonRecord, verified, profiles, RELIANCE_PROGRAM_VERSION);
}

/**
 * ONE compilation body for both versions. The v1 and v2 compilers differ ONLY
 * in which Trust Program profile marker they emit and which validator checks
 * the result, so the stage/requirement mapping, the profile pin check, and the
 * trace cannot drift between them.
 */
function compileVerifiedSource(
  signed: JsonRecord,
  verified: JsonRecord,
  profiles: unknown[],
  resultVersion: string,
): CompiledRelianceProgram {
  const hybrid = resultVersion === RELIANCE_PROGRAM_V2_VERSION;
  const programVersion = hybrid ? TRUST_PROGRAM_V2_VERSION : TRUST_PROGRAM_VERSION;
  const source = canonicalCopy(signed.source);
  const catalog = profileMap(profiles);
  const trace: CompiledRelianceProgram['trace'] = [];
  const stages = source.stages.map((stage: JsonRecord) => ({
    stage_id: stage.stage_id,
    depends_on: [...stage.depends_on],
    rule: canonicalCopy(stage.rule),
    requirements: stage.profiles.map((reference: JsonRecord, index: number) => {
      const profile = catalog.get(reference.profile_id);
      if (!profile || profile.profile_hash !== reference.profile_hash) {
        refuse('profile_pin_mismatch', `profile ${reference.profile_id} does not match the relying-party pin`);
      }
      const requirementId = `admissibility-${String(index + 1).padStart(2, '0')}`;
      trace.push({
        stage_id: stage.stage_id,
        requirement_id: requirementId,
        profile_id: reference.profile_id,
        profile_hash: reference.profile_hash,
      });
      return {
        requirement_id: requirementId,
        evidence_type: RELIANCE_PROGRAM_ADMISSIBILITY_EVIDENCE,
        verifier_profile: RELIANCE_PROGRAM_ADMISSIBILITY_VERIFIER,
        policy_digest: reference.profile_hash,
        max_age_sec: reference.evaluation_max_age_sec,
        revocation_required: reference.revocation_required,
      };
    }),
  }));
  const program = {
    '@version': programVersion,
    program_id: source.program_id,
    version: source.version,
    root_caid: source.root_caid,
    action_digest: source.action_digest,
    valid_from: source.valid_from,
    expires_at: source.expires_at,
    stages,
    execution: canonicalCopy(source.execution),
  };
  const checked = hybrid ? validateTrustProgramV2(program) : validateTrustProgram(program);
  if (!checked.valid) {
    refuse('compiled_program_invalid', `compiled Trust Program is invalid: ${checked.reason}`);
  }
  return deepFreeze({
    version: resultVersion as typeof RELIANCE_PROGRAM_VERSION,
    source_digest: verified.source_digest,
    relying_party_id: verified.relying_party_id,
    program,
    program_digest: hybrid ? trustProgramV2Digest(program) : trustProgramDigest(program),
    trace,
    claim_boundary: 'Compilation proves a pinned RP program maps to the existing Trust Program; it does not prove evidence sufficiency, authorization, or execution.',
  });
}

// ===========================================================================
// EP-RELIANCE-PROGRAM-SOURCE-v2 / EP-RELIANCE-PROGRAM-v2
// the hybrid (Ed25519 + ML-DSA-65) relying-party program source
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the customer-owned Reliance Program
 * source, and moves the SOURCE marker with the envelope: an
 * EP-RELIANCE-PROGRAM-v2 envelope carries an EP-RELIANCE-PROGRAM-SOURCE-v2
 * source, and compiles to an EP-GATE-TRUST-PROGRAM-PROFILE-v2 program.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, key_id, value}`
 *    becomes `proof: {profile, required_algorithms, key_id, public_key,
 *    pq_key_id, pq_public_key, signatures}` -- a wire-format change, so the
 *    envelope takes a new `@version` (-v1 -> -v2), and the source it wraps
 *    takes one too, because the source's own `@version` is inside the signed
 *    bytes. verifyRelianceProgram above is UNCHANGED: handed a v2 envelope it
 *    refuses at `envelope_schema_invalid`, structurally, because a v2 envelope
 *    carries no `signature` member for it to inspect at all. It does not
 *    crash, and it never accepts a hybrid envelope on the strength of the one
 *    leg it understands.
 * 2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (relianceProgramV2SigningBytes). Drop the ML-DSA leg and narrow the set
 *    to ["Ed25519"] and the surviving Ed25519 signature no longer verifies.
 *    Leave the set intact and the missing leg is a structural refusal. The
 *    verifier rebuilds the bytes from the REGISTERED set and the source it
 *    independently re-validated and re-digested.
 * 4. V1 COMPATIBILITY. verifyRelianceProgram and compileRelianceProgram stay
 *    SYNCHRONOUS and untouched. verifyRelianceProgramV2 /
 *    compileRelianceProgramV2 are SEPARATE async entry points (ML-DSA
 *    verification is inherently async); verifyRelianceProgramEnvelope routes
 *    on `@version` for callers holding a mixed bag.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    is `{valid:false, reason}` with the same reason vocabulary as v1 plus the
 *    hybrid-specific ones. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg. Compilation keeps v1's throw-on-refusal contract, because
 *    a compiler is issuer-side.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: compilation proves a pinned RP program
 * maps to the existing Trust Program. It does not prove evidence sufficiency,
 * authorization, or execution. The ML-DSA-65 backend is @noble/post-quantum's
 * pure-JS FIPS 204 implementation, not independently audited and not a FIPS
 * validated module; signing or verifying under this profile is not a
 * certification claim, and this profile is opt-in.
 */

export const RELIANCE_PROGRAM_SOURCE_V2_VERSION = 'EP-RELIANCE-PROGRAM-SOURCE-v2';
export const RELIANCE_PROGRAM_V2_VERSION = 'EP-RELIANCE-PROGRAM-v2';

/** The registered required algorithm set, in canonical order. */
export const RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const DOMAIN_V2 = `${RELIANCE_PROGRAM_V2_VERSION}\0`;
const ENVELOPE_V2_KEYS = new Set(['@version', 'source', 'source_digest', 'proof']);
const PROOF_V2_KEYS = new Set([
  'profile', 'required_algorithms', 'key_id', 'public_key',
  'pq_key_id', 'pq_public_key', 'signatures',
]);
const TRUSTED_SIGNER_V2_KEYS = new Set(['relying_party_id', 'public_key', 'pq_public_key']);

/** A v2 relying-party pin: BOTH public halves, pinned out of band by key_id. */
export interface RelianceProgramV2KeyPin {
  relying_party_id: string;
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

export interface RelianceProgramV2SigningKeys {
  ed: { privateKey: crypto.KeyLike; publicKey?: string };
  pq: { secretKey: Uint8Array | string; publicKey: string };
}

function relianceV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function reliancePqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:reliance-program-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
  } catch {
    return '';
  }
}

function relianceAgilityPassthrough(opts: AgilityOptions | undefined): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts?.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts?.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

/**
 * The bytes BOTH legs sign: the same domain-separated canonical source as v1
 * under the v2 domain tag, plus the committed `required_algorithms` set.
 * Recomputed independently by the verifier from the PRESENTED source and the
 * REGISTERED set. See move 3 above.
 */
export function relianceProgramV2SigningBytes(
  source: JsonRecord,
  requiredAlgorithms: readonly string[] = RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!relianceV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('relianceProgramV2SigningBytes: algorithm set is not the registered EP-RELIANCE-PROGRAM-v2 set');
  }
  return Buffer.concat([
    Buffer.from(DOMAIN_V2, 'utf8'),
    Buffer.from(canonicalize({ source, required_algorithms: [...requiredAlgorithms] }), 'utf8'),
  ]);
}

/** Digest a v2 relying-party source. Refuses an invalid or v1-marked source. */
export function relianceProgramSourceV2Digest(source: unknown): string {
  validateSourceUnder(source, RELIANCE_PROGRAM_SOURCE_V2_VERSION);
  return digest(source);
}

/**
 * Sign a v2 source under BOTH registered algorithms. Throws on an invalid
 * source, malformed keys, or an unavailable ML-DSA backend: an envelope
 * missing the ML-DSA leg must never be emitted, only refused.
 */
export async function signRelianceProgramV2(
  source: unknown,
  keys: RelianceProgramV2SigningKeys,
): Promise<JsonRecord> {
  validateSourceUnder(source, RELIANCE_PROGRAM_SOURCE_V2_VERSION);
  if (!keys?.ed?.privateKey || !keys?.pq?.secretKey || typeof keys?.pq?.publicKey !== 'string') {
    refuse('signing_key_invalid', 'reliance program v2 requires ed.privateKey, pq.secretKey, and pq.publicKey');
  }
  const edKey = keys.ed.privateKey instanceof crypto.KeyObject
    ? keys.ed.privateKey : crypto.createPrivateKey(keys.ed.privateKey as any);
  if (edKey.asymmetricKeyType !== 'ed25519') {
    refuse('signing_key_invalid', 'reliance program classical signing key must be Ed25519');
  }
  const pqKeyId = reliancePqKeyId(keys.pq.publicKey);
  if (!pqKeyId) {
    refuse('signing_key_invalid', 'reliance program ML-DSA-65 public key must be raw base64url bytes');
  }
  const frozenSource = canonicalCopy(source) as JsonRecord;
  const requiredAlgorithms = [...RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS];
  const bytes = relianceProgramV2SigningBytes(frozenSource, requiredAlgorithms);
  const signingKeys: AgileSigningKey[] = [
    { alg: 'Ed25519', private_key: edKey },
    { alg: 'ML-DSA-65', private_key: keys.pq.secretKey },
  ];
  const signatures = await signAgileSet(new Uint8Array(bytes), signingKeys);
  const edPublicKey = keys.ed.publicKey ?? crypto.createPublicKey(edKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  return deepFreeze({
    '@version': RELIANCE_PROGRAM_V2_VERSION,
    source: frozenSource,
    source_digest: digest(frozenSource),
    proof: {
      profile: RELIANCE_PROGRAM_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      key_id: frozenSource.relying_party.key_id,
      public_key: edPublicKey,
      pq_key_id: pqKeyId,
      pq_public_key: keys.pq.publicKey,
      signatures,
    },
  });
}

/**
 * FAIL-CLOSED hybrid verifier for one EP-RELIANCE-PROGRAM-v2 envelope. Never
 * throws on caller input; an envelope NEVER verifies on one leg alone. The
 * result shape matches verifyRelianceProgram exactly so callers can route.
 */
export async function verifyRelianceProgramV2(
  envelope: unknown,
  { trustedKeys = {}, mldsaBackend, mldsaBackendLoader }: {
    trustedKeys?: Record<string, unknown>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
  } = {},
): Promise<JsonRecord> {
  try {
    // 1. Version marker + closed shape.
    if (!exact(envelope, ENVELOPE_V2_KEYS) || envelope['@version'] !== RELIANCE_PROGRAM_V2_VERSION
        || !exact(envelope.proof, PROOF_V2_KEYS)
        || envelope.proof.profile !== RELIANCE_PROGRAM_V2_VERSION
        || typeof envelope.source_digest !== 'string' || !DIGEST.test(envelope.source_digest)
        || typeof envelope.proof.key_id !== 'string'
        || typeof envelope.proof.public_key !== 'string'
        || typeof envelope.proof.pq_public_key !== 'string'
        || typeof envelope.proof.pq_key_id !== 'string') {
      return { valid: false, reason: 'envelope_schema_invalid', source_digest: null };
    }
    const proof = envelope.proof as JsonRecord;

    // 2. Committed algorithm set: exact and order-sensitive. A narrowed set is
    //    the stripping attack's cover story, refused structurally here and
    //    (independently) by the signature check, which rebuilds the bytes from
    //    the REGISTERED set regardless of what the envelope claims.
    if (!relianceV2AlgorithmSetRegistered(proof.required_algorithms)) {
      return { valid: false, reason: 'algorithm_set_unsupported', source_digest: null };
    }

    // 3. Exactly one signature per required algorithm.
    const signatures = Array.isArray(proof.signatures) ? proof.signatures as AgileSignature[] : null;
    if (!signatures) return { valid: false, reason: 'signature_set_invalid', source_digest: null };
    const presented = new Set<string>();
    for (const entry of signatures) {
      if (!isRecord(entry) || typeof entry.alg !== 'string' || typeof entry.sig !== 'string') {
        return { valid: false, reason: 'signature_set_invalid', source_digest: null };
      }
      if (presented.has(entry.alg)) {
        return { valid: false, reason: 'signature_set_invalid', source_digest: null };
      }
      presented.add(entry.alg);
    }
    for (const alg of RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) {
        return { valid: false, reason: 'signature_leg_missing', source_digest: null };
      }
    }
    for (const alg of presented) {
      if (!(RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return { valid: false, reason: 'signature_set_invalid', source_digest: null };
      }
    }

    // 4. Source: independently re-validated and re-digested, same as v1.
    try { validateSourceUnder(envelope.source, RELIANCE_PROGRAM_SOURCE_V2_VERSION); } catch (error) {
      return {
        valid: false,
        reason: error instanceof RelianceProgramValidationError ? error.code : 'source_schema_invalid',
        source_digest: null,
      };
    }
    if (proof.key_id !== envelope.source.relying_party.key_id) {
      return { valid: false, reason: 'signature_key_mismatch', source_digest: envelope.source_digest };
    }
    const computed = digest(envelope.source);
    if (computed !== envelope.source_digest) {
      return { valid: false, reason: 'source_digest_mismatch', source_digest: computed };
    }

    // 5. Relying-party keys: BOTH halves pinned, and the presented halves must
    //    equal the pinned ones. Identified-but-not-trusted, per leg: a key_id
    //    pinned for v1 only (Ed25519 half alone) does NOT satisfy a v2 pin.
    if (!isRecord(trustedKeys) || !Object.hasOwn(trustedKeys, proof.key_id as string)) {
      return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
    }
    const signer = trustedKeys[proof.key_id as string];
    if (!exact(signer, TRUSTED_SIGNER_V2_KEYS)
        || signer.relying_party_id !== envelope.source.relying_party.id) {
      return { valid: false, reason: 'relying_party_identity_mismatch', source_digest: computed };
    }
    if (typeof signer.public_key !== 'string' || signer.public_key !== proof.public_key
        || typeof signer.pq_public_key !== 'string' || signer.pq_public_key !== proof.pq_public_key
        // Curve-pinned: an Ed448 (or any non-Ed25519) SPKI presented as the
        // classical half fails here as well as in the signature check.
        || publicKey(signer.public_key) === null
        || reliancePqKeyId(signer.pq_public_key) === ''
        || proof.pq_key_id !== reliancePqKeyId(signer.pq_public_key)) {
      return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
    }

    // 6. Signature set over bytes rebuilt from the RE-VALIDATED source and the
    //    REGISTERED algorithm set, under the PINNED keys. Never fall back to
    //    the envelope's own self-asserted key material.
    let bytes: Buffer;
    try {
      bytes = relianceProgramV2SigningBytes(
        envelope.source as JsonRecord,
        RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS,
      );
    } catch {
      return { valid: false, reason: 'source_not_canonical', source_digest: computed };
    }
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(bytes),
        signatures,
        [
          { alg: 'Ed25519', public_key: signer.public_key },
          { alg: 'ML-DSA-65', public_key: signer.pq_public_key },
        ],
        {
          ...relianceAgilityPassthrough({ mldsaBackend, mldsaBackendLoader }),
          policy: 'hybrid_all',
          requiredAlgorithms: [...RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      // verifyAgileSignatureSet documents that it never throws; an injected
      // backend that does is still a refusal here, never a pass.
      setResult = null;
    }
    if (setResult?.verified !== true) {
      return {
        valid: false,
        reason: `signature_invalid:${String(setResult?.reason ?? 'signature_set_unverified')}`,
        source_digest: computed,
      };
    }
    return {
      valid: true,
      reason: null,
      source_digest: computed,
      relying_party_id: envelope.source.relying_party.id,
      key_id: proof.key_id,
    };
  } catch {
    return { valid: false, reason: 'envelope_schema_invalid', source_digest: null };
  }
}

/**
 * Route an envelope of EITHER version to its verifier. v1 envelopes keep the
 * exact v1 verdict; v2 envelopes get the hybrid check. An envelope whose
 * `@version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export async function verifyRelianceProgramEnvelope(
  envelope: unknown,
  options: {
    trustedKeys?: Record<string, unknown>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
  } = {},
): Promise<JsonRecord> {
  if (isRecord(envelope) && envelope['@version'] === RELIANCE_PROGRAM_V2_VERSION) {
    return verifyRelianceProgramV2(envelope, options);
  }
  return verifyRelianceProgram(envelope, { trustedKeys: options.trustedKeys });
}

/**
 * Compile a verified v2 envelope into an EP-GATE-TRUST-PROGRAM-PROFILE-v2
 * program. Same compilation body as v1 (compileVerifiedSource); only the
 * emitted profile marker and its validator differ. Refuses by throwing, like
 * v1: a compiler is issuer-side, not attacker-facing.
 */
export async function compileRelianceProgramV2(
  envelope: unknown,
  { trustedKeys = {}, profiles = [], mldsaBackend, mldsaBackendLoader }: {
    trustedKeys?: Record<string, unknown>;
    profiles?: unknown[];
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
  } = {},
): Promise<CompiledRelianceProgram> {
  const verified = await verifyRelianceProgramV2(envelope, {
    trustedKeys, mldsaBackend, mldsaBackendLoader,
  });
  if (verified.valid !== true) {
    refuse(verified.reason ?? 'source_unverified', 'reliance program source did not verify');
  }
  return compileVerifiedSource(envelope as JsonRecord, verified, profiles, RELIANCE_PROGRAM_V2_VERSION);
}
