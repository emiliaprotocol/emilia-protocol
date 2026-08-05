// SPDX-License-Identifier: Apache-2.0
/**
 * Signed local-policy decision evidence for AEB composition.
 *
 * This module does not implement a policy engine and does not convert a
 * machine-policy ALLOW into human authorization. It lets an OPA or Cerbos
 * integration sign the exact decision it observed, then exposes that result as
 * one relying-party-pinned AEB evidence leg. A consequential Gate policy can
 * require this leg together with independent human authorization evidence.
 */
import crypto, { type KeyObject } from 'node:crypto';

// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- narrowed and cross-checked below.
import { computeCaid } from '../vendor/caid.mjs';
import {
  canonicalizeAeb,
  digestAeb,
  type Acceptance,
  type AebAdapter,
  type AebAdapterInput,
  type AebDigest,
  type AebMappingResult,
  type AebNativeResult,
  type AebPinnedProfile,
  type AebStatusInput,
} from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, unknown>;

export const POLICY_DECISION_EVIDENCE_VERSION = 'EP-POLICY-DECISION-EVIDENCE-v1';
export const POLICY_DECISION_EVIDENCE_TYP = 'ep-policy-decision-evidence+jwt';
export const POLICY_DECISION_EVIDENCE_ADAPTER_ID = 'native:policy-decision-evidence';
export const POLICY_DECISION_EVIDENCE_ADAPTER_VERSION = '1';
export const POLICY_DECISION_EVIDENCE_CONFIG_VERSION = 'EP-POLICY-DECISION-EVIDENCE-CONFIG-v1';
export const POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION = 'EP-POLICY-DECISION-EVIDENCE-ROOT-v1';
export const POLICY_DECISION_EVIDENCE_MAPPING_VERSION = 'EP-POLICY-DECISION-CAID-MAPPING-v1';
export const POLICY_DECISION_EVIDENCE_MAPPER_ID = 'mapper:policy-decision-exact-action-v1';

export type PolicyEngineKind = 'opa' | 'cerbos';
export type MachinePolicyDecision = 'ALLOW' | 'DENY' | 'INDETERMINATE';

export interface PolicyDecisionEvidenceClaims {
  ep_version: typeof POLICY_DECISION_EVIDENCE_VERSION;
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  engine: PolicyEngineKind;
  policy_id: string;
  policy_digest: AebDigest;
  policy_decision: MachinePolicyDecision;
  action: Obj;
  action_digest: AebDigest;
  native_decision_ref: string;
  native_result_digest: AebDigest;
}
export interface PolicyDecisionEvidenceSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface PolicyDecisionEvidenceTrustRoot {
  '@version': typeof POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION;
  issuer: string;
  key_id: string;
  algorithm: 'EdDSA';
  public_key: string;
}

export interface PolicyDecisionEvidenceAdapterConfig {
  '@version': typeof POLICY_DECISION_EVIDENCE_CONFIG_VERSION;
  evidence_role: string;
  subject: { id: string; kind: 'workload' | 'system' };
  issuer: string;
  audience: string;
  action_type: string;
  allowed_engines: PolicyEngineKind[];
  allowed_policy_digests: AebDigest[];
  clock_skew_seconds: number;
  max_decision_age_seconds: number;
}

export interface PolicyDecisionProjectionInput {
  issuer: string;
  subject: string;
  audience: string;
  issued_at: number;
  expires_at: number;
  decision_id: string;
  policy_id: string;
  policy_digest: AebDigest;
  action: unknown;
  native_decision_ref: string;
}

export interface OpaPolicyDecisionProjectionInput extends PolicyDecisionProjectionInput {
  result: unknown;
}

export interface CerbosPolicyDecisionProjectionInput extends PolicyDecisionProjectionInput {
  effect: unknown;
}

interface ParsedPins {
  config: PolicyDecisionEvidenceAdapterConfig;
  root: PolicyDecisionEvidenceTrustRoot & { key: KeyObject };
  configDigest: AebDigest;
  rootsDigest: AebDigest;
}

interface VerifiedStatement {
  claims: PolicyDecisionEvidenceClaims;
  replayUnit: AebDigest;
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@-]{0,511}$/;
const URI_RE = /^https:\/\/[^\s]+$/;
const HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const CLAIM_KEYS = new Set([
  'ep_version', 'iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'engine', 'policy_id',
  'policy_digest', 'policy_decision', 'action', 'action_digest', 'native_decision_ref',
  'native_result_digest',
]);
const CONFIG_KEYS = new Set([
  '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
  'allowed_engines', 'allowed_policy_digests', 'clock_skew_seconds', 'max_decision_age_seconds',
]);
const SUBJECT_KEYS = new Set(['id', 'kind']);
const ROOT_KEYS = new Set(['@version', 'issuer', 'key_id', 'algorithm', 'public_key']);

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, allowed: ReadonlySet<string>): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === allowed.size
    && keys.every((key) => typeof key === 'string' && allowed.has(key));
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validRole(value: unknown): value is string {
  return validIdentifier(value) && /^[a-z][a-z0-9-]*$/.test(value);
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function sortedUniqueStrings(value: unknown, predicate: (item: unknown) => boolean): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(predicate)
    && new Set(value).size === value.length;
}

function safeDigest(value: unknown): AebDigest {
  try { return digestAeb(value); } catch { return digestAeb({ invalid_value: true }); }
}

function sameDigest(left: unknown, right: unknown): boolean {
  try { return digestAeb(left) === digestAeb(right); } catch { return false; }
}

function canonicalAction(value: unknown, actionType?: string): Obj | null {
  if (!isRecord(value) || typeof value.action_type !== 'string'
      || !ACTION_TYPE_RE.test(value.action_type)
      || (actionType !== undefined && value.action_type !== actionType)
      || !isRecord(value.parameters)) return null;
  try {
    return JSON.parse(canonicalizeAeb(value)) as Obj;
  } catch {
    return null;
  }
}

function validPrivateKey(key: unknown): key is KeyObject {
  return key instanceof crypto.KeyObject && key.type === 'private' && key.asymmetricKeyType === 'ed25519';
}

function decodeBase64url(value: unknown): Buffer | null {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length > 0 && decoded.toString('base64url') === value ? decoded : null;
  } catch { return null; }
}

function publicKey(spki: unknown): KeyObject | null {
  const der = decodeBase64url(spki);
  if (!der) return null;
  try {
    const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519'
      && key.export({ type: 'spki', format: 'der' }).equals(der) ? key : null;
  } catch { return null; }
}

function parseJsonSegment(value: string): Obj | null {
  const decoded = decodeBase64url(value);
  if (!decoded) return null;
  const text = decoded.toString('utf8');
  if (!strictJsonGate(text).ok) return null;
  try {
    const parsed = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch { return null; }
}

function cloneClaims(value: PolicyDecisionEvidenceClaims): PolicyDecisionEvidenceClaims {
  return JSON.parse(canonicalizeAeb(value)) as PolicyDecisionEvidenceClaims;
}

function parseConfig(value: unknown): PolicyDecisionEvidenceAdapterConfig | null {
  if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== POLICY_DECISION_EVIDENCE_CONFIG_VERSION
      || !validRole(value.evidence_role) || !isRecord(value.subject)
      || !exactKeys(value.subject, SUBJECT_KEYS) || !validIdentifier(value.subject.id)
      || !['workload', 'system'].includes(String(value.subject.kind))
      || typeof value.issuer !== 'string' || !URI_RE.test(value.issuer)
      || typeof value.audience !== 'string' || !URI_RE.test(value.audience)
      || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
      || !sortedUniqueStrings(value.allowed_engines, (item) => item === 'opa' || item === 'cerbos')
      || !sortedUniqueStrings(value.allowed_policy_digests, validDigest)
      || !safeInteger(value.clock_skew_seconds) || !safeInteger(value.max_decision_age_seconds)
      || Number(value.max_decision_age_seconds) === 0) return null;
  return JSON.parse(canonicalizeAeb(value)) as PolicyDecisionEvidenceAdapterConfig;
}

function parseRoot(value: unknown, issuer: string): (PolicyDecisionEvidenceTrustRoot & { key: KeyObject }) | null {
  if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
      || value['@version'] !== POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION
      || value.issuer !== issuer || !validIdentifier(value.key_id)
      || value.algorithm !== 'EdDSA' || typeof value.public_key !== 'string') return null;
  const key = publicKey(value.public_key);
  return key ? { ...(JSON.parse(canonicalizeAeb(value)) as PolicyDecisionEvidenceTrustRoot), key } : null;
}

function parseConstructorPins(input: {
  config: PolicyDecisionEvidenceAdapterConfig;
  trust_roots: readonly PolicyDecisionEvidenceTrustRoot[];
}): ParsedPins {
  const config = parseConfig(input?.config);
  if (!config || !Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
    throw new TypeError('one valid relying-party-pinned policy decision root is required');
  }
  const root = parseRoot(input.trust_roots[0], config.issuer);
  if (!root) throw new TypeError('valid Ed25519 policy decision root required');
  return {
    config,
    root,
    configDigest: digestAeb(config),
    rootsDigest: digestAeb(input.trust_roots),
  };
}

function makeClaims(
  input: PolicyDecisionProjectionInput,
  engine: PolicyEngineKind,
  decision: MachinePolicyDecision,
  nativeResult: unknown,
): PolicyDecisionEvidenceClaims {
  const action = canonicalAction(input.action);
  if (!action || typeof input.issuer !== 'string' || !URI_RE.test(input.issuer)
      || !validIdentifier(input.subject) || typeof input.audience !== 'string' || !URI_RE.test(input.audience)
      || !safeInteger(input.issued_at) || !safeInteger(input.expires_at)
      || input.expires_at <= input.issued_at || !validIdentifier(input.decision_id)
      || !validIdentifier(input.policy_id) || !validDigest(input.policy_digest)
      || !validIdentifier(input.native_decision_ref)) {
    throw new TypeError('valid strict policy decision projection required');
  }
  // The native result digest must fail, not silently omit, executable or
  // non-JSON material such as Symbols, accessors, sparse arrays, or cycles.
  const nativeResultDigest = digestAeb(nativeResult);
  return {
    ep_version: POLICY_DECISION_EVIDENCE_VERSION,
    iss: input.issuer,
    sub: input.subject,
    aud: input.audience,
    iat: input.issued_at,
    exp: input.expires_at,
    jti: input.decision_id,
    engine,
    policy_id: input.policy_id,
    policy_digest: input.policy_digest,
    policy_decision: decision,
    action,
    action_digest: digestAeb(action),
    native_decision_ref: input.native_decision_ref,
    native_result_digest: nativeResultDigest,
  };
}

/** Project an OPA boolean result. Non-boolean results are explicitly indeterminate. */
export function projectOpaPolicyDecision(input: OpaPolicyDecisionProjectionInput): PolicyDecisionEvidenceClaims {
  const decision: MachinePolicyDecision = input.result === true
    ? 'ALLOW' : input.result === false ? 'DENY' : 'INDETERMINATE';
  return makeClaims(input, 'opa', decision, input.result);
}

/** Project a Cerbos CheckResources effect. Unknown effects are explicitly indeterminate. */
export function projectCerbosPolicyDecision(input: CerbosPolicyDecisionProjectionInput): PolicyDecisionEvidenceClaims {
  const decision: MachinePolicyDecision = input.effect === 'EFFECT_ALLOW'
    ? 'ALLOW' : input.effect === 'EFFECT_DENY' ? 'DENY' : 'INDETERMINATE';
  return makeClaims(input, 'cerbos', decision, input.effect);
}

function signableClaims(value: unknown): value is PolicyDecisionEvidenceClaims {
  if (!isRecord(value) || !exactKeys(value, CLAIM_KEYS)
      || value.ep_version !== POLICY_DECISION_EVIDENCE_VERSION
      || typeof value.iss !== 'string' || !URI_RE.test(value.iss)
      || !validIdentifier(value.sub) || typeof value.aud !== 'string' || !URI_RE.test(value.aud)
      || !safeInteger(value.iat) || !safeInteger(value.exp) || Number(value.exp) <= Number(value.iat)
      || !validIdentifier(value.jti) || !['opa', 'cerbos'].includes(String(value.engine))
      || !validIdentifier(value.policy_id) || !validDigest(value.policy_digest)
      || !['ALLOW', 'DENY', 'INDETERMINATE'].includes(String(value.policy_decision))
      || !validDigest(value.action_digest) || !validIdentifier(value.native_decision_ref)
      || !validDigest(value.native_result_digest)) return false;
  const action = canonicalAction(value.action);
  return action !== null && digestAeb(action) === value.action_digest;
}

/** Sign a normalized policy-engine observation with the local bridge key. */
export function signPolicyDecisionEvidence(
  claims: PolicyDecisionEvidenceClaims,
  signer: PolicyDecisionEvidenceSigner,
): string {
  if (!signableClaims(claims) || !validIdentifier(signer?.key_id) || !validPrivateKey(signer?.private_key)) {
    throw new TypeError('valid closed policy decision claims and Ed25519 signer required');
  }
  const header = canonicalizeAeb({ alg: 'EdDSA', typ: POLICY_DECISION_EVIDENCE_TYP, kid: signer.key_id });
  const payload = canonicalizeAeb(claims);
  const protectedHeader = Buffer.from(header, 'utf8').toString('base64url');
  const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
  const signingInput = `${protectedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), signer.private_key).toString('base64url');
  return `${signingInput}.${signature}`;
}

function parseClaims(value: unknown, config: PolicyDecisionEvidenceAdapterConfig): PolicyDecisionEvidenceClaims | null {
  if (!signableClaims(value) || value.iss !== config.issuer || value.aud !== config.audience
      || !config.allowed_engines.includes(value.engine)
      || !config.allowed_policy_digests.includes(value.policy_digest)
      || canonicalAction(value.action, config.action_type) === null) return null;
  return cloneClaims(value);
}

function verifyStatement(artifact: unknown, pins: ParsedPins, now: string):
  { ok: true; value: VerifiedStatement } |
  { ok: false; reason: string; acceptance: Acceptance; verified: boolean } {
  if (typeof artifact !== 'string') {
    return { ok: false, reason: 'policy-decision:artifact_malformed', acceptance: 'REJECTED', verified: false };
  }
  const parts = artifact.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return { ok: false, reason: 'policy-decision:jws_malformed', acceptance: 'REJECTED', verified: false };
  }
  const header = parseJsonSegment(parts[0]);
  const payload = parseJsonSegment(parts[1]);
  const signature = decodeBase64url(parts[2]);
  if (!header || !payload || !signature || signature.length !== 64
      || !exactKeys(header, HEADER_KEYS) || header.alg !== 'EdDSA'
      || header.typ !== POLICY_DECISION_EVIDENCE_TYP || header.kid !== pins.root.key_id
      || !crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), pins.root.key, signature)) {
    return { ok: false, reason: 'policy-decision:signature_or_header_invalid', acceptance: 'REJECTED', verified: false };
  }
  const claims = parseClaims(payload, pins.config);
  if (!claims) {
    return { ok: false, reason: 'policy-decision:claims_or_policy_pin_invalid', acceptance: 'REJECTED', verified: true };
  }
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) {
    return { ok: false, reason: 'policy-decision:now_invalid', acceptance: 'INDETERMINATE', verified: true };
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  if (claims.iat > nowSeconds + pins.config.clock_skew_seconds) {
    return { ok: false, reason: 'policy-decision:issued_in_future', acceptance: 'INDETERMINATE', verified: true };
  }
  if (claims.exp <= nowSeconds - pins.config.clock_skew_seconds) {
    return { ok: false, reason: 'policy-decision:expired', acceptance: 'REJECTED', verified: true };
  }
  if (nowSeconds - claims.iat > pins.config.max_decision_age_seconds + pins.config.clock_skew_seconds) {
    return { ok: false, reason: 'policy-decision:too_old', acceptance: 'INDETERMINATE', verified: true };
  }
  return {
    ok: true,
    value: { claims, replayUnit: digestAeb({ issuer: claims.iss, decision_id: claims.jti }) },
  };
}

function statusDigest(status: AebStatusInput): AebDigest {
  return safeDigest({
    checked_at: status?.checked_at,
    expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked,
    revoked: status?.revoked,
    consumed: status?.consumed,
    unavailable: status?.unavailable === true,
  });
}

function statusDisposition(status: AebStatusInput, now: string): { acceptance: Acceptance; reasons: string[] } {
  const reasons: string[] = [];
  const nowMs = Date.parse(now);
  const checkedMs = Date.parse(status?.checked_at);
  const expiresMs = Date.parse(status?.expires_at);
  if (status?.unavailable === true) reasons.push('status_unavailable');
  if (status?.revocation_checked !== true) reasons.push('revocation_not_checked');
  if (status?.revoked === true) reasons.push('evidence_revoked');
  if (status?.consumed === true) reasons.push('evidence_consumed');
  if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
    reasons.push('status_time_invalid');
  } else {
    if (checkedMs > nowMs) reasons.push('status_checked_in_future');
    if (expiresMs <= nowMs) reasons.push('status_expired');
  }
  const unique = [...new Set(reasons)].sort();
  if (status?.revoked === true || status?.consumed === true
      || (Number.isFinite(expiresMs) && expiresMs <= nowMs)) {
    return { acceptance: 'REJECTED', reasons: unique };
  }
  return unique.length === 0
    ? { acceptance: 'ACCEPTED', reasons: [] }
    : { acceptance: 'INDETERMINATE', reasons: unique };
}

function combineAcceptance(left: Acceptance, right: Acceptance): Acceptance {
  if (left === 'REJECTED' || right === 'REJECTED') return 'REJECTED';
  if (left === 'INDETERMINATE' || right === 'INDETERMINATE') return 'INDETERMINATE';
  return 'ACCEPTED';
}

export function createPolicyDecisionEvidenceActionDefinition(actionType: string): Obj {
  if (!ACTION_TYPE_RE.test(actionType)) throw new TypeError('valid CAID action type required');
  return {
    '@version': POLICY_DECISION_EVIDENCE_MAPPING_VERSION,
    source: 'signed-local-policy-decision-exact-action',
    action_type: actionType,
    suite: 'jcs-sha256',
    definitions: [{
      action_type: actionType,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'parameters', type: 'object' },
      ],
      optional_fields: [],
    }],
  };
}

function validMappingProfile(profile: AebPinnedProfile, actionType: string): unknown[] | null {
  if (!isRecord(profile) || profile.version !== POLICY_DECISION_EVIDENCE_MAPPING_VERSION
      || profile.mapper_id !== POLICY_DECISION_EVIDENCE_MAPPER_ID
      || !isRecord(profile.resolver) || profile.resolver.id !== POLICY_DECISION_EVIDENCE_MAPPER_ID
      || profile.resolver.version !== '1' || !validDigest(profile.resolver.implementation_digest)
      || !isRecord(profile.semantic_equivalence)
      || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
      || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
      || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
      || profile.semantic_equivalence.omitted_material_fields.length !== 0
      || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
      || !isRecord(profile.definition)
      || !sameDigest(profile.definition, createPolicyDecisionEvidenceActionDefinition(actionType))
      || !Array.isArray(profile.definition.definitions)) return null;
  return profile.definition.definitions;
}

function fallback(input: Omit<AebAdapterInput, 'profile'>, pins: ParsedPins): AebNativeResult {
  const evidenceDigest = safeDigest(input.artifact);
  return {
    native_verification: 'FAILED',
    acceptance: 'REJECTED',
    evidence_digest: evidenceDigest,
    status_digest: statusDigest(input.status),
    evidence_role: pins.config.evidence_role,
    subject: { ...pins.config.subject },
    replay_unit: evidenceDigest,
    reasons: [],
  };
}

/**
 * Build the AEB adapter under relying-party-pinned config and bridge keys.
 * The bridge key proves only what this local integration observed. It does not
 * prove complete mediation, policy correctness, human intent, or authorization.
 */
export function createPolicyDecisionEvidenceAdapter(constructorPins: {
  config: PolicyDecisionEvidenceAdapterConfig;
  trust_roots: readonly PolicyDecisionEvidenceTrustRoot[];
}): AebAdapter {
  const pins = parseConstructorPins(constructorPins);
  return Object.freeze({
    id: POLICY_DECISION_EVIDENCE_ADAPTER_ID,
    version: POLICY_DECISION_EVIDENCE_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      const result = fallback(input, pins);
      try {
        if (safeDigest(input.adapter_config) !== pins.configDigest
            || safeDigest(input.trust_roots) !== pins.rootsDigest) {
          result.reasons = ['policy-decision:constructor_pin_mismatch'];
          return result;
        }
        const verified = verifyStatement(input.artifact, pins, input.now);
        if (!verified.ok) {
          result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
          result.acceptance = verified.acceptance;
          result.reasons = [verified.reason];
          return result;
        }
        result.native_verification = 'VERIFIED';
        result.replay_unit = verified.value.replayUnit;
        const status = statusDisposition(input.status, input.now);
        const decisionAcceptance: Acceptance = verified.value.claims.policy_decision === 'ALLOW'
          ? 'ACCEPTED'
          : verified.value.claims.policy_decision === 'DENY' ? 'REJECTED' : 'INDETERMINATE';
        result.acceptance = combineAcceptance(decisionAcceptance, status.acceptance);
        result.reasons = [
          ...(verified.value.claims.policy_decision === 'ALLOW'
            ? [] : [`policy-decision:${verified.value.claims.policy_decision.toLowerCase()}`]),
          ...status.reasons,
        ];
        return result;
      } catch {
        result.reasons = ['policy-decision:unexpected_adapter_error'];
        return result;
      }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try {
        if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
        }
        if (safeDigest(input.adapter_config) !== pins.configDigest
            || safeDigest(input.trust_roots) !== pins.rootsDigest) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
        }
        const definitions = validMappingProfile(input.profile, pins.config.action_type);
        if (!definitions) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
        }
        const statement = verifyStatement(input.artifact, pins, input.now);
        if (!statement.ok || statement.value.claims.policy_decision !== 'ALLOW') {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
        }
        const expected = canonicalAction(input.expected_action, pins.config.action_type);
        const action = canonicalAction(statement.value.claims.action, pins.config.action_type);
        if (!expected || !action) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
        }
        const actionDigest = digestAeb(action);
        if (!sameDigest(action, expected)) {
          return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['exact_action_projection_mismatch'] };
        }
        let computed: unknown;
        try { computed = computeCaid(action, { suite: 'jcs-sha256', definitions }); } catch { computed = null; }
        if (!isRecord(computed) || typeof computed.caid !== 'string'
            || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
        }
        if (computed.digest !== actionDigest) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
        }
        return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
      } catch {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['policy-decision:unexpected_mapping_error'] };
      }
    },
  });
}
