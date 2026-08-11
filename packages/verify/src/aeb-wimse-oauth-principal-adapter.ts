// SPDX-License-Identifier: Apache-2.0
/**
 * Experimental WIMSE/OAuth principal-separation profile v2 for AEB.
 *
 * The v1 adapter remains the cryptographic verifier and CAID mapper. This
 * profile adds relying-party-pinned relationships among the logical agent,
 * live workload instance, OAuth client, delegating principal, executor, and
 * tool. Those identities are evidence metadata and never enter the CAID
 * action projection.
 *
 * A missing or malformed relationship is INDETERMINATE. A well-formed signed
 * relationship that conflicts with a relying-party pin is REJECTED. OAuth
 * `sub` is interpreted only according to the grant-specific semantics carried
 * in this profile; it is never inferred to be a human.
 */
import crypto from 'node:crypto';

import {
  canonicalizeAeb,
  digestAeb,
  type Acceptance,
  type AebAdapter,
  type AebAdapterInput,
  type AebMappingResult,
  type AebNativeResult,
} from './aeb-adapter-contract.js';
import {
  createWimseOAuthSptAebAdapter,
  type WimseOAuthSptAdapterConfig,
  type WimseOAuthSptConstructorPins,
  type WimseOAuthSptTrustRoot,
} from './aeb-wimse-oauth-adapter.js';
import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, unknown>;

export const WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_ID =
  'native:wimse-oauth-principal-separation';
export const WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_VERSION = '2';
export const WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION =
  'AEB-WIMSE-OAUTH-PRINCIPAL-CONFIG-v2';
export const WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION =
  'EP-WIMSE-OAUTH-PRINCIPAL-BINDING-v2';
export const WIMSE_OAUTH_PRINCIPAL_BINDING_CLAIM =
  'https://emiliaprotocol.ai/claims/wimse-principal-binding-v2';
export const WIMSE_TLS_EXPORTER_BINDING_VERSION =
  'EP-WIMSE-TLS-EXPORTER-BINDING-v1';
export const WIMSE_TLS_EXPORTER_HEADER = 'wimse-tls-exporter';

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._~+:/%?-]{0,255}$/;
const BINDING_KEYS = new Set([
  '@version',
  'logical_agent_id',
  'workload_instance_id',
  'wimse_subject_semantics',
  'workload_confirmation_jkt',
  'oauth_client_id',
  'oauth_grant_type',
  'oauth_sub_semantics',
  'delegating_principal',
  'executor_id',
  'tool_id',
]);
const PRINCIPAL_KEYS = new Set(['id', 'kind']);
const CONFIG_KEYS = new Set([
  '@version',
  'base',
  'principal_binding',
  'tls_exporter_binding',
]);
const TLS_EXPORTER_POLICY_KEYS = new Set(['mode']);
const TLS_EXPORTER_BINDING_KEYS = new Set([
  '@version',
  'type',
  'tls_version',
  'value',
]);
const CONSTRUCTOR_KEYS = new Set(['config', 'trust_roots', 'current_tls_exporter']);
const ARTIFACT_KEYS = new Set(['wit', 'wpt', 'txn_token', 'request', 'spt_txn', 'spt_intent']);

export type WimseSubjectSemantics = 'logical-agent' | 'workload-instance';
export type OAuthSubSemantics =
  | 'delegating-principal'
  | 'oauth-client'
  | 'workload-instance';

export interface WimseOAuthPrincipalBinding {
  '@version': typeof WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION;
  logical_agent_id: string;
  workload_instance_id: string;
  /** Declares whether the WIT `sub` names the logical agent or live instance. */
  wimse_subject_semantics: WimseSubjectSemantics;
  /** RFC 7638 SHA-256 JWK thumbprint of the live instance confirmation key. */
  workload_confirmation_jkt: string;
  oauth_client_id: string;
  /** Exact grant semantics selected by the relying party; no inference. */
  oauth_grant_type: string;
  /** Exact meaning assigned to OAuth `sub` for this grant. */
  oauth_sub_semantics: OAuthSubSemantics;
  delegating_principal: {
    id: string;
    kind: 'human' | 'organization' | 'system';
  };
  executor_id: string;
  tool_id: string;
}

export interface WimseOAuthPrincipalAdapterConfig {
  '@version': typeof WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION;
  /** Frozen v1 cryptographic and action-mapping pins. */
  base: WimseOAuthSptAdapterConfig;
  /** Exact relationship values accepted by this relying party. */
  principal_binding: WimseOAuthPrincipalBinding;
  /** Explicit relying-party policy. There is no ambient downgrade to optional. */
  tls_exporter_binding: {
    mode: 'not-required' | 'required-single-authentication-instance';
  };
}

export interface WimseTlsExporterBinding {
  '@version': typeof WIMSE_TLS_EXPORTER_BINDING_VERSION;
  type: 'tls-exporter';
  tls_version: '1.3';
  /** Canonical unpadded base64url encoding of the 32-byte RFC 9266 EKM. */
  value: string;
}

export interface WimseOAuthPrincipalConstructorPins {
  config: WimseOAuthPrincipalAdapterConfig;
  trust_roots: readonly WimseOAuthSptTrustRoot[];
  /**
   * Independently obtained from the current TLS connection by the relying
   * party's TLS terminator. A value copied from the presentation is not an
   * acceptable source for this input.
   */
  current_tls_exporter?: WimseTlsExporterBinding;
}

interface ParsedPins {
  config: WimseOAuthPrincipalAdapterConfig;
  trustRoots: readonly WimseOAuthSptTrustRoot[];
  configDigest: string;
  rootsDigest: string;
  baseAdapter: AebAdapter;
  currentTlsExporter: WimseTlsExporterBinding | null;
}

interface RelationshipFailure {
  acceptance: Acceptance;
  reason: string;
}

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, expected: ReadonlySet<string>): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.size && actual.every((key) => expected.has(key));
}

function nonEmptyString(value: unknown, max = 1024): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f\ufffd]/.test(value);
}

function bindingShape(value: unknown): value is WimseOAuthPrincipalBinding {
  return isRecord(value)
    && exactKeys(value, BINDING_KEYS)
    && value['@version'] === WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION
    && nonEmptyString(value.logical_agent_id)
    && nonEmptyString(value.workload_instance_id)
    && value.logical_agent_id !== value.workload_instance_id
    && (value.wimse_subject_semantics === 'logical-agent'
      || value.wimse_subject_semantics === 'workload-instance')
    && typeof value.workload_confirmation_jkt === 'string'
    && decodeB64url(value.workload_confirmation_jkt)?.length === 32
    && nonEmptyString(value.oauth_client_id)
    && typeof value.oauth_grant_type === 'string'
    && TOKEN_RE.test(value.oauth_grant_type)
    && (value.oauth_sub_semantics === 'delegating-principal'
      || value.oauth_sub_semantics === 'oauth-client'
      || value.oauth_sub_semantics === 'workload-instance')
    && isRecord(value.delegating_principal)
    && exactKeys(value.delegating_principal, PRINCIPAL_KEYS)
    && nonEmptyString(value.delegating_principal.id)
    && (value.delegating_principal.kind === 'human'
      || value.delegating_principal.kind === 'organization'
      || value.delegating_principal.kind === 'system')
    && nonEmptyString(value.executor_id)
    && nonEmptyString(value.tool_id);
}

function tlsExporterPolicyShape(
  value: unknown,
): value is WimseOAuthPrincipalAdapterConfig['tls_exporter_binding'] {
  return isRecord(value)
    && exactKeys(value, TLS_EXPORTER_POLICY_KEYS)
    && (value.mode === 'not-required'
      || value.mode === 'required-single-authentication-instance');
}

function tlsExporterBindingShape(value: unknown): value is WimseTlsExporterBinding {
  return isRecord(value)
    && exactKeys(value, TLS_EXPORTER_BINDING_KEYS)
    && value['@version'] === WIMSE_TLS_EXPORTER_BINDING_VERSION
    && value.type === 'tls-exporter'
    && value.tls_version === '1.3'
    && typeof value.value === 'string'
    && decodeB64url(value.value)?.length === 32;
}

function subjectNamedByBinding(binding: WimseOAuthPrincipalBinding): string {
  return binding.wimse_subject_semantics === 'logical-agent'
    ? binding.logical_agent_id
    : binding.workload_instance_id;
}

function parseConstructorPins(value: WimseOAuthPrincipalConstructorPins): ParsedPins {
  if (!isRecord(value)
      || !Object.keys(value).every((key) => CONSTRUCTOR_KEYS.has(key))
      || !Object.hasOwn(value, 'config')
      || !Object.hasOwn(value, 'trust_roots')) {
    throw new TypeError('invalid WIMSE/OAuth principal constructor pins');
  }
  const rawConfig = value.config;
  if (!isRecord(rawConfig)
      || !exactKeys(rawConfig, CONFIG_KEYS)
      || rawConfig['@version'] !== WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION
      || !isRecord(rawConfig.base)
      || !bindingShape(rawConfig.principal_binding)
      || !tlsExporterPolicyShape(rawConfig.tls_exporter_binding)) {
    throw new TypeError('invalid WIMSE/OAuth principal constructor config');
  }
  if (value.current_tls_exporter !== undefined
      && !tlsExporterBindingShape(value.current_tls_exporter)) {
    throw new TypeError('invalid current TLS exporter binding');
  }
  const config = structuredClone(rawConfig) as unknown as WimseOAuthPrincipalAdapterConfig;
  if (config.base.subject.native_id !== subjectNamedByBinding(config.principal_binding)) {
    throw new TypeError('WIMSE subject semantics do not identify the pinned native subject');
  }
  const basePins: WimseOAuthSptConstructorPins = {
    config: config.base,
    trust_roots: value.trust_roots,
  };
  const baseAdapter = createWimseOAuthSptAebAdapter(basePins);
  const trustRoots = structuredClone(value.trust_roots) as WimseOAuthSptTrustRoot[];
  return {
    config,
    trustRoots,
    configDigest: digestAeb(config),
    rootsDigest: digestAeb(trustRoots),
    baseAdapter,
    currentTlsExporter: value.current_tls_exporter === undefined
      ? null
      : structuredClone(value.current_tls_exporter),
  };
}

function decodeB64url(segment: string): Buffer | null {
  if (!B64URL_RE.test(segment) || segment.length % 4 === 1) return null;
  try {
    const decoded = Buffer.from(segment, 'base64url');
    return decoded.length > 0 && decoded.toString('base64url') === segment ? decoded : null;
  } catch {
    return null;
  }
}

function compactClaims(token: unknown): Obj | null {
  if (typeof token !== 'string' || token.length > 65_536) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) return null;
  const payload = decodeB64url(parts[1]);
  if (!payload) return null;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(payload);
  } catch {
    return null;
  }
  if (!strictJsonGate(text).ok) return null;
  try {
    const value: unknown = JSON.parse(text);
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function jwkThumbprint(value: unknown): string | null {
  if (!isRecord(value)
      || value.kty !== 'OKP'
      || value.crv !== 'Ed25519'
      || typeof value.x !== 'string'
      || !B64URL_RE.test(value.x)) return null;
  try {
    return crypto.createHash('sha256')
      .update(Buffer.from(canonicalizeAeb({ crv: value.crv, kty: value.kty, x: value.x }), 'utf8'))
      .digest('base64url');
  } catch {
    return null;
  }
}

function reject(reason: string): RelationshipFailure {
  return { acceptance: 'REJECTED', reason: `wimse-oauth-principal:${reason}` };
}

function indeterminate(reason: string): RelationshipFailure {
  return { acceptance: 'INDETERMINATE', reason: `wimse-oauth-principal:${reason}` };
}

function normalizedRequestHeaders(artifact: Obj): Map<string, string> | null {
  if (!isRecord(artifact.request) || !isRecord(artifact.request.headers)) return null;
  const headers = new Map<string, string>();
  for (const [rawName, rawValue] of Object.entries(artifact.request.headers)) {
    if (typeof rawValue !== 'string') return null;
    const name = rawName.toLowerCase();
    if (headers.has(name)) return null;
    headers.set(name, rawValue.trim());
  }
  return headers;
}

function signatureInputCovers(signatureInput: string, component: string): boolean {
  if (!signatureInput.startsWith('wimse=(')) return false;
  const close = signatureInput.indexOf(')');
  if (close < 'wimse=('.length) return false;
  const rawComponents = signatureInput.slice('wimse=('.length, close);
  const matches = [...rawComponents.matchAll(/"([^"\\]+)"/g)];
  if (matches.length === 0
      || matches.map((match) => match[0]).join(' ') !== rawComponents) return false;
  return matches.some((match) => match[1] === component);
}

function validateTlsExporterBinding(
  artifact: Obj,
  pins: ParsedPins,
): RelationshipFailure | null {
  if (pins.config.tls_exporter_binding.mode === 'not-required') return null;
  if (pins.currentTlsExporter === null) {
    return indeterminate('current_tls_exporter_unavailable');
  }
  const headers = normalizedRequestHeaders(artifact);
  if (headers === null) return indeterminate('tls_exporter_presentation_unavailable');
  const presentedValue = headers.get(WIMSE_TLS_EXPORTER_HEADER);
  if (presentedValue === undefined) return indeterminate('tls_exporter_presentation_missing');
  const signatureInput = headers.get('signature-input');
  if (signatureInput === undefined
      || !signatureInputCovers(signatureInput, WIMSE_TLS_EXPORTER_HEADER)) {
    return reject('tls_exporter_not_signature_covered');
  }
  const presented = decodeB64url(presentedValue);
  const current = decodeB64url(pins.currentTlsExporter.value);
  if (presented?.length !== 32 || current?.length !== 32) {
    return indeterminate('tls_exporter_presentation_malformed');
  }
  return crypto.timingSafeEqual(presented, current)
    ? null
    : reject('tls_exporter_mismatch');
}

function validateRelationships(
  artifact: unknown,
  pins: ParsedPins,
): RelationshipFailure | null {
  if (!isRecord(artifact)
      || !Object.keys(artifact).every((key) => ARTIFACT_KEYS.has(key))) {
    return indeterminate('principal_binding_unavailable');
  }
  const oauth = compactClaims(artifact.txn_token);
  const wit = compactClaims(artifact.wit);
  if (!oauth || !wit) return indeterminate('principal_binding_unavailable');
  const rawBinding = oauth[WIMSE_OAUTH_PRINCIPAL_BINDING_CLAIM];
  if (rawBinding === undefined) return indeterminate('principal_binding_missing');
  if (!bindingShape(rawBinding)) return indeterminate('principal_binding_malformed');
  const binding = rawBinding;
  const expected = pins.config.principal_binding;

  if (binding.logical_agent_id !== expected.logical_agent_id) return reject('logical_agent_mismatch');
  if (binding.workload_instance_id !== expected.workload_instance_id
      || binding.wimse_subject_semantics !== expected.wimse_subject_semantics) {
    return reject('workload_instance_mismatch');
  }
  if (binding.oauth_client_id !== expected.oauth_client_id) return reject('oauth_client_mismatch');
  if (binding.oauth_grant_type !== expected.oauth_grant_type) {
    return reject('oauth_grant_semantics_mismatch');
  }
  if (binding.oauth_sub_semantics !== expected.oauth_sub_semantics
      || binding.delegating_principal.id !== expected.delegating_principal.id
      || binding.delegating_principal.kind !== expected.delegating_principal.kind) {
    return reject('oauth_sub_semantics_mismatch');
  }
  if (binding.executor_id !== expected.executor_id) return reject('executor_mismatch');
  if (binding.tool_id !== expected.tool_id) return reject('tool_mismatch');

  const expectedSub = binding.oauth_sub_semantics === 'delegating-principal'
    ? binding.delegating_principal.id
    : binding.oauth_sub_semantics === 'oauth-client'
      ? binding.oauth_client_id
      : binding.workload_instance_id;
  if (oauth.sub !== expectedSub) return reject('oauth_sub_semantics_mismatch');
  if (oauth.req_wl !== binding.workload_instance_id) return reject('workload_instance_mismatch');

  const cnf = isRecord(wit.cnf) ? wit.cnf : null;
  const confirmationJkt = cnf ? jwkThumbprint(cnf.jwk) : null;
  if (confirmationJkt === null) return indeterminate('workload_confirmation_key_unprovable');
  if (binding.workload_confirmation_jkt !== expected.workload_confirmation_jkt
      || binding.workload_confirmation_jkt !== confirmationJkt) {
    return reject('workload_confirmation_key_mismatch');
  }
  if (!isRecord(artifact.spt_intent) || artifact.spt_intent.tool !== binding.tool_id) {
    return indeterminate('tool_binding_unprovable');
  }
  return null;
}

function pinnedInvocation(
  input: Omit<AebAdapterInput, 'profile'>,
  pins: ParsedPins,
): boolean {
  try {
    return digestAeb(input.adapter_config) === pins.configDigest
      && digestAeb(input.trust_roots) === pins.rootsDigest;
  } catch {
    return false;
  }
}

function baseInput(
  input: Omit<AebAdapterInput, 'profile'>,
  pins: ParsedPins,
): Omit<AebAdapterInput, 'profile'> {
  return { ...input, adapter_config: pins.config.base };
}

function verifyNative(
  input: Omit<AebAdapterInput, 'profile'>,
  pins: ParsedPins,
): AebNativeResult {
  const base = pins.baseAdapter.verifyNative(baseInput(input, pins));
  if (!pinnedInvocation(input, pins)) {
    return {
      ...base,
      native_verification: 'FAILED',
      acceptance: 'INDETERMINATE',
      reasons: ['wimse-oauth-principal:constructor_pin_mismatch'],
    };
  }
  if (base.native_verification !== 'VERIFIED' || base.acceptance !== 'ACCEPTED') return base;
  const relationship = validateRelationships(input.artifact, pins);
  if (relationship !== null) {
    return { ...base, acceptance: relationship.acceptance, reasons: [relationship.reason] };
  }
  if (!isRecord(input.artifact)) {
    return {
      ...base,
      acceptance: 'INDETERMINATE',
      reasons: ['wimse-oauth-principal:tls_exporter_presentation_unavailable'],
    };
  }
  const channelBinding = validateTlsExporterBinding(input.artifact, pins);
  return channelBinding === null
    ? base
    : { ...base, acceptance: channelBinding.acceptance, reasons: [channelBinding.reason] };
}

function mapAction(
  input: AebAdapterInput & { native: AebNativeResult },
  pins: ParsedPins,
): AebMappingResult {
  if (!pinnedInvocation(input, pins)) {
    return {
      mapping: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      reasons: ['wimse-oauth-principal:mapping_constructor_pin_mismatch'],
    };
  }
  const reverified = verifyNative(input, pins);
  if (input.native.native_verification !== 'VERIFIED'
      || input.native.acceptance !== 'ACCEPTED'
      || reverified.native_verification !== 'VERIFIED'
      || reverified.acceptance !== 'ACCEPTED') {
    return {
      mapping: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      reasons: ['native_acceptance_required'],
    };
  }
  return pins.baseAdapter.mapAction({
    ...input,
    adapter_config: pins.config.base,
    native: reverified,
  });
}

export function createWimseOAuthPrincipalAebAdapter(
  constructorPins: WimseOAuthPrincipalConstructorPins,
): AebAdapter {
  const pins = parseConstructorPins(constructorPins);
  return Object.freeze({
    id: WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_ID,
    version: WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      try {
        return verifyNative(input, pins);
      } catch {
        const base = pins.baseAdapter.verifyNative(baseInput(input, pins));
        return {
          ...base,
          native_verification: 'FAILED',
          acceptance: 'INDETERMINATE',
          reasons: ['wimse-oauth-principal:unexpected_adapter_error'],
        };
      }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try {
        return mapAction(input, pins);
      } catch {
        return {
          mapping: 'INDETERMINATE',
          caid: null,
          action_digest: null,
          reasons: ['wimse-oauth-principal:unexpected_mapping_error'],
        };
      }
    },
  });
}
