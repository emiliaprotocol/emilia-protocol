// SPDX-License-Identifier: Apache-2.0
/**
 * Native AEB adapter for Discovery-to-Permit Continuity.
 *
 * The adapter emits one evidence role. It deliberately has no invocation,
 * reservation, permit-consumption, or authorization operation.
 */

import {
  digestAeb,
  type AebAdapter,
  type AebAdapterInput,
  type AebDigest,
  type AebMappingResult,
  type AebNativeResult,
} from './aeb-adapter-contract.js';
import {
  DISCOVERY_PERMIT_RESOLUTION_VERSION,
  digestDiscoveryPermit,
  isDiscoveryPermitResolverAttestation,
  isDiscoveryPermitResolution,
  pinDiscoveryPermitTrust,
  rederiveDiscoveryPermitResolutionFromPinnedDocuments,
  verifyDiscoveryPermitResolverAttestationSignature,
  type DiscoveryPermitResolution,
  type DiscoveryPermitTrustPins,
} from './discovery-permit-contract.js';

export const AEB_DISCOVERY_PERMIT_ADAPTER_ID = 'native:discovery-permit-continuity';
export const AEB_DISCOVERY_PERMIT_ADAPTER_VERSION = '1';
export const AEB_DISCOVERY_PERMIT_CONFIG_VERSION = 'AEB-DISCOVERY-PERMIT-CONFIG-v1';
export const DISCOVERY_PERMIT_EVIDENCE_ROLE = 'discovery-permit-continuity';

export interface AebDiscoveryPermitConfig {
  '@version': typeof AEB_DISCOVERY_PERMIT_CONFIG_VERSION;
  source: {
    origin: string;
    discovery_url: string;
    permit_url: string;
  };
  schema_digests: {
    discovery: AebDigest;
    permit_binding: AebDigest;
  };
  mapping_digest: AebDigest;
  max_age_seconds: number;
  redirect_map: Record<string, string>;
  resolver: {
    id: string;
    key_id: string;
    public_key: string;
    max_attestation_age_seconds: number;
  };
  evidence_role: typeof DISCOVERY_PERMIT_EVIDENCE_ROLE;
}

export interface DiscoveryPermitAebNativeResult extends AebNativeResult {
  /** Explicitly prevents a native evidence result from being mistaken for Gate authorization. */
  authorization: 'EVIDENCE_ONLY';
  authorizes_action: false;
}

export interface AebDiscoveryPermitAdapter extends Omit<AebAdapter, 'verifyNative'> {
  verifyNative(
    input: Omit<AebAdapterInput, 'profile'>,
  ): DiscoveryPermitAebNativeResult;
}

const CONFIG_KEYS = new Set([
  '@version',
  'source',
  'schema_digests',
  'mapping_digest',
  'max_age_seconds',
  'redirect_map',
  'resolver',
  'evidence_role',
]);
const SOURCE_KEYS = new Set(['origin', 'discovery_url', 'permit_url']);
const SCHEMA_KEYS = new Set(['discovery', 'permit_binding']);
const RESOLVER_KEYS = new Set([
  'id',
  'key_id',
  'public_key',
  'max_attestation_age_seconds',
]);
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ZERO_DIGEST = `sha256:${'0'.repeat(64)}` as AebDigest;

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: unknown, keys: ReadonlySet<string>): value is Record<string, any> {
  if (!isObject(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function isDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function validConfig(value: unknown): value is AebDiscoveryPermitConfig {
  if (!exactKeys(value, CONFIG_KEYS)
    || value['@version'] !== AEB_DISCOVERY_PERMIT_CONFIG_VERSION
    || value.evidence_role !== DISCOVERY_PERMIT_EVIDENCE_ROLE
    || !Number.isSafeInteger(value.max_age_seconds)
    || value.max_age_seconds <= 0
    || !isDigest(value.mapping_digest)
    || !exactKeys(value.source, SOURCE_KEYS)
    || !exactKeys(value.schema_digests, SCHEMA_KEYS)
    || !isObject(value.redirect_map)
    || !exactKeys(value.resolver, RESOLVER_KEYS)
    || typeof value.resolver.id !== 'string'
    || value.resolver.id.length === 0
    || typeof value.resolver.key_id !== 'string'
    || value.resolver.key_id.length === 0
    || typeof value.resolver.public_key !== 'string'
    || value.resolver.public_key.length === 0
    || !Number.isSafeInteger(value.resolver.max_attestation_age_seconds)
    || value.resolver.max_attestation_age_seconds <= 0) return false;
  if (!Object.values(value.source).every((item) => typeof item === 'string')
    || !isDigest(value.schema_digests.discovery)
    || !isDigest(value.schema_digests.permit_binding)) return false;
  try {
    trustPins(value as unknown as AebDiscoveryPermitConfig);
    return true;
  } catch {
    return false;
  }
}

function trustPins(config: AebDiscoveryPermitConfig): DiscoveryPermitTrustPins {
  return pinDiscoveryPermitTrust({
    origin: config.source.origin,
    discovery_url: config.source.discovery_url,
    permit_url: config.source.permit_url,
    discovery_schema_digest: config.schema_digests.discovery,
    permit_schema_digest: config.schema_digests.permit_binding,
    mapping_digest: config.mapping_digest,
    max_age_seconds: config.max_age_seconds,
    redirect_map: config.redirect_map,
  });
}

function configMatches(
  config: AebDiscoveryPermitConfig,
  resolution: DiscoveryPermitResolution,
): boolean {
  return config.source.origin === resolution.source.origin
    && config.source.discovery_url === resolution.source.discovery_url
    && config.source.permit_url === resolution.source.permit_url
    && config.schema_digests.discovery === resolution.schema_digests.discovery
    && config.schema_digests.permit_binding === resolution.schema_digests.permit_binding
    && config.mapping_digest === resolution.mapping_digest
    && config.max_age_seconds === resolution.max_age_seconds;
}

function safeDigest(value: unknown): AebDigest {
  try {
    return digestAeb(value);
  } catch {
    return ZERO_DIGEST;
  }
}

function statusDigest(input: Omit<AebAdapterInput, 'profile'>): AebDigest {
  return safeDigest({
    checked_at: input.status?.checked_at,
    expires_at: input.status?.expires_at,
    revocation_checked: input.status?.revocation_checked,
    revoked: input.status?.revoked,
    consumed: input.status?.consumed,
    unavailable: input.status?.unavailable,
  });
}

function baseResult(
  input: Omit<AebAdapterInput, 'profile'>,
  overrides: Partial<AebNativeResult>,
  reasons: string[],
): DiscoveryPermitAebNativeResult {
  const subject: AebNativeResult['subject'] = overrides.subject ?? {
    id: 'discovery-origin:unknown',
    kind: 'organization',
  };
  return Object.freeze({
    native_verification: overrides.native_verification ?? 'FAILED',
    acceptance: overrides.acceptance ?? 'REJECTED',
    evidence_digest: overrides.evidence_digest ?? safeDigest(input.artifact),
    status_digest: overrides.status_digest ?? statusDigest(input),
    evidence_role: DISCOVERY_PERMIT_EVIDENCE_ROLE,
    subject,
    replay_unit: overrides.replay_unit ?? ZERO_DIGEST,
    reasons: [...reasons],
    authorization: 'EVIDENCE_ONLY',
    authorizes_action: false,
  });
}

function nativeStatusReasons(input: Omit<AebAdapterInput, 'profile'>): {
  acceptance: AebNativeResult['acceptance'];
  reasons: string[];
} {
  const status = input.status;
  if (!status || status.unavailable === true || status.revocation_checked !== true) {
    return { acceptance: 'INDETERMINATE', reasons: ['current_status_unavailable'] };
  }
  if (status.revoked === true) return { acceptance: 'REJECTED', reasons: ['evidence_revoked'] };
  if (status.consumed === true) return { acceptance: 'REJECTED', reasons: ['evidence_consumed'] };
  const now = Date.parse(input.now);
  const checkedAt = Date.parse(status.checked_at);
  const expiresAt = Date.parse(status.expires_at);
  if (!Number.isFinite(now)
    || !Number.isFinite(checkedAt)
    || !Number.isFinite(expiresAt)
    || checkedAt > now
    || expiresAt < now) {
    return { acceptance: 'INDETERMINATE', reasons: ['current_status_stale'] };
  }
  return { acceptance: 'ACCEPTED', reasons: [] };
}

function verifyNative(
  input: Omit<AebAdapterInput, 'profile'>,
): DiscoveryPermitAebNativeResult {
  if (!Array.isArray(input.trust_roots) || input.trust_roots.length !== 0) {
    return baseResult(input, {}, ['transaction_trust_roots_forbidden']);
  }
  if (!validConfig(input.adapter_config)) {
    return baseResult(input, {}, ['adapter_config_invalid']);
  }
  if (isDiscoveryPermitResolution(input.artifact)) {
    return baseResult(input, {}, ['resolver_attestation_required']);
  }
  if (!isDiscoveryPermitResolverAttestation(input.artifact)) {
    return baseResult(input, {}, ['resolver_attestation_shape_invalid']);
  }

  const attestation = input.artifact;
  const config = input.adapter_config;
  if (!verifyDiscoveryPermitResolverAttestationSignature(attestation, {
    resolver_id: config.resolver.id,
    key_id: config.resolver.key_id,
    public_key: config.resolver.public_key,
  })) {
    return baseResult(input, {}, ['resolver_attestation_signature_invalid']);
  }
  if (attestation.configuration_digest !== digestDiscoveryPermit(config)) {
    return baseResult(input, {}, ['resolver_attestation_config_mismatch']);
  }

  const resolution = attestation.resolution;
  if (!configMatches(config, resolution)) {
    return baseResult(input, {
      subject: {
        id: resolution.source.origin,
        kind: 'organization',
      },
    }, ['adapter_config_does_not_match_resolution']);
  }
  if (attestation.caid !== resolution.binding.caid
    || attestation.action_digest !== resolution.binding.action_digest
    || attestation.source_digest !== digestDiscoveryPermit(resolution.source)
    || attestation.provenance_digest !== digestDiscoveryPermit(resolution.provenance)
    || attestation.resolution_digest !== digestDiscoveryPermit(resolution)) {
    return baseResult(input, {}, ['resolver_attestation_binding_mismatch']);
  }

  let signedResolution: DiscoveryPermitResolution;
  let currentResolution: DiscoveryPermitResolution;
  try {
    signedResolution = rederiveDiscoveryPermitResolutionFromPinnedDocuments({
      pins: trustPins(config),
      resolution,
      now: attestation.evaluated_at,
    });
    currentResolution = rederiveDiscoveryPermitResolutionFromPinnedDocuments({
      pins: trustPins(config),
      resolution,
      now: input.now,
    });
  } catch {
    return baseResult(input, {}, ['resolver_resolution_rederivation_failed']);
  }
  if (digestDiscoveryPermit(signedResolution) !== attestation.resolution_digest) {
    return baseResult(input, {}, ['resolver_resolution_rederivation_mismatch']);
  }

  const evidenceDigest = digestDiscoveryPermit(attestation);
  const replayUnit = digestDiscoveryPermit({
    '@type': DISCOVERY_PERMIT_RESOLUTION_VERSION,
    resolver_id: attestation.resolver_id,
    evaluated_at: attestation.evaluated_at,
    configuration_digest: attestation.configuration_digest,
    source: resolution.source,
    mapping_digest: resolution.mapping_digest,
    caid: attestation.caid,
    action_digest: attestation.action_digest,
    source_digest: attestation.source_digest,
    provenance_digest: attestation.provenance_digest,
    resolution_digest: attestation.resolution_digest,
  });
  const shared = {
    native_verification: 'VERIFIED' as const,
    evidence_digest: evidenceDigest,
    subject: {
      id: resolution.source.origin,
      kind: 'organization' as const,
    },
    replay_unit: replayUnit,
  };

  const now = Date.parse(input.now);
  const evaluatedAt = Date.parse(attestation.evaluated_at);
  const expiresAt = Date.parse(attestation.expires_at);
  if (!Number.isFinite(now)
    || evaluatedAt > now
    || expiresAt < now
    || now - evaluatedAt > config.resolver.max_attestation_age_seconds * 1000
    || expiresAt - evaluatedAt > config.resolver.max_attestation_age_seconds * 1000) {
    return baseResult(input, {
      ...shared,
      acceptance: 'INDETERMINATE',
    }, ['resolver_attestation_stale', 'native_evidence_only_not_authorization']);
  }

  if (currentResolution.disposition === 'stale') {
    return baseResult(input, {
      ...shared,
      acceptance: 'INDETERMINATE',
    }, ['discovery_permit_stale', 'native_evidence_only_not_authorization']);
  }
  if (currentResolution.disposition === 'unknown') {
    return baseResult(input, {
      ...shared,
      acceptance: 'INDETERMINATE',
    }, ['discovery_permit_unknown', 'native_evidence_only_not_authorization']);
  }
  if (currentResolution.disposition === 'deprecated') {
    return baseResult(input, {
      ...shared,
      acceptance: 'REJECTED',
    }, ['discovery_permit_deprecated', 'native_evidence_only_not_authorization']);
  }

  const status = nativeStatusReasons(input);
  return baseResult(input, {
    ...shared,
    acceptance: status.acceptance,
  }, [...status.reasons, 'native_evidence_only_not_authorization']);
}

function mapAction(
  input: AebAdapterInput & { native: AebNativeResult },
): AebMappingResult {
  if (!isDiscoveryPermitResolverAttestation(input.artifact)
    || !validConfig(input.adapter_config)
    || !configMatches(input.adapter_config, input.artifact.resolution)
    || input.artifact.configuration_digest !== digestDiscoveryPermit(input.adapter_config)
    || input.native.evidence_digest !== digestDiscoveryPermit(input.artifact)
    || input.native.native_verification !== 'VERIFIED'
    || input.native.acceptance !== 'ACCEPTED') {
    return {
      mapping: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      reasons: ['verified_current_discovery_evidence_required'],
    };
  }

  let expectedDigest: AebDigest;
  try {
    expectedDigest = digestDiscoveryPermit(input.expected_action);
  } catch {
    return {
      mapping: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      reasons: ['expected_action_not_canonicalizable'],
    };
  }
  if (expectedDigest !== input.artifact.action_digest
    || expectedDigest !== input.artifact.resolution.binding.action_digest) {
    return {
      mapping: 'MISMATCH',
      caid: null,
      action_digest: null,
      reasons: ['action_digest_mismatch'],
    };
  }
  return {
    mapping: 'MATCH',
    caid: input.artifact.caid,
    action_digest: input.artifact.action_digest,
    reasons: ['discovery_permit_continuity_match', 'evidence_only_not_authorization'],
  };
}

export function createAebDiscoveryPermitAdapter(): AebDiscoveryPermitAdapter {
  return Object.freeze({
    id: AEB_DISCOVERY_PERMIT_ADAPTER_ID,
    version: AEB_DISCOVERY_PERMIT_ADAPTER_VERSION,
    verifyNative,
    mapAction,
  });
}
