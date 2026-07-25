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
  isDiscoveryPermitResolution,
  type DiscoveryPermitResolution,
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
  'evidence_role',
]);
const SOURCE_KEYS = new Set(['origin', 'discovery_url', 'permit_url']);
const SCHEMA_KEYS = new Set(['discovery', 'permit_binding']);
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
    || !exactKeys(value.schema_digests, SCHEMA_KEYS)) return false;
  return Object.values(value.source).every((item) => typeof item === 'string')
    && isDigest(value.schema_digests.discovery)
    && isDigest(value.schema_digests.permit_binding);
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
  if (!isDiscoveryPermitResolution(input.artifact)) {
    return baseResult(input, {}, ['resolution_shape_invalid']);
  }
  const resolution = input.artifact;
  if (!configMatches(input.adapter_config, resolution)) {
    return baseResult(input, {
      subject: {
        id: resolution.source.origin,
        kind: 'organization',
      },
    }, ['adapter_config_does_not_match_resolution']);
  }

  const evidenceDigest = digestDiscoveryPermit(resolution);
  const replayUnit = digestDiscoveryPermit({
    '@type': DISCOVERY_PERMIT_RESOLUTION_VERSION,
    source: resolution.source,
    mapping_digest: resolution.mapping_digest,
    caid: resolution.binding.caid,
    action_digest: resolution.binding.action_digest,
    permit_raw_digest: resolution.provenance.permit.raw_digest,
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

  if (resolution.disposition === 'stale') {
    return baseResult(input, {
      ...shared,
      acceptance: 'INDETERMINATE',
    }, ['discovery_permit_stale', 'native_evidence_only_not_authorization']);
  }
  if (resolution.disposition === 'unknown') {
    return baseResult(input, {
      ...shared,
      acceptance: 'INDETERMINATE',
    }, ['discovery_permit_unknown', 'native_evidence_only_not_authorization']);
  }
  if (resolution.disposition === 'deprecated') {
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
  if (!isDiscoveryPermitResolution(input.artifact)
    || !validConfig(input.adapter_config)
    || !configMatches(input.adapter_config, input.artifact)
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
  if (expectedDigest !== input.artifact.binding.action_digest) {
    return {
      mapping: 'MISMATCH',
      caid: null,
      action_digest: null,
      reasons: ['action_digest_mismatch'],
    };
  }
  return {
    mapping: 'MATCH',
    caid: input.artifact.binding.caid,
    action_digest: input.artifact.binding.action_digest,
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
