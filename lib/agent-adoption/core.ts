// SPDX-License-Identifier: Apache-2.0
/**
 * Pure domain kernel for the public Agent Adoption MVP.
 *
 * It accepts one closed candidate record and binds it to immutable, server-owned
 * synthetic templates. It performs no I/O and grants no authority to execute.
 */
import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';

import { canonicalizeStrictJson } from '../strict-json.js';
import type {
  AgentAdoptionClaimBoundaries,
  AgentAdoptionInputErrorCode,
  AgentCandidate,
  AgentSourceKind,
  OperatingBond,
  OperatingBondResult,
  PublicOperatingBondProjection,
  Sha256Digest,
  SyntheticAllowanceTemplate,
  SyntheticAllowanceTemplateId,
  SyntheticJobTemplate,
  SyntheticJobTemplateId,
} from './types';

export const AGENT_CANDIDATE_VERSION = 'EP-AGENT-ADOPTION-CANDIDATE-v1' as const;
export const OPERATING_BOND_VERSION = 'EP-OPERATING-BOND-v1' as const;
export const PUBLIC_OPERATING_BOND_VERSION = 'EP-OPERATING-BOND-PUBLIC-v1' as const;

export const SYNTHETIC_JOB_TEMPLATE_ID: SyntheticJobTemplateId =
  'job_vendor_intake_v1';
export const SYNTHETIC_ALLOWANCE_TEMPLATE_ID: SyntheticAllowanceTemplateId =
  'allowance_cautious_v1';

export const AGENT_ADOPTION_LIMITS = Object.freeze({
  maxLogicalRequestBytes: 8 * 1024,
  maxDepth: 32,
  maxNodes: 10_000,
  maxLabelBytes: 80,
  maxSourceUrlBytes: 2_048,
  maxTemplateStringBytes: 128,
  maxTemplateArrayItems: 16,
} as const);

const CANDIDATE_KEYS = new Set([
  'label',
  'source_kind',
  'source_url',
  'agent_key_thumbprint',
  'job_template_id',
  'allowance_template_id',
]);
const REQUIRED_CANDIDATE_KEYS = [
  'label',
  'source_kind',
  'job_template_id',
  'allowance_template_id',
] as const;
const SOURCE_KINDS = new Set<AgentSourceKind>(['github', 'mcp', 'a2a', 'local']);
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const DISALLOWED_LABEL_CONTROLS = /[\u0000-\u001f\u007f-\u009f\p{Cf}\p{Bidi_Control}]/u;

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== 'object') return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);

  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor && 'value' in descriptor) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}

export const CLAIM_BOUNDARIES: AgentAdoptionClaimBoundaries = deepFreeze({
  scope: 'synthetic_no_egress_demonstration',
  real_money: 'not_used_or_represented',
  provider_credentials: 'not_collected_or_used',
  civil_identity: 'not_verified_or_claimed',
  certification: 'not_issued_or_claimed',
  marketplace: 'not_offered_or_claimed',
  production_execution: 'not_authorized_or_claimed',
  source_metadata: 'url_is_metadata_only_never_fetched',
});

function syntheticJobTemplate(
  templateId: SyntheticJobTemplateId,
  displayName: string,
  actionType: string,
  target: string,
): SyntheticJobTemplate {
  return deepFreeze({
    '@version': 'EP-AGENT-ADOPTION-JOB-TEMPLATE-v1',
    template_id: templateId,
    display_name: displayName,
    environment: 'synthetic',
    network_egress: 'forbidden',
    external_side_effects: 'forbidden',
    allowed_action_types: [actionType],
    allowed_targets: [target],
    max_actions: 5,
    max_concurrency: 1,
  });
}

function syntheticAllowanceTemplate(
  templateId: SyntheticAllowanceTemplateId,
  total: number,
  maxPerAction: number,
): SyntheticAllowanceTemplate {
  return deepFreeze({
    '@version': 'EP-AGENT-ADOPTION-ALLOWANCE-TEMPLATE-v1',
    template_id: templateId,
    unit: 'synthetic_credit',
    total,
    max_per_action: maxPerAction,
    max_actions: 5,
    validity_seconds: 900,
    transferable: false,
    redeemable: false,
    real_world_value: false,
  });
}

export const JOB_TEMPLATES: Readonly<Record<SyntheticJobTemplateId, SyntheticJobTemplate>> =
  deepFreeze({
    job_vendor_intake_v1: syntheticJobTemplate(
      'job_vendor_intake_v1',
      'Vendor intake',
      'agent-adoption.synthetic.vendor-intake.1',
      'vendor.demo',
    ),
    job_compute_batch_v1: syntheticJobTemplate(
      'job_compute_batch_v1',
      'Batch compute request',
      'agent-adoption.synthetic.compute-allocate.1',
      'compute.batch',
    ),
    job_document_route_v1: syntheticJobTemplate(
      'job_document_route_v1',
      'Document routing',
      'agent-adoption.synthetic.document-route.1',
      'documents.demo',
    ),
  });

export const ALLOWANCE_TEMPLATES: Readonly<
  Record<SyntheticAllowanceTemplateId, SyntheticAllowanceTemplate>
> = deepFreeze({
  allowance_cautious_v1: syntheticAllowanceTemplate('allowance_cautious_v1', 200, 40),
  allowance_balanced_v1: syntheticAllowanceTemplate('allowance_balanced_v1', 500, 100),
  allowance_stretch_v1: syntheticAllowanceTemplate('allowance_stretch_v1', 1_000, 250),
});

export class AgentAdoptionInputError extends TypeError {
  readonly code: AgentAdoptionInputErrorCode;

  constructor(code: AgentAdoptionInputErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'AgentAdoptionInputError';
    this.code = code;
  }
}

function inputError(
  code: AgentAdoptionInputErrorCode,
  message: string,
  cause?: unknown,
): AgentAdoptionInputError {
  return new AgentAdoptionInputError(code, message, cause);
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function assertNoProxyValues(value: unknown): void {
  const pending: unknown[] = [value];
  const seen = new WeakSet<object>();
  let objectNodes = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === null || (typeof current !== 'object' && typeof current !== 'function')) {
      continue;
    }
    if (isProxy(current)) {
      throw inputError('invalid_json_domain', 'candidate cannot contain JavaScript proxies');
    }
    if (typeof current === 'function' || seen.has(current)) continue;
    seen.add(current);
    objectNodes += 1;
    if (objectNodes > AGENT_ADOPTION_LIMITS.maxNodes
        || (Array.isArray(current) && current.length > AGENT_ADOPTION_LIMITS.maxNodes)) {
      throw inputError('invalid_json_domain', 'candidate exceeds the bounded JSON node limit');
    }

    let keys: (string | symbol)[];
    try {
      keys = Reflect.ownKeys(current);
    } catch (cause) {
      throw inputError('invalid_json_domain', 'candidate object inspection failed', cause);
    }
    for (const key of keys) {
      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(current, key);
      } catch (cause) {
        throw inputError('invalid_json_domain', 'candidate property inspection failed', cause);
      }
      if (descriptor && 'value' in descriptor) pending.push(descriptor.value);
    }
  }
}

function canonicalizeBounded(value: unknown, label: string): string {
  let canonical: string;
  try {
    canonical = canonicalizeStrictJson(value, {
      maxDepth: AGENT_ADOPTION_LIMITS.maxDepth,
      maxNodes: AGENT_ADOPTION_LIMITS.maxNodes,
      maxStringBytes: AGENT_ADOPTION_LIMITS.maxLogicalRequestBytes,
    });
  } catch (cause) {
    throw inputError('invalid_json_domain', `${label} is outside the bounded JSON domain`, cause);
  }
  if (utf8Bytes(canonical) > AGENT_ADOPTION_LIMITS.maxLogicalRequestBytes) {
    throw inputError(
      'invalid_json_domain',
      `${label} exceeds the ${AGENT_ADOPTION_LIMITS.maxLogicalRequestBytes}-byte logical limit`,
    );
  }
  return canonical;
}

function assertCandidateRecord(value: unknown): asserts value is Record<string, unknown> {
  assertNoProxyValues(value);
  canonicalizeBounded(value, 'candidate');
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw inputError('invalid_json_domain', 'candidate must be an ordinary JSON object');
  }

  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string' || !CANDIDATE_KEYS.has(key))) {
    throw inputError('unknown_field', 'candidate contains an unrecognized field');
  }
  if (REQUIRED_CANDIDATE_KEYS.some((key) => !Object.hasOwn(value, key))) {
    throw inputError('missing_field', 'candidate is missing a required field');
  }
}

function ownValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) {
    throw inputError('invalid_json_domain', 'candidate fields must be enumerable data properties');
  }
  return descriptor.value;
}

function optionalOwnValue(record: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(record, key) ? ownValue(record, key) : undefined;
}

function parseLabel(value: unknown): string {
  if (typeof value !== 'string'
      || value.length === 0
      || value !== value.trim()
      || value.normalize('NFC') !== value
      || DISALLOWED_LABEL_CONTROLS.test(value)
      || utf8Bytes(value) > AGENT_ADOPTION_LIMITS.maxLabelBytes) {
    throw inputError('invalid_label', 'candidate label is not canonical or is too long');
  }
  return value;
}

function parseSourceKind(value: unknown): AgentSourceKind {
  if (typeof value !== 'string' || !SOURCE_KINDS.has(value as AgentSourceKind)) {
    throw inputError('invalid_source_kind', 'candidate source_kind is not supported');
  }
  return value as AgentSourceKind;
}

function parseSourceUrl(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || utf8Bytes(value) > AGENT_ADOPTION_LIMITS.maxSourceUrlBytes) {
    throw inputError('invalid_source_url', 'candidate source_url is invalid');
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw inputError('invalid_source_url', 'candidate source_url is invalid', cause);
  }
  if (parsed.protocol !== 'https:'
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.port !== ''
      || parsed.href !== value) {
    throw inputError(
      'invalid_source_url',
      'candidate source_url must be canonical HTTPS metadata without userinfo, query, or fragment',
    );
  }
  return value;
}

function parseThumbprint(value: unknown): Sha256Digest | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !SHA256_DIGEST.test(value)) {
    throw inputError(
      'invalid_agent_key_thumbprint',
      'candidate agent_key_thumbprint must be a lowercase SHA-256 digest',
    );
  }
  return value as Sha256Digest;
}

function parseJobTemplateId(value: unknown): SyntheticJobTemplateId {
  if (typeof value !== 'string' || !Object.hasOwn(JOB_TEMPLATES, value)) {
    throw inputError('unknown_job_template', 'candidate job_template_id is not server-owned');
  }
  return value as SyntheticJobTemplateId;
}

function parseAllowanceTemplateId(value: unknown): SyntheticAllowanceTemplateId {
  if (typeof value !== 'string' || !Object.hasOwn(ALLOWANCE_TEMPLATES, value)) {
    throw inputError(
      'unknown_allowance_template',
      'candidate allowance_template_id is not server-owned',
    );
  }
  return value as SyntheticAllowanceTemplateId;
}

function normalizeCandidate(input: unknown): AgentCandidate {
  assertCandidateRecord(input);
  const label = parseLabel(ownValue(input, 'label'));
  const sourceKind = parseSourceKind(ownValue(input, 'source_kind'));
  const sourceUrl = parseSourceUrl(optionalOwnValue(input, 'source_url'));
  const thumbprint = parseThumbprint(optionalOwnValue(input, 'agent_key_thumbprint'));
  const jobTemplateId = parseJobTemplateId(ownValue(input, 'job_template_id'));
  const allowanceTemplateId = parseAllowanceTemplateId(ownValue(input, 'allowance_template_id'));

  return deepFreeze({
    '@version': AGENT_CANDIDATE_VERSION,
    label,
    source_kind: sourceKind,
    ...(sourceUrl === undefined ? {} : { source_url: sourceUrl }),
    ...(thumbprint === undefined ? {} : { agent_key_thumbprint: thumbprint }),
    job_template_id: jobTemplateId,
    allowance_template_id: allowanceTemplateId,
  });
}

function digestCanonical(value: unknown, label: string): Sha256Digest {
  const canonical = canonicalizeBounded(value, label);
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function buildPublicProjection(
  bond: OperatingBond,
  bondDigest: Sha256Digest,
): PublicOperatingBondProjection {
  return deepFreeze({
    '@version': PUBLIC_OPERATING_BOND_VERSION,
    bond_digest: bondDigest,
    candidate_digest: bond.candidate_digest,
    candidate: {
      label: bond.candidate.label,
      source_kind: bond.candidate.source_kind,
    },
    operating_limits: {
      job_template_id: bond.job.template_id,
      allowance_template_id: bond.allowance.template_id,
      environment: bond.constraints.environment,
      network_egress: bond.constraints.network_egress,
      allowed_action_types: bond.constraints.allowed_action_types,
      max_actions: bond.constraints.max_actions,
      max_concurrency: bond.constraints.max_concurrency,
      validity_seconds: bond.constraints.validity_seconds,
      allowance_unit: bond.allowance.unit,
      allowance_total: bond.allowance.total,
      allowance_max_per_action: bond.allowance.max_per_action,
    },
    claim_boundaries: CLAIM_BOUNDARIES,
  });
}

/**
 * Validate a candidate and bind it to the fixed synthetic no-egress profile.
 * This function is deterministic and has no network, storage, credential, or
 * execution capability. The returned bond is an unactivated domain artifact.
 */
export function createOperatingBond(input: unknown): OperatingBondResult {
  const candidate = normalizeCandidate(input);
  const candidateDigest = digestCanonical(candidate, 'candidate artifact');
  const job = JOB_TEMPLATES[candidate.job_template_id];
  const allowance = ALLOWANCE_TEMPLATES[candidate.allowance_template_id];
  const maxActions = Math.min(job.max_actions, allowance.max_actions, allowance.total);

  const bond: OperatingBond = deepFreeze({
    '@version': OPERATING_BOND_VERSION,
    candidate,
    candidate_digest: candidateDigest,
    job,
    allowance,
    constraints: {
      environment: 'synthetic',
      network_egress: 'forbidden',
      external_side_effects: 'forbidden',
      allowed_action_types: job.allowed_action_types,
      allowed_targets: job.allowed_targets,
      max_actions: maxActions,
      max_concurrency: job.max_concurrency,
      validity_seconds: allowance.validity_seconds,
    },
    claim_boundaries: CLAIM_BOUNDARIES,
  });
  const bondDigest = digestCanonical(bond, 'operating bond');
  const publicProjection = buildPublicProjection(bond, bondDigest);

  // Keep server-owned changes inside the same hard resource profile as input.
  canonicalizeBounded(publicProjection, 'public operating bond projection');

  return deepFreeze({
    candidate,
    candidate_digest: candidateDigest,
    bond,
    bond_digest: bondDigest,
    public_projection: publicProjection,
  });
}

export type {
  AgentAdoptionClaimBoundaries,
  AgentAdoptionInputErrorCode,
  AgentCandidate,
  AgentCandidateInput,
  AgentSourceKind,
  OperatingBond,
  OperatingBondResult,
  PublicOperatingBondProjection,
  Sha256Digest,
  SyntheticAllowanceTemplate,
  SyntheticAllowanceTemplateId,
  SyntheticJobTemplate,
  SyntheticJobTemplateId,
} from './types';
