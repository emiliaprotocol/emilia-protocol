// SPDX-License-Identifier: Apache-2.0

import {
  canonicalizeQualification,
  evaluateQualification,
  GATE_QUALIFICATION_LIMITS,
  IN_TOTO_PAYLOAD_TYPE,
  RUNTIME_MEASUREMENT_PAYLOAD_TYPE,
  validateCandidateManifest,
  type QualificationBundle,
  type QualificationDecision,
  type QualificationEvaluationContext,
} from '../../packages/verify/gate-qualification.js';
import { strictJsonGate } from '../strict-json.js';

export const MARKETPLACE_QUALIFICATION_MAX_BYTES = 256 * 1024;
export const MARKETPLACE_QUALIFICATION_CONFIG_VERSION = 'emilia.works.qualification-config/v1';
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_AGE_SECONDS = 300;
const SCOPE_ID = /^[a-z0-9][a-z0-9._-]{0,95}$/;
const CONFIG_INVALID = Object.freeze({ invalid: true });
const EVIDENCE_KEYS = [
  'candidate_manifest', 'campaigns', 'test_results', 'agent_evaluation_evidence',
  'qualification_statement', 'runtime_measurement',
];

export type MarketplaceQualificationEvidence = Omit<
  QualificationBundle, 'qualification_status_chain' | 'qualification_status_observation'
>;

export interface MarketplaceQualificationRequest {
  scope_id: string;
  evidence: MarketplaceQualificationEvidence;
}

/** Trusted host configuration. Never populated from an HTTP request or scan. */
export interface MarketplaceQualificationScope {
  scope_id: string;
  scope_label: string;
  context: Omit<QualificationEvaluationContext, 'now'>;
  qualification_status_chain: unknown[];
  qualification_status_observation: {
    authority_id: string;
    head_payload_digest: string;
    sequence: number;
    observed_at: string;
  };
}

export interface MarketplaceQualificationConfiguration {
  version: typeof MARKETPLACE_QUALIFICATION_CONFIG_VERSION;
  scopes: MarketplaceQualificationScope[];
}

export interface MarketplaceQualificationResponse {
  status: QualificationDecision['decision'] | 'INVALID_REQUEST' | 'UNAVAILABLE';
  reason: string;
  checked_at: string | null;
  result: QualificationDecision | null;
  display: null | {
    label: 'Qualified for this test scope';
    scope_id: string;
    scope_label: string;
    candidate_manifest_digest: string;
    assignment_digest: string;
    qualification_policy_digest: string;
    protected_request_digest: string;
    qualification_statement_digest: string;
    qualification_status_head_digest: string;
    status_observed_at: string;
    checked_at: string;
    expires_at: string;
  };
  boundary: string;
}

const BOUNDARY = 'Qualification covers the named candidate, assignment and test policy at the observed time. It is not authorization, deployment evidence, certification, safety, compliance or a promise of performance. Nothing is published by this check.';

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function closed(value: unknown, keys: string[]): value is Record<string, unknown> {
  return object(value) && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function snapshot(value: unknown, maxBytes: number): unknown {
  // The existing canonicalizer rejects accessors, cycles and non-JSON members
  // without running them. The copy prevents caller mutation of accepted input.
  const text = canonicalizeQualification(value);
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('oversized');
  return JSON.parse(text);
}

function envelope(value: unknown, payloadType: string): boolean {
  if (!closed(value, ['payloadType', 'payload', 'signatures']) || value.payloadType !== payloadType
    || typeof value.payload !== 'string' || !value.payload.length
    || !Array.isArray(value.signatures) || value.signatures.length < 1
    || value.signatures.length > GATE_QUALIFICATION_LIMITS.max_signatures) return false;
  return value.signatures.every((signature: unknown) => closed(signature, ['keyid', 'sig'])
    && typeof signature.keyid === 'string' && signature.keyid.length > 0 && signature.keyid.length <= 512
    && typeof signature.sig === 'string' && signature.sig.length > 0 && signature.sig.length <= 1024);
}

export function validateMarketplaceQualificationRequest(value: unknown):
  { ok: true; value: MarketplaceQualificationRequest } | { ok: false; reason: 'invalid_qualification_request' } {
  try {
    const copy = snapshot(value, MARKETPLACE_QUALIFICATION_MAX_BYTES);
    if (!closed(copy, ['scope_id', 'evidence']) || typeof copy.scope_id !== 'string'
      || !SCOPE_ID.test(copy.scope_id) || !closed(copy.evidence, EVIDENCE_KEYS)) throw new Error('shape');
    const evidence = copy.evidence;
    if (!validateCandidateManifest(evidence.candidate_manifest).valid) throw new Error('manifest');
    for (const [key, minimum, maximum] of [
      ['campaigns', 1, 8], ['test_results', 0, 128], ['agent_evaluation_evidence', 1, 8],
    ] as const) {
      const entries = evidence[key];
      if (!Array.isArray(entries) || entries.length < minimum || entries.length > maximum
        || !entries.every((entry) => envelope(entry, IN_TOTO_PAYLOAD_TYPE))) throw new Error('artifacts');
    }
    if (!envelope(evidence.qualification_statement, IN_TOTO_PAYLOAD_TYPE)
      || !envelope(evidence.runtime_measurement, RUNTIME_MEASUREMENT_PAYLOAD_TYPE)) throw new Error('artifacts');
    return { ok: true, value: copy as unknown as MarketplaceQualificationRequest };
  } catch {
    return { ok: false, reason: 'invalid_qualification_request' };
  }
}

/** Reads only server environment. No defaults, demo keys, URLs or remote fetch. */
export function readHostedQualificationConfiguration(): unknown {
  const raw = process.env.EMILIA_WORKS_QUALIFICATION_CONFIG_JSON;
  if (!raw) return null;
  try {
    if (Buffer.byteLength(raw, 'utf8') > MAX_CONFIG_BYTES || !strictJsonGate(raw).ok) return CONFIG_INVALID;
    return JSON.parse(raw);
  } catch {
    return CONFIG_INVALID;
  }
}

function configuration(value: unknown, now: string): MarketplaceQualificationConfiguration | null {
  try {
    const copy = snapshot(value, MAX_CONFIG_BYTES);
    if (!closed(copy, ['version', 'scopes']) || copy.version !== MARKETPLACE_QUALIFICATION_CONFIG_VERSION
      || !Array.isArray(copy.scopes) || copy.scopes.length < 1 || copy.scopes.length > 16) return null;
    const ids = new Set<string>();
    for (const scope of copy.scopes) {
      if (!closed(scope, ['scope_id', 'scope_label', 'context', 'qualification_status_chain', 'qualification_status_observation'])
        || typeof scope.scope_id !== 'string' || !SCOPE_ID.test(scope.scope_id) || ids.has(scope.scope_id)
        || typeof scope.scope_label !== 'string' || !scope.scope_label.trim() || scope.scope_label.length > 240
        || /[\u0000-\u001f\u007f]/.test(scope.scope_label)
        || !object(scope.context) || Object.hasOwn(scope.context, 'now')) return null;
      // Reuse the public verifier's context validation, including key parsing,
      // thresholds, alias rejection, exact fields and the model-pinning floor.
      if (evaluateQualification(null, { ...scope.context, now }).reason !== 'invalid_qualification_bundle') return null;
      const context = scope.context as unknown as MarketplaceQualificationScope['context'];
      if (context.max_status_observation_age_seconds < 1 || context.max_status_observation_age_seconds > MAX_AGE_SECONDS
        || context.max_runtime_measurement_age_seconds < 1 || context.max_runtime_measurement_age_seconds > MAX_AGE_SECONDS
        || !['VERSION_PINNED', 'IMMUTABLE_DIGEST'].includes(context.minimum_model_pinning_strength)) return null;
      if (!Array.isArray(scope.qualification_status_chain) || scope.qualification_status_chain.length < 1
        || scope.qualification_status_chain.length > GATE_QUALIFICATION_LIMITS.max_status_entries
        || !object(scope.qualification_status_observation)) return null;
      ids.add(scope.scope_id);
    }
    return copy as unknown as MarketplaceQualificationConfiguration;
  } catch {
    return null;
  }
}

function unavailable(reason: string, checkedAt: string | null = null): MarketplaceQualificationResponse {
  return { status: 'UNAVAILABLE', reason, checked_at: checkedAt, result: null, display: null, boundary: BOUNDARY };
}

/** Pure projection of the existing verifier. It stores, publishes and authorizes nothing. */
export function evaluateMarketplaceQualification(
  input: unknown,
  operatorConfiguration: unknown,
  serverNow: Date = new Date(),
): MarketplaceQualificationResponse {
  const parsed = validateMarketplaceQualificationRequest(input);
  if (!parsed.ok) {
    return { ...unavailable(parsed.reason), status: 'INVALID_REQUEST' };
  }
  let checkedAt: string;
  try { checkedAt = serverNow.toISOString(); } catch { return unavailable('qualification_clock_unavailable'); }
  if (operatorConfiguration === null || operatorConfiguration === undefined) return unavailable('qualification_not_configured', checkedAt);
  const config = configuration(operatorConfiguration, checkedAt);
  if (!config) return unavailable('qualification_configuration_invalid', checkedAt);
  const scope = config.scopes.find((entry) => entry.scope_id === parsed.value.scope_id);
  if (!scope) return unavailable('qualification_scope_unavailable', checkedAt);

  const bundle = {
    ...parsed.value.evidence,
    qualification_status_chain: scope.qualification_status_chain,
    qualification_status_observation: scope.qualification_status_observation,
  };
  const result = evaluateQualification(bundle, { ...scope.context, now: checkedAt });
  const response: MarketplaceQualificationResponse = {
    status: result.decision, reason: result.reason, checked_at: checkedAt,
    result, display: null, boundary: BOUNDARY,
  };
  if (result.decision !== 'QUALIFIED') return response;

  // Decode only after the existing verifier has authenticated the complete
  // graph. These timestamps limit a display; they never issue fresh status.
  try {
    const head = scope.qualification_status_chain.at(-1) as { payload: string };
    const status = JSON.parse(Buffer.from(head.payload, 'base64').toString('utf8'));
    const runtime = JSON.parse(Buffer.from((bundle.runtime_measurement as { payload: string }).payload, 'base64').toString('utf8'));
    const expiresAt = Math.min(
      Date.parse(status.next_update), Date.parse(status.valid_until),
      Date.parse(scope.qualification_status_observation.observed_at) + scope.context.max_status_observation_age_seconds * 1000,
      Date.parse(runtime.measured_at) + scope.context.max_runtime_measurement_age_seconds * 1000,
    );
    if (!Number.isFinite(expiresAt) || expiresAt <= serverNow.getTime()) {
      return unavailable('qualification_display_expired', checkedAt);
    }
    response.display = {
      label: 'Qualified for this test scope', scope_id: scope.scope_id, scope_label: scope.scope_label,
      candidate_manifest_digest: scope.context.expected_candidate_manifest_digest,
      assignment_digest: scope.context.expected_assignment_digest,
      qualification_policy_digest: scope.context.expected_qualification_policy_digest,
      protected_request_digest: scope.context.expected_protected_request_digest,
      qualification_statement_digest: result.payload_digests.qualification_statement!,
      qualification_status_head_digest: result.payload_digests.qualification_status_head!,
      status_observed_at: scope.qualification_status_observation.observed_at,
      checked_at: checkedAt, expires_at: new Date(expiresAt).toISOString(),
    };
    return response;
  } catch {
    return unavailable('qualification_projection_unavailable', checkedAt);
  }
}
