// SPDX-License-Identifier: Apache-2.0
// Customer-signed activation of an EMILIA protection plan. This artifact is
// gateway configuration. It is not per-action authority and it does not prove
// that a connector is installed, complete, or enforcing traffic.

import {
  RISK_DIGEST,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskInstant,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';
import {
  PROTECTION_PLAN_VERSION,
} from './protection-plan.js';
import { validateActionControlManifest } from './action-control-manifest.js';

export const PROTECTION_ACTIVATION_VERSION = 'EP-PROTECTION-ACTIVATION-v1';
export const PROTECTION_ACTIVATION_CLAIM_BOUNDARY =
  'customer_pinned_gateway_configuration_not_per_action_authority_connector_coverage_deployment_or_effect_truth';

const BODY_KEYS = [
  '@version',
  'activation_id',
  'tenant_id',
  'gateway_id',
  'epoch',
  'issued_at',
  'valid_from',
  'expires_at',
  'plan',
  'plan_digest',
  'manifest_digest',
  'claim_boundary',
] as const;

export type ProtectionActivationExpected = Readonly<{
  activation_id: string;
  tenant_id: string;
  gateway_id: string;
  minimum_epoch?: number;
  plan_digest?: string;
  manifest_digest?: string;
  authorizer_id: string;
}>;

function validPlan(plan: unknown): plan is RiskRecord {
  if (!riskExact(plan, [
    '@version',
    'plan_id',
    'owner',
    'created_at',
    'selections',
    'action_control_manifest',
    'authority',
    'activation',
  ]) || plan['@version'] !== PROTECTION_PLAN_VERSION
      || !riskIdentifier(plan.plan_id)
      || !riskExact(plan.owner, ['label'])
      || typeof plan.owner.label !== 'string'
      || !Number.isFinite(riskInstant(plan.created_at))
      || !Array.isArray(plan.selections) || plan.selections.length < 1
      || !riskExact(plan.authority, ['status', 'limitation'])
      || plan.authority.status !== 'unsigned_owner_draft'
      || typeof plan.authority.limitation !== 'string'
      || !riskExact(plan.activation, ['status', 'limitation'])
      || plan.activation.status !== 'not_active'
      || typeof plan.activation.limitation !== 'string') return false;
  return validateActionControlManifest(plan.action_control_manifest).ok;
}

function validateBody(value: unknown): asserts value is RiskRecord {
  if (!riskRecord(value)) throw new TypeError('protection_activation_shape_invalid');
  const { issuer, proof: _proof, ...body } = value;
  if (issuer !== undefined && (!riskExact(issuer, ['id', 'key_id'])
      || !riskIdentifier(issuer.id) || !riskIdentifier(issuer.key_id))) {
    throw new TypeError('protection_activation_issuer_invalid');
  }
  if (!riskExact(body, BODY_KEYS)
      || body['@version'] !== PROTECTION_ACTIVATION_VERSION
      || !riskIdentifier(body.activation_id)
      || !riskIdentifier(body.tenant_id)
      || !riskIdentifier(body.gateway_id)
      || !Number.isSafeInteger(body.epoch) || body.epoch < 1
      || !validPlan(body.plan)
      || typeof body.plan_digest !== 'string' || !RISK_DIGEST.test(body.plan_digest)
      || typeof body.manifest_digest !== 'string' || !RISK_DIGEST.test(body.manifest_digest)
      || body.plan_digest !== riskDigest(body.plan)
      || body.manifest_digest !== riskDigest(body.plan.action_control_manifest)
      || body.claim_boundary !== PROTECTION_ACTIVATION_CLAIM_BOUNDARY) {
    throw new TypeError('protection_activation_shape_invalid');
  }
  const issued = riskInstant(body.issued_at);
  const validFrom = riskInstant(body.valid_from);
  const expires = riskInstant(body.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(validFrom)
      || !Number.isFinite(expires) || validFrom < issued || expires <= validFrom) {
    throw new TypeError('protection_activation_window_invalid');
  }
}

export function signProtectionActivation(input: RiskRecord, signer: {
  issuer_id: string;
  key_id: string;
  private_key: import('node:crypto').KeyLike;
}): RiskRecord {
  if (!riskRecord(input) || !validPlan(input.plan)) {
    throw new TypeError('protection_activation_input_invalid');
  }
  const artifact = signRiskBody(PROTECTION_ACTIVATION_VERSION, {
    '@version': PROTECTION_ACTIVATION_VERSION,
    activation_id: input.activation_id,
    tenant_id: input.tenant_id,
    gateway_id: input.gateway_id,
    epoch: input.epoch,
    issued_at: input.issued_at,
    valid_from: input.valid_from,
    expires_at: input.expires_at,
    plan: input.plan,
    plan_digest: riskDigest(input.plan),
    manifest_digest: riskDigest(input.plan.action_control_manifest),
    claim_boundary: PROTECTION_ACTIVATION_CLAIM_BOUNDARY,
  }, signer);
  validateBody(artifact);
  return artifact;
}

export function verifyProtectionActivation(
  artifact: unknown,
  options: {
    trusted_keys?: TrustedRiskKeys;
    expected?: ProtectionActivationExpected;
    now?: number | string | (() => number | string);
  } = {},
): RiskRecord {
  const refuse = (reason: string) => riskFreeze({
    accepted: false,
    reason,
    activation: null,
    activation_digest: null,
    manifest: null,
  });
  try {
    validateBody(artifact);
  } catch (error) {
    return refuse((error as Error)?.message || 'protection_activation_invalid');
  }
  const verified = verifyRiskBody(
    artifact,
    PROTECTION_ACTIVATION_VERSION,
    options.trusted_keys,
  );
  if (!verified.valid || !verified.body) return refuse(verified.reason || 'protection_activation_invalid');
  const body = verified.body;
  const expected = options.expected;
  if (!expected) return refuse('protection_activation_expected_context_required');
  if (body.activation_id !== expected.activation_id
      || body.tenant_id !== expected.tenant_id
      || body.gateway_id !== expected.gateway_id
      || body.issuer.id !== expected.authorizer_id) {
    return refuse('protection_activation_context_mismatch');
  }
  if (expected.minimum_epoch !== undefined
      && (!Number.isSafeInteger(expected.minimum_epoch) || body.epoch < expected.minimum_epoch)) {
    return refuse('protection_activation_epoch_stale');
  }
  if ((expected.plan_digest && body.plan_digest !== expected.plan_digest)
      || (expected.manifest_digest && body.manifest_digest !== expected.manifest_digest)) {
    return refuse('protection_activation_pin_mismatch');
  }
  const rawNow = typeof options.now === 'function' ? options.now() : (options.now ?? Date.now());
  const now = typeof rawNow === 'string' ? riskInstant(rawNow) : rawNow;
  if (!Number.isFinite(now)) return refuse('protection_activation_now_invalid');
  if (now < riskInstant(body.valid_from)) return refuse('protection_activation_not_yet_valid');
  if (now >= riskInstant(body.expires_at)) return refuse('protection_activation_expired');
  return riskFreeze({
    accepted: true,
    reason: null,
    activation: body,
    activation_digest: verified.artifact_digest,
    manifest: body.plan.action_control_manifest,
    manifest_digest: body.manifest_digest,
    owner_key_id: body.issuer.key_id,
    owner_id: body.issuer.id,
    claim_boundary: PROTECTION_ACTIVATION_CLAIM_BOUNDARY,
  });
}

export default {
  PROTECTION_ACTIVATION_VERSION,
  PROTECTION_ACTIVATION_CLAIM_BOUNDARY,
  signProtectionActivation,
  verifyProtectionActivation,
};
