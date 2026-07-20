// SPDX-License-Identifier: Apache-2.0
//
// Exact-action preparation and consume-time verification for Accountable
// Signoff on policy rollout activation.

import { hashCanonicalAction } from '../guard-policies.js';
import { boundSignoffDecisionEvents, findBoundSignoffDecision } from '../guard-signoff-binding.js';
import { deriveSignoffUserVerification } from '../guard-signoff-uv.js';
import { resolveGuardAuthority } from '../guard-authority.js';
import { getRpConfig } from '../webauthn.js';
import { decisionsToMembers } from '../signoff/attestation-members.js';
import { quorumGate } from '../signoff/quorum-session.js';

export const POLICY_ROLLOUT_ACTION_TYPE = 'policy_rollout';
export const POLICY_ROLLOUT_EXECUTING_SYSTEM = 'emilia.cloud.policy_rollout';
export const POLICY_ROLLOUT_RECEIPT_TTL_SEC = 15 * 60;
export const POLICY_ROLLOUT_APPROVER_ROLES = Object.freeze([
  'policy_admin',
  'control_plane_approver',
]);

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sameCanonical(left, right) {
  try {
    return hashCanonicalAction(left) === hashCanonicalAction(right);
  } catch {
    return false;
  }
}

export function policyRolloutTargetResource(policyKey) {
  return `policy:${policyKey}`;
}

export function buildPolicyRolloutBeforeState(activeRollouts = []) {
  const normalized = (activeRollouts || []).map((row) => ({
    rollout_id: row.rollout_id,
    policy_id: row.policy_id,
    version: row.version,
    environment: row.environment,
    strategy: row.strategy,
    canary_pct: row.canary_pct ?? null,
    metadata: row.metadata || {},
    authorization_receipt_id: row.authorization_receipt_id || null,
  }));
  normalized.sort((a, b) => String(a.rollout_id).localeCompare(String(b.rollout_id)));
  return { active_rollouts: normalized };
}

export function buildPolicyRolloutAfterState({
  policyId,
  policyKey,
  version,
  policyRules,
  policyMode,
  policyStatus,
  environment,
  strategy,
  canaryPct,
  metadata,
}) {
  return {
    policy_id: policyId,
    policy_key: policyKey,
    policy_version: version,
    policy_rules: policyRules,
    policy_mode: policyMode,
    policy_status: policyStatus,
    environment,
    strategy,
    canary_pct: strategy === 'canary' ? canaryPct : null,
    metadata: metadata || {},
  };
}

export function buildPolicyRolloutReceiptRequest({
  tenantId,
  executingKeyId,
  policyId,
  policyKey,
  version,
  policyRules,
  policyMode,
  policyStatus,
  environment,
  strategy,
  canaryPct,
  metadata,
  beforeState,
  afterState,
  quorumPolicy = null,
}) {
  return {
    organization_id: tenantId,
    action_type: POLICY_ROLLOUT_ACTION_TYPE,
    target_resource_id: policyRolloutTargetResource(policyKey),
    before_state: beforeState,
    after_state: afterState,
    executing_key_id: executingKeyId,
    rollout_policy_id: policyId,
    rollout_policy_key: policyKey,
    rollout_policy_version: version,
    rollout_policy_rules: policyRules,
    rollout_policy_mode: policyMode,
    rollout_policy_status: policyStatus,
    rollout_environment: environment,
    rollout_strategy: strategy,
    rollout_canary_pct: strategy === 'canary' ? canaryPct : null,
    rollout_metadata: metadata || {},
    expires_in_sec: POLICY_ROLLOUT_RECEIPT_TTL_SEC,
    enforcement_mode: 'enforce',
    ...(quorumPolicy ? { quorum_policy: quorumPolicy } : {}),
  };
}

/**
 * Materialize the exact rollout quorum from an org-pinned template.
 *
 * Rollout issuance never lets the executing key choose its own approvers. A
 * mandatory rollout quorum therefore needs a concrete pinned roster, not only
 * an abstract threshold floor. Incomplete templates fail closed before a 428
 * response can advertise an authorization flow that cannot finish.
 */
export function buildPolicyRolloutQuorumPolicy(template) {
  if (!template?.quorum_required) return { policy: null };
  const approvers = Array.isArray(template.allowed_approvers)
    ? template.allowed_approvers.filter(
      (entry) => typeof entry?.role === 'string'
        && entry.role
        && typeof entry?.approver === 'string'
        && entry.approver,
    )
    : [];
  if (approvers.length === 0 || approvers.length !== template.allowed_approvers.length) {
    return failure(
      409,
      'policy_rollout_quorum_roster_required',
      'Mandatory policy-rollout quorum requires a concrete org-pinned approver roster',
    );
  }

  const allowedModes = Array.isArray(template.allowed_modes) ? template.allowed_modes : [];
  const mode = allowedModes.includes('threshold')
    ? 'threshold'
    : (allowedModes.includes('ordered') ? 'ordered' : 'threshold');
  const required = mode === 'ordered'
    ? approvers.length
    : (Number.isInteger(template.min_required) ? template.min_required : approvers.length);
  if (required < 1 || required > approvers.length) {
    return failure(
      409,
      'policy_rollout_quorum_template_invalid',
      'The org-pinned policy-rollout quorum threshold cannot be satisfied by its roster',
    );
  }

  return {
    policy: {
      mode,
      required,
      approvers,
      // Class-A production rollout is intentionally stricter than a generic
      // org template: one person cannot occupy multiple authorization seats.
      distinct_humans: true,
      window_sec: Number.isInteger(template.max_window_sec)
        ? template.max_window_sec
        : POLICY_ROLLOUT_RECEIPT_TTL_SEC,
    },
  };
}

export function validatePolicyRolloutInput(body, { requireAuthorization = false } = {}) {
  if (!Number.isSafeInteger(body?.version) || body.version < 1) {
    return { status: 400, code: 'invalid_version', detail: 'version must be a positive integer' };
  }
  if (typeof body.environment !== 'string' || !body.environment.trim() || body.environment.length > 128) {
    return {
      status: 400,
      code: 'invalid_environment',
      detail: 'environment must be a non-empty string of at most 128 characters',
    };
  }
  if (body.metadata !== undefined && !isPlainObject(body.metadata)) {
    return { status: 400, code: 'invalid_metadata', detail: 'metadata must be a JSON object' };
  }

  if (!requireAuthorization && body.authorization === undefined) return null;
  const authorization = body.authorization;
  if (!isPlainObject(authorization)) {
    return {
      status: 428,
      code: 'accountable_signoff_required',
      detail: 'A pending, approved Class-A Accountable Signoff receipt is required for policy rollout activation',
    };
  }
  const keys = Object.keys(authorization);
  if (keys.length !== 1 || keys[0] !== 'receipt_id' || !RECEIPT_ID_PATTERN.test(authorization.receipt_id || '')) {
    return {
      status: 400,
      code: 'invalid_rollout_authorization',
      detail: 'authorization must contain exactly receipt_id matching tr_<32-hex>',
    };
  }
  return null;
}

function failure(status, code, detail) {
  return { ok: false, status, code, detail };
}

export function verifyPolicyRolloutEvidenceShape(events, {
  tenantId,
  executingKeyId,
  policyId,
  policyKey,
  version,
  policyRules,
  policyMode,
  policyStatus,
  environment,
  strategy,
  canaryPct,
  metadata,
  beforeState,
  afterState,
  receiptId,
  quorumPolicy = null,
  now = Date.now(),
}) {
  if (!Array.isArray(events)) {
    return failure(503, 'rollout_authorization_unavailable', 'Could not load Accountable Signoff evidence');
  }
  const createdEvents = events.filter((event) => event?.event_type === 'guard.trust_receipt.created');
  const consumedEvents = events.filter((event) => event?.event_type === 'guard.trust_receipt.consumed');
  if (createdEvents.length !== 1) {
    return failure(403, 'accountable_signoff_required', 'The authorization receipt has no unique creation event');
  }
  if (consumedEvents.length !== 0) {
    return failure(409, 'rollout_authorization_replayed', 'The authorization receipt has already been consumed');
  }

  const createdEvent = createdEvents[0];
  const created = createdEvent.after_state;
  const action = created?.canonical_action;
  if (!isPlainObject(created) || !isPlainObject(action) || !createdEvent.actor_id) {
    return failure(403, 'rollout_authorization_corrupt', 'The authorization receipt is missing creator-bound evidence');
  }
  if (createdEvent.actor_id !== `ep:cloud-key:${executingKeyId}`) {
    return failure(
      403,
      'rollout_authorization_creator_mismatch',
      'The authorization receipt was not created by the executing tenant rollout key',
    );
  }
  if (created.organization_id !== tenantId || action.organization_id !== tenantId) {
    return failure(403, 'rollout_authorization_tenant_mismatch', 'The authorization receipt is not bound to this tenant');
  }
  if (created.action_type !== POLICY_ROLLOUT_ACTION_TYPE
      || action.action_type !== POLICY_ROLLOUT_ACTION_TYPE
      || created.target_resource_id !== policyRolloutTargetResource(policyKey)
      || action.target_resource_id !== policyRolloutTargetResource(policyKey)) {
    return failure(403, 'rollout_authorization_target_mismatch', 'The authorization receipt is not bound to this policy target');
  }
  if (created.decision !== 'allow_with_signoff'
      || created.signoff_required !== true
      || created.required_assurance !== 'A'
      || !sameCanonical(created.quorum_policy ?? null, quorumPolicy ?? null)) {
    return failure(
      403,
      'rollout_authorization_assurance_insufficient',
      'Policy rollout authorization does not match the required Class-A signoff or quorum policy',
    );
  }
  const expiresAt = Date.parse(created.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    return failure(410, 'rollout_authorization_expired', 'The policy rollout authorization receipt has expired');
  }
  if (hashCanonicalAction(action) !== created.action_hash) {
    return failure(403, 'rollout_authorization_action_mismatch', 'The stored canonical action does not match its action hash');
  }
  if (created.before_state_hash !== hashCanonicalAction(beforeState)
      || created.after_state_hash !== hashCanonicalAction(afterState)
      || action.before_state_hash !== created.before_state_hash
      || action.after_state_hash !== created.after_state_hash) {
    return failure(409, 'rollout_authorization_stale', 'The active rollout or requested rollout changed after approval');
  }

  const expectedFields = {
    executing_key_id: executingKeyId,
    rollout_policy_id: policyId,
    rollout_policy_key: policyKey,
    rollout_policy_version: version,
    rollout_policy_rules: policyRules,
    rollout_policy_mode: policyMode,
    rollout_policy_status: policyStatus,
    rollout_environment: environment,
    rollout_strategy: strategy,
    rollout_canary_pct: strategy === 'canary' ? canaryPct : null,
    rollout_metadata: metadata || {},
    rollout_before_state: beforeState,
    rollout_after_state: afterState,
  };
  for (const [field, expected] of Object.entries(expectedFields)) {
    if (!sameCanonical(action[field], expected)) {
      return failure(403, 'rollout_authorization_action_mismatch', `The authorization receipt does not bind ${field}`);
    }
  }

  const rejected = boundSignoffDecisionEvents(events, createdEvent, 'guard.signoff.rejected');
  if (rejected.length > 0) return failure(403, 'signoff_rejected', 'The Accountable Signoff was rejected');
  if (quorumPolicy) {
    const approvals = boundSignoffDecisionEvents(events, createdEvent, 'guard.signoff.approved');
    if (approvals.length === 0) {
      return failure(403, 'accountable_signoff_required', 'The authorization receipt has no creator-bound quorum approvals');
    }
    if (approvals.some((event) => event.after_state?.key_class !== 'A')) {
      return failure(403, 'rollout_authorization_assurance_insufficient', 'Every quorum approval must be Class A');
    }
    return {
      ok: true,
      createdEvent,
      created,
      action,
      approvals,
      quorumPolicy,
      actionHash: created.action_hash,
    };
  }

  const approved = findBoundSignoffDecision(events, createdEvent, 'guard.signoff.approved');
  if (!approved) return failure(403, 'accountable_signoff_required', 'The authorization receipt has no creator-bound approval');
  if (approved.after_state?.key_class !== 'A') {
    return failure(403, 'rollout_authorization_assurance_insufficient', 'The approval is not Class A');
  }

  return {
    ok: true,
    createdEvent,
    created,
    action,
    approved,
    actionHash: created.action_hash,
  };
}

/**
 * Re-verify the Class-A approval and authority immediately before the atomic
 * database consume+activation transaction.
 *
 * @param {{
 *   supabase: object,
 *   events: object[],
 *   expected: object,
 *   dependencies?: {
 *     getRpConfig?: typeof getRpConfig,
 *     deriveSignoffUserVerification?: typeof deriveSignoffUserVerification,
 *     resolveGuardAuthority?: typeof resolveGuardAuthority,
 *     quorumGate?: typeof quorumGate
 *   }
 * }} input
 */
export async function verifyPolicyRolloutAuthorization({
  supabase,
  events,
  expected,
  dependencies = {},
}) {
  const shaped = verifyPolicyRolloutEvidenceShape(events, expected);
  if (!shaped.ok) return shaped;

  if (shaped.quorumPolicy) {
    const approvedStates = shaped.approvals.map((event) => event.after_state);
    const credentialIds = approvedStates
      .map((state) => state?.webauthn?.credential_id)
      .filter(Boolean);
    if (credentialIds.length !== approvedStates.length
        || new Set(credentialIds).size !== credentialIds.length) {
      return failure(403, 'rollout_authorization_assurance_insufficient', 'Every quorum member must use one distinct enrolled credential');
    }

    const { data: credentials, error: credentialError } = await supabase
      .from('approver_credentials')
      .select('credential_id, approver_id, public_key_spki, key_class, valid_from, valid_to, revoked_at')
      .eq('organization_id', expected.tenantId)
      .in('credential_id', credentialIds);
    if (credentialError) {
      return failure(503, 'rollout_authorization_unavailable', 'Could not re-verify quorum credentials');
    }

    const now = new Date(expected.now ?? Date.now());
    const credentialsById = Object.fromEntries(
      (credentials || []).map((credential) => [credential.credential_id, credential]),
    );
    for (const state of approvedStates) {
      const approverId = state?.approver_id || state?.context?.approver || null;
      const credential = credentialsById[state?.webauthn?.credential_id] || null;
      if (!credential
          || credential.approver_id !== approverId
          || credential.key_class !== 'A'
          || credential.revoked_at
          || (credential.valid_from && new Date(credential.valid_from) > now)
          || (credential.valid_to && new Date(credential.valid_to) <= now)) {
        return failure(
          403,
          'rollout_authorization_assurance_insufficient',
          'A quorum credential is not active and owned by its approved approver',
        );
      }
    }

    const members = decisionsToMembers(shaped.quorumPolicy, approvedStates, credentialsById);
    const rpConfig = (dependencies.getRpConfig || getRpConfig)();
    const gate = (dependencies.quorumGate || quorumGate)(shaped.quorumPolicy, shaped.actionHash, members, {
      rpId: rpConfig.rpID,
      allowedOrigins: [rpConfig.origin],
    });
    if (!gate.satisfied) {
      return failure(403, 'quorum_not_satisfied', 'The policy-rollout quorum could not be cryptographically re-verified');
    }

    const authorityMembers = [];
    for (const state of approvedStates) {
      const approverId = state?.approver_id || state?.context?.approver || null;
      const credentialId = state?.webauthn?.credential_id;
      const authority = await (dependencies.resolveGuardAuthority || resolveGuardAuthority)(supabase, {
        organizationId: expected.tenantId,
        approverId,
        at: now.toISOString(),
        requiredAssurance: 'A',
        actionType: POLICY_ROLLOUT_ACTION_TYPE,
        requireExplicitScope: true,
        allowedRoles: [...POLICY_ROLLOUT_APPROVER_ROLES],
      });
      if (!authority.authorized || !authority.authority_id) {
        return failure(403, 'authority_invalid', `Policy rollout quorum authority failed for ${approverId}: ${authority.reason}`);
      }
      authorityMembers.push({
        authority_id: authority.authority_id,
        approver_id: approverId,
        credential_id: credentialId,
        assurance_class: authority.assurance_class || null,
        authority_check: authority.reason,
        action_scope: POLICY_ROLLOUT_ACTION_TYPE,
        role: authority.role || null,
        user_verification: 'verified',
      });
    }
    authorityMembers.sort((left, right) => left.approver_id.localeCompare(right.approver_id));

    return {
      ...shaped,
      authority: {
        quorum: true,
        members: authorityMembers,
      },
      authorityIds: authorityMembers.map((member) => member.authority_id),
    };
  }

  const approvedState = shaped.approved.after_state;
  const approverId = approvedState?.approver_id || shaped.approved.actor_id || null;
  const credentialId = approvedState?.webauthn?.credential_id || null;
  if (!credentialId) {
    return failure(403, 'rollout_authorization_assurance_insufficient', 'The Class-A approval has no enrolled credential');
  }
  const { data: credentials, error: credentialError } = await supabase
    .from('approver_credentials')
    .select('credential_id, approver_id, public_key_spki, key_class, valid_from, valid_to, revoked_at')
    .eq('organization_id', expected.tenantId)
    .eq('credential_id', credentialId)
    .is('revoked_at', null)
    .limit(1);
  if (credentialError) {
    return failure(503, 'rollout_authorization_unavailable', 'Could not re-verify the approver credential');
  }
  const credential = (credentials || [])[0] || null;
  const now = new Date(expected.now ?? Date.now());
  if (!credential
      || credential.approver_id !== approverId
      || credential.key_class !== 'A'
      || credential.revoked_at
      || (credential.valid_from && new Date(credential.valid_from) > now)
      || (credential.valid_to && new Date(credential.valid_to) <= now)) {
    return failure(
      403,
      'rollout_authorization_assurance_insufficient',
      'The Class-A credential is not active and owned by the approved approver',
    );
  }
  const publicKey = credential.public_key_spki || null;
  const rpConfig = (dependencies.getRpConfig || getRpConfig)();
  const uv = (dependencies.deriveSignoffUserVerification || deriveSignoffUserVerification)({
    decision: approvedState,
    approverPublicKeySpki: publicKey,
    expectedActionHash: shaped.actionHash,
    rpId: rpConfig.rpID,
    allowedOrigins: [rpConfig.origin],
  });
  if (!uv.verified) {
    return failure(
      403,
      'rollout_authorization_assurance_insufficient',
      `The Class-A approval could not be re-verified (${uv.reason})`,
    );
  }

  const authority = await (dependencies.resolveGuardAuthority || resolveGuardAuthority)(supabase, {
    organizationId: expected.tenantId,
    approverId,
    at: now.toISOString(),
    requiredAssurance: 'A',
    actionType: POLICY_ROLLOUT_ACTION_TYPE,
    requireExplicitScope: true,
    allowedRoles: [...POLICY_ROLLOUT_APPROVER_ROLES],
  });
  if (!authority.authorized) {
    return failure(403, 'authority_invalid', `Policy rollout approver authority failed: ${authority.reason}`);
  }

  return {
    ...shaped,
    authority: {
      authority_id: authority.authority_id || null,
      assurance_class: authority.assurance_class || null,
      authority_check: authority.reason,
      action_scope: POLICY_ROLLOUT_ACTION_TYPE,
      // The registry is the permission root. The normal single-signoff event
      // does not carry an operator-supplied role, so persist the role resolved
      // from the active authority row rather than trusting event metadata.
      role: authority.role || null,
      user_verification: 'verified',
    },
    authorityIds: [authority.authority_id],
  };
}

const policyRolloutAuthorization = {
  POLICY_ROLLOUT_ACTION_TYPE,
  POLICY_ROLLOUT_EXECUTING_SYSTEM,
  POLICY_ROLLOUT_RECEIPT_TTL_SEC,
  buildPolicyRolloutQuorumPolicy,
  buildPolicyRolloutAfterState,
  buildPolicyRolloutBeforeState,
  buildPolicyRolloutReceiptRequest,
  policyRolloutTargetResource,
  validatePolicyRolloutInput,
  verifyPolicyRolloutAuthorization,
  verifyPolicyRolloutEvidenceShape,
};

export default policyRolloutAuthorization;
