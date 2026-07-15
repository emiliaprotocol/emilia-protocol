// SPDX-License-Identifier: Apache-2.0
/**
 * System-of-record controller for government mobile approval flows.
 *
 * The requester supplies only references and ceremony routing. The protected
 * action and human presentation are resolved by the government system of
 * record, so an agent cannot choose the bytes a human is asked to approve.
 */
export function createGovernmentMobileController({
  service,
  profiles,
  resolveRequest,
  authorize,
  registerChallenge = null,
} = {}) {
  if (typeof service?.issue !== 'function' || typeof service?.verifyAndConsume !== 'function') {
    throw new TypeError('service must be an EMILIA mobile ceremony service');
  }
  if (!(profiles instanceof Map) || profiles.size === 0) throw new TypeError('profiles must be a non-empty Map');
  if (typeof resolveRequest !== 'function') throw new TypeError('resolveRequest must read the system of record');
  if (typeof authorize !== 'function') throw new TypeError('authorize must enforce the government caller policy');
  if (registerChallenge !== null && typeof registerChallenge !== 'function') {
    throw new TypeError('registerChallenge must be a function when provided');
  }
  const byHash = new Map([...profiles.values()].map((profile) => [profile.profile_hash, profile]));
  const issueMembers = new Set([
    'profile_id', 'action_reference', 'approver_id', 'decision', 'platform',
    'app_id', 'device_key_id',
  ]);

  async function isAuthorized(input) {
    try {
      return (await authorize(input)) === true;
    } catch {
      return false;
    }
  }

  return {
    async issue(request, caller = null) {
      if (!request || typeof request !== 'object' || Array.isArray(request)
          || !Object.keys(request).every((key) => issueMembers.has(key))
          || typeof request.profile_id !== 'string'
          || typeof request.action_reference !== 'string'
          || typeof request.approver_id !== 'string'
          || !['approved', 'denied'].includes(request.decision)
          || !['ios', 'android'].includes(request.platform)
          || typeof request.app_id !== 'string'
          || typeof request.device_key_id !== 'string') {
        return { ok: false, verdict: 'refuse_malformed', challenge: null };
      }
      const profile = profiles.get(request.profile_id);
      if (!profile) return { ok: false, verdict: 'refuse_profile_mismatch', challenge: null };
      if (!(await isAuthorized({
        operation: 'mobile.challenge.issue',
        caller,
        profile_id: request.profile_id,
        profile_hash: profile.profile_hash,
        action_reference: request.action_reference,
        approver_id: request.approver_id,
        decision: request.decision,
        platform: request.platform,
        app_id: request.app_id,
        device_key_id: request.device_key_id,
      }))) {
        return { ok: false, verdict: 'refuse_unauthorized', challenge: null };
      }

      let resolved;
      try {
        resolved = await resolveRequest({
          action_reference: request.action_reference,
          approver_id: request.approver_id,
          decision: request.decision,
        });
      } catch {
        return { ok: false, verdict: 'refuse_store_unavailable', challenge: null };
      }
      if (!resolved || typeof resolved !== 'object' || Array.isArray(resolved)
          || !resolved.action || !resolved.presentation
          || typeof resolved.initiator_id !== 'string'
          || typeof resolved.approver_id !== 'string'
          || typeof resolved.issued_at !== 'string'
          || typeof resolved.expires_at !== 'string') {
        return { ok: false, verdict: 'refuse_malformed', challenge: null };
      }
      if (resolved.approver_id !== request.approver_id) {
        return { ok: false, verdict: 'refuse_unauthorized', challenge: null };
      }
      const issued = await service.issue({
        action: resolved.action,
        policy: resolved.policy || null,
        policyId: resolved.policy_id || null,
        initiatorId: resolved.initiator_id,
        approverId: resolved.approver_id,
        approverIndex: resolved.approver_index || 1,
        requiredApprovals: resolved.required_approvals || 1,
        decision: request.decision,
        presentation: resolved.presentation,
        platform: request.platform,
        appId: request.app_id,
        deviceKeyId: request.device_key_id,
        profile,
        issuedAt: resolved.issued_at,
        expiresAt: resolved.expires_at,
        challengeId: resolved.challenge_id,
        nonce: resolved.nonce,
      });
      if (issued.ok !== true || registerChallenge === null) return issued;
      try {
        const registered = await registerChallenge({
          action_reference: request.action_reference,
          approver_id: request.approver_id,
          decision: request.decision,
          challenge_id: issued.challenge.challenge_id,
          action_hash: issued.challenge.action_hash,
          expires_at: issued.challenge.expires_at,
        });
        if (registered !== true) {
          return { ok: false, verdict: 'refuse_replay', challenge: null };
        }
      } catch {
        return { ok: false, verdict: 'refuse_store_unavailable', challenge: null };
      }
      return issued;
    },

    async verify(presentation, caller = null) {
      const profile = byHash.get(presentation?.challenge?.profile_hash);
      if (!profile) {
        return {
          valid: false,
          verdict: 'refuse_profile_mismatch',
          decision: null,
          reason: 'challenge does not name a server-pinned profile',
          checks: {},
        };
      }
      const challenge = presentation?.challenge;
      const context = challenge?.authorization_context;
      const binding = context?.mobile_binding;
      if (!(await isAuthorized({
        operation: 'mobile.ceremony.verify',
        caller,
        profile_id: profile.profile_id,
        profile_hash: profile.profile_hash,
        challenge_id: challenge?.challenge_id || null,
        action_hash: challenge?.action_hash || null,
        approver_id: context?.approver || null,
        decision: context?.decision || null,
        platform: binding?.platform || null,
        app_id: binding?.app_id || null,
        device_key_id: binding?.device_key_id || null,
      }))) {
        return {
          valid: false,
          verdict: 'refuse_unauthorized',
          decision: null,
          reason: 'caller is not authorized for this mobile ceremony',
          checks: {},
        };
      }
      return service.verifyAndConsume({
        challenge,
        response: presentation.response,
        profile,
      });
    },
  };
}

export default { createGovernmentMobileController };
