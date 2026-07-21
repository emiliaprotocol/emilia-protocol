// SPDX-License-Identifier: Apache-2.0
//
// Narrow authentication bridge for Guard control-plane flows. Normal EP
// entity keys retain the existing authenticateRequest path. Tenant
// control-plane keys are admitted only when they are the generated ept_* form
// and hold admin, policy_rollout, or approval_request permission. The full
// permission grant is preserved so each route can enforce its own capability.

import { authenticateRequest } from './supabase.js';
import { authenticateCloudRequest } from './cloud/auth.js';

const GUARD_CLOUD_PERMISSIONS = new Set([
  'admin',
  'policy_rollout',
  'approval_request',
]);

/**
 * @param {Request} request
 * @param {{
 *   authenticateProtocol?: typeof authenticateRequest,
 *   authenticateCloud?: typeof authenticateCloudRequest
 * }} [dependencies]
 */
export async function authenticateGuardRequest(request, dependencies = {}) {
  const header = request.headers.get('authorization') || '';
  const isTenantControlPlaneKey = /^Bearer\s+ept_/i.test(header);
  if (!isTenantControlPlaneKey) {
    return (dependencies.authenticateProtocol || authenticateRequest)(request);
  }

  const cloud = await (dependencies.authenticateCloud || authenticateCloudRequest)(request);
  if (!cloud) {
    return {
      error: 'Cloud API key authentication failed',
      code: 'cloud_auth_failed',
      status: 401,
    };
  }
  if (!Array.isArray(cloud.permissions)
      || !cloud.permissions.some((permission) => GUARD_CLOUD_PERMISSIONS.has(permission))) {
    return {
      error: 'Cloud API key requires admin, policy_rollout, or approval_request permission for Guard authorization',
      code: 'cloud_guard_permission_required',
      status: 403,
    };
  }

  const principalId = `ep:cloud-key:${cloud.keyId}`;
  return {
    entity: {
      id: principalId,
      entity_id: principalId,
      organization_id: cloud.tenantId,
    },
    permissions: [...cloud.permissions],
    auth_strength: 'service_account',
    guard_cloud: {
      key_id: cloud.keyId,
      environment: cloud.environment || null,
    },
  };
}

export function isCloudGuardPrincipal(auth) {
  return Boolean(auth?.guard_cloud?.key_id);
}

const guardAuth = {
  authenticateGuardRequest,
  isCloudGuardPrincipal,
};

export default guardAuth;
