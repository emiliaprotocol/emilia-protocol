/**
 * Cloud Control Plane — Authorization
 *
 * Permission check layer for cloud routes. Works with the auth context
 * returned by authenticateCloudRequest().
 *
 * Permissions follow a simple model: 'read', 'write', 'admin', plus named
 * least-privilege capabilities such as 'policy_rollout' and
 * 'approval_request'.
 * 'admin' implies 'write', and 'write' implies 'read'.
 *
 * @license Apache-2.0
 */

/** Permission hierarchy — higher includes all lower levels. */
const PERMISSION_LEVEL: Record<string, number> = Object.freeze({
  read: 1,
  write: 2,
  admin: 3,
});
const NAMED_PERMISSIONS = new Set(['policy_rollout', 'approval_request']);

export interface CloudAuthResultLike {
  tenantId: string;
  environment: string;
  permissions: string[];
  [key: string]: unknown;
}

/**
 * Check whether the auth result has the required permission.
 *
 * @param authResult  The auth context from authenticateCloudRequest().
 * @param requiredPermission  The minimum permission needed for this operation.
 * @throws {CloudAuthorizationError} If the permission is not held.
 */
export function requirePermission(authResult: CloudAuthResultLike | null | undefined, requiredPermission: string): void {
  if (!authResult || !Array.isArray(authResult.permissions)) {
    throw new CloudAuthorizationError(
      'No valid auth context provided',
      requiredPermission,
    );
  }

  const requiredLevel = PERMISSION_LEVEL[requiredPermission] || 0;
  if (requiredLevel === 0 && !NAMED_PERMISSIONS.has(requiredPermission)) {
    throw new CloudAuthorizationError(
      `Unknown required permission: '${requiredPermission}'`,
      requiredPermission,
    );
  }
  // Hierarchical permissions keep their existing semantics. Named
  // capabilities are exact-match, with admin as the documented
  // super-capability.
  const hasPermission = requiredLevel > 0
    ? authResult.permissions.some((p) => (PERMISSION_LEVEL[p] || 0) >= requiredLevel)
    : authResult.permissions.includes(requiredPermission)
      || authResult.permissions.includes('admin');

  if (!hasPermission) {
    throw new CloudAuthorizationError(
      `Insufficient permissions: '${requiredPermission}' required`,
      requiredPermission,
    );
  }
}

/**
 * Map an HTTP method to the default required permission.
 *
 * @param method - HTTP method (GET, POST, PUT, DELETE, etc.)
 */
export function permissionForMethod(method: string | null | undefined): 'read' | 'write' | 'admin' {
  switch (method?.toUpperCase()) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
      return 'read';
    case 'POST':
    case 'PUT':
    case 'PATCH':
    case 'DELETE':
      return 'write';
    default:
      return 'read';
  }
}

/**
 * Thrown when a cloud route authorization check fails.
 * Route handlers catch this and return a 403 response.
 */
export class CloudAuthorizationError extends Error {
  requiredPermission: string;

  constructor(message: string, requiredPermission: string) {
    super(message);
    this.name = 'CloudAuthorizationError';
    this.requiredPermission = requiredPermission;
  }
}
