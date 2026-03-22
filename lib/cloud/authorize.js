/**
 * Cloud Control Plane — Authorization
 *
 * Permission check layer for cloud routes. Works with the auth context
 * returned by authenticateCloudRequest().
 *
 * Permissions follow a simple model: 'read', 'write', 'admin'.
 * 'admin' implies 'write', and 'write' implies 'read'.
 *
 * @license Apache-2.0
 */

/** Permission hierarchy — higher includes all lower levels. */
const PERMISSION_LEVEL = Object.freeze({
  read: 1,
  write: 2,
  admin: 3,
});

/**
 * Check whether the auth result has the required permission.
 *
 * @param {{ tenantId: string, environment: string, permissions: string[] }} authResult
 *   The auth context from authenticateCloudRequest().
 * @param {'read' | 'write' | 'admin'} requiredPermission
 *   The minimum permission needed for this operation.
 * @throws {CloudAuthorizationError} If the permission is not held.
 */
export function requirePermission(authResult, requiredPermission) {
  if (!authResult || !Array.isArray(authResult.permissions)) {
    throw new CloudAuthorizationError(
      'No valid auth context provided',
      requiredPermission,
    );
  }

  const requiredLevel = PERMISSION_LEVEL[requiredPermission];
  if (!requiredLevel) {
    throw new CloudAuthorizationError(
      `Unknown permission: ${requiredPermission}`,
      requiredPermission,
    );
  }

  // The caller is authorized if ANY of their permissions meets or exceeds
  // the required level (e.g. 'admin' satisfies a 'read' requirement).
  const hasPermission = authResult.permissions.some(
    (p) => (PERMISSION_LEVEL[p] || 0) >= requiredLevel,
  );

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
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE, etc.)
 * @returns {'read' | 'write' | 'admin'}
 */
export function permissionForMethod(method) {
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
  constructor(message, requiredPermission) {
    super(message);
    this.name = 'CloudAuthorizationError';
    this.requiredPermission = requiredPermission;
  }
}
