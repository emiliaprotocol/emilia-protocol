// SPDX-License-Identifier: Apache-2.0
// API-key permission helpers for sensitive control-plane routes.
//
// `read` and `write` are intentionally not sufficient for identity-plane
// administration. A route that mints credentials or changes SSO configuration
// must name its capability explicitly; `admin` is the documented super-capability.

export function hasApiPermission(auth: any, permission: string): boolean {
  const permissions = auth?.permissions;
  return (
    Array.isArray(permissions) &&
    (permissions.includes(permission) || permissions.includes('admin'))
  );
}
