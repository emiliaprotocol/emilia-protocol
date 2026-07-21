// SPDX-License-Identifier: Apache-2.0

/**
 * Enrollment is a directory mutation, not ordinary organization access.
 * Keep the capability explicit so read/write keys cannot mint an approver
 * credential. `admin` remains a documented super-capability for the hosted
 * enrollment surface.
 */
export const APPROVER_ENROLL_PERMISSION = 'approver.enroll';

export function hasApproverEnrollmentPermission(auth) {
  const permissions = auth?.permissions;
  return Array.isArray(permissions)
    && (permissions.includes(APPROVER_ENROLL_PERMISSION) || permissions.includes('admin'));
}
