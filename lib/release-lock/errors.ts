// SPDX-License-Identifier: Apache-2.0

type SqlRefusalEntry = readonly [status: number, code: string, detail: string];

const SQL_REFUSALS: Readonly<Record<string, SqlRefusalEntry>> = Object.freeze({
  RL_ARGUMENT_INVALID: [400, 'invalid_request', 'The Release Lock request is malformed.'],
  RL_INVITATION_NOT_FOUND: [401, 'invitation_invalid', 'Invitation capability is invalid.'],
  RL_INVITATION_EXPIRED: [410, 'invitation_expired', 'Invitation capability has expired.'],
  RL_INVITATION_REPLAYED: [409, 'invitation_replayed', 'Invitation capability has already been exchanged.'],
  RL_INVITATION_SCOPE: [403, 'invitation_scope_mismatch', 'Invitation capability is bound to a different lock or role.'],
  RL_INVITATION_INACTIVE: [409, 'invitation_inactive', 'Invitation delivery can no longer be activated.'],
  RL_PAIRING_NOT_FOUND: [401, 'pairing_invalid', 'Action Mirror pairing is invalid.'],
  RL_PAIRING_EXPIRED: [410, 'pairing_expired', 'Action Mirror pairing has expired.'],
  RL_PAIRING_REPLAYED: [409, 'pairing_replayed', 'Action Mirror pairing has already been exchanged.'],
  RL_PAIRING_SCOPE: [403, 'pairing_scope_mismatch', 'Action Mirror pairing is bound to a different lock, role, or round.'],
  RL_SESSION_INVALID: [401, 'session_invalid', 'Release Lock session is invalid or expired.'],
  RL_SESSION_SCOPE: [403, 'session_scope_mismatch', 'Release Lock session is bound to a different lock.'],
  RL_LOCK_NOT_FOUND: [404, 'release_lock_not_found', 'Release Lock was not found.'],
  RL_ORGANIZATION_MISMATCH: [404, 'release_lock_not_found', 'Release Lock was not found.'],
  RL_CONTRACTOR_MISMATCH: [403, 'contractor_mismatch', 'Only the creating contractor entity may change this Release Lock.'],
  RL_VERSION_STALE: [409, 'stale_release_lock_version', 'The submitted Release Lock version is no longer current.'],
  RL_VERSION_FROZEN: [409, 'release_lock_effect_in_progress', 'The Release Lock effect is already reserved or in progress.'],
  RL_LOCK_EXPIRED: [410, 'release_lock_expired', 'The Release Lock version has expired.'],
  RL_ROUND_INVALID: [400, 'invalid_release_lock_round', 'Release Lock round is invalid.'],
  RL_ROUND_UNAVAILABLE: [409, 'release_lock_round_unavailable', 'This Release Lock round has not been staged.'],
  RL_ROUND_COMPLETE: [409, 'release_lock_round_complete', 'This Release Lock round is already complete.'],
  RL_CO_NOT_ACCEPTED: [409, 'change_order_not_accepted', 'DRAW_RELEASE requires a complete CO_ACCEPTED round for the current version.'],
  RL_DRAW_ALREADY_STAGED: [409, 'draw_release_already_staged', 'DRAW_RELEASE is already staged for this version.'],
  RL_CHALLENGE_NOT_FOUND: [404, 'challenge_not_found', 'No matching live challenge exists.'],
  RL_CHALLENGE_EXPIRED: [410, 'challenge_expired', 'The challenge has expired.'],
  RL_CHALLENGE_REPLAYED: [409, 'challenge_replayed', 'The challenge has already been consumed.'],
  RL_CHALLENGE_SCOPE: [403, 'challenge_scope_mismatch', 'The challenge is bound to a different lock, role, version, or contact.'],
  RL_CREDENTIAL_EXISTS: [409, 'credential_exists', 'This credential is already enrolled.'],
  RL_CREDENTIAL_NOT_FOUND: [403, 'credential_not_enrolled', 'Credential is not enrolled for this lock, role, and contact.'],
  RL_CREDENTIAL_REUSED: [409, 'credential_reused_across_roles', 'Each role must approve with a distinct enrolled credential.'],
  RL_CONTACT_REUSED: [409, 'contact_reused_across_roles', 'Each role must use a separately verified contact binding.'],
  RL_AUTHORITY_REUSED: [409, 'authority_subject_reused', 'Each role must use a distinct externally verified authority subject.'],
  RL_COUNTER_REPLAYED: [409, 'credential_counter_replayed', 'Credential counter did not advance.'],
  RL_APPROVAL_REPLAYED: [409, 'approval_already_recorded', 'This role has already approved this version.'],
  RL_APPROVAL_LIMIT: [409, 'approval_quorum_already_complete', 'This version already has its complete approval set.'],
  RL_APPROVAL_BINDING: [409, 'approval_binding_mismatch', 'Approval does not bind the current exact action and Action Check.'],
  RL_EFFECT_NOT_RECONCILABLE: [409, 'effect_not_reconcilable', 'The provider effect is not in an ambiguous state.'],
  RL_EFFECT_BINDING: [409, 'effect_binding_mismatch', 'Provider effect does not match the reserved exact instruction.'],
  RL_EFFECT_ALREADY_CLAIMED: [409, 'effect_already_claimed', 'The provider effect has already been claimed.'],
  RL_EFFECT_RESERVATION_ACTIVE: [409, 'effect_recovery_too_early', 'The provider effect reservation is still active.'],
  RL_EFFECT_NOT_RECOVERABLE: [409, 'effect_not_recoverable', 'The provider effect is not eligible for execution recovery.'],
  RL_AMENDMENT_IDENTICAL: [409, 'identical_amendment', 'An amendment must change the exact material action.'],
});

export interface ReleaseLockErrorOptions {
  cause?: unknown;
  expose?: boolean;
}

export class ReleaseLockError extends Error {
  status: number;

  code: string;

  detail: string;

  expose: boolean;

  constructor(
    status: number,
    code: string,
    detail: string,
    { cause = null, expose = true }: ReleaseLockErrorOptions = {},
  ) {
    super(detail);
    this.name = 'ReleaseLockError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.expose = expose;
    if (cause) this.cause = cause;
  }
}

export function releaseLockRefusal(
  status: number,
  code: string,
  detail: string,
  options: ReleaseLockErrorOptions = {},
): ReleaseLockError {
  return new ReleaseLockError(status, code, detail, options);
}

export function mapReleaseLockRpcError(
  error: unknown,
  operation: string = 'release_lock_storage',
): ReleaseLockError {
  const errorRecord = error as { message?: unknown; details?: unknown; hint?: unknown } | null | undefined;
  const text = [
    errorRecord?.message,
    errorRecord?.details,
    errorRecord?.hint,
  ].filter((value) => typeof value === 'string').join(' ');
  for (const [marker, [status, code, detail]] of Object.entries(SQL_REFUSALS)) {
    if (text.includes(marker)) return releaseLockRefusal(status, code, detail);
  }
  return new ReleaseLockError(
    503,
    'release_lock_storage_unavailable',
    'Release Lock storage is unavailable.',
    {
      cause: error,
      expose: false,
    },
  );
}

export function isReleaseLockError(error: unknown): error is ReleaseLockError {
  return error instanceof ReleaseLockError;
}
