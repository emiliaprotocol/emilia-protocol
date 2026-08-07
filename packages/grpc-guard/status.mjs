// SPDX-License-Identifier: Apache-2.0
//
// gRPC status codes and the refusal-reason mapping.
//
// Copied here as plain constants rather than imported from @grpc/grpc-js so the
// core stays testable, and refusable, with no gRPC runtime installed. The
// numeric values are the wire codes; they are identical to `grpc.status`.

export const GRPC_STATUS = Object.freeze({
  OK: 0,
  CANCELLED: 1,
  UNKNOWN: 2,
  INVALID_ARGUMENT: 3,
  DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5,
  ALREADY_EXISTS: 6,
  PERMISSION_DENIED: 7,
  RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9,
  ABORTED: 10,
  OUT_OF_RANGE: 11,
  UNIMPLEMENTED: 12,
  INTERNAL: 13,
  UNAVAILABLE: 14,
  DATA_LOSS: 15,
  UNAUTHENTICATED: 16,
});

export const GRPC_STATUS_NAME = Object.freeze(
  Object.fromEntries(Object.entries(GRPC_STATUS).map(([name, code]) => [code, name])),
);

/**
 * Refusal reason to gRPC status.
 *
 *   FAILED_PRECONDITION — nothing is wrong with the call; it is missing a
 *     precondition the client can satisfy and retry. This is the gRPC analogue
 *     of the HTTP 428 Receipt Required challenge, and it is the only refusal
 *     that tells a well-behaved agent to go get a receipt.
 *   ALREADY_EXISTS      — the authority was real and is spent. Retrying with
 *     the same receipt will never succeed; a NEW approval is required.
 *   INVALID_ARGUMENT    — the call could not even be bound (unbindable method
 *     path, missing request bytes, ambiguous metadata). Nothing was verified.
 *   UNAVAILABLE         — the consumption store could not answer. Fail closed:
 *     an unknown replay state is a refusal, never an allow.
 *   PERMISSION_DENIED   — default. The receipt was read and did not authorize
 *     this exact call.
 */
const REASON_STATUS = Object.freeze({
  receipt_required: GRPC_STATUS.FAILED_PRECONDITION,
  replay_refused: GRPC_STATUS.ALREADY_EXISTS,
  consumption_store_unavailable: GRPC_STATUS.UNAVAILABLE,
  consumption_commit_failed: GRPC_STATUS.INTERNAL,
  handler_failed: GRPC_STATUS.UNKNOWN,
  handler_outcome_indeterminate: GRPC_STATUS.UNKNOWN,
  action_binding_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  base_action_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  max_request_bytes_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  material_metadata_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  metadata_ambiguous: GRPC_STATUS.INVALID_ARGUMENT,
  metadata_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  metadata_key_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  metadata_value_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  method_path_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  observed_action_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  observed_action_required: GRPC_STATUS.INVALID_ARGUMENT,
  request_binding_source_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  request_bytes_invalid: GRPC_STATUS.INVALID_ARGUMENT,
  request_bytes_reserialization_not_permitted: GRPC_STATUS.INVALID_ARGUMENT,
  request_bytes_unavailable: GRPC_STATUS.INVALID_ARGUMENT,
  request_serialization_failed: GRPC_STATUS.INVALID_ARGUMENT,
  request_too_large: GRPC_STATUS.RESOURCE_EXHAUSTED,
  target_invalid: GRPC_STATUS.INVALID_ARGUMENT,
});

/** Map a refusal reason to its gRPC status code. Unknown reasons deny. */
export function statusForReason(reason) {
  return Object.prototype.hasOwnProperty.call(REASON_STATUS, reason)
    ? REASON_STATUS[reason]
    : GRPC_STATUS.PERMISSION_DENIED;
}

/**
 * Render a refusal as a plain gRPC ServiceError-shaped object.
 *
 * Returned, not thrown. A refusal is an answer the guard computed, and the
 * caller decides how to deliver it; a guard that throws on an ordinary refusal
 * turns "you need a receipt" into a server fault.
 */
export function refusalToServiceError(refusal) {
  return {
    code: refusal.code,
    details: refusal.reason,
    message: `${GRPC_STATUS_NAME[refusal.code] ?? refusal.code}: ${refusal.reason}`,
    metadata: undefined,
  };
}
