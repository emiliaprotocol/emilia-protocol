// SPDX-License-Identifier: Apache-2.0
//
// The gRPC receipt guard core: pure, synchronous to construct, and testable
// without a live server or @grpc/grpc-js.
//
// It owns three things the transport adapters must not be able to get wrong:
//
//   1. THE BINDING IS NOT INJECTABLE. The guard builds its own action from the
//      call. There is no option to hand it a precomputed action, an action
//      hash, or a "description" of the request, because every one of those is a
//      way to approve one thing and execute another.
//   2. VERIFICATION IS THE PUBLISHED PATH. The guard constructs
//      `makeReceiptGate` from @emilia-protocol/require-receipt and uses it.
//      No signature checking, freshness logic, or assurance evaluation is
//      reimplemented here.
//   3. AUTHORITY IS NEVER RELEASED AFTER INVOCATION. Once the downstream
//      handler has been entered, the one-time authority is committed on every
//      exit path — success, failure, and an outcome the handler never
//      resolved. `abandon()` (release) is only reachable while the handler has
//      provably not been entered.

import { makeReceiptGate, parseReceiptCarrier } from '@emilia-protocol/require-receipt';

import {
  DEFAULT_MAX_CARRIER_BYTES,
  DEFAULT_MAX_REQUEST_BYTES,
  DEFAULT_REQUIRED_FIELDS,
  GrpcBindingError,
  grpcActionBinding,
  readSingleMetadataValue,
  selectMaterialMetadata,
} from './binding.mjs';
import { GRPC_STATUS, statusForReason } from './status.mjs';

export const DEFAULT_RECEIPT_METADATA_KEY = 'x-emilia-receipt';

/** Outcome the guard reports for a handler that never resolved. */
export const INDETERMINATE_REASON = 'handler_outcome_indeterminate';

function refuse(reason, { binding, challenge } = {}) {
  return Object.freeze({
    ok: false,
    code: statusForReason(reason),
    reason,
    ...(binding ? { boundAction: binding.boundAction, canonicalAction: binding.canonicalAction } : {}),
    ...(challenge ? { challenge } : {}),
  });
}

/**
 * Build a guard for ONE base action.
 *
 * @param {object} options
 * @param {string} options.baseAction         server-owned action name. Never caller-supplied.
 * @param {string} options.target             authority this guard protects (`host:port`).
 * @param {string[]} [options.trustedKeys]    pinned issuer SPKI keys, base64url DER.
 * @param {boolean} [options.allowInlineKey]  accept the receipt's own key. Integrity only, NOT trust. Demo use.
 * @param {object} [options.store]            atomic reserve/commit/release consumption store.
 * @param {string} [options.assuranceClass]   required tier: software | class_a | quorum.
 * @param {string[]} [options.materialMetadata] pinned metadata keys folded into the action.
 * @param {string} [options.metadataKey]      metadata key carrying the receipt.
 * @param {number} [options.maxRequestBytes]
 * @param {number} [options.maxCarrierBytes]
 * @param {string[]} [options.requiredFields] canonical-action fields the receipt must bind.
 */
export function createGrpcReceiptGuard(options = {}) {
  const {
    baseAction,
    target,
    metadataKey = DEFAULT_RECEIPT_METADATA_KEY,
    materialMetadata = [],
    maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
    maxCarrierBytes = DEFAULT_MAX_CARRIER_BYTES,
    requiredFields = DEFAULT_REQUIRED_FIELDS,
    ...gateOptions
  } = options;

  if (typeof baseAction !== 'string' || baseAction.length === 0) {
    throw new Error('createGrpcReceiptGuard: `baseAction` is required');
  }
  if (typeof target !== 'string' || target.length === 0) {
    throw new Error('createGrpcReceiptGuard: `target` is required');
  }
  if (!Array.isArray(materialMetadata)) {
    throw new Error('createGrpcReceiptGuard: `materialMetadata` must be an array of metadata keys');
  }
  // Binding the carrier into the action it authorizes is unsatisfiable: the
  // receipt would have to contain its own digest. Refuse at construction rather
  // than let a deployment discover it as a permanent action_mismatch.
  if (materialMetadata.some((name) => String(name).toLowerCase() === metadataKey.toLowerCase())) {
    throw new Error('createGrpcReceiptGuard: the receipt carrier cannot be pinned as material metadata');
  }

  // The action is a function of the binding, so the relying party cannot
  // configure a gate whose action ignores the request.
  const gate = makeReceiptGate({
    ...gateOptions,
    action: (binding) => binding.boundAction,
    requiredFields: [...requiredFields],
  });

  /**
   * Decide one call.
   *
   * @param {object} call
   * @param {string} call.methodPath       `/package.Service/Method`
   * @param {Uint8Array} call.requestBytes serialized request message bytes
   * @param {object} [call.metadata]       gRPC Metadata or a plain header map
   * @param {string} [call.requestBindingSource] `wire` (default) or `reserialized`
   */
  async function authorize(call = {}) {
    const {
      methodPath,
      requestBytes,
      metadata,
      requestBindingSource = 'wire',
      target: callTarget = target,
    } = call;

    let binding;
    let carrier;
    try {
      binding = grpcActionBinding({
        baseAction,
        methodPath,
        target: callTarget,
        requestBytes,
        requestBindingSource,
        materialMetadata: selectMaterialMetadata(metadata, materialMetadata),
        maxRequestBytes,
      });
      carrier = readSingleMetadataValue(metadata, metadataKey);
    } catch (error) {
      // A call that cannot be bound is refused before anything is verified.
      // There is no "bind what we can" path: a partial binding is an unbound
      // receipt wearing a binding's clothes.
      if (error instanceof GrpcBindingError) return refuse(error.reason);
      throw error;
    }

    const receipt = carrier === undefined || carrier.length === 0
      ? null
      : parseReceiptCarrier(carrier, { maxBytes: maxCarrierBytes });
    if (carrier !== undefined && carrier.length > 0 && receipt === null) {
      return refuse('malformed_receipt', { binding });
    }

    const checked = await gate.check(receipt, {
      target: binding,
      observedAction: binding.canonicalAction,
    });
    if (!checked.ok) {
      const reason = checked.body?.rejected?.reason ?? 'receipt_required';
      return refuse(reason, { binding, challenge: checked.body });
    }

    return authorized(checked.receiptId, binding);
  }

  function authorized(receiptId, binding) {
    // `authorized` -> `invoked` -> `settled`, or `authorized` -> `abandoned`.
    // The only transition that releases authority leaves from `authorized`.
    let state = 'authorized';

    async function consume() {
      try {
        await gate.commit(receiptId);
        return true;
      } catch {
        return false;
      }
    }

    /**
     * Run the downstream handler under this authority.
     *
     * `runner` receives a `settle` callback and MUST call it with the handler's
     * outcome. A runner that returns without settling is the indeterminate
     * case: the guard cannot tell "nothing happened" from "it happened and the
     * answer was lost", so it consumes the authority and refuses to report
     * success. The next call needs a fresh approval.
     */
    async function invoke(runner) {
      if (typeof runner !== 'function') throw new TypeError('grpc_guard_runner_required');
      if (state !== 'authorized') throw new Error('grpc_guard_authority_already_settled');
      state = 'invoked';

      const NOT_SETTLED = Symbol('not_settled');
      let settled = NOT_SETTLED;
      const settle = (outcome) => {
        if (settled === NOT_SETTLED) settled = outcome;
      };

      let failure;
      let failed = false;
      try {
        await runner(settle);
      } catch (error) {
        failed = true;
        failure = error;
      }

      // Every path below has entered the handler, so every path below consumes.
      const committed = await consume();
      state = 'settled';
      if (!committed) {
        // The reservation stands. It was never released, so a replay of this
        // receipt still loses the reserve() race and is refused.
        return refuse('consumption_commit_failed', { binding });
      }
      if (failed) {
        return Object.freeze({
          ok: false,
          code: statusForReason('handler_failed'),
          reason: 'handler_failed',
          error: failure,
          authority: 'consumed',
          boundAction: binding.boundAction,
        });
      }
      if (settled === NOT_SETTLED) {
        return Object.freeze({
          ok: false,
          code: statusForReason(INDETERMINATE_REASON),
          reason: INDETERMINATE_REASON,
          authority: 'consumed',
          boundAction: binding.boundAction,
        });
      }
      return Object.freeze({
        ok: true,
        code: GRPC_STATUS.OK,
        outcome: settled,
        authority: 'consumed',
        receiptId,
        boundAction: binding.boundAction,
      });
    }

    /**
     * Release the authority WITHOUT consuming it. Legal only while the handler
     * has provably not been entered — a transport-level abort between
     * authorization and dispatch, for instance.
     */
    async function abandon() {
      if (state !== 'authorized') {
        return Object.freeze({ ok: false, reason: 'authority_not_releasable', authority: state });
      }
      state = 'abandoned';
      try {
        await gate.release(receiptId);
        return Object.freeze({ ok: true, authority: 'released' });
      } catch {
        return Object.freeze({ ok: false, reason: 'consumption_release_failed', authority: 'reserved' });
      }
    }

    return Object.freeze({
      ok: true,
      code: GRPC_STATUS.OK,
      receiptId,
      boundAction: binding.boundAction,
      canonicalAction: binding.canonicalAction,
      requestSha256: binding.requestSha256,
      invoke,
      abandon,
      get state() { return state; },
    });
  }

  return Object.freeze({
    authorize,
    baseAction,
    target,
    metadataKey,
    requiredFields: Object.freeze([...requiredFields]),
    /** Exposed for the client attacher: the exact action a call will demand. */
    bindingFor(call = {}) {
      return grpcActionBinding({
        baseAction,
        methodPath: call.methodPath,
        target: call.target ?? target,
        requestBytes: call.requestBytes,
        requestBindingSource: call.requestBindingSource ?? 'wire',
        materialMetadata: selectMaterialMetadata(call.metadata, materialMetadata),
        maxRequestBytes,
      });
    },
  });
}
