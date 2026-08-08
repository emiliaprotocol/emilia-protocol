// SPDX-License-Identifier: Apache-2.0
//
// The external-authorization core: a pure function from a request descriptor to
// a decision. No proxy, no socket, no framework. Envoy and Kong are thin
// translations of this decision into their own response shapes.
//
// The core owns two properties the adapters must not be able to undo:
//
//   1. THE BINDING IS NOT INJECTABLE. There is no option to hand the authorizer
//      a precomputed action or action hash. It derives the action from the
//      descriptor, and the descriptor has no optional body.
//   2. VERIFICATION IS THE PUBLISHED PATH. `makeReceiptGate` from
//      @emilia-protocol/require-receipt does the signature, freshness,
//      assurance, and one-time consumption work. None of it is reimplemented.

import { makeReceiptGate, parseReceiptCarrier } from '@emilia-protocol/require-receipt';

import {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_CARRIER_BYTES,
  DEFAULT_PROOF_HEADER,
  DEFAULT_REQUIRED_FIELDS,
  GatewayBindingError,
  httpActionBinding,
  readSingleHeader,
  selectMaterialHeaders,
} from './descriptor.mjs';

export const RECEIPT_REQUIRED_STATUS = 428;
export const REFUSAL_REASON_HEADER = 'x-ep-refusal-reason';
export const VERIFIED_ACTION_HEADER = 'x-emilia-verified-action';
export const VERIFIED_RECEIPT_ID_HEADER = 'x-emilia-verified-receipt-id';

/**
 * Refusal reason to HTTP status.
 *
 * 428 is the Receipt Required rail: everything the caller can fix by obtaining
 * the right receipt answers with the challenge, exactly as
 * `packages/require-receipt` does. The exceptions are the reasons the caller
 * cannot fix, and they must not masquerade as caller error:
 *
 *   500 — the DEPLOYMENT is wrong. The proxy did not give the authorizer a body
 *         to bind, or gave it a truncated one. A 4xx here would teach operators
 *         to blame callers for a gateway they never configured.
 *   503 — the consumption store could not answer. Retrying is correct.
 *   413 — the body exceeded the bound, so it was never hashed.
 *   400 — the descriptor could not be parsed at all.
 */
const REASON_STATUS = Object.freeze({
  request_body_not_buffered: 500,
  request_body_truncated: 500,
  // The proxy did not project the original method, path, or host. Same class as
  // an unbuffered body: the gateway is misconfigured, not the caller.
  proxy_metadata_invalid: 500,
  consumption_store_unavailable: 503,
  consumption_commit_failed: 500,
  request_body_too_large: 413,
  request_body_invalid: 400,
  request_method_invalid: 400,
  request_path_invalid: 400,
  request_query_invalid: 400,
  request_target_invalid: 400,
  content_length_invalid: 400,
  content_length_mismatch: 400,
  header_ambiguous: 400,
  header_name_invalid: 400,
  header_value_invalid: 400,
  headers_invalid: 400,
  material_headers_invalid: 400,
  max_body_bytes_invalid: 400,
  base_action_invalid: 400,
  action_binding_invalid: 400,
});

export function statusForReason(reason) {
  return Object.prototype.hasOwnProperty.call(REASON_STATUS, reason)
    ? REASON_STATUS[reason]
    : RECEIPT_REQUIRED_STATUS;
}

const PROBLEM_TYPE = 'https://emiliaprotocol.ai/errors/emilia_receipt_required';

function problemBody(reason, status, challenge) {
  if (challenge) {
    return { ...challenge, status, rejected: { reason } };
  }
  return {
    type: PROBLEM_TYPE,
    title: 'EMILIA Receipt Required',
    status,
    detail: 'This request could not be bound to an authorization receipt.',
    rejected: { reason },
  };
}

function refuse(reason, { binding, challenge } = {}) {
  const status = statusForReason(reason);
  return Object.freeze({
    ok: false,
    status,
    reason,
    headers: Object.freeze({
      'cache-control': 'no-store',
      'content-type': 'application/problem+json',
      [REFUSAL_REASON_HEADER]: reason,
    }),
    body: problemBody(reason, status, challenge),
    ...(binding
      ? { boundAction: binding.boundAction, canonicalAction: binding.canonicalAction }
      : {}),
  });
}

/**
 * Build an external authorizer for ONE base action.
 *
 * @param {object} options
 * @param {string} options.baseAction        server-owned action name, never caller-supplied
 * @param {string} [options.target]          default authority; a descriptor may override it
 * @param {string[]} [options.materialHeaders] pinned header names folded into the action
 * @param {string} [options.proofHeader]     header carrying the receipt
 * @param {number} [options.maxBodyBytes]
 * @param {number} [options.maxCarrierBytes]
 * @param {string[]} [options.requiredFields]
 * @param {object} [options.store]           atomic reserve/commit/release consumption store
 * ...plus every `makeReceiptGate` option (trustedKeys, assuranceClass, maxAgeSec, …)
 */
export function createExternalAuthorizer(options = {}) {
  const {
    baseAction,
    target: defaultTarget,
    materialHeaders = [],
    proofHeader = DEFAULT_PROOF_HEADER,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    maxCarrierBytes = DEFAULT_MAX_CARRIER_BYTES,
    requiredFields = DEFAULT_REQUIRED_FIELDS,
    ...gateOptions
  } = options;

  if (typeof baseAction !== 'string' || baseAction.length === 0) {
    throw new Error('createExternalAuthorizer: `baseAction` is required');
  }
  if (!Array.isArray(materialHeaders)) {
    throw new Error('createExternalAuthorizer: `materialHeaders` must be an array of header names');
  }
  // Binding the carrier into the action it authorizes is unsatisfiable: the
  // receipt would have to contain its own digest. Refuse at construction rather
  // than let a deployment discover it as a permanent action_mismatch.
  if (materialHeaders.some((name) => String(name).toLowerCase() === proofHeader.toLowerCase())) {
    throw new Error('createExternalAuthorizer: the receipt carrier cannot be pinned as a material header');
  }

  const gate = makeReceiptGate({
    ...gateOptions,
    action: (binding) => binding.boundAction,
    requiredFields: [...requiredFields],
  });

  /**
   * Decide one request.
   *
   * @returns {Promise<object>} an allow carrying the headers to add and remove,
   *   or a refusal carrying a status, a reason, and a problem body. Never throws
   *   for an operational condition.
   */
  async function authorize(descriptor = {}) {
    let binding;
    let carrier;
    try {
      binding = httpActionBinding({
        baseAction,
        descriptor: { target: defaultTarget, ...descriptor },
        materialHeaders,
        maxBodyBytes,
      });
      carrier = readSingleHeader(binding.descriptor.headers, proofHeader);
    } catch (error) {
      if (error instanceof GatewayBindingError) return refuse(error.reason);
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

    return allowed(checked.receiptId, binding);
  }

  function allowed(receiptId, binding) {
    let state = 'authorized';

    /**
     * Commit the one-time authority.
     *
     * A gateway hands the request to an upstream it cannot observe. The moment
     * the request is forwarded, the outcome is indeterminate: the authorizer
     * cannot tell "the upstream refused" from "the upstream acted and the
     * response was lost". So forwarding consumes, unconditionally.
     */
    async function commitOnForward() {
      if (state !== 'authorized') {
        return Object.freeze({ ok: false, reason: 'authority_already_settled', authority: state });
      }
      state = 'forwarded';
      try {
        await gate.commit(receiptId);
        return Object.freeze({ ok: true, authority: 'consumed' });
      } catch {
        // The reservation stands, so a replay still loses the reserve() race.
        state = 'commit_failed';
        return Object.freeze({ ok: false, reason: 'consumption_commit_failed', authority: 'reserved' });
      }
    }

    /** Release. Legal only while the request has provably not been forwarded. */
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
      status: 200,
      receiptId,
      boundAction: binding.boundAction,
      canonicalAction: binding.canonicalAction,
      bodySha256: binding.bodySha256,
      // Added to the request the upstream sees, so the protected service can
      // record which authorization admitted it.
      setHeaders: Object.freeze({
        [VERIFIED_ACTION_HEADER]: binding.boundAction,
        [VERIFIED_RECEIPT_ID_HEADER]: receiptId,
      }),
      // The proof carrier is evidence for the boundary, not for the upstream.
      // It never travels past the gate.
      removeHeaders: Object.freeze([proofHeader]),
      commitOnForward,
      abandon,
      get state() { return state; },
    });
  }

  return Object.freeze({
    authorize,
    baseAction,
    proofHeader,
    materialHeaders: Object.freeze([...materialHeaders]),
    requiredFields: Object.freeze([...requiredFields]),
    maxBodyBytes,
    /** Exposed so a client can obtain a receipt for the exact request it will send. */
    bindingFor(descriptor) {
      return httpActionBinding({
        baseAction,
        descriptor: { target: defaultTarget, ...descriptor },
        materialHeaders,
        maxBodyBytes,
      });
    },
  });
}

/**
 * Authorize and, on an allow, commit before the request is forwarded.
 *
 * This is the shape an inline proxy plugin wants: by the time the plugin
 * returns, the request is on its way and there is no later moment at which the
 * authority could be safely released.
 */
export async function authorizeAndForward(authorizer, descriptor) {
  const decision = await authorizer.authorize(descriptor);
  if (!decision.ok) return decision;
  const committed = await decision.commitOnForward();
  if (!committed.ok) {
    return refuse(committed.reason, {
      binding: { boundAction: decision.boundAction, canonicalAction: decision.canonicalAction },
    });
  }
  return decision;
}
