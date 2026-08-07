// SPDX-License-Identifier: Apache-2.0
//
// Kong — access-phase plugin.
//
// Kong is an inline proxy, not a sidecar: the plugin runs in the request path
// and either lets the request continue or terminates it with
// `kong.response.exit`. That makes the body question sharper than it is for
// Envoy, because Kong will happily proxy a body the plugin never read.
//
// The body is only bindable when nginx has it in memory. `get_raw_body()`
// returns nothing when the body was streamed past the buffer or spilled to a
// temporary file, which happens as soon as it exceeds
// `client_body_buffer_size`. This adapter treats "no body available" as a
// deployment fault and REFUSES; it never proxies a request whose body it could
// not bind.
//
// The PDK is duck-typed and injectable so the decision logic is testable
// without a Kong runtime. `kongAuthzDecision` and `toKongExit` are pure.

import { GatewayBindingError } from './descriptor.mjs';
import { authorizeAndForward, statusForReason } from './authz.mjs';

/**
 * Build a request descriptor from a Kong request snapshot.
 *
 * @param {object} snapshot
 * @param {string} snapshot.method
 * @param {string} snapshot.path                path without the query string
 * @param {string} [snapshot.rawQuery]          query string without `?`
 * @param {object} snapshot.headers
 * @param {Uint8Array|string|null} [snapshot.rawBody]  the buffered body
 * @param {boolean} [snapshot.bodyBuffered]     false when nginx did not buffer it
 * @param {string} snapshot.target              the upstream authority
 */
export function kongDescriptor({
  method,
  path,
  rawQuery = '',
  headers = {},
  rawBody,
  bodyBuffered,
  target,
} = {}) {
  // `bodyBuffered: false` is an explicit statement that nginx spilled or
  // streamed the body. `rawBody` absent says the same thing implicitly. Both
  // are refusals, and both are refusals about the DEPLOYMENT, not the caller.
  if (bodyBuffered === false || rawBody === undefined || rawBody === null) {
    throw new GatewayBindingError('request_body_not_buffered');
  }
  const bodyBytes = typeof rawBody === 'string'
    ? new Uint8Array(Buffer.from(rawBody, 'utf8'))
    : rawBody;
  return { method, path, query: rawQuery, target, headers, bodyBytes };
}

/**
 * Translate a decision into a Kong termination, or an instruction to continue.
 *
 * On an allow Kong does not "return a response" — it proxies. The plugin has to
 * mutate the outgoing request instead, so the allow carries the headers to set
 * and the headers to clear rather than a status and a body.
 */
export function toKongExit(decision) {
  if (decision.ok) {
    return {
      exit: false,
      setHeaders: { ...decision.setHeaders },
      clearHeaders: [...decision.removeHeaders],
    };
  }
  return {
    exit: true,
    status: decision.status,
    body: decision.body,
    headers: { ...decision.headers },
  };
}

/** Authorize a Kong snapshot and return the exit instruction. Pure; never throws. */
export async function kongAuthzDecision(authorizer, snapshot) {
  let descriptor;
  try {
    descriptor = kongDescriptor(snapshot);
  } catch (error) {
    if (!(error instanceof GatewayBindingError)) throw error;
    const status = statusForReason(error.reason);
    return {
      exit: true,
      status,
      headers: {
        'cache-control': 'no-store',
        'content-type': 'application/problem+json',
        'x-ep-refusal-reason': error.reason,
      },
      body: {
        type: 'https://emiliaprotocol.ai/errors/emilia_receipt_required',
        title: 'EMILIA Receipt Required',
        status,
        detail: 'This request could not be bound to an authorization receipt.',
        rejected: { reason: error.reason },
      },
    };
  }
  return toKongExit(await authorizeAndForward(authorizer, descriptor));
}

/**
 * An access-phase handler for the Kong JS PDK.
 *
 * Thin on purpose: it reads the request through the PDK, hands a plain snapshot
 * to `kongAuthzDecision`, and applies the result. All the judgement lives in
 * the pure function above.
 */
export function createKongAccessHandler(authorizer, { target } = {}) {
  if (!authorizer || typeof authorizer.authorize !== 'function') {
    throw new TypeError('createKongAccessHandler: an authorizer is required');
  }

  return async function access(kong) {
    const [method, path, rawQuery, headers, rawBody] = await Promise.all([
      kong.request.getMethod(),
      kong.request.getPath(),
      kong.request.getRawQuery(),
      kong.request.getHeaders(),
      kong.request.getRawBody(),
    ]);

    const decision = await kongAuthzDecision(authorizer, {
      method,
      path,
      rawQuery,
      headers,
      rawBody,
      target: target ?? (await kong.request.getHost?.()),
    });

    if (decision.exit) {
      await kong.response.exit(decision.status, decision.body, decision.headers);
      return decision;
    }
    for (const [name, value] of Object.entries(decision.setHeaders)) {
      await kong.service.request.setHeader(name, value);
    }
    for (const name of decision.clearHeaders) {
      await kong.service.request.clearHeader(name);
    }
    return decision;
  };
}
