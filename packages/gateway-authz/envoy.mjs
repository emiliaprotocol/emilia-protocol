// SPDX-License-Identifier: Apache-2.0
//
// Envoy `ext_authz` — HTTP variant.
//
// Envoy calls an authorization service with the original request's headers and,
// ONLY when `with_request_body` is configured, the original body. Everything
// this adapter does is downstream of that one configuration line:
//
//   * `with_request_body` absent  -> no body reaches the authorizer, so nothing
//     is bindable, so every request is REFUSED with `request_body_not_buffered`.
//     The deployment is carrying an unbound receipt and is told so in a 500.
//   * `allow_partial_message: true` and a body over `max_request_bytes` -> Envoy
//     sends what it has and sets `x-envoy-auth-partial-body: true`. A digest
//     over a prefix of the body is not a digest of the body, so that is
//     REFUSED too, with `request_body_truncated`.
//
// The pseudo-headers `:method`, `:path`, and `:authority` are not forwarded as
// ordinary headers by the HTTP ext_authz variant, so this adapter reads the
// same `x-ep-original-*` projection that
// `examples/receipt-required-gateways/envoy/envoy.yaml` already establishes
// with a Lua filter, and which that filter OVERWRITES before ext_authz sees it
// so a client cannot supply its own.

import { GatewayBindingError } from './descriptor.mjs';
import { authorizeAndForward, statusForReason } from './authz.mjs';

export const ENVOY_PARTIAL_BODY_HEADER = 'x-envoy-auth-partial-body';
export const ENVOY_ORIGINAL_METHOD_HEADER = 'x-ep-original-method';
export const ENVOY_ORIGINAL_URI_HEADER = 'x-ep-original-uri';
export const ENVOY_ORIGINAL_HOST_HEADER = 'x-ep-original-host';

/** Header names the Lua projection owns; they must never reach the upstream. */
export const ENVOY_INTERNAL_HEADERS = Object.freeze([
  ENVOY_ORIGINAL_METHOD_HEADER,
  ENVOY_ORIGINAL_URI_HEADER,
  ENVOY_ORIGINAL_HOST_HEADER,
  'x-ep-original-scheme',
]);

function first(headers, name) {
  const value = headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Build a request descriptor from an Envoy ext_authz HTTP call.
 *
 * @param {object} authRequest
 * @param {object} authRequest.headers   headers Envoy forwarded
 * @param {Uint8Array} [authRequest.bodyBytes]  body Envoy forwarded, when it did
 */
export function envoyDescriptor({ headers = {}, bodyBytes } = {}) {
  const method = first(headers, ENVOY_ORIGINAL_METHOD_HEADER);
  const uri = first(headers, ENVOY_ORIGINAL_URI_HEADER);
  const host = first(headers, ENVOY_ORIGINAL_HOST_HEADER);
  if (typeof method !== 'string' || typeof uri !== 'string' || !uri.startsWith('/')) {
    throw new GatewayBindingError('proxy_metadata_invalid');
  }
  if (typeof host !== 'string' || host.length === 0) {
    throw new GatewayBindingError('proxy_metadata_invalid');
  }

  // Absence is not "an empty body". It means Envoy was never told to send one.
  const partial = first(headers, ENVOY_PARTIAL_BODY_HEADER);
  if (partial === undefined) throw new GatewayBindingError('request_body_not_buffered');
  if (partial !== 'false' && partial !== 'true') {
    throw new GatewayBindingError('proxy_metadata_invalid');
  }

  const queryStart = uri.indexOf('?');
  return {
    method,
    path: queryStart === -1 ? uri : uri.slice(0, queryStart),
    query: queryStart === -1 ? '' : uri.slice(queryStart + 1),
    target: host,
    headers,
    bodyBytes,
    bodyTruncated: partial === 'true',
  };
}

/**
 * Translate a decision into the response Envoy expects from an HTTP ext_authz
 * service: 2xx allows and its headers are copied onto the upstream request
 * (subject to `allowed_upstream_headers`); any other status denies and the
 * response is returned to the downstream client verbatim.
 */
export function toEnvoyHttpResponse(decision) {
  if (decision.ok) {
    return {
      status: 200,
      headers: { ...decision.setHeaders },
      body: '',
    };
  }
  return {
    status: decision.status,
    headers: { ...decision.headers },
    body: JSON.stringify(decision.body),
  };
}

async function readBoundedBody(request, maxBodyBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBodyBytes) throw new GatewayBindingError('request_body_too_large');
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks, total));
}

/**
 * A `node:http` request handler implementing the ext_authz HTTP contract.
 *
 * The authority is committed BEFORE the allow is returned, because once Envoy
 * has the 200 the request is forwarded and there is no later moment at which
 * releasing it would be sound.
 */
export function createEnvoyHttpHandler(authorizer, { maxBodyBytes } = {}) {
  if (!authorizer || typeof authorizer.authorize !== 'function') {
    throw new TypeError('createEnvoyHttpHandler: an authorizer is required');
  }
  const bodyLimit = maxBodyBytes ?? authorizer.maxBodyBytes;

  return async function envoyExtAuthzHandler(request, response) {
    let result;
    try {
      const bodyBytes = await readBoundedBody(request, bodyLimit);
      const descriptor = envoyDescriptor({ headers: request.headers, bodyBytes });
      result = toEnvoyHttpResponse(await authorizeAndForward(authorizer, descriptor));
    } catch (error) {
      // Even an unexpected fault answers with a refusal shape. An ext_authz
      // service that hangs up is a service that gets `failure_mode_allow: true`
      // switched on by whoever is paged at 3am.
      const reason = error instanceof GatewayBindingError ? error.reason : 'authorizer_error';
      const status = error instanceof GatewayBindingError ? statusForReason(reason) : 500;
      result = {
        status,
        headers: { 'cache-control': 'no-store', 'content-type': 'application/problem+json', 'x-ep-refusal-reason': reason },
        body: JSON.stringify({
          type: 'https://emiliaprotocol.ai/errors/emilia_receipt_required',
          title: 'EMILIA Receipt Required',
          status,
          detail: 'This request could not be bound to an authorization receipt.',
          rejected: { reason },
        }),
      };
    }
    response.writeHead(result.status, result.headers);
    response.end(result.body);
  };
}
