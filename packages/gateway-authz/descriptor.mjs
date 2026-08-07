// SPDX-License-Identifier: Apache-2.0
//
// EP-GATEWAY-BINDING-v1 — turn an external-authorization request descriptor
// into the exact action it is asking to perform.
//
// An external authorization call is a description of somebody else's request.
// That is the whole hazard: the proxy tells the authorizer what it thinks is
// happening, the authorizer says yes, and the proxy then forwards the real
// request. If the description omits the body, the authorizer approved a method
// and a path while the body — the beneficiary, the amount, the record being
// deleted — went entirely unexamined, and a receipt for one body is spendable
// on any other body at the same path.
//
// So the descriptor here is closed and strict. `bodyBytes` is REQUIRED; there
// is no "bind what we have" path, because a partial binding is an unbound
// receipt wearing a binding's clothes. A proxy that does not buffer the body
// cannot produce a bindable descriptor, and this module says so out loud
// instead of approving the part it can see.

import crypto from 'node:crypto';
import { bindExecutorAction } from '@emilia-protocol/require-receipt';

export const GATEWAY_BINDING_VERSION = 'EP-GATEWAY-BINDING-v1';
export const HTTP_TRANSPORT = 'http';
export const DEFAULT_PROOF_HEADER = 'x-emilia-receipt';
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export const DEFAULT_MAX_CARRIER_BYTES = 96 * 1024;

export const METHOD_PATTERN = /^[A-Z][A-Z0-9-]{0,31}$/;
/** Absolute path, printable ASCII, no query or fragment folded in. */
export const PATH_PATTERN = /^\/[!-~]{0,2047}$/;
export const QUERY_PATTERN = /^[!-~]{0,2047}$/;
export const TARGET_PATTERN = /^[!-~]{1,255}$/;
export const HEADER_NAME_PATTERN = /^[a-z0-9][a-z0-9_.\-]{0,127}$/;
export const HEADER_VALUE_PATTERN = /^[ -~]{0,8192}$/;

/** A refusal reason. Carries no stack trace and nothing about the receipt. */
export class GatewayBindingError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'GatewayBindingError';
    this.reason = reason;
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sha256Prefixed(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Read exactly one header value.
 *
 * Two entries that differ only in case, or one name carrying two values, are
 * ambiguous. Picking one of them would hand a caller the choice of which value
 * the guard reads while the upstream reads the other.
 */
export function readSingleHeader(headers, name) {
  if (typeof name !== 'string' || !HEADER_NAME_PATTERN.test(name)) {
    throw new GatewayBindingError('header_name_invalid');
  }
  if (headers === undefined || headers === null) return undefined;
  if (!isPlainObject(headers)) throw new GatewayBindingError('headers_invalid');

  const matches = Object.keys(headers).filter((key) => key.toLowerCase() === name);
  if (matches.length > 1) throw new GatewayBindingError('header_ambiguous');
  if (matches.length === 0) return undefined;

  const raw = headers[matches[0]];
  const values = Array.isArray(raw) ? raw : [raw];
  if (values.length === 0) return undefined;
  if (values.length > 1) throw new GatewayBindingError('header_ambiguous');
  const value = values[0];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !HEADER_VALUE_PATTERN.test(value)) {
    throw new GatewayBindingError('header_value_invalid');
  }
  return value;
}

/**
 * Project the relying-party-pinned material headers into a closed object.
 *
 * The name list is configuration. A caller cannot add a name to it, so a caller
 * cannot change what the approval covers by adding a header.
 */
export function selectMaterialHeaders(headers, names) {
  if (!Array.isArray(names)) throw new GatewayBindingError('material_headers_invalid');
  if (names.length === 0) return undefined;
  if (names.length > 32 || new Set(names).size !== names.length) {
    throw new GatewayBindingError('material_headers_invalid');
  }
  const selected = {};
  for (const name of [...names].sort()) {
    if (typeof name !== 'string' || !HEADER_NAME_PATTERN.test(name)) {
      throw new GatewayBindingError('material_headers_invalid');
    }
    const value = readSingleHeader(headers, name);
    // Absent is bound as absent, never skipped: dropping a pinned header must
    // not silently produce a weaker action than the one that was approved.
    selected[name] = value === undefined ? null : value;
  }
  return Object.freeze(selected);
}

/**
 * Normalize and validate an external-authorization descriptor.
 *
 * @param {object} descriptor
 * @param {string} descriptor.method
 * @param {string} descriptor.path            absolute path, no query string
 * @param {string} [descriptor.query]         raw query string without `?`
 * @param {string} descriptor.target          authority the request is bound for
 * @param {object} [descriptor.headers]       full header map
 * @param {Uint8Array} descriptor.bodyBytes   REQUIRED. The buffered request body.
 * @param {boolean} [descriptor.bodyTruncated] true when the proxy truncated it
 */
export function normalizeRequestDescriptor(descriptor = {}, { maxBodyBytes = DEFAULT_MAX_BODY_BYTES } = {}) {
  const {
    method,
    path,
    query = '',
    target,
    headers = {},
    bodyBytes,
    bodyTruncated = false,
  } = descriptor;

  const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : method;
  if (typeof normalizedMethod !== 'string' || !METHOD_PATTERN.test(normalizedMethod)) {
    throw new GatewayBindingError('request_method_invalid');
  }
  if (typeof path !== 'string' || !PATH_PATTERN.test(path) || path.includes('?') || path.includes('#')) {
    throw new GatewayBindingError('request_path_invalid');
  }
  if (typeof query !== 'string' || !QUERY_PATTERN.test(query) || query.includes('#')) {
    throw new GatewayBindingError('request_query_invalid');
  }
  if (typeof target !== 'string' || !TARGET_PATTERN.test(target)) {
    throw new GatewayBindingError('request_target_invalid');
  }
  if (headers !== undefined && headers !== null && !isPlainObject(headers)) {
    throw new GatewayBindingError('headers_invalid');
  }

  // The deployment fault this whole package exists to surface.
  if (bodyTruncated === true) throw new GatewayBindingError('request_body_truncated');
  if (bodyBytes === undefined || bodyBytes === null) {
    throw new GatewayBindingError('request_body_not_buffered');
  }
  if (!(bodyBytes instanceof Uint8Array)) throw new GatewayBindingError('request_body_invalid');
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new GatewayBindingError('max_body_bytes_invalid');
  }
  if (bodyBytes.byteLength > maxBodyBytes) throw new GatewayBindingError('request_body_too_large');

  // A content-length that disagrees with the bytes in hand means the authorizer
  // and the upstream are looking at different requests.
  const advertised = readSingleHeader(headers, 'content-length');
  if (advertised !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(advertised)) throw new GatewayBindingError('content_length_invalid');
    if (Number(advertised) !== bodyBytes.byteLength) {
      throw new GatewayBindingError('content_length_mismatch');
    }
  }

  return Object.freeze({
    method: normalizedMethod,
    path,
    query,
    target,
    headers: headers ?? {},
    bodyBytes,
  });
}

/**
 * Build the canonical action and the bound action string for one HTTP request.
 *
 * @returns {{boundAction:string, canonicalAction:object, bodySha256:string,
 *   bodyByteLength:number, descriptor:object}}
 */
export function httpActionBinding({
  baseAction,
  descriptor,
  materialHeaders = [],
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
} = {}) {
  if (typeof baseAction !== 'string' || baseAction.length === 0 || baseAction.length > 256) {
    throw new GatewayBindingError('base_action_invalid');
  }
  const normalized = normalizeRequestDescriptor(descriptor, { maxBodyBytes });
  const headers = selectMaterialHeaders(normalized.headers, materialHeaders);

  const canonicalAction = {
    transport: HTTP_TRANSPORT,
    method: normalized.method,
    target: normalized.target,
    path: normalized.path,
    query: normalized.query,
    body_sha256: sha256Prefixed(normalized.bodyBytes),
    body_bytes: normalized.bodyBytes.byteLength,
    ...(headers === undefined ? {} : { headers }),
  };

  let boundAction;
  try {
    boundAction = bindExecutorAction(baseAction, canonicalAction);
  } catch {
    throw new GatewayBindingError('action_binding_invalid');
  }

  return Object.freeze({
    boundAction,
    canonicalAction: Object.freeze(canonicalAction),
    bodySha256: canonicalAction.body_sha256,
    bodyByteLength: canonicalAction.body_bytes,
    descriptor: normalized,
  });
}

/** The canonical-action fields a receipt must carry for an HTTP request. */
export const DEFAULT_REQUIRED_FIELDS = Object.freeze([
  'transport',
  'method',
  'target',
  'path',
  'query',
  'body_sha256',
]);
