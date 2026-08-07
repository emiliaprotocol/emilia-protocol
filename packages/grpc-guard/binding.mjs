// SPDX-License-Identifier: Apache-2.0
//
// EP-GRPC-BINDING-v1 — derive the action a gRPC call is asking to perform from
// the call itself.
//
// The failure this module exists to prevent: a receipt that merely TRAVELS in
// gRPC metadata authorizes nothing. Metadata is detachable. A valid receipt
// lifted from one call and pasted onto another is still a valid receipt, so a
// guard that checks "is there a good receipt in the metadata" authorizes the
// attacker's request just as happily as the approved one.
//
// The only thing that closes that gap is deriving the action from material the
// attacker would have to change to mount the substitution: the serialized
// request message bytes, the fully-qualified method path, and the target the
// call is addressed to. All three go into the canonical action, so a receipt
// approved for one request cannot verify against any other.
//
// Nothing here accepts a caller-supplied summary of the request. `requestBytes`
// must be the actual octets; a string, a plain object, or a precomputed digest
// is refused, because each of those is a place where a caller could describe a
// harmless action and execute a different one.

import crypto from 'node:crypto';
import { bindExecutorAction } from '@emilia-protocol/require-receipt';

export const GRPC_BINDING_VERSION = 'EP-GRPC-BINDING-v1';
export const GRPC_TRANSPORT = 'grpc';
export const DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024;
export const DEFAULT_MAX_CARRIER_BYTES = 96 * 1024;

/** `/package.Service/Method`, as gRPC puts it on the wire. */
export const METHOD_PATH_PATTERN =
  /^\/[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\/[A-Za-z_][A-Za-z0-9_]*$/;
/** Printable ASCII, no spaces: covers `host:port`, `dns:///name`, `unix:/path`. */
export const TARGET_PATTERN = /^[!-~]{1,255}$/;
/** Lowercase gRPC metadata key, matching the wire form. */
export const METADATA_KEY_PATTERN = /^[a-z0-9][a-z0-9_.\-]{0,127}$/;
/** ASCII metadata values only. A `-bin` key carries bytes and is never material here. */
export const METADATA_VALUE_PATTERN = /^[ -~]{0,4096}$/;

/**
 * How the guard obtained the bytes it bound.
 *
 *   `wire`         — the exact octets the peer sent or is about to send.
 *   `reserialized` — the message was deserialized before the guard saw it and
 *                    re-encoded to bind. Protobuf encoding is not canonical:
 *                    field order, varint width, map order, and unknown fields
 *                    can all differ, and unknown fields are usually dropped
 *                    entirely. A re-serialized binding therefore covers what
 *                    this process understood, NOT what the peer sent.
 *
 * The source is part of the canonical action, so a receipt approved under one
 * source never verifies under the other. That is deliberate: it makes a
 * deployment that silently downgrades its own binding fail closed instead of
 * quietly accepting weaker evidence.
 */
export const REQUEST_BINDING_SOURCES = Object.freeze(['wire', 'reserialized']);

/** A refusal reason, never a stack trace to leak to a peer. */
export class GrpcBindingError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'GrpcBindingError';
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
 * Normalize one metadata lookup to a list of ASCII string values.
 *
 * Accepts a `@grpc/grpc-js` Metadata (duck-typed on `get`) or a plain header
 * map. Two entries that differ only in case are ambiguous, not mergeable: a
 * guard that picked one of them would let a peer choose which value the guard
 * reads. Refuse instead.
 */
export function readMetadataValues(metadata, name) {
  // `-bin` keys carry raw bytes, not ASCII. Neither the carrier nor a material
  // value may live on one, so refuse the key rather than the value and keep the
  // failure at configuration time.
  if (typeof name !== 'string' || !METADATA_KEY_PATTERN.test(name) || name.endsWith('-bin')) {
    throw new GrpcBindingError('metadata_key_invalid');
  }
  if (metadata === undefined || metadata === null) return [];

  let raw;
  if (typeof metadata.get === 'function') {
    raw = metadata.get(name);
  } else if (isPlainObject(metadata)) {
    const matches = Object.keys(metadata).filter((key) => key.toLowerCase() === name);
    if (matches.length > 1) throw new GrpcBindingError('metadata_ambiguous');
    raw = matches.length === 1 ? metadata[matches[0]] : undefined;
  } else {
    throw new GrpcBindingError('metadata_invalid');
  }

  if (raw === undefined || raw === null) return [];
  const values = Array.isArray(raw) ? raw : [raw];
  for (const value of values) {
    if (typeof value !== 'string' || !METADATA_VALUE_PATTERN.test(value)) {
      throw new GrpcBindingError('metadata_value_invalid');
    }
  }
  return values;
}

/** Read exactly one value, or none. Two values are ambiguous, never "the first". */
export function readSingleMetadataValue(metadata, name) {
  const values = readMetadataValues(metadata, name);
  if (values.length === 0) return undefined;
  if (values.length > 1) throw new GrpcBindingError('metadata_ambiguous');
  return values[0];
}

/**
 * Project the pinned material metadata keys into a closed object.
 *
 * The key list is relying-party configuration. A caller cannot add a key to it,
 * so a caller cannot enlarge or shrink what the approval covers.
 */
export function selectMaterialMetadata(metadata, names) {
  if (!Array.isArray(names)) throw new GrpcBindingError('material_metadata_invalid');
  if (names.length === 0) return undefined;
  if (names.length > 32) throw new GrpcBindingError('material_metadata_invalid');
  if (new Set(names).size !== names.length) throw new GrpcBindingError('material_metadata_invalid');

  const selected = {};
  for (const name of [...names].sort()) {
    if (typeof name !== 'string' || !METADATA_KEY_PATTERN.test(name) || name.endsWith('-bin')) {
      throw new GrpcBindingError('material_metadata_invalid');
    }
    const value = readSingleMetadataValue(metadata, name);
    // A pinned material key that is absent is bound as absent (null), not
    // skipped. Otherwise removing the key would silently produce a different,
    // weaker action than the one that was approved.
    selected[name] = value === undefined ? null : value;
  }
  return Object.freeze(selected);
}

/**
 * Turn a deserialized message back into bytes, under an explicit policy.
 *
 * The strong configuration hands the guard the wire octets directly (register
 * the guarded method with a pass-through request codec — see
 * `passthroughRequestDefinition`). Re-serialization is available but must be
 * opted into, because it binds this process's re-encoding rather than the
 * peer's bytes.
 */
export function resolveRequestBytes(message, {
  serializeRequest,
  allowReserializedRequestBinding = false,
} = {}) {
  if (message instanceof Uint8Array) {
    return { bytes: message, source: 'wire' };
  }
  if (typeof serializeRequest !== 'function') {
    throw new GrpcBindingError('request_bytes_unavailable');
  }
  if (allowReserializedRequestBinding !== true) {
    throw new GrpcBindingError('request_bytes_reserialization_not_permitted');
  }
  let bytes;
  try {
    bytes = serializeRequest(message);
  } catch {
    throw new GrpcBindingError('request_serialization_failed');
  }
  if (!(bytes instanceof Uint8Array)) throw new GrpcBindingError('request_bytes_invalid');
  return { bytes, source: 'reserialized' };
}

/**
 * Build the canonical action and the bound action string for one gRPC call.
 *
 * `boundAction` is what the receipt's `claim.action_type` must equal, and
 * `canonicalAction` is what the receipt's signed `claim.canonical_action` must
 * hash to. Both cover the request bytes, so both change when the bytes change.
 *
 * @returns {{boundAction:string, canonicalAction:object, requestSha256:string,
 *   requestByteLength:number, requestBindingSource:string}}
 */
export function grpcActionBinding({
  baseAction,
  methodPath,
  target,
  requestBytes,
  requestBindingSource = 'wire',
  materialMetadata,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
} = {}) {
  if (typeof baseAction !== 'string' || baseAction.length === 0 || baseAction.length > 256) {
    throw new GrpcBindingError('base_action_invalid');
  }
  if (typeof methodPath !== 'string' || !METHOD_PATH_PATTERN.test(methodPath)) {
    throw new GrpcBindingError('method_path_invalid');
  }
  if (typeof target !== 'string' || !TARGET_PATTERN.test(target)) {
    throw new GrpcBindingError('target_invalid');
  }
  if (!REQUEST_BINDING_SOURCES.includes(requestBindingSource)) {
    throw new GrpcBindingError('request_binding_source_invalid');
  }
  if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes <= 0) {
    throw new GrpcBindingError('max_request_bytes_invalid');
  }
  // Deliberately narrow. A string, a number, a JSON object, or a precomputed
  // digest are each a way to describe a request instead of binding it.
  if (!(requestBytes instanceof Uint8Array)) throw new GrpcBindingError('request_bytes_invalid');
  if (requestBytes.byteLength > maxRequestBytes) throw new GrpcBindingError('request_too_large');
  if (materialMetadata !== undefined && !isPlainObject(materialMetadata)) {
    throw new GrpcBindingError('material_metadata_invalid');
  }

  const canonicalAction = {
    transport: GRPC_TRANSPORT,
    method: methodPath,
    target,
    request_sha256: sha256Prefixed(requestBytes),
    request_bytes: requestBytes.byteLength,
    request_binding: requestBindingSource,
    ...(materialMetadata === undefined ? {} : { metadata: materialMetadata }),
  };

  let boundAction;
  try {
    boundAction = bindExecutorAction(baseAction, canonicalAction);
  } catch {
    throw new GrpcBindingError('action_binding_invalid');
  }

  return Object.freeze({
    boundAction,
    canonicalAction: Object.freeze(canonicalAction),
    requestSha256: canonicalAction.request_sha256,
    requestByteLength: canonicalAction.request_bytes,
    requestBindingSource,
  });
}

/** The canonical-action field names a receipt must carry for a gRPC call. */
export const DEFAULT_REQUIRED_FIELDS = Object.freeze([
  'transport',
  'method',
  'target',
  'request_sha256',
  'request_binding',
]);
