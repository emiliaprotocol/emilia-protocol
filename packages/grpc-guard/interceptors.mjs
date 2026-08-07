// SPDX-License-Identifier: Apache-2.0
//
// Transport adapters: a server-side interceptor over a gRPC service definition,
// and a client-side interceptor that attaches the receipt for the exact bytes
// it is about to send.
//
// The server adapter carries the load. It swaps the guarded methods' request
// codec for a pass-through so the handler chain sees the WIRE OCTETS, binds
// those, and only then deserializes with the service's own deserializer and
// enters the application handler. That ordering is the difference between
// binding what the peer sent and binding what this process decided the peer
// probably meant.

import {
  DEFAULT_MAX_REQUEST_BYTES,
  GrpcBindingError,
  grpcActionBinding,
  resolveRequestBytes,
  selectMaterialMetadata,
} from './binding.mjs';
import { DEFAULT_RECEIPT_METADATA_KEY } from './guard.mjs';
import { GRPC_STATUS, refusalToServiceError, statusForReason } from './status.mjs';

const PASSTHROUGH_DESERIALIZE = (value) => value;

function serviceError(code, details) {
  return Object.assign(new Error(`${details}`), { code, details });
}

/**
 * Rewrite a gRPC service definition so the named methods deliver raw request
 * bytes to the handler chain.
 *
 * Returns a NEW definition; the input is not mutated. `originalDeserialize`
 * hands back each method's real deserializer so the guard can decode the
 * message after it has bound the bytes.
 */
export function passthroughRequestDefinition(serviceDefinition, methodNames) {
  if (!serviceDefinition || typeof serviceDefinition !== 'object') {
    throw new TypeError('passthroughRequestDefinition: a service definition is required');
  }
  const names = methodNames === undefined ? Object.keys(serviceDefinition) : methodNames;
  if (!Array.isArray(names)) {
    throw new TypeError('passthroughRequestDefinition: methodNames must be an array');
  }
  const definition = { ...serviceDefinition };
  const originalDeserialize = new Map();
  for (const name of names) {
    const method = serviceDefinition[name];
    if (!method || typeof method !== 'object') {
      throw new Error(`passthroughRequestDefinition: unknown method "${name}"`);
    }
    originalDeserialize.set(name, method.requestDeserialize);
    definition[name] = { ...method, requestDeserialize: PASSTHROUGH_DESERIALIZE };
  }
  return { definition, originalDeserialize };
}

/**
 * Guard one unary handler.
 *
 * @param {Function} handler                the application handler `(call, callback)`
 * @param {object} config
 * @param {object} config.guard             from `createGrpcReceiptGuard`
 * @param {string} config.methodPath        `/package.Service/Method`
 * @param {Function} [config.deserializeRequest] decode the bound bytes for the handler
 * @param {Function} [config.serializeRequest]   only for the reserialized binding source
 * @param {boolean} [config.allowReserializedRequestBinding]
 * @param {number} [config.handlerTimeoutMs] treat a handler that has not settled
 *   within this window as INDETERMINATE. Without it, a handler that never calls
 *   back holds the authority open until the transport deadline fires.
 */
export function guardUnaryHandler(handler, {
  guard,
  methodPath,
  deserializeRequest,
  serializeRequest,
  allowReserializedRequestBinding = false,
  handlerTimeoutMs,
} = {}) {
  if (typeof handler !== 'function') throw new TypeError('guardUnaryHandler: handler is required');
  if (!guard || typeof guard.authorize !== 'function') {
    throw new TypeError('guardUnaryHandler: guard is required');
  }
  if (handlerTimeoutMs !== undefined
      && (!Number.isSafeInteger(handlerTimeoutMs) || handlerTimeoutMs <= 0)) {
    throw new TypeError('guardUnaryHandler: handlerTimeoutMs must be a positive integer');
  }

  return async function guardedUnaryHandler(call, callback) {
    let bytes;
    let source;
    try {
      ({ bytes, source } = resolveRequestBytes(call?.request, {
        serializeRequest,
        allowReserializedRequestBinding,
      }));
    } catch (error) {
      if (!(error instanceof GrpcBindingError)) throw error;
      callback(serviceError(statusForReason(error.reason), error.reason));
      return;
    }

    const decision = await guard.authorize({
      methodPath,
      requestBytes: bytes,
      metadata: call?.metadata,
      requestBindingSource: source,
    });
    if (!decision.ok) {
      callback(refusalToServiceError(decision));
      return;
    }

    // Decoding happens AFTER the bytes are bound and BEFORE the handler runs.
    // A decode failure means the handler was never entered, so the authority is
    // released rather than burned; the receipt is bound to bytes that will
    // never decode, so releasing it cannot buy an attacker a different action.
    let request = bytes;
    if (typeof deserializeRequest === 'function') {
      try {
        request = deserializeRequest(bytes);
      } catch {
        await decision.abandon();
        callback(serviceError(GRPC_STATUS.INVALID_ARGUMENT, 'request_deserialization_failed'));
        return;
      }
    }

    const authorization = Object.freeze({
      receipt_id: decision.receiptId,
      action: decision.boundAction,
      request_sha256: decision.requestSha256,
    });
    // Mutate rather than clone. A grpc-js ServerUnaryCall carries private state
    // and prototype methods bound to its own identity; copying property
    // descriptors onto a fresh object detaches both. Cloning is the fallback
    // for a call object that refuses assignment, not the default.
    let guardedCall = call;
    try {
      call.request = request;
      call.emiliaReceipt = authorization;
    } catch {
      guardedCall = Object.assign(
        Object.create(Object.getPrototypeOf(call) ?? Object.prototype),
        call,
        { request, emiliaReceipt: authorization },
      );
    }

    const outcome = await decision.invoke((settle) => new Promise((resolve, reject) => {
      let finished = false;
      // Deliberately NOT unref'd. This timer is the only thing that can resolve
      // the promise when a handler never answers; an unref'd timer would let
      // the process exit with the authority still reserved and nothing to
      // commit it.
      const timer = handlerTimeoutMs === undefined
        ? null
        : setTimeout(() => { if (!finished) { finished = true; resolve(); } }, handlerTimeoutMs);
      const done = (error, value) => {
        if (finished) return; // a late callback cannot revive a settled call
        finished = true;
        if (timer) clearTimeout(timer);
        settle({ error: error ?? null, value });
        resolve();
      };
      let returned;
      try {
        returned = handler(guardedCall, done);
      } catch (error) {
        finished = true;
        if (timer) clearTimeout(timer);
        reject(error);
        return;
      }
      if (returned && typeof returned.then === 'function') {
        returned.then(undefined, (error) => {
          if (finished) return;
          finished = true;
          if (timer) clearTimeout(timer);
          reject(error);
        });
      }
    }));

    if (outcome.ok) {
      callback(outcome.outcome.error, outcome.outcome.value);
      return;
    }
    if (outcome.reason === 'handler_failed') {
      const error = outcome.error;
      callback(error instanceof Error
        ? error
        : serviceError(GRPC_STATUS.UNKNOWN, 'handler_failed'));
      return;
    }
    callback(serviceError(outcome.code, outcome.reason));
  };
}

/**
 * Guard every named method of a service.
 *
 * @returns {{definition: object, wrap: (implementation: object) => object}}
 *   `definition` must be the one passed to `server.addService`; `wrap` produces
 *   the implementation object to pair with it. Using the original definition
 *   with the wrapped implementation silently restores deserialized-message
 *   delivery, so `wrap` refuses a method it has no raw-byte path for.
 */
export function createServerInterceptor({
  guard,
  service,
  methods,
  handlerTimeoutMs,
} = {}) {
  if (!guard || typeof guard.authorize !== 'function') {
    throw new TypeError('createServerInterceptor: guard is required');
  }
  const names = methods === undefined ? Object.keys(service ?? {}) : methods;
  const { definition, originalDeserialize } = passthroughRequestDefinition(service, names);

  return {
    definition,
    guardedMethods: Object.freeze([...names]),
    wrap(implementation) {
      if (!implementation || typeof implementation !== 'object') {
        throw new TypeError('createServerInterceptor.wrap: implementation is required');
      }
      const wrapped = { ...implementation };
      for (const name of names) {
        const handler = implementation[name];
        if (typeof handler !== 'function') {
          throw new Error(`createServerInterceptor.wrap: implementation is missing "${name}"`);
        }
        wrapped[name] = guardUnaryHandler(handler, {
          guard,
          methodPath: service[name].path,
          deserializeRequest: originalDeserialize.get(name),
          handlerTimeoutMs,
        });
      }
      return wrapped;
    },
  };
}

/**
 * Client-side attacher: bind the bytes this call will send, obtain a receipt
 * for exactly that binding, and put it in metadata.
 *
 * The attach is a convenience, never the enforcement. If the client binds
 * different bytes than the server receives, the server refuses. There is no
 * configuration in which a client-side mistake produces an accepted call.
 */
export function createClientReceiptAttacher({
  baseAction,
  target,
  metadataKey = DEFAULT_RECEIPT_METADATA_KEY,
  materialMetadata = [],
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
  acquireReceipt,
} = {}) {
  if (typeof acquireReceipt !== 'function') {
    throw new TypeError('createClientReceiptAttacher: acquireReceipt is required');
  }

  function encode(receipt) {
    if (typeof receipt === 'string') return receipt;
    return Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64');
  }

  function setMetadata(metadata, carrier) {
    if (metadata && typeof metadata.set === 'function') {
      metadata.set(metadataKey, carrier);
      return metadata;
    }
    if (metadata && typeof metadata === 'object') {
      metadata[metadataKey] = carrier;
      return metadata;
    }
    return { [metadataKey]: carrier };
  }

  /**
   * @returns {{ok:true, binding:object, carrier:string, metadata:object}
   *   | {ok:false, code:number, reason:string}}
   */
  async function attach(metadata, {
    methodPath,
    requestBytes,
    requestBindingSource = 'wire',
    target: callTarget = target,
  } = {}) {
    let binding;
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
    } catch (error) {
      if (!(error instanceof GrpcBindingError)) throw error;
      return { ok: false, code: statusForReason(error.reason), reason: error.reason };
    }

    let receipt;
    try {
      receipt = await acquireReceipt(binding);
    } catch {
      return { ok: false, code: GRPC_STATUS.FAILED_PRECONDITION, reason: 'receipt_acquisition_failed' };
    }
    if (receipt === null || receipt === undefined) {
      return { ok: false, code: GRPC_STATUS.FAILED_PRECONDITION, reason: 'receipt_unavailable' };
    }

    const carrier = encode(receipt);
    return { ok: true, binding, carrier, metadata: setMetadata(metadata, carrier) };
  }

  return Object.freeze({ attach, metadataKey, baseAction, target });
}

/**
 * A @grpc/grpc-js client interceptor built on the attacher.
 *
 * `start` is deliberately held until `sendMessage`, because the receipt binds
 * the message and metadata is only sendable once. On any attach failure the
 * call is failed locally through the listener rather than sent unauthorized.
 *
 * @param {object} config
 * @param {object} config.grpc      the `@grpc/grpc-js` module (injected, so the
 *   package has no hard dependency and the wiring is testable offline)
 * @param {object} config.attacher  from `createClientReceiptAttacher`
 * @param {boolean} [config.allowReserializedRequestBinding]
 */
export function createClientInterceptor({
  grpc,
  attacher,
  allowReserializedRequestBinding = false,
} = {}) {
  if (!grpc || typeof grpc.InterceptingCall !== 'function') {
    throw new TypeError('createClientInterceptor: the @grpc/grpc-js module is required');
  }
  if (!attacher || typeof attacher.attach !== 'function') {
    throw new TypeError('createClientInterceptor: attacher is required');
  }

  return function receiptRequiredClientInterceptor(options, nextCall) {
    let savedMetadata;
    let savedListener;
    let savedNext;

    const requester = {
      start(metadata, listener, next) {
        savedMetadata = metadata;
        savedListener = listener;
        savedNext = next;
      },
      sendMessage(message, next) {
        const fail = (code, details) => {
          savedListener?.onReceiveStatus?.({
            code,
            details,
            metadata: typeof grpc.Metadata === 'function' ? new grpc.Metadata() : undefined,
          });
        };
        let bytes;
        let source;
        try {
          ({ bytes, source } = resolveRequestBytes(message, {
            serializeRequest: options?.method_definition?.requestSerialize,
            allowReserializedRequestBinding,
          }));
        } catch (error) {
          if (!(error instanceof GrpcBindingError)) throw error;
          fail(statusForReason(error.reason), error.reason);
          return;
        }
        attacher.attach(savedMetadata, {
          methodPath: options?.method_definition?.path,
          requestBytes: bytes,
          requestBindingSource: source,
        }).then((result) => {
          if (!result.ok) {
            fail(result.code, result.reason);
            return;
          }
          savedNext(savedMetadata, savedListener);
          next(message);
        }, () => {
          fail(GRPC_STATUS.INTERNAL, 'receipt_attach_failed');
        });
      },
      halfClose(next) {
        next();
      },
      cancel(next) {
        next();
      },
    };

    return new grpc.InterceptingCall(nextCall(options), requester);
  };
}
