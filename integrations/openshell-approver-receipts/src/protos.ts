// SPDX-License-Identifier: Apache-2.0
// Loads the vendored OpenShell protos (byte-identical upstream copies, see
// proto/UPSTREAM.json) with protobufjs and builds @grpc/grpc-js service
// definitions from them. Message objects use the ORIGINAL proto field names
// (keepCase), enum names, and int64 values as decimal strings.

import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import protobuf from 'protobufjs';
import type { ServiceDefinition } from '@grpc/grpc-js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PROTO_DIR = path.resolve(here, '..', 'proto');

const require = createRequire(import.meta.url);
const DESCRIPTOR_PROTO = path.join(path.dirname(require.resolve('protobufjs/package.json')), 'google', 'protobuf', 'descriptor.proto');

export const TO_OBJECT: protobuf.IConversionOptions = {
  enums: String,
  longs: String,
  bytes: String,
  defaults: false,
  arrays: false,
  objects: false,
  oneofs: true,
};

let cachedRoot: protobuf.Root | null = null;

export function loadRoot(): protobuf.Root {
  if (cachedRoot) return cachedRoot;
  const root = new protobuf.Root();
  root.resolvePath = (_origin: string, target: string): string => {
    if (target === 'google/protobuf/descriptor.proto') return DESCRIPTOR_PROTO;
    // struct/timestamp/duration are protobufjs built-in "common" protos.
    if (target.startsWith('google/protobuf/')) return target;
    return path.join(PROTO_DIR, path.basename(target));
  };
  root.loadSync([path.join(PROTO_DIR, 'gateway_interceptor.proto')], { keepCase: true });
  root.resolveAll();
  cachedRoot = root;
  return root;
}

export function lookupType(name: string): protobuf.Type {
  return loadRoot().lookupType(name);
}

export function lookupEnum(name: string): protobuf.Enum {
  return loadRoot().lookupEnum(name);
}

/**
 * Build a grpc-js ServiceDefinition for a unary-only service. Serializers
 * go through fromObject/encode and toObject/decode with TO_OBJECT, so callers
 * work with plain objects that carry the original proto field names.
 */
export function serviceDefinition(serviceName: string): ServiceDefinition {
  const service = loadRoot().lookupService(serviceName);
  const definition: Record<string, unknown> = {};
  for (const method of service.methodsArray) {
    method.resolve();
    const requestType = method.resolvedRequestType as protobuf.Type;
    const responseType = method.resolvedResponseType as protobuf.Type;
    definition[method.name] = {
      path: `/${service.fullName.replace(/^\./, '')}/${method.name}`,
      requestStream: Boolean(method.requestStream),
      responseStream: Boolean(method.responseStream),
      originalName: method.name,
      requestSerialize: (value: object) => Buffer.from(requestType.encode(requestType.fromObject(value)).finish()),
      requestDeserialize: (bytes: Buffer) => requestType.toObject(requestType.decode(bytes), TO_OBJECT),
      responseSerialize: (value: object) => Buffer.from(responseType.encode(responseType.fromObject(value)).finish()),
      responseDeserialize: (bytes: Buffer) => responseType.toObject(responseType.decode(bytes), TO_OBJECT),
    };
  }
  return definition as ServiceDefinition;
}

export const INTERCEPTOR_SERVICE = 'openshell.gateway_interceptor.v1.GatewayInterceptor';
export const OPENSHELL_SERVICE = 'openshell.v1.OpenShell';
