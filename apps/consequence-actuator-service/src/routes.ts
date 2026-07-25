// SPDX-License-Identifier: Apache-2.0
import type { IncomingMessage, ServerResponse } from 'node:http';

import { strictJsonGate } from '@emilia-protocol/require-receipt/strict-json';

const MAX_BODY_BYTES = 96 * 1024;
const RESPONSE_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
});

type JsonObject = Record<string, any>;

interface ActuatorRuntime {
  authenticate(authorization: unknown): Promise<boolean>;
  execute(body: unknown): Promise<{ status: number; body: JsonObject }>;
  observe(body: unknown): Promise<{ status: number; body: JsonObject }>;
  live(): { status: number; body: JsonObject };
  ready(): Promise<{ status: number; body: JsonObject }>;
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: JsonObject,
) {
  const encoded = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    ...RESPONSE_HEADERS,
    'content-length': encoded.byteLength,
  });
  response.end(encoded);
}

function refused(response: ServerResponse, status: number, code: string) {
  writeJson(response, status, {
    status: 'refused',
    error: { code },
  });
}

async function readStrictBody(request: IncomingMessage): Promise<unknown> {
  const announced = Number(request.headers['content-length']);
  if (Number.isFinite(announced) && announced > MAX_BODY_BYTES) {
    throw new Error('body_too_large');
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_BODY_BYTES) throw new Error('body_too_large');
    chunks.push(bytes);
  }
  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true })
      .decode(Buffer.concat(chunks, total));
  } catch {
    throw new Error('json_invalid');
  }
  if (source.length === 0 || !strictJsonGate(source).ok) {
    throw new Error('json_invalid');
  }
  try {
    return JSON.parse(source);
  } catch {
    throw new Error('json_invalid');
  }
}

export function createConsequenceActuatorRouteHandler(runtime: ActuatorRuntime) {
  if (!runtime || typeof runtime.authenticate !== 'function'
      || typeof runtime.execute !== 'function'
      || typeof runtime.observe !== 'function'
      || typeof runtime.live !== 'function'
      || typeof runtime.ready !== 'function') {
    throw new TypeError('actuator_http_runtime_invalid');
  }
  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
  ) {
    response.setHeader('connection', 'close');
    const url = new URL(request.url ?? '/', 'http://actuator.invalid');
    if (url.search) return refused(response, 400, 'query_parameters_forbidden');
    const path = url.pathname;
    const health = path === '/v1/live' || path === '/v1/ready';
    const operation = path === '/v1/execute' || path === '/v1/observe';
    if (!health && !operation) return refused(response, 404, 'not_found');
    if (!await runtime.authenticate(request.headers.authorization)) {
      request.resume();
      response.setHeader(
        'www-authenticate',
        'Bearer realm="emilia-consequence-actuator"',
      );
      return refused(response, 401, 'authentication_required');
    }
    if (health) {
      if (request.method !== 'GET') {
        request.resume();
        return refused(response, 405, 'method_not_allowed');
      }
      const result = path === '/v1/live' ? runtime.live() : await runtime.ready();
      return writeJson(response, result.status, result.body);
    }
    if (request.method !== 'POST') return refused(response, 405, 'method_not_allowed');
    const contentType = request.headers['content-type'];
    if (typeof contentType !== 'string'
        || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)) {
      return refused(response, 415, 'content_type_invalid');
    }
    let body: unknown;
    try {
      body = await readStrictBody(request);
    } catch (error: any) {
      return refused(
        response,
        error?.message === 'body_too_large' ? 413 : 400,
        error?.message === 'body_too_large' ? 'body_too_large' : 'json_invalid',
      );
    }
    const result = path === '/v1/execute'
      ? await runtime.execute(body)
      : await runtime.observe(body);
    return writeJson(response, result.status, result.body);
  };
}

export default Object.freeze({ createConsequenceActuatorRouteHandler });
