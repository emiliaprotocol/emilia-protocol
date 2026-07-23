// SPDX-License-Identifier: Apache-2.0
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const JSON_CONTENT_TYPE = /^application\/json(?:\s*;|$)/i;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const PROPOSAL_ID_SEGMENT = '[A-Za-z0-9:_.@-]{3,256}';
const LIFECYCLE_PATH = new RegExp(
  `^/v1/proposals/(${PROPOSAL_ID_SEGMENT})/(approval-requests(?:/poll)?|attempts/lookup|execute|reconcile|repair)$`,
);

class HttpInputError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function safeHeaders(headers: Record<string, unknown> = {}): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === 'string' && !/[\r\n]/.test(value)) result[name] = value;
  }
  return result;
}

function sendJson(response: any, status: number, body: unknown, headers: Record<string, string> = {}) {
  if (response.headersSent || response.destroyed) return;
  try {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    response.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(payload.length),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      ...safeHeaders(headers),
    });
    response.end(payload);
  } catch {
    if (!response.destroyed) response.destroy();
  }
}

function readBody(request: any, maxBytes: number): Promise<Buffer> {
  const announced = Number(request.headers['content-length']);
  if (Number.isFinite(announced) && announced > maxBytes) {
    request.on('error', () => {});
    request.resume();
    throw new HttpInputError(413, 'request_body_too_large');
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.resume();
      reject(error);
    };
    const onData = (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        fail(new HttpInputError(413, 'request_body_too_large'));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      if (total === 0) {
        reject(new HttpInputError(400, 'request_body_required'));
        return;
      }
      resolve(Buffer.concat(chunks, total));
    };
    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', () => fail(new HttpInputError(400, 'request_body_read_failed')));
  });
}

async function readStrictJson(request: any, maxBytes: number): Promise<Record<string, unknown>> {
  if (!JSON_CONTENT_TYPE.test(String(request.headers['content-type'] ?? ''))) {
    throw new HttpInputError(415, 'application_json_required');
  }
  const bytes = await readBody(request, maxBytes);
  let text: string;
  try {
    text = UTF8.decode(bytes);
  } catch {
    throw new HttpInputError(400, 'request_utf8_invalid');
  }
  if (!strictJsonGate(text).ok) throw new HttpInputError(400, 'json_invalid');
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpInputError(400, 'request_object_required');
  }
  return parsed;
}

function lifecycleMethod(segment: string): string {
  if (segment === 'approval-requests') return 'beginApproval';
  if (segment === 'approval-requests/poll') return 'pollApproval';
  if (segment === 'attempts/lookup') return 'lookupAttempt';
  return segment === 'repair' ? 'repair' : segment;
}

export function createRequestHandler(runtime: any) {
  const required = [
    'authenticate',
    'live',
    'ready',
    'admit',
    'prepare',
    'beginApproval',
    'pollApproval',
    'lookupAttempt',
    'execute',
    'reconcile',
    'repair',
  ];
  if (!runtime || required.some((method) => typeof runtime[method] !== 'function')
      || !Number.isSafeInteger(runtime?.limits?.maxBodyBytes)) {
    throw new TypeError('consequence control runtime contract is invalid');
  }

  return async function handleRequest(request: any, response: any) {
    try {
      let url: URL;
      try {
        url = new URL(request.url ?? '/', 'http://emilia-consequence-control.local');
      } catch {
        throw new HttpInputError(400, 'request_target_invalid');
      }
      if (url.search) throw new HttpInputError(400, 'query_parameters_forbidden');

      if (url.pathname === '/v1/live' || url.pathname === '/v1/ready') {
        if (request.method !== 'GET') {
          sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, { Allow: 'GET' });
          return;
        }
        const result = url.pathname === '/v1/live' ? runtime.live() : await runtime.ready();
        sendJson(response, result.status, result.body, result.headers);
        return;
      }

      const lifecycle = LIFECYCLE_PATH.exec(url.pathname);
      const proposalCollection = url.pathname === '/v1/proposals';
      if (!proposalCollection && !lifecycle) {
        sendJson(response, 404, { status: 'refused', error: { code: 'route_not_found' } });
        return;
      }
      if (request.method !== 'POST') {
        sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, { Allow: 'POST' });
        return;
      }

      const release = runtime.admit();
      if (typeof release !== 'function') {
        sendJson(
          response,
          503,
          { status: 'unavailable', error: { code: 'service_draining' } },
          { Connection: 'close' },
        );
        return;
      }
      try {
        const body = await readStrictJson(request, runtime.limits.maxBodyBytes);
        const principal = await runtime.authenticate(request);
        const result = proposalCollection
          ? await runtime.prepare({ principal, body })
          : await runtime[lifecycleMethod(lifecycle![2])]({
            principal,
            proposalId: lifecycle![1],
            body,
          });
        sendJson(response, result.status, result.body, result.headers);
      } finally {
        release();
      }
    } catch (error) {
      if (error instanceof HttpInputError) {
        sendJson(response, error.status, { status: 'refused', error: { code: error.code } });
        return;
      }
      sendJson(response, 500, { status: 'failed', error: { code: 'internal_error' } });
    }
  };
}

export default Object.freeze({ createRequestHandler });
