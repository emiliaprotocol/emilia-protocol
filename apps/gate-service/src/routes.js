// SPDX-License-Identifier: Apache-2.0
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const JSON_CONTENT_TYPE = /^application\/json(?:\s*;|$)/i;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

class HttpInputError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function sendJson(response, status, body, headers = {}) {
  if (response.headersSent || response.destroyed) return;
  try {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const safeHeaders = {};
    for (const [name, value] of Object.entries(headers)) {
      if (typeof value === 'string' && !/[\r\n]/.test(value)) safeHeaders[name] = value;
    }
    response.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(payload.length),
      'Cache-Control': 'no-store',
      ...safeHeaders,
    });
    response.end(payload);
  } catch {
    if (!response.destroyed) response.destroy();
  }
}

function readBody(request, maxBytes) {
  const announced = Number(request.headers['content-length']);
  if (Number.isFinite(announced) && announced > maxBytes) {
    request.on('error', () => {});
    request.resume();
    throw new HttpInputError(413, 'request_body_too_large');
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    const fail = (error) => {
      if (settled) return;
      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.resume();
      reject(error);
    };
    const onData = (chunk) => {
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
    const onError = () => fail(new HttpInputError(400, 'request_body_read_failed'));

    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', onError);
  });
}

async function readStrictJsonBody(request, maxBytes) {
  if (!JSON_CONTENT_TYPE.test(String(request.headers['content-type'] ?? ''))) {
    throw new HttpInputError(415, 'application_json_required');
  }
  const bytes = await readBody(request, maxBytes);
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    throw new HttpInputError(400, 'request_utf8_invalid');
  }
  if (!strictJsonGate(text).ok) throw new HttpInputError(400, 'request_json_invalid');
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpInputError(400, 'request_object_required');
  }
  return parsed;
}

function receiptCarrier(request, maxChars) {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (String(request.rawHeaders[index]).toLowerCase() === 'x-emilia-receipt') count += 1;
  }
  const value = request.headers['x-emilia-receipt'];
  if (count > 1 || Array.isArray(value)) return 'duplicate-receipt-carrier';
  if (value === undefined) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > maxChars) {
    return 'invalid-receipt-carrier';
  }
  return value;
}

export function createRequestHandler(runtime) {
  if (!runtime || typeof runtime.executeDelete !== 'function'
      || typeof runtime.getAction !== 'function' || typeof runtime.health !== 'function') {
    throw new TypeError('runtime contract is invalid');
  }

  return async function handleRequest(request, response) {
    try {
      let url;
      try {
        url = new URL(request.url ?? '/', 'http://emilia-gate.local');
      } catch {
        throw new HttpInputError(400, 'request_target_invalid');
      }
      if (url.search) throw new HttpInputError(400, 'query_parameters_forbidden');

      if (request.method === 'GET' && url.pathname === '/v1/health') {
        const result = runtime.health();
        sendJson(response, result.status, result.body, result.headers);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/v1/actions') {
        const body = await readStrictJsonBody(request, runtime.limits.maxBodyBytes);
        const result = await runtime.executeDelete({
          body,
          receiptCarrier: receiptCarrier(request, runtime.limits.maxReceiptCarrierChars),
        });
        sendJson(response, result.status, result.body, result.headers);
        return;
      }

      const actionMatch = /^\/v1\/actions\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
      if (request.method === 'GET' && actionMatch) {
        const result = await runtime.getAction(actionMatch[1]);
        sendJson(response, result.status, result.body, result.headers);
        return;
      }

      if (url.pathname === '/v1/actions' || actionMatch || url.pathname === '/v1/health') {
        sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, {
          Allow: url.pathname === '/v1/actions' ? 'POST' : 'GET',
        });
        return;
      }
      sendJson(response, 404, { status: 'refused', error: { code: 'route_not_found' } });
    } catch (error) {
      if (error instanceof HttpInputError) {
        sendJson(response, error.status, { status: 'refused', error: { code: error.code } });
        return;
      }
      sendJson(response, 500, { status: 'failed', error: { code: 'internal_error' } });
    }
  };
}
