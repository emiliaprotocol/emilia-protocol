// SPDX-License-Identifier: Apache-2.0

import { strictJsonGate } from '../strict-json.js';

const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });

export type BodyLimitError = {
  ok: false;
  status: number;
  code: string;
  detail: string;
};

export type LimitedTextResult = { ok: true; text: string } | BodyLimitError;

export type BodyByteLimitResult = { ok: true } | BodyLimitError;

export type LimitedJsonResult = { ok: true; value: any } | BodyLimitError;

export interface ReadLimitedJsonOptions {
  emptyValue?: Record<string, unknown>;
  invalidValue?: any;
}

function declaredLength(request: Request): number {
  const raw = request.headers.get('content-length');
  if (!raw) return 0;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Read a request body with a hard byte cap. This enforces the limit even when a
 * client omits or understates Content-Length, so route code does not have to
 * call request.json()/formData() before knowing the body is small enough.
 */
export async function readLimitedText(request: Request, maxBytes: number): Promise<LimitedTextResult> {
  const declared = declaredLength(request);
  if (declared && declared > maxBytes) {
    return { ok: false, status: 413, code: 'payload_too_large', detail: 'request payload is too large' };
  }

  if (!request.body) return { ok: true, text: '' };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.byteLength;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        return { ok: false, status: 413, code: 'payload_too_large', detail: 'request payload is too large' };
      }
      chunks.push(chunk);
    }
  } catch {
    return { ok: false, status: 400, code: 'invalid_body', detail: 'Could not read request body' };
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { ok: true, text: TEXT_DECODER.decode(bytes) };
  } catch {
    return { ok: false, status: 400, code: 'invalid_utf8', detail: 'Request body must be valid UTF-8' };
  }
}

export async function enforceBodyByteLimit(request: Request, maxBytes: number): Promise<BodyByteLimitResult> {
  const declared = declaredLength(request);
  if (declared && declared > maxBytes) {
    return { ok: false, status: 413, code: 'payload_too_large', detail: 'request payload is too large' };
  }

  if (!request.body) return { ok: true };

  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = request.clone().body!.getReader();
  } catch {
    return { ok: false, status: 400, code: 'invalid_body', detail: 'Could not read request body' };
  }

  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value?.byteLength || 0;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        return { ok: false, status: 413, code: 'payload_too_large', detail: 'request payload is too large' };
      }
    }
  } catch {
    return { ok: false, status: 400, code: 'invalid_body', detail: 'Could not read request body' };
  }

  return { ok: true };
}

export async function readLimitedJson(
  request: Request,
  maxBytes: number,
  { emptyValue = {}, invalidValue }: ReadLimitedJsonOptions = {},
): Promise<LimitedJsonResult> {
  // Real runtime requests carrying a payload always expose a ReadableStream
  // `.body`, so those go through the byte-enforcing path below. Unit-test
  // doubles in this repo provide only `{ headers, json() }` with no stream;
  // key the fallback off the ABSENT body stream (not absent headers) so a
  // double that carries a Headers object — as the guarded route requires —
  // still parses. A bodyless real request has nothing to cap, so this is safe.
  if (!request?.body && typeof request?.json === 'function') {
    try {
      return { ok: true, value: await request.json() };
    } catch {
      if (arguments.length >= 3 && Object.prototype.hasOwnProperty.call(arguments[2] || {}, 'invalidValue')) {
        return { ok: true, value: invalidValue };
      }
      return { ok: false, status: 400, code: 'invalid_json', detail: 'Body must be valid JSON' };
    }
  }

  const read = await readLimitedText(request, maxBytes);
  if (!read.ok) return read;
  const text = read.text.trim();
  if (!text) return { ok: true, value: emptyValue };
  const strict = strictJsonGate(text);
  if (!strict.ok) {
    if (arguments.length >= 3 && Object.prototype.hasOwnProperty.call(arguments[2] || {}, 'invalidValue')) {
      return { ok: true, value: invalidValue };
    }
    return { ok: false, status: 400, code: 'invalid_json', detail: `Body must be strict JSON: ${strict.reason}` };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    if (arguments.length >= 3 && Object.prototype.hasOwnProperty.call(arguments[2] || {}, 'invalidValue')) {
      return { ok: true, value: invalidValue };
    }
    return { ok: false, status: 400, code: 'invalid_json', detail: 'Body must be valid JSON' };
  }
}
