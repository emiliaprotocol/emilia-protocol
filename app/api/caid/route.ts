// SPDX-License-Identifier: Apache-2.0

import { CaidDemoInputError, buildCaidComparison } from '@/app/caid/model';
import type { CaidDemoInput } from '@/app/caid/types';

const JSON_HEADERS = {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
};

const MAX_BODY_BYTES = 4096;

class RequestTooLargeError extends Error {}

async function readBoundedBody(request: Request): Promise<Uint8Array> {
  const declaredLength = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new RequestTooLargeError();
  }

  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new RequestTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function POST(request: Request): Promise<Response> {
  let input: unknown;
  try {
    const bytes = await readBoundedBody(request);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    input = JSON.parse(text);
  } catch (error) {
    if (error instanceof RequestTooLargeError) {
      return Response.json({ error: 'Request is too large' }, { status: 413, headers: JSON_HEADERS });
    }
    return Response.json({ error: 'Request body must be JSON' }, { status: 400, headers: JSON_HEADERS });
  }

  try {
    return Response.json(buildCaidComparison(input as CaidDemoInput), {
      status: 200,
      headers: JSON_HEADERS,
    });
  } catch (error) {
    if (error instanceof CaidDemoInputError) {
      return Response.json({ error: error.message }, { status: 400, headers: JSON_HEADERS });
    }
    return Response.json({ error: 'The identifier could not be computed' }, {
      status: 500,
      headers: JSON_HEADERS,
    });
  }
}
