// SPDX-License-Identifier: Apache-2.0
//
// Unit coverage for the bounded-body helpers added in the app/api body-cap
// sweep: readEpJson (lib/http/route-body.js) and enforceBodyByteLimit
// (lib/http/body-limit.js). These are in the coverage-measured lib/** set;
// the sweep wired them across 45 routes but the routes themselves aren't
// coverage-included, so their branches are pinned here directly.

import { describe, it, expect } from 'vitest';
import { readEpJson } from '../lib/http/route-body.js';
import { enforceBodyByteLimit } from '../lib/http/body-limit.js';

function jsonReq(body, { contentLength } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (contentLength != null) headers['content-length'] = String(contentLength);
  return new Request('https://ep.test/x', {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

// A body carried as a ReadableStream has no Content-Length, forcing the
// byte-counting stream path (not the declared-length short-circuit).
function streamReq(nBytes) {
  const chunk = new Uint8Array(nBytes).fill(97); // 'a'
  const stream = new ReadableStream({
    start(c) { c.enqueue(chunk); c.close(); },
  });
  return new Request('https://ep.test/x', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: stream,
    duplex: 'half',
  });
}

describe('readEpJson', () => {
  it('returns {ok:true, value} for a valid within-cap body', async () => {
    const r = await readEpJson(jsonReq({ a: 1 }), 64 * 1024);
    expect(r.ok).toBe(true);
    expect(r.value).toEqual({ a: 1 });
  });

  it('returns {ok:false, response:413} when over the cap', async () => {
    const r = await readEpJson(jsonReq({ blob: 'a'.repeat(4096) }), 512);
    expect(r.ok).toBe(false);
    expect(r.response.status).toBe(413);
    expect(r.error.code).toBe('payload_too_large');
  });

  it('returns {ok:false, response:400} on invalid JSON', async () => {
    const r = await readEpJson(jsonReq('not-json'), 64 * 1024);
    expect(r.ok).toBe(false);
    expect(r.response.status).toBe(400);
  });
});

describe('enforceBodyByteLimit', () => {
  it('rejects a declared Content-Length over the cap (413, before reading)', async () => {
    const r = await enforceBodyByteLimit(jsonReq({ a: 1 }, { contentLength: 10_000 }), 1024);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(413);
    expect(r.code).toBe('payload_too_large');
  });

  it('passes a within-cap streamed body (ok:true)', async () => {
    const r = await enforceBodyByteLimit(streamReq(256), 64 * 1024);
    expect(r.ok).toBe(true);
  });

  it('rejects an oversized streamed body with no declared length (413 from the byte counter)', async () => {
    const r = await enforceBodyByteLimit(streamReq(4096), 512);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(413);
  });

  it('passes when there is no body to read (ok:true)', async () => {
    const r = await enforceBodyByteLimit(new Request('https://ep.test/x', { method: 'GET' }), 1024);
    expect(r.ok).toBe(true);
  });

  it('fails closed (400) when the body stream errors mid-read', async () => {
    const stream = new ReadableStream({ start(c) { c.error(new Error('stream boom')); } });
    const req = new Request('https://ep.test/x', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: stream,
      duplex: 'half',
    });
    const r = await enforceBodyByteLimit(req, 1024);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
    expect(r.code).toBe('invalid_body');
  });

  it('fails closed (400) when the body cannot be cloned/read', async () => {
    // Truthy body, no declared length, but clone() throws — hits the reader-setup catch.
    const fakeRequest = {
      headers: { get: () => null },
      body: {},
      clone() { throw new Error('cannot clone'); },
    };
    const r = await enforceBodyByteLimit(fakeRequest, 1024);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
    expect(r.code).toBe('invalid_body');
  });
});
