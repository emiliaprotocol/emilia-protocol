// SPDX-License-Identifier: Apache-2.0
// Branch coverage for the stream-enforced body cap. These caps sit on every
// public write surface, so the limit/error branches must be exercised, not just
// the happy path.
import { describe, it, expect } from 'vitest';
import { readLimitedText, readLimitedJson } from '../lib/http/body-limit.js';

function streamFrom(text, { contentLength } = {}) {
  const headers = new Headers();
  if (contentLength !== undefined) headers.set('content-length', String(contentLength));
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(text));
      controller.close();
    },
  });
  return { headers, body };
}

describe('readLimitedText', () => {
  it('rejects when the declared Content-Length already exceeds the cap', async () => {
    const r = await readLimitedText({ headers: new Headers({ 'content-length': '999' }), body: null }, 8);
    expect(r).toMatchObject({ ok: false, status: 413, code: 'payload_too_large' });
  });

  it('returns empty text when there is no body', async () => {
    const r = await readLimitedText({ headers: new Headers(), body: null }, 8);
    expect(r).toEqual({ ok: true, text: '' });
  });

  it('reads a body that fits under the cap', async () => {
    const r = await readLimitedText(streamFrom('hello'), 64);
    expect(r).toEqual({ ok: true, text: 'hello' });
  });

  it('rejects mid-stream when the actual bytes exceed the cap (understated length)', async () => {
    // No Content-Length, so the byte counter is the only thing that can stop it.
    const r = await readLimitedText(streamFrom('0123456789'), 4);
    expect(r).toMatchObject({ ok: false, status: 413, code: 'payload_too_large' });
  });

  it('returns invalid_body when the stream errors while reading', async () => {
    const body = new ReadableStream({
      pull(controller) {
        controller.error(new Error('boom'));
      },
    });
    const r = await readLimitedText({ headers: new Headers(), body }, 64);
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_body' });
  });

  it('treats a non-numeric Content-Length as unknown (falls through to byte counting)', async () => {
    const r = await readLimitedText(streamFrom('hi', { contentLength: 'not-a-number' }), 64);
    expect(r).toEqual({ ok: true, text: 'hi' });
  });

  it('normalizes a non-Uint8Array chunk before counting/decoding', async () => {
    const body = new ReadableStream({
      start(controller) {
        // Enqueue a raw ArrayBuffer, not a Uint8Array, to exercise the coercion.
        controller.enqueue(new TextEncoder().encode('ok').buffer);
        controller.close();
      },
    });
    const r = await readLimitedText({ headers: new Headers(), body }, 64);
    expect(r).toEqual({ ok: true, text: 'ok' });
  });
});

describe('readLimitedJson — json()-only test-double path', () => {
  const jsonDouble = (impl) => ({ json: impl });

  it('parses via the json() double when no Headers are present', async () => {
    const r = await readLimitedJson(jsonDouble(async () => ({ a: 1 })), 64);
    expect(r).toEqual({ ok: true, value: { a: 1 } });
  });

  it('falls back to invalidValue when json() throws and invalidValue is supplied', async () => {
    const r = await readLimitedJson(
      jsonDouble(async () => { throw new Error('bad'); }),
      64,
      { invalidValue: { fallback: true } },
    );
    expect(r).toEqual({ ok: true, value: { fallback: true } });
  });

  it('returns invalid_json when json() throws and no invalidValue is supplied', async () => {
    const r = await readLimitedJson(jsonDouble(async () => { throw new Error('bad'); }), 64, {});
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_json' });
  });

  it('returns invalid_json when json() throws and options are omitted entirely (2-arg call)', async () => {
    const r = await readLimitedJson(jsonDouble(async () => { throw new Error('bad'); }), 64);
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_json' });
  });

  it('returns invalid_json when json() throws and an explicit undefined options arg is passed (3-arg, no invalidValue)', async () => {
    // Exercises the `arguments[2] || {}` fallback: arguments.length is 3 but the
    // options value is falsy (undefined), so the right-hand `|| {}` is taken.
    const r = await readLimitedJson(jsonDouble(async () => { throw new Error('bad'); }), 64, undefined);
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_json' });
  });
});

describe('readLimitedJson — real stream path', () => {
  it('returns emptyValue for an empty/whitespace body', async () => {
    const r = await readLimitedJson(streamFrom('   '), 64);
    expect(r).toEqual({ ok: true, value: {} });
  });

  it('honors a custom emptyValue', async () => {
    const r = await readLimitedJson(streamFrom(''), 64, { emptyValue: null });
    expect(r).toEqual({ ok: true, value: null });
  });

  it('parses valid JSON from the stream', async () => {
    const r = await readLimitedJson(streamFrom('{"k":"v"}'), 64);
    expect(r).toEqual({ ok: true, value: { k: 'v' } });
  });

  it('propagates a 413 from the stream cap', async () => {
    const r = await readLimitedJson(streamFrom('{"big":"0123456789"}'), 4);
    expect(r).toMatchObject({ ok: false, status: 413, code: 'payload_too_large' });
  });

  it('falls back to invalidValue on malformed JSON when supplied', async () => {
    const r = await readLimitedJson(streamFrom('not-json'), 64, { invalidValue: {} });
    expect(r).toEqual({ ok: true, value: {} });
  });

  it('returns invalid_json on malformed JSON when no invalidValue is supplied', async () => {
    const r = await readLimitedJson(streamFrom('not-json'), 64);
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_json' });
  });

  it('returns invalid_json on malformed JSON when a falsy (undefined) options arg is passed', async () => {
    // Stream-path counterpart of the `arguments[2] || {}` fallback branch.
    const r = await readLimitedJson(streamFrom('not-json'), 64, undefined);
    expect(r).toMatchObject({ ok: false, status: 400, code: 'invalid_json' });
  });
});
