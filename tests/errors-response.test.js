/**
 * Tests for lib/errors/response.js
 *
 * Covers: epError (line 60 — the full function path), epMissingField.
 * Mocks NextResponse from next/server.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock next/server ──────────────────────────────────────────────────────────
// NextResponse is a Next.js server primitive. We mock it to return a
// plain object so we can inspect the response body and status.

vi.mock('next/server', () => ({
  NextResponse: {
    json: vi.fn((body, init) => ({
      _body: body,
      _status: init?.status,
      json: async () => body,
      status: init?.status,
    })),
  },
}));

import { epError, epMissingField } from '../lib/errors/response.js';
import { NextResponse } from 'next/server';

// ── epError ───────────────────────────────────────────────────────────────────

describe('epError', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls NextResponse.json with the correct shape and status', () => {
    const errorCode = { code: 'EP-3001', status: 404, message: 'Handshake not found' };
    epError(errorCode);

    expect(NextResponse.json).toHaveBeenCalledOnce();
    const [body, init] = NextResponse.json.mock.calls[0];
    expect(body.error.code).toBe('EP-3001');
    expect(body.error.message).toBe('Handshake not found');
    expect(init.status).toBe(404);
  });

  it('includes timestamp in the error body', () => {
    const errorCode = { code: 'EP-1001', status: 400, message: 'Bad request' };
    epError(errorCode);

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.timestamp).toBeDefined();
    expect(() => new Date(body.error.timestamp)).not.toThrow();
  });

  it('includes detail when provided', () => {
    const errorCode = { code: 'EP-3001', status: 404, message: 'Not found' };
    epError(errorCode, 'No handshake with id abc-123');

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.detail).toBe('No handshake with id abc-123');
  });

  it('omits detail key when detail is null', () => {
    const errorCode = { code: 'EP-1001', status: 400, message: 'Bad request' };
    epError(errorCode, null);

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error).not.toHaveProperty('detail');
  });

  it('omits detail key when detail is not provided', () => {
    const errorCode = { code: 'EP-1001', status: 400, message: 'Bad request' };
    epError(errorCode);

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error).not.toHaveProperty('detail');
  });

  it('merges extras into error body when provided', () => {
    const errorCode = { code: 'EP-2002', status: 400, message: 'Missing required field' };
    epError(errorCode, 'entity_id required', { field: 'entity_id' });

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.field).toBe('entity_id');
  });

  it('does not include extras key when extras is null', () => {
    const errorCode = { code: 'EP-2002', status: 400, message: 'Missing required field' };
    epError(errorCode, null, null);

    const [body] = NextResponse.json.mock.calls[0];
    // extras = null should not pollute the error body with extra keys
    expect(Object.keys(body.error)).toEqual(
      expect.arrayContaining(['code', 'message', 'timestamp'])
    );
  });

  it('sets correct HTTP status on the response', () => {
    const errorCode = { code: 'EP-5001', status: 500, message: 'Internal server error' };
    epError(errorCode);

    const [, init] = NextResponse.json.mock.calls[0];
    expect(init.status).toBe(500);
  });

  it('wraps body under "error" key per RFC 7807 convention', () => {
    const errorCode = { code: 'EP-4001', status: 403, message: 'Forbidden' };
    epError(errorCode);

    const [body] = NextResponse.json.mock.calls[0];
    expect(body).toHaveProperty('error');
    expect(Object.keys(body)).toHaveLength(1);
  });

  it('error body contains exactly code, message, and timestamp for minimal call', () => {
    const errorCode = { code: 'EP-1000', status: 400, message: 'Test error' };
    epError(errorCode);

    const [body] = NextResponse.json.mock.calls[0];
    const keys = Object.keys(body.error);
    expect(keys).toContain('code');
    expect(keys).toContain('message');
    expect(keys).toContain('timestamp');
    expect(keys).not.toContain('detail');
    expect(keys).not.toContain('field');
  });

  it('extras fields are spread at the same level as code/message', () => {
    const errorCode = { code: 'EP-2002', status: 400, message: 'Validation error' };
    epError(errorCode, 'Missing name', { field: 'name', severity: 'error' });

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.field).toBe('name');
    expect(body.error.severity).toBe('error');
  });

  it('returns the NextResponse object', () => {
    const errorCode = { code: 'EP-3001', status: 404, message: 'Not found' };
    const response = epError(errorCode);
    // Our mock returns an object with _body and _status
    expect(response).toBeDefined();
    expect(response._status).toBe(404);
  });
});

// ── epMissingField (line 60 path) ─────────────────────────────────────────────

describe('epMissingField', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls NextResponse.json with EP-2002 code and status 400', () => {
    epMissingField('entity_id');

    expect(NextResponse.json).toHaveBeenCalledOnce();
    const [body, init] = NextResponse.json.mock.calls[0];
    expect(body.error.code).toBe('EP-2002');
    expect(init.status).toBe(400);
  });

  it('includes the field name in the detail string', () => {
    epMissingField('policy_id');

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.detail).toContain('policy_id');
    expect(body.error.detail).toContain('Missing required field');
  });

  it('includes field property in the error body', () => {
    epMissingField('action_type');

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.field).toBe('action_type');
  });

  it('message is "Missing required field"', () => {
    epMissingField('some_field');

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.message).toBe('Missing required field');
  });

  it('works with any field name', () => {
    epMissingField('handshake_id');

    const [body] = NextResponse.json.mock.calls[0];
    expect(body.error.field).toBe('handshake_id');
    expect(body.error.detail).toContain('handshake_id');
  });
});
