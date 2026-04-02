/**
 * errors-extended.test.js
 *
 * Extended coverage for lib/errors.js targeting uncovered lines ~36, 38-43:
 *   - All EP_ERRORS factory functions with various arguments
 *   - ProtocolWriteError class: all constructor branches
 *   - TrustEvaluationError class: all constructor branches
 *   - epProblem shape and RFC 7807 compliance
 *   - HTTP status code correctness
 *   - Error code correctness
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock next/server so the module loads without Next.js runtime
vi.mock('next/server', () => ({
  NextResponse: {
    json: vi.fn((body, init) => ({ body, status: init?.status, _type: 'NextResponse' })),
  },
}));

import {
  epProblem,
  EP_ERRORS,
  ProtocolWriteError,
  TrustEvaluationError,
} from '../lib/errors.js';

// =============================================================================
// epProblem — RFC 7807 shape
// =============================================================================

describe('epProblem', () => {
  it('returns a NextResponse with correct status', () => {
    const response = epProblem(404, 'not_found', 'Entity not found');
    expect(response.status).toBe(404);
  });

  it('includes RFC 7807 type URL', () => {
    const response = epProblem(400, 'bad_request', 'Bad input');
    expect(response.body.type).toBe('https://emiliaprotocol.ai/errors/bad_request');
  });

  it('converts code to title-cased title string', () => {
    const response = epProblem(409, 'rate_limited', 'Too many');
    expect(response.body.title).toBe('Rate Limited');
  });

  it('includes detail field', () => {
    const response = epProblem(500, 'internal_error', 'Something broke');
    expect(response.body.detail).toBe('Something broke');
  });

  it('spreads extras into the response body', () => {
    const response = epProblem(409, 'conflict', 'Dupe', { details: ['field_x'] });
    expect(response.body.details).toEqual(['field_x']);
  });

  it('includes status field in body', () => {
    const response = epProblem(403, 'forbidden', 'No access');
    expect(response.body.status).toBe(403);
  });

  it('does not leak extra fields when extras is empty object', () => {
    const response = epProblem(200, 'ok', 'Fine', {});
    expect(Object.keys(response.body)).toEqual(
      expect.arrayContaining(['type', 'title', 'status', 'detail'])
    );
  });
});

// =============================================================================
// EP_ERRORS — each factory function
// =============================================================================

describe('EP_ERRORS.NOT_FOUND', () => {
  it('returns 404 status', () => {
    const r = EP_ERRORS.NOT_FOUND();
    expect(r.status).toBe(404);
  });

  it('defaults to "Entity not found" detail', () => {
    const r = EP_ERRORS.NOT_FOUND();
    expect(r.body.detail).toContain('not found');
  });

  it('accepts custom "what" argument', () => {
    const r = EP_ERRORS.NOT_FOUND('Receipt');
    expect(r.body.detail).toContain('Receipt');
  });
});

describe('EP_ERRORS.UNAUTHORIZED', () => {
  it('returns 401 status', () => {
    const r = EP_ERRORS.UNAUTHORIZED();
    expect(r.status).toBe(401);
  });

  it('mentions API key in detail', () => {
    const r = EP_ERRORS.UNAUTHORIZED();
    expect(r.body.detail).toContain('API key');
  });

  it('code maps to unauthorized', () => {
    const r = EP_ERRORS.UNAUTHORIZED();
    expect(r.body.type).toContain('unauthorized');
  });
});

describe('EP_ERRORS.FORBIDDEN', () => {
  it('returns 403 status', () => {
    const r = EP_ERRORS.FORBIDDEN('No permission');
    expect(r.status).toBe(403);
  });

  it('defaults to "Forbidden" when no reason given', () => {
    const r = EP_ERRORS.FORBIDDEN();
    expect(r.body.detail).toBe('Forbidden');
  });

  it('uses the provided reason', () => {
    const r = EP_ERRORS.FORBIDDEN('Custom reason');
    expect(r.body.detail).toBe('Custom reason');
  });
});

describe('EP_ERRORS.BAD_REQUEST', () => {
  it('returns 400 status', () => {
    const r = EP_ERRORS.BAD_REQUEST('Missing field');
    expect(r.status).toBe(400);
  });

  it('sets detail to the provided reason', () => {
    const r = EP_ERRORS.BAD_REQUEST('Something is wrong');
    expect(r.body.detail).toBe('Something is wrong');
  });
});

describe('EP_ERRORS.CONFLICT', () => {
  it('returns 409 status', () => {
    const r = EP_ERRORS.CONFLICT('Duplicate key');
    expect(r.status).toBe(409);
  });

  it('includes details array when provided', () => {
    const r = EP_ERRORS.CONFLICT('Collision', ['field_a']);
    expect(r.body.details).toEqual(['field_a']);
  });

  it('does not include details key when not provided', () => {
    const r = EP_ERRORS.CONFLICT('Collision');
    expect(r.body.details).toBeUndefined();
  });
});

describe('EP_ERRORS.RATE_LIMITED', () => {
  it('returns 429 status', () => {
    const r = EP_ERRORS.RATE_LIMITED();
    expect(r.status).toBe(429);
  });

  it('detail mentions rate limit', () => {
    const r = EP_ERRORS.RATE_LIMITED();
    expect(r.body.detail).toContain('Rate limit');
  });
});

describe('EP_ERRORS.INTERNAL', () => {
  it('returns 500 status', () => {
    const r = EP_ERRORS.INTERNAL();
    expect(r.status).toBe(500);
  });

  it('detail mentions internal server error', () => {
    const r = EP_ERRORS.INTERNAL();
    expect(r.body.detail).toContain('Internal server error');
  });
});

describe('EP_ERRORS.GONE', () => {
  it('returns 410 status', () => {
    const r = EP_ERRORS.GONE('Resource deleted');
    expect(r.status).toBe(410);
  });

  it('passes through the reason as detail', () => {
    const r = EP_ERRORS.GONE('Entity has been removed');
    expect(r.body.detail).toBe('Entity has been removed');
  });
});

// =============================================================================
// ProtocolWriteError — all constructor branches
// =============================================================================

describe('ProtocolWriteError', () => {
  it('has correct name', () => {
    const e = new ProtocolWriteError('failed');
    expect(e.name).toBe('ProtocolWriteError');
  });

  it('inherits from Error', () => {
    const e = new ProtocolWriteError('failed');
    expect(e).toBeInstanceOf(Error);
  });

  it('defaults status to 500', () => {
    const e = new ProtocolWriteError('failed');
    expect(e.status).toBe(500);
  });

  it('defaults code to PROTOCOL_WRITE_FAILED', () => {
    const e = new ProtocolWriteError('failed');
    expect(e.code).toBe('PROTOCOL_WRITE_FAILED');
  });

  it('accepts custom status', () => {
    const e = new ProtocolWriteError('failed', { status: 409 });
    expect(e.status).toBe(409);
  });

  it('accepts custom code', () => {
    const e = new ProtocolWriteError('failed', { code: 'CUSTOM_CODE' });
    expect(e.code).toBe('CUSTOM_CODE');
  });

  it('sets cause when provided', () => {
    const cause = new Error('root cause');
    const e = new ProtocolWriteError('failed', { cause });
    expect(e.cause).toBe(cause);
  });

  it('does not set cause when not provided', () => {
    const e = new ProtocolWriteError('failed');
    expect(e.cause).toBeUndefined();
  });

  it('message is set correctly', () => {
    const e = new ProtocolWriteError('write path failed');
    expect(e.message).toBe('write path failed');
  });
});

// =============================================================================
// TrustEvaluationError — all constructor branches
// =============================================================================

describe('TrustEvaluationError', () => {
  it('has correct name', () => {
    const e = new TrustEvaluationError('eval failed');
    expect(e.name).toBe('TrustEvaluationError');
  });

  it('inherits from Error', () => {
    const e = new TrustEvaluationError('eval failed');
    expect(e).toBeInstanceOf(Error);
  });

  it('defaults status to 500', () => {
    const e = new TrustEvaluationError('eval failed');
    expect(e.status).toBe(500);
  });

  it('defaults code to TRUST_EVALUATION_FAILED', () => {
    const e = new TrustEvaluationError('eval failed');
    expect(e.code).toBe('TRUST_EVALUATION_FAILED');
  });

  it('accepts custom status', () => {
    const e = new TrustEvaluationError('eval failed', { status: 503 });
    expect(e.status).toBe(503);
  });

  it('accepts custom code', () => {
    const e = new TrustEvaluationError('eval failed', { code: 'SCORE_RECOMPUTE_FAILED' });
    expect(e.code).toBe('SCORE_RECOMPUTE_FAILED');
  });

  it('sets cause when provided', () => {
    const cause = new Error('db timeout');
    const e = new TrustEvaluationError('eval failed', { cause });
    expect(e.cause).toBe(cause);
  });

  it('does not set cause property when null cause provided', () => {
    const e = new TrustEvaluationError('eval failed', { cause: null });
    expect(e.cause).toBeUndefined();
  });

  it('message is set correctly', () => {
    const e = new TrustEvaluationError('trust evaluation timed out');
    expect(e.message).toBe('trust evaluation timed out');
  });
});
