/**
 * lib/handshake/bind.js — checkBinding coverage for uncovered lines.
 *
 * Uncovered lines:
 *   21-22  missing_binding when binding is null
 *   30     binding_already_consumed when binding.consumed_at is set
 *   40     nonce_mismatch when provided nonce doesn't match stored nonce
 */

import { describe, it, expect } from 'vitest';
import { checkBinding } from '../lib/handshake/bind.js';

describe('checkBinding', () => {
  const futureDate = new Date(Date.now() + 60_000).toISOString();

  it('returns [missing_binding] when binding is null — lines 21-22', () => {
    const result = checkBinding(null);
    expect(result).toContain('missing_binding');
    expect(result).toHaveLength(1);
  });

  it('returns [missing_binding] when binding is undefined', () => {
    const result = checkBinding(undefined);
    expect(result).toContain('missing_binding');
  });

  it('returns [] for a valid binding with no issues', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: 'abc123',
      payload_hash: null,
    };
    const result = checkBinding(binding);
    expect(result).toHaveLength(0);
  });

  it('returns [binding_expired] when binding is expired', () => {
    const binding = {
      expires_at: new Date(Date.now() - 1000).toISOString(),
      consumed_at: null,
      nonce: 'abc123',
    };
    const result = checkBinding(binding);
    expect(result).toContain('binding_expired');
  });

  it('returns [binding_already_consumed] when consumed_at is set — line 30', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: new Date().toISOString(),
      nonce: 'abc123',
    };
    const result = checkBinding(binding);
    expect(result).toContain('binding_already_consumed');
  });

  it('returns [missing_nonce] when nonce is absent', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: null,
    };
    const result = checkBinding(binding);
    expect(result).toContain('missing_nonce');
  });

  it('returns [nonce_mismatch] when provided nonce does not match stored — line 40', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: 'stored-nonce-abc',
      payload_hash: null,
    };
    const result = checkBinding(binding, null, 'different-nonce');
    expect(result).toContain('nonce_mismatch');
  });

  it('does NOT flag nonce_mismatch when nonces match', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: 'same-nonce',
    };
    const result = checkBinding(binding, null, 'same-nonce');
    expect(result).not.toContain('nonce_mismatch');
  });

  it('returns [payload_hash_mismatch] when payload hashes differ', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: 'abc',
      payload_hash: 'hash-A',
    };
    const result = checkBinding(binding, 'hash-B');
    expect(result).toContain('payload_hash_mismatch');
  });

  it('returns [payload_hash_required] when binding has hash but none provided', () => {
    const binding = {
      expires_at: futureDate,
      consumed_at: null,
      nonce: 'abc',
      payload_hash: 'some-hash',
    };
    const result = checkBinding(binding);
    expect(result).toContain('payload_hash_required');
  });
});
