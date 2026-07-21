/**
 * lib/handshake/schema.js — coverage for uncovered lines 101, 121, 124, 127.
 */

import { describe, it, expect } from 'vitest';
import {
  validateInitiateBody,
  validatePresentBody,
  validateRevokeBody,
} from '../lib/handshake/schema.js';

// ── validateInitiateBody ───────────────────────────────────────────────────────

describe('validateInitiateBody', () => {
  const validBody = {
    mode: 'basic',
    policy_id: 'pol-1',
    parties: [
      { role: 'initiator', entity_ref: 'entity-A' },
      { role: 'responder', entity_ref: 'entity-B' },
    ],
  };

  it('passes with valid body', () => {
    const result = validateInitiateBody(validBody);
    expect(result.valid).toBe(true);
  });

  it('fails with non-object body', () => {
    expect(validateInitiateBody(null).valid).toBe(false);
    expect(validateInitiateBody('bad').valid).toBe(false);
  });

  it('fails with invalid mode', () => {
    const result = validateInitiateBody({ ...validBody, mode: 'invalid' });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('mode');
  });

  it('fails with missing policy_id', () => {
    const result = validateInitiateBody({ ...validBody, policy_id: undefined });
    expect(result.valid).toBe(false);
  });

  it('fails when parties has fewer than 2 entries', () => {
    const result = validateInitiateBody({ ...validBody, parties: [{ role: 'initiator', entity_ref: 'e1' }] });
    expect(result.valid).toBe(false);
  });

  it('fails when a party is not an object', () => {
    const result = validateInitiateBody({ ...validBody, parties: [null, { role: 'responder', entity_ref: 'e2' }] });
    expect(result.valid).toBe(false);
  });

  it('fails when a party has invalid role', () => {
    const result = validateInitiateBody({
      ...validBody,
      parties: [
        { role: 'bad_role', entity_ref: 'e1' },
        { role: 'responder', entity_ref: 'e2' },
      ],
    });
    expect(result.valid).toBe(false);
  });

  it('fails when a party has no entity_ref', () => {
    const result = validateInitiateBody({
      ...validBody,
      parties: [
        { role: 'initiator' },
        { role: 'responder', entity_ref: 'e2' },
      ],
    });
    expect(result.valid).toBe(false);
  });

  it('fails with invalid action_type', () => {
    const result = validateInitiateBody({ ...validBody, action_type: 'bad' });
    expect(result.valid).toBe(false);
  });

  it('fails with non-string resource_ref', () => {
    const result = validateInitiateBody({ ...validBody, resource_ref: 123 });
    expect(result.valid).toBe(false);
  });

  it('fails with non-string intent_ref', () => {
    const result = validateInitiateBody({ ...validBody, intent_ref: 123 });
    expect(result.valid).toBe(false);
  });

  it('fails with non-positive binding_ttl_ms', () => {
    const result = validateInitiateBody({ ...validBody, binding_ttl_ms: -1 });
    expect(result.valid).toBe(false);
  });

  it('fails with non-numeric binding_ttl_ms', () => {
    const result = validateInitiateBody({ ...validBody, binding_ttl_ms: 'fast' });
    expect(result.valid).toBe(false);
  });
});

// ── validatePresentBody ───────────────────────────────────────────────────────

describe('validatePresentBody', () => {
  const validBody = {
    party_role: 'initiator',
    presentation_type: 'self_asserted',
    claims: { name: 'Alice' },
  };

  it('passes with valid body', () => {
    const result = validatePresentBody(validBody);
    expect(result.valid).toBe(true);
  });

  it('fails with non-object body', () => {
    expect(validatePresentBody(null).valid).toBe(false);
  });

  it('fails with invalid party_role', () => {
    const result = validatePresentBody({ ...validBody, party_role: 'bad_role' });
    expect(result.valid).toBe(false);
  });

  it('fails with invalid presentation_type', () => {
    const result = validatePresentBody({ ...validBody, presentation_type: 'invalid' });
    expect(result.valid).toBe(false);
  });

  it('fails when claims is missing', () => {
    const result = validatePresentBody({ ...validBody, claims: undefined });
    expect(result.valid).toBe(false);
  });

  it('fails when claims is an array', () => {
    const result = validatePresentBody({ ...validBody, claims: [] });
    expect(result.valid).toBe(false);
  });

  it('fails with invalid disclosure_mode', () => {
    const result = validatePresentBody({ ...validBody, disclosure_mode: 'bad_mode' });
    expect(result.valid).toBe(false);
  });

  it('fails when issuer_ref is not a string — line 101', () => {
    // Line 101: issuer_ref is provided but not a string
    const result = validatePresentBody({ ...validBody, issuer_ref: 123 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('issuer_ref');
  });

  it('passes when issuer_ref is a valid string', () => {
    const result = validatePresentBody({ ...validBody, issuer_ref: 'key-abc' });
    expect(result.valid).toBe(true);
    expect(result.sanitized.issuer_ref).toBe('key-abc');
  });

  it('passes when disclosure_mode is valid', () => {
    const result = validatePresentBody({ ...validBody, disclosure_mode: 'full' });
    expect(result.valid).toBe(true);
  });
});

// ── validateRevokeBody ────────────────────────────────────────────────────────

describe('validateRevokeBody', () => {
  it('passes with valid reason', () => {
    const result = validateRevokeBody({ reason: 'Test reason' });
    expect(result.valid).toBe(true);
    expect(result.sanitized.reason).toBe('Test reason');
  });

  it('fails with non-object body — line 121', () => {
    // Line 121: body is null or not an object
    const result = validateRevokeBody(null);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('JSON object');

    const result2 = validateRevokeBody('not-an-object');
    expect(result2.valid).toBe(false);
  });

  it('fails with missing reason — line 124', () => {
    // Line 124: reason is missing or not a non-empty string
    const result = validateRevokeBody({});
    expect(result.valid).toBe(false);
    expect(result.error).toContain('reason');
  });

  it('fails when reason is empty string', () => {
    const result = validateRevokeBody({ reason: '   ' });
    expect(result.valid).toBe(false);
  });

  it('fails when reason is not a string', () => {
    const result = validateRevokeBody({ reason: 42 });
    expect(result.valid).toBe(false);
  });

  it('fails when reason exceeds 1000 characters — line 127', () => {
    // Line 127: reason.length > 1000
    const result = validateRevokeBody({ reason: 'x'.repeat(1001) });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('1000');
  });

  it('passes when reason is exactly 1000 characters', () => {
    const result = validateRevokeBody({ reason: 'x'.repeat(1000) });
    expect(result.valid).toBe(true);
  });
});
