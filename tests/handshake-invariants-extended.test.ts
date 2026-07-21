/**
 * lib/handshake/invariants.js — extended coverage.
 *
 * Targets uncovered lines:
 *   248   checkInteractionBound: pass path (handshake has interaction_id)
 *   355-357 runAllInvariants: authority lookup inside Inv-5 loop (authority found)
 *   364   runAllInvariants: Inv-6 assurance check (both fields present)
 */

import { describe, it, expect } from 'vitest';
import {
  checkInteractionBound,
  runAllInvariants,
  ASSURANCE_RANK,
} from '../lib/handshake/invariants.js';

// ── checkInteractionBound: pass path ─────────────────────────────────────────

describe('checkInteractionBound — pass path (line 255)', () => {
  it('passes when handshake has an interaction_id', () => {
    const result = checkInteractionBound({ interaction_id: 'ia-001' });
    expect(result.ok).toBe(true);
    expect(result.code).toBe('MISSING_INTERACTION_REF');
  });
});

// ── runAllInvariants: Inv-5 authority not revoked (lines 355-357) ─────────────

describe('runAllInvariants — Inv-5: authority not revoked path', () => {
  function futureDate(mins = 10) {
    return new Date(Date.now() + mins * 60_000).toISOString();
  }

  it('runs checkAuthorityNotRevoked when authority is found for issuer_ref', () => {
    // Provide a presentation with issuer_ref that matches an authority in the list
    const context = {
      handshake: { interaction_id: 'ia-1', assurance_level: null, required_assurance: null },
      parties: [],
      presentations: [
        { party_role: 'initiator', issuer_ref: 'key-abc' },
      ],
      binding: { nonce: 'nonce123', expires_at: futureDate(10) },
      policy: null,
      authorities: [
        { key_id: 'key-abc', status: 'active' },
      ],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    // With a valid authority, Inv-5 should pass (authority not revoked)
    const inv5Violation = result.violations.find(v => v.code === 'AUTHORITY_REVOKED');
    expect(inv5Violation).toBeUndefined();
  });

  it('fails Inv-5 when authority is revoked', () => {
    const context = {
      handshake: { interaction_id: 'ia-2' },
      parties: [],
      presentations: [
        { party_role: 'initiator', issuer_ref: 'key-revoked' },
      ],
      binding: { nonce: 'nonce456', expires_at: futureDate(10) },
      policy: null,
      authorities: [
        { key_id: 'key-revoked', status: 'revoked' },
      ],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    const inv5Violation = result.violations.find(v => v.code === 'AUTHORITY_REVOKED');
    expect(inv5Violation).toBeDefined();
    expect(inv5Violation.ok).toBe(false);
  });

  it('skips Inv-5 when authority not found for issuer_ref', () => {
    // issuer_ref present but no matching authority in list — inner if(authority) is false
    const context = {
      handshake: { interaction_id: 'ia-3' },
      parties: [],
      presentations: [
        { party_role: 'initiator', issuer_ref: 'key-unknown' },
      ],
      binding: { nonce: 'nonce789', expires_at: futureDate(10) },
      policy: null,
      authorities: [
        { key_id: 'key-other', status: 'active' },
      ],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    // Inv-4 will fail (ISSUER_NOT_TRUSTED), but Inv-5 should NOT have a violation
    // (because the authority was not found, so we skip the revocation check)
    const result = runAllInvariants(context);
    const inv5Violation = result.violations.find(v => v.code === 'AUTHORITY_REVOKED');
    expect(inv5Violation).toBeUndefined();
  });
});

// ── runAllInvariants: Inv-6 assurance check (line 364) ───────────────────────

describe('runAllInvariants — Inv-6: assurance level check', () => {
  function futureDate(mins = 10) {
    return new Date(Date.now() + mins * 60_000).toISOString();
  }

  it('runs assurance check when both assurance_level and required_assurance are set', () => {
    const context = {
      handshake: {
        interaction_id: 'ia-4',
        assurance_level: 'high',
        required_assurance: 'medium',
      },
      parties: [],
      presentations: [],
      binding: { nonce: 'nonce-asl', expires_at: futureDate(10) },
      policy: null,
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    // 'high' (rank 4) >= 'medium' (rank 2) — should pass
    const inv6Violation = result.violations.find(v => v.code === 'ASSURANCE_BELOW_MINIMUM');
    expect(inv6Violation).toBeUndefined();
  });

  it('adds ASSURANCE_BELOW_MINIMUM violation when level is too low', () => {
    const context = {
      handshake: {
        interaction_id: 'ia-5',
        assurance_level: 'low',
        required_assurance: 'high',
      },
      parties: [],
      presentations: [],
      binding: { nonce: 'nonce-asl2', expires_at: futureDate(10) },
      policy: null,
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    const inv6Violation = result.violations.find(v => v.code === 'ASSURANCE_BELOW_MINIMUM');
    expect(inv6Violation).toBeDefined();
    expect(inv6Violation.ok).toBe(false);
  });

  it('skips Inv-6 when assurance_level is missing', () => {
    const context = {
      handshake: { interaction_id: 'ia-6', required_assurance: 'high' },
      parties: [],
      presentations: [],
      binding: { nonce: 'nonce-skip', expires_at: futureDate(10) },
      policy: null,
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    const inv6Violation = result.violations.find(v => v.code === 'ASSURANCE_BELOW_MINIMUM');
    expect(inv6Violation).toBeUndefined();
  });
});
