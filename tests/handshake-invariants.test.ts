/**
 * EP Handshake — Invariant function tests.
 *
 * Tests every invariant function individually with boundary cases.
 * Pure functions — no mocks needed.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  checkNotExpired,
  checkAllPartiesPresent,
  checkBindingValid,
  checkIssuerTrusted,
  checkAuthorityNotRevoked,
  checkAssuranceLevel,
  checkNoDuplicateResult,
  checkInteractionBound,
  checkNoRoleSpoofing,
  checkResultImmutability,
  runAllInvariants,
  ASSURANCE_RANK,
} from '../lib/handshake/invariants.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function futureDate(minutes = 10) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function pastDate(minutes = 10) {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

// ── Invariant 1: checkNotExpired ─────────────────────────────────────────────

describe('checkNotExpired', () => {
  it('passes when expiry is in the future', () => {
    const result = checkNotExpired({ binding: { expires_at: futureDate(10) } });
    expect(result.ok).toBe(true);
    expect(result.code).toBe('BINDING_EXPIRED');
  });

  it('fails when expiry is in the past', () => {
    const result = checkNotExpired({ binding: { expires_at: pastDate(10) } });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('BINDING_EXPIRED');
    expect(result.message).toContain('expired');
  });

  it('fails at exact boundary (now >= expiresAt)', () => {
    // Use a date that is essentially "now" minus 1ms to guarantee >= check
    const justExpired = new Date(Date.now() - 1).toISOString();
    const result = checkNotExpired({ binding: { expires_at: justExpired } });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('BINDING_EXPIRED');
  });
});

// ── Invariant 2: checkAllPartiesPresent ──────────────────────────────────────

describe('checkAllPartiesPresent', () => {
  const policy = {
    rules: {
      required_parties: {
        initiator: { required_claims: ['name'], minimum_assurance: 'low' },
        responder: { required_claims: ['name'], minimum_assurance: 'low' },
      },
    },
  };

  it('passes when all required parties have presentations', () => {
    const presentations = [
      { party_role: 'initiator' },
      { party_role: 'responder' },
    ];
    const result = checkAllPartiesPresent({}, [], presentations, policy);
    expect(result.ok).toBe(true);
  });

  it('fails when a required party is missing a presentation', () => {
    const presentations = [{ party_role: 'initiator' }];
    const result = checkAllPartiesPresent({}, [], presentations, policy);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('MISSING_REQUIRED_PARTY');
    expect(result.message).toContain('responder');
  });

  it('passes when extra parties beyond requirements are present', () => {
    const presentations = [
      { party_role: 'initiator' },
      { party_role: 'responder' },
      { party_role: 'verifier' },
    ];
    const result = checkAllPartiesPresent({}, [], presentations, policy);
    expect(result.ok).toBe(true);
  });
});

// ── Invariant 3: checkBindingValid ──────────────────────────────────────────

describe('checkBindingValid', () => {
  it('passes when payload hash matches', () => {
    const binding = { payload_hash: 'abc123', nonce: 'nonce1' };
    const result = checkBindingValid(binding, 'abc123');
    expect(result.ok).toBe(true);
  });

  it('fails when payload hash does not match', () => {
    const binding = { payload_hash: 'abc123', nonce: 'nonce1' };
    const result = checkBindingValid(binding, 'different');
    expect(result.ok).toBe(false);
    expect(result.code).toBe('BINDING_INVALID');
    expect(result.message).toContain('mismatch');
  });

  it('fails when binding is missing', () => {
    const result = checkBindingValid(null, 'abc123');
    expect(result.ok).toBe(false);
    expect(result.code).toBe('BINDING_INVALID');
  });
});

// ── Invariant 4: checkIssuerTrusted ─────────────────────────────────────────

describe('checkIssuerTrusted', () => {
  const authorities = [
    { key_id: 'iss_trusted', status: 'active' },
    { key_id: 'iss_other', status: 'active' },
  ];

  it('passes when issuer is in authorities list', () => {
    const result = checkIssuerTrusted({ issuer_ref: 'iss_trusted' }, authorities);
    expect(result.ok).toBe(true);
  });

  it('fails when issuer is not in authorities list', () => {
    const result = checkIssuerTrusted({ issuer_ref: 'iss_unknown' }, authorities);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ISSUER_NOT_TRUSTED');
    expect(result.message).toContain('not found');
  });

  it('fails when no authorities are provided', () => {
    const result = checkIssuerTrusted({ issuer_ref: 'iss_trusted' }, []);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ISSUER_NOT_TRUSTED');
  });
});

// ── Invariant 5: checkAuthorityNotRevoked ───────────────────────────────────

describe('checkAuthorityNotRevoked', () => {
  it('passes when authority is active', () => {
    const result = checkAuthorityNotRevoked({ status: 'active' });
    expect(result.ok).toBe(true);
  });

  it('fails when authority is revoked', () => {
    const result = checkAuthorityNotRevoked({ status: 'revoked' });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('AUTHORITY_REVOKED');
    expect(result.message).toContain('revoked');
  });
});

// ── Invariant 6: checkAssuranceLevel ────────────────────────────────────────

describe('checkAssuranceLevel', () => {
  it('passes when achieved level equals required level', () => {
    const result = checkAssuranceLevel('substantial', 'substantial', ASSURANCE_RANK);
    expect(result.ok).toBe(true);
  });

  it('passes when achieved level exceeds required level', () => {
    const result = checkAssuranceLevel('high', 'low', ASSURANCE_RANK);
    expect(result.ok).toBe(true);
  });

  it('fails when achieved level is below required level', () => {
    const result = checkAssuranceLevel('low', 'high', ASSURANCE_RANK);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ASSURANCE_BELOW_MINIMUM');
    expect(result.message).toContain('below');
  });

  it('fails when achieved level is unknown', () => {
    const result = checkAssuranceLevel('unknown', 'low', ASSURANCE_RANK);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ASSURANCE_BELOW_MINIMUM');
    expect(result.message).toContain('Unknown achieved');
  });
});

// ── Invariant 7: checkNoDuplicateResult ─────────────────────────────────────

describe('checkNoDuplicateResult', () => {
  it('passes when no existing results', () => {
    const result = checkNoDuplicateResult([], 'hash1');
    expect(result.ok).toBe(true);
  });

  it('fails when an accepted result with same binding hash exists', () => {
    const existing = [{ outcome: 'accepted', binding_hash: 'hash1' }];
    const result = checkNoDuplicateResult(existing, 'hash1');
    expect(result.ok).toBe(false);
    expect(result.code).toBe('DUPLICATE_RESULT');
  });
});

// ── Invariant 8: checkInteractionBound ──────────────────────────────────────

describe('checkInteractionBound', () => {
  it('passes when interaction_id is present', () => {
    const result = checkInteractionBound({ interaction_id: 'int_123' });
    expect(result.ok).toBe(true);
  });

  it('fails when interaction_id is missing', () => {
    const result = checkInteractionBound({});
    expect(result.ok).toBe(false);
    expect(result.code).toBe('MISSING_INTERACTION_REF');
  });
});

// ── Invariant 9: checkNoRoleSpoofing ────────────────────────────────────────

describe('checkNoRoleSpoofing', () => {
  it('passes when authenticated entity matches party entity_ref', () => {
    const party = { entity_ref: 'entity_abc' };
    const result = checkNoRoleSpoofing({}, 'entity_abc', party);
    expect(result.ok).toBe(true);
  });

  it('fails when authenticated entity does not match party entity_ref', () => {
    const party = { entity_ref: 'entity_abc' };
    const result = checkNoRoleSpoofing({}, 'entity_xyz', party);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ROLE_SPOOFING');
    expect(result.message).toContain('does not match');
  });
});

// ── Invariant 10: checkResultImmutability ───────────────────────────────────

describe('checkResultImmutability', () => {
  it('passes when no existing result', () => {
    const result = checkResultImmutability(null);
    expect(result.ok).toBe(true);
  });

  it('fails when existing result is finalized', () => {
    const result = checkResultImmutability({ outcome: 'accepted' });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('RESULT_IMMUTABLE');
    expect(result.message).toContain('finalized');
  });
});

// ── runAllInvariants ────────────────────────────────────────────────────────

describe('runAllInvariants', () => {
  it('passes with a clean context (all invariants satisfied)', () => {
    const context = {
      handshake: { interaction_id: 'int_1' },
      parties: [{ party_role: 'initiator', entity_ref: 'e1' }],
      presentations: [{ party_role: 'initiator' }],
      binding: {
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: futureDate(10),
      },
      policy: {
        rules: {
          required_parties: {
            initiator: { required_claims: ['name'], minimum_assurance: 'low' },
          },
        },
      },
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: 'hash1',
      authenticatedEntity: 'e1',
    };

    const result = runAllInvariants(context);
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('reports multiple violations when context has several issues', () => {
    const context = {
      handshake: {}, // no interaction_id
      parties: [],
      presentations: [],
      binding: null, // missing binding
      policy: {
        rules: {
          required_parties: {
            initiator: { required_claims: ['name'], minimum_assurance: 'low' },
          },
        },
      },
      authorities: [],
      existingResults: [],
      existingResult: { outcome: 'accepted' }, // immutable
      verificationPayloadHash: null,
      authenticatedEntity: null,
    };

    const result = runAllInvariants(context);
    expect(result.passed).toBe(false);
    expect(result.violations.length).toBeGreaterThanOrEqual(3);

    const codes = result.violations.map((v) => v.code);
    expect(codes).toContain('BINDING_EXPIRED');
    expect(codes).toContain('MISSING_REQUIRED_PARTY');
    expect(codes).toContain('BINDING_INVALID');
    expect(codes).toContain('MISSING_INTERACTION_REF');
    expect(codes).toContain('RESULT_IMMUTABLE');
  });
});
