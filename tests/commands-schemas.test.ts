/**
 * Tests for lib/commands/schemas.js
 * Covers all exported validators and the COMMAND_SCHEMAS map.
 */

import { vi, describe, it, expect } from 'vitest';

// Mock the protocol-write module so ProtocolWriteError is available in tests
vi.mock('@/lib/protocol-write', async (importOriginal) => {
  // Use the real errors module so we get the real class
  const { ProtocolWriteError } = await import('@/lib/errors');
  return { ProtocolWriteError };
});

import {
  validateSubmitReceipt,
  validateSubmitAutoReceipt,
  validateConfirmReceipt,
  validateIssueCommit,
  validateVerifyCommit,
  validateRevokeCommit,
  validateFileDispute,
  validateRespondDispute,
  validateResolveDispute,
  validateAppealDispute,
  validateResolveAppeal,
  validateWithdrawDispute,
  validateFileReport,
  validateInitiateHandshake,
  validateAddPresentation,
  validateVerifyHandshake,
  validateRevokeHandshake,
  COMMAND_SCHEMAS,
} from '@/lib/commands/schemas.js';

import { ProtocolWriteError } from '@/lib/errors';

// Helper — assert that calling fn() throws a ProtocolWriteError with VALIDATION_ERROR code
function expectValidationError(fn) {
  expect(fn).toThrow(ProtocolWriteError);
  try { fn(); } catch (e) {
    expect(e.code).toBe('VALIDATION_ERROR');
    expect(e.status).toBe(400);
  }
}

// ── Receipt Commands ───────────────────────────────────────────────────────

describe('validateSubmitReceipt', () => {
  it('passes with a valid entity_id string', () => {
    expect(() => validateSubmitReceipt({ entity_id: 'ent_123' })).not.toThrow();
  });

  it('throws when entity_id is missing', () => {
    expectValidationError(() => validateSubmitReceipt({}));
  });

  it('throws when entity_id is not a string', () => {
    expectValidationError(() => validateSubmitReceipt({ entity_id: 42 }));
  });
});

describe('validateSubmitAutoReceipt', () => {
  it('passes with a valid entity_id string', () => {
    expect(() => validateSubmitAutoReceipt({ entity_id: 'ent_auto' })).not.toThrow();
  });

  it('throws when entity_id is missing', () => {
    expectValidationError(() => validateSubmitAutoReceipt({}));
  });
});

describe('validateConfirmReceipt', () => {
  const valid = { receipt_id: 'r_1', confirming_entity_id: 'e_1', confirm: true };

  it('passes with all required fields (confirm=true)', () => {
    expect(() => validateConfirmReceipt(valid)).not.toThrow();
  });

  it('passes with confirm=false', () => {
    expect(() => validateConfirmReceipt({ ...valid, confirm: false })).not.toThrow();
  });

  it('throws when receipt_id is missing', () => {
    expectValidationError(() => validateConfirmReceipt({ confirming_entity_id: 'e_1', confirm: true }));
  });

  it('throws when confirming_entity_id is missing', () => {
    expectValidationError(() => validateConfirmReceipt({ receipt_id: 'r_1', confirm: true }));
  });

  it('throws when confirm is not a boolean', () => {
    expectValidationError(() => validateConfirmReceipt({ receipt_id: 'r_1', confirming_entity_id: 'e_1', confirm: 'yes' }));
  });

  it('throws when confirm is undefined', () => {
    expectValidationError(() => validateConfirmReceipt({ receipt_id: 'r_1', confirming_entity_id: 'e_1' }));
  });
});

// ── Commit Commands ────────────────────────────────────────────────────────

describe('validateIssueCommit', () => {
  it('passes with entity_id and action_type', () => {
    expect(() => validateIssueCommit({ entity_id: 'e_1', action_type: 'install' })).not.toThrow();
  });

  it('throws when entity_id is missing', () => {
    expectValidationError(() => validateIssueCommit({ action_type: 'install' }));
  });

  it('throws when action_type is missing', () => {
    expectValidationError(() => validateIssueCommit({ entity_id: 'e_1' }));
  });
});

describe('validateVerifyCommit', () => {
  it('passes with a valid commit_id', () => {
    expect(() => validateVerifyCommit({ commit_id: 'c_abc' })).not.toThrow();
  });

  it('throws when commit_id is missing', () => {
    expectValidationError(() => validateVerifyCommit({}));
  });
});

describe('validateRevokeCommit', () => {
  it('passes with commit_id and reason', () => {
    expect(() => validateRevokeCommit({ commit_id: 'c_abc', reason: 'policy violation' })).not.toThrow();
  });

  it('throws when commit_id is missing', () => {
    expectValidationError(() => validateRevokeCommit({ reason: 'policy violation' }));
  });

  it('throws when reason is missing', () => {
    expectValidationError(() => validateRevokeCommit({ commit_id: 'c_abc' }));
  });
});

// ── Dispute Commands ───────────────────────────────────────────────────────

describe('validateFileDispute', () => {
  it('passes with receipt_id and reason', () => {
    expect(() => validateFileDispute({ receipt_id: 'r_1', reason: 'bad actor' })).not.toThrow();
  });

  it('throws when receipt_id is missing', () => {
    expectValidationError(() => validateFileDispute({ reason: 'bad' }));
  });

  it('throws when reason is missing', () => {
    expectValidationError(() => validateFileDispute({ receipt_id: 'r_1' }));
  });
});

describe('validateRespondDispute', () => {
  it('passes with dispute_id, responder_id, response', () => {
    expect(() => validateRespondDispute({ dispute_id: 'd_1', responder_id: 'e_2', response: 'I disagree' })).not.toThrow();
  });

  it('throws when any required field is missing', () => {
    expectValidationError(() => validateRespondDispute({ responder_id: 'e_2', response: 'I disagree' }));
    expectValidationError(() => validateRespondDispute({ dispute_id: 'd_1', response: 'I disagree' }));
    expectValidationError(() => validateRespondDispute({ dispute_id: 'd_1', responder_id: 'e_2' }));
  });
});

describe('validateResolveDispute', () => {
  it('passes with all required fields', () => {
    expect(() => validateResolveDispute({
      dispute_id: 'd_1', resolution: 'upheld', rationale: 'clear evidence', operator_id: 'op_1',
    })).not.toThrow();
  });

  it('throws when dispute_id is missing', () => {
    expectValidationError(() => validateResolveDispute({ resolution: 'upheld', rationale: 'x', operator_id: 'op_1' }));
  });

  it('throws when operator_id is missing', () => {
    expectValidationError(() => validateResolveDispute({ dispute_id: 'd_1', resolution: 'upheld', rationale: 'x' }));
  });
});

describe('validateAppealDispute', () => {
  it('passes with dispute_id and a sufficiently long reason', () => {
    expect(() => validateAppealDispute({ dispute_id: 'd_1', reason: 'I strongly disagree with this decision' })).not.toThrow();
  });

  it('throws when dispute_id is missing', () => {
    expectValidationError(() => validateAppealDispute({ reason: 'long enough reason here' }));
  });

  it('throws when reason is too short (< 10 chars)', () => {
    expectValidationError(() => validateAppealDispute({ dispute_id: 'd_1', reason: 'short' }));
  });

  it('throws when reason is exactly at the boundary (< 10 chars)', () => {
    expectValidationError(() => validateAppealDispute({ dispute_id: 'd_1', reason: '123456789' }));
  });

  it('passes when reason is exactly 10 chars', () => {
    expect(() => validateAppealDispute({ dispute_id: 'd_1', reason: '1234567890' })).not.toThrow();
  });
});

describe('validateResolveAppeal', () => {
  it('passes with all required fields', () => {
    expect(() => validateResolveAppeal({
      dispute_id: 'd_1', resolution: 'overturned', rationale: 'new evidence', operator_id: 'op_2',
    })).not.toThrow();
  });

  it('throws when resolution is missing', () => {
    expectValidationError(() => validateResolveAppeal({ dispute_id: 'd_1', rationale: 'x', operator_id: 'op_2' }));
  });
});

describe('validateWithdrawDispute', () => {
  it('passes with a valid dispute_id', () => {
    expect(() => validateWithdrawDispute({ dispute_id: 'd_1' })).not.toThrow();
  });

  it('throws when dispute_id is missing', () => {
    expectValidationError(() => validateWithdrawDispute({}));
  });
});

describe('validateFileReport', () => {
  it('passes with entity_id, report_type, description', () => {
    expect(() => validateFileReport({ entity_id: 'e_1', report_type: 'spam', description: 'They spammed me' })).not.toThrow();
  });

  it('throws when entity_id is missing', () => {
    expectValidationError(() => validateFileReport({ report_type: 'spam', description: 'x' }));
  });

  it('throws when report_type is missing', () => {
    expectValidationError(() => validateFileReport({ entity_id: 'e_1', description: 'x' }));
  });

  it('throws when description is missing', () => {
    expectValidationError(() => validateFileReport({ entity_id: 'e_1', report_type: 'spam' }));
  });
});

// ── Handshake Commands ────────────────────────────────────────────────────

describe('validateInitiateHandshake', () => {
  it('passes with mode, policy_id, and non-empty parties array', () => {
    expect(() => validateInitiateHandshake({ mode: 'mutual', policy_id: 'pol_1', parties: ['a', 'b'] })).not.toThrow();
  });

  it('throws when mode is missing', () => {
    expectValidationError(() => validateInitiateHandshake({ policy_id: 'pol_1', parties: ['a'] }));
  });

  it('throws when policy_id is missing', () => {
    expectValidationError(() => validateInitiateHandshake({ mode: 'mutual', parties: ['a'] }));
  });

  it('throws when parties is an empty array', () => {
    expectValidationError(() => validateInitiateHandshake({ mode: 'mutual', policy_id: 'pol_1', parties: [] }));
  });

  it('throws when parties is not an array', () => {
    expectValidationError(() => validateInitiateHandshake({ mode: 'mutual', policy_id: 'pol_1', parties: 'a,b' }));
  });
});

describe('validateAddPresentation', () => {
  it('passes with all required fields', () => {
    expect(() => validateAddPresentation({ handshake_id: 'h_1', party_role: 'initiator', presentation_hash: 'abc123' })).not.toThrow();
  });

  it('throws when handshake_id is missing', () => {
    expectValidationError(() => validateAddPresentation({ party_role: 'initiator', presentation_hash: 'abc' }));
  });

  it('throws when party_role is missing', () => {
    expectValidationError(() => validateAddPresentation({ handshake_id: 'h_1', presentation_hash: 'abc' }));
  });

  it('throws when presentation_hash is missing', () => {
    expectValidationError(() => validateAddPresentation({ handshake_id: 'h_1', party_role: 'initiator' }));
  });
});

describe('validateVerifyHandshake', () => {
  it('passes with valid handshake_id', () => {
    expect(() => validateVerifyHandshake({ handshake_id: 'h_1' })).not.toThrow();
  });

  it('throws when handshake_id is missing', () => {
    expectValidationError(() => validateVerifyHandshake({}));
  });
});

describe('validateRevokeHandshake', () => {
  it('passes with handshake_id and reason', () => {
    expect(() => validateRevokeHandshake({ handshake_id: 'h_1', reason: 'policy breach' })).not.toThrow();
  });

  it('throws when handshake_id is missing', () => {
    expectValidationError(() => validateRevokeHandshake({ reason: 'policy breach' }));
  });

  it('throws when reason is missing', () => {
    expectValidationError(() => validateRevokeHandshake({ handshake_id: 'h_1' }));
  });
});

// ── COMMAND_SCHEMAS map ────────────────────────────────────────────────────

describe('COMMAND_SCHEMAS', () => {
  it('is an object with all expected command_type keys', () => {
    const expectedKeys = [
      'submit_receipt', 'submit_auto_receipt', 'confirm_receipt',
      'issue_commit', 'verify_commit', 'revoke_commit',
      'file_dispute', 'respond_dispute', 'resolve_dispute',
      'appeal_dispute', 'resolve_appeal', 'withdraw_dispute', 'file_report',
      'initiate_handshake', 'add_presentation', 'verify_handshake', 'revoke_handshake',
    ];
    for (const key of expectedKeys) {
      expect(COMMAND_SCHEMAS).toHaveProperty(key);
      expect(typeof COMMAND_SCHEMAS[key]).toBe('function');
    }
  });

  it('has 17 entries in total', () => {
    expect(Object.keys(COMMAND_SCHEMAS).length).toBe(17);
  });

  it('each schema function validates correctly when invoked via the map', () => {
    // submit_receipt — valid
    expect(() => COMMAND_SCHEMAS.submit_receipt({ entity_id: 'e_1' })).not.toThrow();
    // submit_receipt — invalid
    expect(() => COMMAND_SCHEMAS.submit_receipt({})).toThrow(ProtocolWriteError);
    // verify_commit — valid
    expect(() => COMMAND_SCHEMAS.verify_commit({ commit_id: 'c_1' })).not.toThrow();
  });
});
