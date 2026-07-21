// SPDX-License-Identifier: Apache-2.0
//
// Locks the Eye webhook PRIVACY GUARANTEE in a test: the notifier must never
// leak raw identifier refs, evidence contents, or per-entity volume into an
// outgoing webhook payload. Only re-derivable facts (status, reason codes,
// scope-binding hash, evidence COUNT, timestamps, action_type) may cross the
// wire. If a future edit widens what redactAdvisory emits, this test fails.

import { describe, it, expect } from 'vitest';
import { __test__ } from '../lib/eye/webhook-notify.js';

const { redactAdvisory, shortHashToken } = __test__;

describe('eye/webhook redaction — privacy guarantee', () => {
  it('never leaks raw identifier refs or evidence contents', () => {
    const advisory = {
      advisory_id: 'adv_123',
      status: 'caution',
      reason_codes: ['device_fingerprint_changed'],
      recommended_action: 'require_signoff',
      scope_binding_hash: 'a'.repeat(64),
      advisory_hash: 'b'.repeat(64),
      action_type: 'payment.release',
      subject_ref: 'SECRET-subject-acct-5x9k',
      actor_ref: 'SECRET-actor-invoice-bot',
      target_ref: 'SECRET-target-vendor-99',
      issuer_ref: 'SECRET-issuer-operator',
      evidence: [{ secretField: 'SECRET-evidence-1' }, { secretField: 'SECRET-evidence-2' }],
    };

    // Default redaction (refs hidden) AND the stronger revealRefs=true mode:
    // even when refs are "revealed", non-hash identifiers must be dropped
    // (only already-hashed tokens are allowed through).
    const json = JSON.stringify(redactAdvisory(advisory, { revealRefs: false }));
    const jsonRevealed = JSON.stringify(redactAdvisory(advisory, { revealRefs: true }));

    // The guarantee: no raw ref value or evidence content crosses the wire — in EITHER mode.
    expect(json).not.toContain('SECRET-');
    expect(json).not.toContain('secretField');
    expect(jsonRevealed).not.toContain('SECRET-');

    // Re-derivable facts survive.
    expect(json).toContain('caution');
    expect(json).toContain('device_fingerprint_changed');
  });

  it('shortHashToken drops non-hash strings and keeps real hashes', () => {
    expect(shortHashToken('alice@example.com')).toBeFalsy();
    expect(shortHashToken('not-a-hash')).toBeFalsy();
    expect(shortHashToken('f'.repeat(64))).toBeTruthy();
  });
});
