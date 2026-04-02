/**
 * Signoff barrel — 100% export coverage.
 *
 * lib/signoff/index.js is a pure re-export barrel. Importing it and asserting
 * on every named export guarantees the module is evaluated (and thus covered).
 */

import * as signoff from '../lib/signoff/index.js';

it('signoff barrel exports all functions and constants', () => {
  // Challenge
  expect(typeof signoff.issueChallenge).toBe('function');
  // Attestation
  expect(typeof signoff.createAttestation).toBe('function');
  // Consumption
  expect(typeof signoff.consumeSignoff).toBe('function');
  expect(typeof signoff.isSignoffConsumed).toBe('function');
  // Denial
  expect(typeof signoff.denyChallenge).toBe('function');
  // Revocation
  expect(typeof signoff.revokeChallenge).toBe('function');
  expect(typeof signoff.revokeAttestation).toBe('function');
  // Events
  expect(typeof signoff.emitSignoffEvent).toBe('function');
  expect(typeof signoff.requireSignoffEvent).toBe('function');
  expect(typeof signoff.getSignoffEvents).toBe('function');
  expect(typeof signoff.SIGNOFF_EVENT_TYPES).toBeDefined();
  // Invariants
  expect(Array.isArray(signoff.SIGNOFF_STATUS_ORDER)).toBe(true);
  expect(signoff.SIGNOFF_TERMINAL_STATES).toBeDefined();
  expect(signoff.SIGNOFF_ALLOWED_METHODS).toBeDefined();
  expect(signoff.SIGNOFF_ASSURANCE_LEVELS).toBeDefined();
  expect(signoff.SIGNOFF_ASSURANCE_RANK).toBeDefined();
  // Errors
  expect(typeof signoff.SignoffError).toBe('function');
});
