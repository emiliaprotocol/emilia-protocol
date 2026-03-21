/**
 * EP Conformance Suite -- Signoff Invariants
 *
 * Structural invariant tests for the Accountable Signoff extension.
 * Proves that the signoff subsystem's internal constants, status ordering,
 * terminal states, event types, write-guard coverage, and protocol-write
 * integration are consistent and correct.
 *
 * Pure structural checks -- no mocks, no DB, no network.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';

import {
  SIGNOFF_STATUS_ORDER,
  SIGNOFF_TERMINAL_STATES,
  SIGNOFF_ALLOWED_METHODS,
  SIGNOFF_ASSURANCE_LEVELS,
  SIGNOFF_ASSURANCE_RANK,
  VALID_SIGNOFF_STATUSES,
  VALID_TERMINAL_STATES,
  VALID_ALLOWED_METHODS,
  VALID_ASSURANCE_LEVELS,
} from '../lib/signoff/invariants.js';

import {
  SIGNOFF_EVENT_TYPES,
} from '../lib/signoff/events.js';

import { SignoffError } from '../lib/signoff/errors.js';

import { COMMAND_TYPES, _internals } from '@/lib/protocol-write';
import { _internals as writeGuardInternals } from '@/lib/write-guard';

// ═══════════════════════════════════════════════════════════════════════════════
// Invariant S1: Signoff status transitions are forward-only
// ═══════════════════════════════════════════════════════════════════════════════

describe('Signoff Conformance Suite', () => {

  describe('Invariant S1: Status transitions are forward-only', () => {
    it('SIGNOFF_STATUS_ORDER is non-empty', () => {
      expect(SIGNOFF_STATUS_ORDER.length).toBeGreaterThan(0);
    });

    it('SIGNOFF_STATUS_ORDER is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_STATUS_ORDER)).toBe(true);
    });

    it('SIGNOFF_STATUS_ORDER starts with challenge_issued', () => {
      expect(SIGNOFF_STATUS_ORDER[0]).toBe('challenge_issued');
    });

    it('SIGNOFF_STATUS_ORDER contains all expected statuses', () => {
      const expected = [
        'challenge_issued',
        'challenge_viewed',
        'approved',
        'denied',
        'consumed',
        'expired',
        'revoked',
      ];
      for (const status of expected) {
        expect(
          SIGNOFF_STATUS_ORDER,
          `SIGNOFF_STATUS_ORDER missing "${status}"`,
        ).toContain(status);
      }
    });

    it('no duplicate statuses in SIGNOFF_STATUS_ORDER', () => {
      const unique = new Set(SIGNOFF_STATUS_ORDER);
      expect(unique.size).toBe(SIGNOFF_STATUS_ORDER.length);
    });

    it('VALID_SIGNOFF_STATUSES Set matches SIGNOFF_STATUS_ORDER array', () => {
      expect(VALID_SIGNOFF_STATUSES.size).toBe(SIGNOFF_STATUS_ORDER.length);
      for (const status of SIGNOFF_STATUS_ORDER) {
        expect(VALID_SIGNOFF_STATUSES.has(status)).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S2: Terminal states are truly terminal
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S2: Terminal states', () => {
    it('SIGNOFF_TERMINAL_STATES is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_TERMINAL_STATES)).toBe(true);
    });

    it('SIGNOFF_TERMINAL_STATES contains all expected terminal states', () => {
      const expected = ['denied', 'consumed', 'expired', 'revoked'];
      for (const state of expected) {
        expect(
          SIGNOFF_TERMINAL_STATES,
          `Missing terminal state: ${state}`,
        ).toContain(state);
      }
    });

    it('VALID_TERMINAL_STATES Set matches SIGNOFF_TERMINAL_STATES array', () => {
      expect(VALID_TERMINAL_STATES.size).toBe(SIGNOFF_TERMINAL_STATES.length);
      for (const state of SIGNOFF_TERMINAL_STATES) {
        expect(VALID_TERMINAL_STATES.has(state)).toBe(true);
      }
    });

    it('all terminal states are also valid signoff statuses', () => {
      for (const state of SIGNOFF_TERMINAL_STATES) {
        expect(
          VALID_SIGNOFF_STATUSES.has(state),
          `Terminal state "${state}" not in VALID_SIGNOFF_STATUSES`,
        ).toBe(true);
      }
    });

    it('non-terminal statuses are not in SIGNOFF_TERMINAL_STATES', () => {
      const nonTerminal = ['challenge_issued', 'challenge_viewed', 'approved'];
      for (const status of nonTerminal) {
        expect(
          VALID_TERMINAL_STATES.has(status),
          `"${status}" should NOT be terminal`,
        ).toBe(false);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S3: Allowed authentication methods
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S3: Allowed authentication methods', () => {
    it('SIGNOFF_ALLOWED_METHODS is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ALLOWED_METHODS)).toBe(true);
    });

    it('contains all required auth methods', () => {
      const expected = ['passkey', 'secure_app', 'platform_authenticator', 'out_of_band', 'dual_signoff'];
      for (const method of expected) {
        expect(
          SIGNOFF_ALLOWED_METHODS,
          `Missing auth method: ${method}`,
        ).toContain(method);
      }
    });

    it('VALID_ALLOWED_METHODS Set matches SIGNOFF_ALLOWED_METHODS array', () => {
      expect(VALID_ALLOWED_METHODS.size).toBe(SIGNOFF_ALLOWED_METHODS.length);
      for (const method of SIGNOFF_ALLOWED_METHODS) {
        expect(VALID_ALLOWED_METHODS.has(method)).toBe(true);
      }
    });

    it('no duplicate methods', () => {
      const unique = new Set(SIGNOFF_ALLOWED_METHODS);
      expect(unique.size).toBe(SIGNOFF_ALLOWED_METHODS.length);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S4: Assurance level ordering
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S4: Assurance level ordering', () => {
    it('SIGNOFF_ASSURANCE_LEVELS is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ASSURANCE_LEVELS)).toBe(true);
    });

    it('assurance levels are ordered low to high', () => {
      expect(SIGNOFF_ASSURANCE_LEVELS).toEqual(['low', 'substantial', 'high']);
    });

    it('SIGNOFF_ASSURANCE_RANK values are monotonically increasing', () => {
      for (let i = 0; i < SIGNOFF_ASSURANCE_LEVELS.length - 1; i++) {
        const current = SIGNOFF_ASSURANCE_RANK[SIGNOFF_ASSURANCE_LEVELS[i]];
        const next = SIGNOFF_ASSURANCE_RANK[SIGNOFF_ASSURANCE_LEVELS[i + 1]];
        expect(next).toBeGreaterThan(current);
      }
    });

    it('every assurance level has a rank', () => {
      for (const level of SIGNOFF_ASSURANCE_LEVELS) {
        expect(SIGNOFF_ASSURANCE_RANK[level]).toBeDefined();
        expect(typeof SIGNOFF_ASSURANCE_RANK[level]).toBe('number');
      }
    });

    it('SIGNOFF_ASSURANCE_RANK is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ASSURANCE_RANK)).toBe(true);
    });

    it('VALID_ASSURANCE_LEVELS Set matches SIGNOFF_ASSURANCE_LEVELS array', () => {
      expect(VALID_ASSURANCE_LEVELS.size).toBe(SIGNOFF_ASSURANCE_LEVELS.length);
      for (const level of SIGNOFF_ASSURANCE_LEVELS) {
        expect(VALID_ASSURANCE_LEVELS.has(level)).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S5: Signoff event types cover all state transitions
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S5: Signoff event types', () => {
    it('SIGNOFF_EVENT_TYPES covers all required lifecycle events', () => {
      const expected = [
        'challenge_issued',
        'challenge_viewed',
        'challenge_expired',
        'approved',
        'denied',
        'revoked',
        'consumed',
        'attestation_expired',
        'attestation_revoked',
      ];
      for (const eventType of expected) {
        expect(
          SIGNOFF_EVENT_TYPES,
          `Missing event type: ${eventType}`,
        ).toContain(eventType);
      }
    });

    it('no duplicate event types', () => {
      const unique = new Set(SIGNOFF_EVENT_TYPES);
      expect(unique.size).toBe(SIGNOFF_EVENT_TYPES.length);
    });

    it('SIGNOFF_EVENT_TYPES is an array', () => {
      expect(Array.isArray(SIGNOFF_EVENT_TYPES)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S6: Signoff tables are in TRUST_TABLES
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S6: Write-guard signoff table coverage', () => {
    it('all signoff tables are guarded by TRUST_TABLES', () => {
      const SIGNOFF_TABLES = [
        'signoff_challenges',
        'signoff_attestations',
        'signoff_consumptions',
        'signoff_events',
      ];
      for (const table of SIGNOFF_TABLES) {
        expect(
          writeGuardInternals.TRUST_TABLES,
          `TRUST_TABLES missing "${table}"`,
        ).toContain(table);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S7: protocolWrite handles all signoff command types
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S7: Protocol-write signoff command coverage', () => {
    const SIGNOFF_COMMAND_KEYS = [
      'SIGNOFF_CHALLENGE_ISSUE',
      'SIGNOFF_CHALLENGE_VIEW',
      'SIGNOFF_ATTEST',
      'SIGNOFF_DENY',
      'SIGNOFF_CONSUME',
      'SIGNOFF_CHALLENGE_REVOKE',
      'SIGNOFF_ATTESTATION_REVOKE',
      'SIGNOFF_CHALLENGE_EXPIRE',
      'SIGNOFF_ATTESTATION_EXPIRE',
    ];

    it('all signoff command type keys exist in COMMAND_TYPES', () => {
      for (const key of SIGNOFF_COMMAND_KEYS) {
        expect(
          COMMAND_TYPES[key],
          `COMMAND_TYPES missing key "${key}"`,
        ).toBeDefined();
      }
    });

    it('all signoff command types are in VALID_COMMAND_TYPES', () => {
      for (const key of SIGNOFF_COMMAND_KEYS) {
        const type = COMMAND_TYPES[key];
        expect(
          _internals.VALID_COMMAND_TYPES.has(type),
          `VALID_COMMAND_TYPES missing "${type}"`,
        ).toBe(true);
      }
    });

    it('all signoff command types map to "signoff" aggregate', () => {
      for (const key of SIGNOFF_COMMAND_KEYS) {
        const type = COMMAND_TYPES[key];
        expect(
          _internals.COMMAND_TO_AGGREGATE[type],
          `COMMAND_TO_AGGREGATE missing "${type}"`,
        ).toBe('signoff');
      }
    });

    it('signoff command types with validators are all functions', () => {
      for (const key of SIGNOFF_COMMAND_KEYS) {
        const type = COMMAND_TYPES[key];
        const validator = _internals.VALIDATORS[type];
        if (validator !== undefined) {
          expect(typeof validator).toBe('function');
        }
      }
    });

    it('signoff command types with handlers are all functions', () => {
      for (const key of SIGNOFF_COMMAND_KEYS) {
        const type = COMMAND_TYPES[key];
        const handler = _internals.HANDLERS[type];
        if (handler !== undefined) {
          expect(typeof handler).toBe('function');
        }
      }
    });

    it('signoff validator and handler counts match (no orphaned validators)', () => {
      let validatorCount = 0;
      let handlerCount = 0;
      for (const key of SIGNOFF_COMMAND_KEYS) {
        const type = COMMAND_TYPES[key];
        if (_internals.VALIDATORS[type]) validatorCount++;
        if (_internals.HANDLERS[type]) handlerCount++;
      }
      // Every command with a validator must also have a handler
      expect(validatorCount).toBe(handlerCount);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S8: Signoff invariant constants are frozen
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S8: All signoff invariant constants are frozen', () => {
    it('SIGNOFF_STATUS_ORDER is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_STATUS_ORDER)).toBe(true);
    });

    it('SIGNOFF_TERMINAL_STATES is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_TERMINAL_STATES)).toBe(true);
    });

    it('SIGNOFF_ALLOWED_METHODS is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ALLOWED_METHODS)).toBe(true);
    });

    it('SIGNOFF_ASSURANCE_LEVELS is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ASSURANCE_LEVELS)).toBe(true);
    });

    it('SIGNOFF_ASSURANCE_RANK is frozen', () => {
      expect(Object.isFrozen(SIGNOFF_ASSURANCE_RANK)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant S9: SignoffError structural correctness
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant S9: SignoffError class', () => {
    it('SignoffError extends Error', () => {
      const err = new SignoffError('test');
      expect(err).toBeInstanceOf(Error);
    });

    it('SignoffError has name "SignoffError"', () => {
      const err = new SignoffError('test');
      expect(err.name).toBe('SignoffError');
    });

    it('SignoffError carries status and code', () => {
      const err = new SignoffError('msg', 409, 'CONFLICT');
      expect(err.status).toBe(409);
      expect(err.code).toBe('CONFLICT');
    });
  });
});
