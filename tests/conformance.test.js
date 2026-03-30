/**
 * EP Conformance Suite -- Protocol Invariants
 *
 * This suite proves that the EMILIA Protocol's structural invariants hold.
 * It imports the actual source-of-truth modules and verifies internal
 * consistency: every command type has a validator, handler, and aggregate
 * mapping; the write-guard covers all trust-bearing tables; binding
 * material fields are canonical and frozen; assurance levels are ordered;
 * handshake lifecycle states are complete; and the CI enforcement script
 * covers all forbidden imports.
 *
 * Pure structural checks -- no mocks, no DB, no network.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import path from 'path';

import { COMMAND_TYPES, _internals } from '@/lib/protocol-write';
import { _internals as writeGuardInternals } from '@/lib/write-guard';
import {
  CANONICAL_BINDING_FIELDS,
  BINDING_MATERIAL_VERSION,
  ASSURANCE_LEVELS,
  HANDSHAKE_STATUSES,
  HANDSHAKE_MODES,
  VALID_MODES,
  VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES,
  ASSURANCE_RANK,
} from '@/lib/handshake/invariants';

// ── Helpers ──────────────────────────────────────────────────────────────────

const ROOT = path.resolve(import.meta.dirname, '..');

// ═══════════════════════════════════════════════════════════════════════════════
// Invariant 1: Write-path completeness
// Every COMMAND_TYPE has a validator, handler, and aggregate mapping.
// ═══════════════════════════════════════════════════════════════════════════════

describe('EP Conformance Suite -- Protocol Invariants', () => {

  describe('Invariant 1: Write-path completeness', () => {
    const types = Object.values(COMMAND_TYPES);

    it('COMMAND_TYPES is non-empty and has exactly 34 command types', () => {
      expect(types.length).toBe(34);
    });

    it('every trust-changing command type has a validator', () => {
      for (const type of types) {
        expect(
          _internals.VALIDATORS[type],
          `Missing validator for ${type}`,
        ).toBeDefined();
      }
    });

    it('every trust-changing command type has a handler', () => {
      for (const type of types) {
        expect(
          _internals.HANDLERS[type],
          `Missing handler for ${type}`,
        ).toBeDefined();
      }
    });

    it('every trust-changing command type has an aggregate mapping', () => {
      for (const type of types) {
        expect(
          _internals.COMMAND_TO_AGGREGATE[type],
          `Missing aggregate for ${type}`,
        ).toBeDefined();
      }
    });

    it('VALID_COMMAND_TYPES matches COMMAND_TYPES values', () => {
      const expected = new Set(Object.values(COMMAND_TYPES));
      const actual = _internals.VALID_COMMAND_TYPES;
      // VALID_COMMAND_TYPES is a Set in the source
      expect(actual.size).toBe(expected.size);
      for (const t of expected) {
        expect(actual.has(t), `VALID_COMMAND_TYPES missing ${t}`).toBe(true);
      }
    });

    it('every validator is a function', () => {
      for (const type of types) {
        expect(typeof _internals.VALIDATORS[type]).toBe('function');
      }
    });

    it('every handler is a function', () => {
      for (const type of types) {
        expect(typeof _internals.HANDLERS[type]).toBe('function');
      }
    });

    it('aggregate types are one of the known aggregates', () => {
      const KNOWN_AGGREGATES = new Set(['receipt', 'commit', 'dispute', 'report', 'handshake', 'signoff', 'continuity', 'eye']);
      for (const type of types) {
        const agg = _internals.COMMAND_TO_AGGREGATE[type];
        expect(
          KNOWN_AGGREGATES.has(agg),
          `Aggregate "${agg}" for ${type} is not a known aggregate`,
        ).toBe(true);
      }
    });

    it('no orphan validators (every validator key is a valid command type)', () => {
      for (const key of Object.keys(_internals.VALIDATORS)) {
        expect(
          _internals.VALID_COMMAND_TYPES.has(key),
          `Orphan validator for unknown command type: ${key}`,
        ).toBe(true);
      }
    });

    it('no orphan handlers (every handler key is a valid command type)', () => {
      for (const key of Object.keys(_internals.HANDLERS)) {
        expect(
          _internals.VALID_COMMAND_TYPES.has(key),
          `Orphan handler for unknown command type: ${key}`,
        ).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 2: Write-guard table coverage
  // All trust-bearing tables are listed in TRUST_TABLES.
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 2: Write-guard table coverage', () => {
    it('TRUST_TABLES is frozen', () => {
      expect(Object.isFrozen(writeGuardInternals.TRUST_TABLES)).toBe(true);
    });

    it('all trust-bearing tables are guarded', () => {
      const EXPECTED_TABLES = [
        'receipts',
        'commits',
        'disputes',
        'trust_reports',
        'protocol_events',
        'handshakes',
        'handshake_parties',
        'handshake_presentations',
        'handshake_bindings',
        'handshake_results',
        'handshake_policies',
        'handshake_events',
        'handshake_consumptions',
        'signoff_challenges',
        'signoff_attestations',
        'signoff_consumptions',
        'signoff_events',
      ];
      for (const table of EXPECTED_TABLES) {
        expect(
          writeGuardInternals.TRUST_TABLES,
          `TRUST_TABLES missing "${table}"`,
        ).toContain(table);
      }
    });

    it('TRUST_TABLES has no empty strings or null entries', () => {
      for (const table of writeGuardInternals.TRUST_TABLES) {
        expect(typeof table).toBe('string');
        expect(table.length).toBeGreaterThan(0);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 3: Binding material canonical fields
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 3: Binding material canonical fields', () => {
    it('canonical binding fields list is frozen', () => {
      expect(Object.isFrozen(CANONICAL_BINDING_FIELDS)).toBe(true);
    });

    it('binding material version is a positive integer', () => {
      expect(BINDING_MATERIAL_VERSION).toBeGreaterThan(0);
      expect(Number.isInteger(BINDING_MATERIAL_VERSION)).toBe(true);
    });

    it('all required binding fields are present', () => {
      const required = [
        'action_type',
        'resource_ref',
        'policy_id',
        'policy_hash',
        'party_set_hash',
        'nonce',
        'expires_at',
        'binding_material_version',
      ];
      for (const field of required) {
        expect(
          CANONICAL_BINDING_FIELDS,
          `Missing required binding field: ${field}`,
        ).toContain(field);
      }
    });

    it('canonical binding fields include version-tracking fields', () => {
      expect(CANONICAL_BINDING_FIELDS).toContain('binding_material_version');
      expect(CANONICAL_BINDING_FIELDS).toContain('policy_version');
    });

    it('canonical binding fields include crypto-integrity fields', () => {
      expect(CANONICAL_BINDING_FIELDS).toContain('payload_hash');
      expect(CANONICAL_BINDING_FIELDS).toContain('context_hash');
      expect(CANONICAL_BINDING_FIELDS).toContain('nonce');
    });

    it('no duplicate fields in canonical binding fields', () => {
      const unique = new Set(CANONICAL_BINDING_FIELDS);
      expect(unique.size).toBe(CANONICAL_BINDING_FIELDS.length);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 4: Assurance level ordering
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 4: Assurance level ordering', () => {
    it('assurance levels are ordered low to high', () => {
      expect(ASSURANCE_LEVELS).toEqual(['low', 'medium', 'substantial', 'high']);
    });

    it('ASSURANCE_RANK values are monotonically increasing with level index', () => {
      for (let i = 0; i < ASSURANCE_LEVELS.length - 1; i++) {
        const current = ASSURANCE_RANK[ASSURANCE_LEVELS[i]];
        const next = ASSURANCE_RANK[ASSURANCE_LEVELS[i + 1]];
        expect(next).toBeGreaterThan(current);
      }
    });

    it('every assurance level has a rank', () => {
      for (const level of ASSURANCE_LEVELS) {
        expect(ASSURANCE_RANK[level]).toBeDefined();
        expect(typeof ASSURANCE_RANK[level]).toBe('number');
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 5: Handshake lifecycle states
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 5: Handshake lifecycle states', () => {
    it('handshake has all required status values', () => {
      const required = [
        'initiated',
        'pending_verification',
        'verified',
        'rejected',
        'expired',
        'revoked',
      ];
      for (const status of required) {
        expect(
          HANDSHAKE_STATUSES,
          `Missing handshake status: ${status}`,
        ).toContain(status);
      }
    });

    it('handshake modes include all required modes', () => {
      const required = ['basic', 'mutual', 'selective', 'delegated'];
      for (const mode of required) {
        expect(HANDSHAKE_MODES).toContain(mode);
      }
    });

    it('VALID_MODES set matches HANDSHAKE_MODES array', () => {
      expect(VALID_MODES.size).toBe(HANDSHAKE_MODES.length);
      for (const mode of HANDSHAKE_MODES) {
        expect(VALID_MODES.has(mode)).toBe(true);
      }
    });

    it('party roles include required roles', () => {
      const required = ['initiator', 'responder', 'verifier', 'delegate'];
      for (const role of required) {
        expect(VALID_PARTY_ROLES.has(role), `Missing party role: ${role}`).toBe(true);
      }
    });

    it('disclosure modes include required modes', () => {
      const required = ['full', 'selective', 'commitment'];
      for (const mode of required) {
        expect(VALID_DISCLOSURE_MODES.has(mode), `Missing disclosure mode: ${mode}`).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 6: CI enforcement script coverage
  // The check-write-discipline.js script must forbid all canonical writer
  // functions that protocol-write.js wraps.
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 6: CI enforcement script covers all canonical functions', () => {
    const scriptPath = path.join(ROOT, 'scripts', 'check-write-discipline.js');
    const scriptSource = readFileSync(scriptPath, 'utf-8');

    const CANONICAL_FUNCTIONS = [
      'canonicalSubmitReceipt',
      'canonicalSubmitAutoReceipt',
      'canonicalBilateralConfirm',
      'canonicalFileDispute',
      'canonicalResolveDispute',
      'canonicalRespondDispute',
      'canonicalAppealDispute',
      'canonicalResolveAppeal',
      'canonicalWithdrawDispute',
      'canonicalFileReport',
      'issueCommit',
      'verifyCommit',
      'revokeCommit',
    ];

    it('FORBIDDEN_IMPORTS in CI script covers all canonical functions', () => {
      for (const fn of CANONICAL_FUNCTIONS) {
        expect(
          scriptSource.includes(`'${fn}'`),
          `CI script missing forbidden import: ${fn}`,
        ).toBe(true);
      }
    });

    it('CI script checks for getServiceClient usage in routes', () => {
      expect(scriptSource).toContain('getServiceClient');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 7: Protocol event builder structural correctness
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 7: Protocol event builder', () => {
    it('buildProtocolEvent returns all required fields', () => {
      const event = _internals.buildProtocolEvent({
        aggregateType: 'receipt',
        aggregateId: 'test-id',
        commandType: 'submit_receipt',
        payload: { entity_id: 'e1' },
        actorAuthorityId: 'actor-1',
        idempotencyKey: 'idem-1',
        parentEventHash: null,
      });

      expect(event.event_id).toBeDefined();
      expect(event.aggregate_type).toBe('receipt');
      expect(event.aggregate_id).toBe('test-id');
      expect(event.command_type).toBe('submit_receipt');
      expect(event.payload_hash).toBeDefined();
      expect(typeof event.payload_hash).toBe('string');
      expect(event.payload_hash.length).toBe(64); // SHA-256 hex
      expect(event.actor_authority_id).toBe('actor-1');
      expect(event.idempotency_key).toBe('idem-1');
      expect(event.created_at).toBeDefined();
    });

    it('payload_hash is deterministic for same input', () => {
      const params = {
        aggregateType: 'receipt',
        aggregateId: 'test-id',
        commandType: 'submit_receipt',
        payload: { b: 2, a: 1 },
        actorAuthorityId: 'actor-1',
        idempotencyKey: 'idem-1',
      };
      const e1 = _internals.buildProtocolEvent(params);
      const e2 = _internals.buildProtocolEvent(params);
      expect(e1.payload_hash).toBe(e2.payload_hash);
    });

    it('different event_ids for each call (UUID uniqueness)', () => {
      const params = {
        aggregateType: 'receipt',
        aggregateId: 'test-id',
        commandType: 'submit_receipt',
        payload: {},
        actorAuthorityId: 'actor-1',
        idempotencyKey: 'idem-1',
      };
      const e1 = _internals.buildProtocolEvent(params);
      const e2 = _internals.buildProtocolEvent(params);
      expect(e1.event_id).not.toBe(e2.event_id);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 8: Idempotency key determinism
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 8: Idempotency key determinism', () => {
    it('same command produces same idempotency key', () => {
      const cmd = { type: 'submit_receipt', actor: 'a1', input: { entity_id: 'e1' } };
      const k1 = _internals.computeIdempotencyKey(cmd);
      const k2 = _internals.computeIdempotencyKey(cmd);
      expect(k1).toBe(k2);
    });

    it('different actors produce different idempotency keys', () => {
      const cmd1 = { type: 'submit_receipt', actor: 'a1', input: { entity_id: 'e1' } };
      const cmd2 = { type: 'submit_receipt', actor: 'a2', input: { entity_id: 'e1' } };
      expect(_internals.computeIdempotencyKey(cmd1)).not.toBe(
        _internals.computeIdempotencyKey(cmd2),
      );
    });

    it('different command types produce different idempotency keys', () => {
      const cmd1 = { type: 'submit_receipt', actor: 'a1', input: { entity_id: 'e1' } };
      const cmd2 = { type: 'file_dispute', actor: 'a1', input: { entity_id: 'e1' } };
      expect(_internals.computeIdempotencyKey(cmd1)).not.toBe(
        _internals.computeIdempotencyKey(cmd2),
      );
    });

    it('idempotency key is a 64-char hex string (SHA-256)', () => {
      const cmd = { type: 'submit_receipt', actor: 'a1', input: {} };
      const key = _internals.computeIdempotencyKey(cmd);
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 9: Authority resolution
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 9: Authority resolution', () => {
    it('resolves string actor to id', () => {
      const auth = _internals.resolveAuthority({ actor: 'user-123' });
      expect(auth.id).toBe('user-123');
    });

    it('resolves object actor with id field', () => {
      const auth = _internals.resolveAuthority({ actor: { id: 'user-456' } });
      expect(auth.id).toBe('user-456');
    });

    it('resolves object actor with entity_id field', () => {
      const auth = _internals.resolveAuthority({ actor: { entity_id: 'ent-789' } });
      expect(auth.id).toBe('ent-789');
    });

    it('falls back to anonymous when actor is missing', () => {
      const auth = _internals.resolveAuthority({});
      expect(auth.id).toBe('anonymous');
    });

    it('includes role and source from requestMeta', () => {
      const auth = _internals.resolveAuthority({
        actor: 'a1',
        requestMeta: { role: 'operator', source: 'admin-ui' },
      });
      expect(auth.role).toBe('operator');
      expect(auth.source).toBe('admin-ui');
    });

    it('defaults role to entity and source to api', () => {
      const auth = _internals.resolveAuthority({ actor: 'a1' });
      expect(auth.role).toBe('entity');
      expect(auth.source).toBe('api');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Invariant 10: assertInvariants rejects bad commands
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Invariant 10: Protocol-level assertInvariants', () => {
    it('rejects command with no type', () => {
      expect(() => _internals.assertInvariants({})).toThrow('command.type is required');
    });

    it('rejects unknown command type', () => {
      expect(() => _internals.assertInvariants({ type: 'delete_everything' })).toThrow(
        'Unknown command type',
      );
    });

    it('rejects non-object input', () => {
      expect(() =>
        _internals.assertInvariants({ type: 'submit_receipt', input: 'not-an-object' }),
      ).toThrow('command.input must be an object');
    });

    it('accepts valid command structure', () => {
      expect(() =>
        _internals.assertInvariants({
          type: 'submit_receipt',
          input: { entity_id: 'e1' },
        }),
      ).not.toThrow();
    });

    it('accepts null input (some commands may not need input)', () => {
      expect(() =>
        _internals.assertInvariants({ type: 'submit_receipt', input: null }),
      ).not.toThrow();
    });
  });
});
