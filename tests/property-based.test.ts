/**
 * EMILIA Protocol — Property-Based Test Suite (Section 2.4)
 *
 * Uses fast-check to verify EP protocol invariants hold across
 * randomly generated inputs. Covers:
 *   - Binding canonicalization stability
 *   - Hash determinism
 *   - Collision resistance per field
 *   - Party set order independence
 *   - State machine terminal/non-terminal partition
 *   - Canonical field coverage
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import crypto from 'crypto';
import {
  buildBindingMaterial,
  canonicalizeBinding,
  hashBinding,
  validateBindingCompleteness,
  computePartySetHash,
  computeContextHash,
  computePayloadHash,
  computePolicyHash,
} from '@/lib/handshake/binding';
import {
  CANONICAL_BINDING_FIELDS,
  BINDING_MATERIAL_VERSION,
  HANDSHAKE_STATUSES,
  ASSURANCE_LEVELS,
} from '@/lib/handshake/invariants';

// ============================================================================
// Generators
// ============================================================================

const arbNonce = fc.stringMatching(/^[0-9a-f]{64}$/);
const arbHash = fc.stringMatching(/^[0-9a-f]{64}$/);
const arbISODate = fc.date({ min: new Date('2020-01-01T00:00:00.000Z'), max: new Date('2030-12-31T23:59:59.999Z') })
  .filter(d => !isNaN(d.getTime()))
  .map(d => d.toISOString());
const arbActionType = fc.constantFrom('connect', 'transact', 'delegate', 'install', null);

const arbBindingMaterial = fc.record({
  action_type: arbActionType,
  resource_ref: fc.option(fc.string({ minLength: 1, maxLength: 100 }), { nil: null }),
  policy_id: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: null }),
  policy_version: fc.option(fc.string({ minLength: 1, maxLength: 20 }), { nil: null }),
  policy_hash: fc.option(arbHash, { nil: null }),
  interaction_id: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: null }),
  party_set_hash: arbHash,
  payload_hash: fc.option(arbHash, { nil: null }),
  context_hash: fc.option(arbHash, { nil: null }),
  nonce: arbNonce,
  expires_at: arbISODate,
});

// ============================================================================
// Binding Property Tests (Section 2.4)
// ============================================================================

describe('Property-Based Tests — Binding Invariants', () => {

  it('canonicalization is stable under key insertion order', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const material = buildBindingMaterial(params);

      // Create same material with keys in reverse order
      const reversed = {};
      const keys = Object.keys(material).reverse();
      for (const k of keys) reversed[k] = material[k];

      expect(canonicalizeBinding(material)).toBe(canonicalizeBinding(reversed));
    }), { numRuns: 200 });
  });

  it('same input always produces same hash (deterministic)', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const material = buildBindingMaterial(params);
      const hash1 = hashBinding(material);
      const hash2 = hashBinding(material);
      expect(hash1).toBe(hash2);
    }), { numRuns: 200 });
  });

  it('different action_type => different hash', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const m1 = buildBindingMaterial({ ...params, action_type: 'connect' });
      const m2 = buildBindingMaterial({ ...params, action_type: 'transact' });
      expect(hashBinding(m1)).not.toBe(hashBinding(m2));
    }), { numRuns: 100 });
  });

  it('different policy_hash => different binding', () => {
    fc.assert(fc.property(arbBindingMaterial, arbHash, arbHash, (params, hash1, hash2) => {
      fc.pre(hash1 !== hash2);
      const m1 = buildBindingMaterial({ ...params, policy_hash: hash1 });
      const m2 = buildBindingMaterial({ ...params, policy_hash: hash2 });
      expect(hashBinding(m1)).not.toBe(hashBinding(m2));
    }), { numRuns: 100 });
  });

  it('different party_set_hash => different binding', () => {
    fc.assert(fc.property(arbBindingMaterial, arbHash, arbHash, (params, psh1, psh2) => {
      fc.pre(psh1 !== psh2);
      const m1 = buildBindingMaterial({ ...params, party_set_hash: psh1 });
      const m2 = buildBindingMaterial({ ...params, party_set_hash: psh2 });
      expect(hashBinding(m1)).not.toBe(hashBinding(m2));
    }), { numRuns: 100 });
  });

  it('different nonce => different binding', () => {
    fc.assert(fc.property(arbBindingMaterial, arbNonce, arbNonce, (params, n1, n2) => {
      fc.pre(n1 !== n2);
      const m1 = buildBindingMaterial({ ...params, nonce: n1 });
      const m2 = buildBindingMaterial({ ...params, nonce: n2 });
      expect(hashBinding(m1)).not.toBe(hashBinding(m2));
    }), { numRuns: 100 });
  });

  it('different resource_ref => different binding', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const m1 = buildBindingMaterial({ ...params, resource_ref: 'target-a' });
      const m2 = buildBindingMaterial({ ...params, resource_ref: 'target-b' });
      expect(hashBinding(m1)).not.toBe(hashBinding(m2));
    }), { numRuns: 100 });
  });

  it('binding material always has exactly CANONICAL_BINDING_FIELDS keys', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const material = buildBindingMaterial(params);
      const keys = Object.keys(material).sort();
      expect(keys).toEqual([...CANONICAL_BINDING_FIELDS].sort());
    }), { numRuns: 200 });
  });

  it('hash output is always 64-char hex string', () => {
    fc.assert(fc.property(arbBindingMaterial, (params) => {
      const hash = hashBinding(buildBindingMaterial(params));
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }), { numRuns: 200 });
  });
});

describe('Property-Based Tests — Hash Canonicalization (nested objects)', () => {
  it('computePayloadHash is stable under nested key insertion order', () => {
    const a = computePayloadHash({ z: 1, nested: { y: 2, x: 3 } });
    const b = computePayloadHash({ nested: { x: 3, y: 2 }, z: 1 });
    expect(a).toBe(b);
  });

  it('computeContextHash is stable under nested key insertion order', () => {
    const a = computeContextHash({ action_type: 'connect', meta: { b: 2, a: 1 } });
    const b = computeContextHash({ meta: { a: 1, b: 2 }, action_type: 'connect' });
    expect(a).toBe(b);
  });

  it('computePolicyHash is stable under nested key insertion order', () => {
    const a = computePolicyHash({ required_parties: { responder: true, initiator: true }, min_assurance: 'high' });
    const b = computePolicyHash({ min_assurance: 'high', required_parties: { initiator: true, responder: true } });
    expect(a).toBe(b);
  });

  it('computePayloadHash detects changes in nested values', () => {
    const a = computePayloadHash({ nested: { key: 'value-a' } });
    const b = computePayloadHash({ nested: { key: 'value-b' } });
    expect(a).not.toBe(b);
  });
});

describe('Property-Based Tests — Party Set Hash', () => {
  const arbParty = fc.record({
    role: fc.constantFrom('initiator', 'responder', 'verifier', 'delegate'),
    entity_ref: fc.string({ minLength: 1, maxLength: 50 }),
  });

  it('party set hash is order-independent', () => {
    fc.assert(fc.property(fc.array(arbParty, { minLength: 2, maxLength: 5 }), (parties) => {
      const hash1 = computePartySetHash(parties);
      const reversed = [...parties].reverse();
      const hash2 = computePartySetHash(reversed);
      expect(hash1).toBe(hash2);
    }), { numRuns: 100 });
  });

  it('different party sets => different hashes', () => {
    fc.assert(fc.property(arbParty, arbParty, (p1, p2) => {
      fc.pre(p1.entity_ref !== p2.entity_ref || p1.role !== p2.role);
      const hash1 = computePartySetHash([p1]);
      const hash2 = computePartySetHash([p2]);
      expect(hash1).not.toBe(hash2);
    }), { numRuns: 100 });
  });
});

describe('Property-Based Tests — State Machine', () => {
  const TERMINAL_STATES = ['revoked', 'expired', 'rejected'];
  const NON_TERMINAL_STATES = ['initiated', 'pending_verification', 'verified'];

  it('terminal states are a strict subset of all statuses', () => {
    for (const s of TERMINAL_STATES) {
      expect(HANDSHAKE_STATUSES).toContain(s);
    }
    for (const s of NON_TERMINAL_STATES) {
      expect(HANDSHAKE_STATUSES).toContain(s);
    }
  });

  it('no status is both terminal and non-terminal', () => {
    const overlap = TERMINAL_STATES.filter(s => NON_TERMINAL_STATES.includes(s));
    expect(overlap).toEqual([]);
  });

  it('terminal and non-terminal together cover all statuses', () => {
    const all = [...TERMINAL_STATES, ...NON_TERMINAL_STATES].sort();
    expect(all).toEqual([...HANDSHAKE_STATUSES].sort());
  });
});

describe('Property-Based Tests — Consumption', () => {
  it('consumption idempotency key is deterministic', () => {
    fc.assert(fc.property(
      fc.string({ minLength: 1 }),
      fc.string({ minLength: 1 }),
      fc.string({ minLength: 1 }),
      (entity, type, ref) => {
        const hash = (input) => crypto.createHash('sha256').update(input).digest('hex');
        const key1 = hash(`${entity}|${type}|${ref}`);
        const key2 = hash(`${entity}|${type}|${ref}`);
        expect(key1).toBe(key2);
      }
    ), { numRuns: 100 });
  });
});
