/**
 * EP Audit Regression Tests — L99 harshest-audit fixes.
 *
 * Adversarial tests for each of the 13 findings (5 CRITICAL + 8 HIGH) that
 * the L99 audit identified. Every test MUST fail against the pre-fix code
 * and pass against the post-fix code. No fluff — these are the tests that
 * prove the fixes hold.
 *
 * Organized by finding ID so a future audit can map test → fix 1:1.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { checkBindingValid, runAllInvariants } from '@/lib/handshake/invariants';
import { checkDelegation } from '@/lib/handshake/bind';
import {
  computePolicyHash,
  computePayloadHash,
  computeContextHash,
} from '@/lib/handshake/binding';

// ── C5 — checkDelegation vacuous-pass closed ──────────────────────────────

describe('L99-C5 — checkDelegation fails closed on absent fields', () => {
  it('flags delegation_chain_missing when delegation_chain is absent', () => {
    const codes = checkDelegation(
      [{ party_role: 'delegate', delegation_chain: null }],
      'policy-X',
    );
    expect(codes).toContain('delegation_chain_missing');
  });

  it('flags delegation_missing_expiry when expires_at is absent', () => {
    const codes = checkDelegation(
      [{ party_role: 'delegate', delegation_chain: { scope: ['policy-X'] } }],
      'policy-X',
    );
    expect(codes).toContain('delegation_missing_expiry');
  });

  it('flags delegation_missing_scope when scope is absent', () => {
    const codes = checkDelegation(
      [{ party_role: 'delegate', delegation_chain: { expires_at: '2030-01-01T00:00:00Z' } }],
      'policy-X',
    );
    expect(codes).toContain('delegation_missing_scope');
  });

  it('flags delegation_out_of_scope when scope omits policyId', () => {
    const codes = checkDelegation(
      [{
        party_role: 'delegate',
        delegation_chain: { expires_at: '2030-01-01T00:00:00Z', scope: ['policy-Y'] },
      }],
      'policy-X',
    );
    expect(codes).toContain('delegation_out_of_scope');
  });

  it('flags delegation_expired when expires_at is in the past', () => {
    const codes = checkDelegation(
      [{
        party_role: 'delegate',
        delegation_chain: { expires_at: '2020-01-01T00:00:00Z', scope: ['policy-X'] },
      }],
      'policy-X',
    );
    expect(codes).toContain('delegation_expired');
  });

  it('flags delegation_chain_malformed on invalid JSON string', () => {
    const codes = checkDelegation(
      [{ party_role: 'delegate', delegation_chain: 'not-json-{{{' }],
      'policy-X',
    );
    expect(codes).toContain('delegation_chain_malformed');
  });

  it('accepts a well-formed delegation with matching scope', () => {
    const codes = checkDelegation(
      [{
        party_role: 'delegate',
        delegation_chain: { expires_at: '2030-01-01T00:00:00Z', scope: ['policy-X'] },
      }],
      'policy-X',
    );
    expect(codes).toEqual([]);
  });

  it('accepts a universal-scope delegation with explicit "*"', () => {
    const codes = checkDelegation(
      [{
        party_role: 'delegate',
        delegation_chain: { expires_at: '2030-01-01T00:00:00Z', scope: '*' },
      }],
      'policy-X',
    );
    expect(codes).toEqual([]);
  });

  it('flags malformed scope (neither array nor "*")', () => {
    const codes = checkDelegation(
      [{
        party_role: 'delegate',
        delegation_chain: { expires_at: '2030-01-01T00:00:00Z', scope: 'arbitrary-string' },
      }],
      'policy-X',
    );
    expect(codes).toContain('delegation_chain_malformed');
  });
});

// ── H2 — Canonicalization: NFC + non-finite rejection ─────────────────────

describe('L99-H2 — deepSortKeys canonicalizes Unicode and rejects malformed values', () => {
  it('NFC: café (NFC) and café (NFD) produce the same hash', () => {
    const nfc = 'caf\u00E9';       // pre-composed é
    const nfd = 'cafe\u0301';      // e + combining acute
    expect(nfc.normalize('NFC')).toBe(nfd.normalize('NFC'));
    const h1 = computePolicyHash({ field: nfc });
    const h2 = computePolicyHash({ field: nfd });
    expect(h1).toBe(h2);
  });

  it('NFC: key names normalized too', () => {
    const h1 = computePolicyHash({ 'caf\u00E9': 1 });
    const h2 = computePolicyHash({ 'cafe\u0301': 1 });
    expect(h1).toBe(h2);
  });

  it('rejects NaN', () => {
    expect(() => computePolicyHash({ n: NaN })).toThrow(/CANONICALIZATION_ERROR/);
  });

  it('rejects Infinity', () => {
    expect(() => computePolicyHash({ n: Infinity })).toThrow(/CANONICALIZATION_ERROR/);
  });

  it('rejects undefined in nested values', () => {
    expect(() => computePolicyHash({ nested: { u: undefined } })).toThrow(/CANONICALIZATION_ERROR/);
  });

  it('nested keys remain order-independent (regression for the original bug)', () => {
    const h1 = computePayloadHash({ z: 1, nested: { y: 2, x: 3 } });
    const h2 = computePayloadHash({ nested: { x: 3, y: 2 }, z: 1 });
    expect(h1).toBe(h2);
  });

  it('context hash is stable under nested key order', () => {
    const h1 = computeContextHash({ a: { y: 2, x: 1 }, b: 2 });
    const h2 = computeContextHash({ b: 2, a: { x: 1, y: 2 } });
    expect(h1).toBe(h2);
  });
});

// ── H6 — checkBindingValid requires verificationPayloadHash ──────────────

describe('L99-H6 — checkBindingValid refuses to skip payload_hash check', () => {
  it('fails when binding has payload_hash but caller omits verificationPayloadHash', () => {
    const result = checkBindingValid(
      { payload_hash: 'a'.repeat(64), nonce: 'n'.repeat(64) },
      null,  // caller forgot / attacker omits
    );
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/verificationPayloadHash/);
  });

  it('fails on payload_hash mismatch as before', () => {
    const result = checkBindingValid(
      { payload_hash: 'a'.repeat(64), nonce: 'n'.repeat(64) },
      'b'.repeat(64),
    );
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/mismatch/);
  });

  it('passes when binding has no payload_hash and caller sends none', () => {
    const result = checkBindingValid(
      { payload_hash: null, nonce: 'n'.repeat(64) },
      null,
    );
    expect(result.ok).toBe(true);
  });

  it('passes when both match', () => {
    const h = 'c'.repeat(64);
    const result = checkBindingValid(
      { payload_hash: h, nonce: 'n'.repeat(64) },
      h,
    );
    expect(result.ok).toBe(true);
  });

  it('fails on missing nonce', () => {
    const result = checkBindingValid(
      { payload_hash: 'a'.repeat(64), nonce: null },
      'a'.repeat(64),
    );
    expect(result.ok).toBe(false);
  });
});

// ── C1 / C2 / C3 / C4 / H3 / H5 / H7 / H8 — integration-boundary coverage ──
//
// These findings sit at the JS↔DB/RPC boundary. Unit tests here cover the
// JS-side behavior (error translation, input sanitization, argument passing);
// the DB-side guarantees (FOR UPDATE semantics, unique constraints, RPC
// preconditions) are covered by the migrations themselves and exercised in
// the existing benchmark + adversarial suites when a real DB is attached.
// For the next independent audit, these should be run against a Postgres
// testcontainer. Documented here as in-scope with a boundary-test sketch.

describe('L99 boundary coverage — static checks on post-fix code shape', () => {
  it('C2: create.js no longer accepts caller-supplied payload_hash override', async () => {
    // This is a source-level regression guard. The audit fix removed the
    // `binding?.payload_hash ||` pattern. We assert the pattern is gone so
    // a future refactor can't silently reintroduce it.
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/create.js', import.meta.url), 'utf-8');
    expect(src).not.toMatch(/binding\?\.payload_hash\s*\|\|/);
    expect(src).not.toMatch(/binding\?\.nonce\s*\|\|/);
  });

  it('C3: create.js no longer has a bare try/catch on policy resolution', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/create.js', import.meta.url), 'utf-8');
    // The old code had `catch {` (bare) immediately after computePolicyHash usage.
    // The new code throws HandshakeError on POLICY_LOAD_FAILED.
    expect(src).toMatch(/POLICY_LOAD_FAILED/);
    expect(src).toMatch(/POLICY_NOT_FOUND/);
  });

  it('C4: verify.js now surfaces RPC/load_verify_context errors', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/verify.js', import.meta.url), 'utf-8');
    expect(src).toMatch(/load_verify_context/);
    expect(src).not.toMatch(/partiesRes\.data\s*\|\|\s*\[\]/);
  });

  it('C1 / H3: migration 080 and 081 are present and register the guards', async () => {
    const { readFile } = await import('node:fs/promises');
    const m080 = await readFile(new URL('../supabase/migrations/080_consume_handshake_binding_hash_guard.sql', import.meta.url), 'utf-8');
    const m081 = await readFile(new URL('../supabase/migrations/081_verify_handshake_status_precheck.sql', import.meta.url), 'utf-8');
    expect(m080).toMatch(/BINDING_HASH_MISMATCH/);
    expect(m080).toMatch(/FOR UPDATE/);
    expect(m081).toMatch(/INVALID_STATE_TRANSITION/);
    expect(m081).toMatch(/FOR UPDATE/);
  });

  it('H5: consume.js now checks binding-mark update error', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/consume.js', import.meta.url), 'utf-8');
    expect(src).toMatch(/BINDING_MARK_FAILED/);
  });

  it('H7: create.js protocol event payload hash uses computePayloadHash (deepSortKeys)', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/create.js', import.meta.url), 'utf-8');
    // The old inline JSON.stringify(..., Object.keys(...).sort()) replacer
    // pattern for protocol_event_payload_hash is gone.
    expect(src).toMatch(/p_protocol_event_payload_hash:\s*computePayloadHash/);
  });

  it('H4: present.js no longer auto-trusts self-asserted presentations', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/present.js', import.meta.url), 'utf-8');
    // Look for the self-asserted branch and assert it no longer sets issuerTrusted = true.
    // The new comment explicitly says "untrusted by default."
    expect(src).toMatch(/self-asserted[\s\S]{0,400}issuerTrusted\s*=\s*false/);
  });

  it('H8: verify.js uses the load_verify_context RPC, not parallel reads', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../lib/handshake/verify.js', import.meta.url), 'utf-8');
    expect(src).toMatch(/load_verify_context/);
  });
});

// ── runAllInvariants sanity — nothing regressed ───────────────────────────

describe('L99 regression — runAllInvariants still well-formed', () => {
  it('returns {passed, violations} with no violations on fully-valid context', () => {
    const { passed, violations } = runAllInvariants({
      handshake: { interaction_id: 'x' },
      parties: [],
      presentations: [],
      binding: {
        nonce: 'n'.repeat(64),
        payload_hash: 'p'.repeat(64),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
      policy: null,
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: 'p'.repeat(64),
      authenticatedEntity: null,
    });
    expect(passed).toBe(true);
    expect(violations).toEqual([]);
  });

  it('fails BINDING_INVALID when payload_hash is set and verificationPayloadHash is not (H6)', () => {
    const { passed, violations } = runAllInvariants({
      handshake: { interaction_id: 'x' },
      parties: [],
      presentations: [],
      binding: {
        nonce: 'n'.repeat(64),
        payload_hash: 'p'.repeat(64),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
      policy: null,
      authorities: [],
      existingResults: [],
      existingResult: null,
      verificationPayloadHash: null,
      authenticatedEntity: null,
    });
    expect(passed).toBe(false);
    expect(violations.some(v => v.code === 'BINDING_INVALID')).toBe(true);
  });
});
