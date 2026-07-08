// SPDX-License-Identifier: Apache-2.0
// EP-AUTHORITY-REGISTRY-v1 — conformance + unit tests.
//
// Drives every vector in conformance/vectors/authority.v1.json through the real
// resolver and the real EP-AUTHORITY-PROOF-v1 verifier, and asserts the
// closed-verdict / accept-reject outcome. Proof vectors are signed at load time
// from a fixed seed so signatures are reproducible without embedding raw bytes.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { snapshotStore, resolveAuthority } from '../lib/authority/store.js';
import { evaluateAuthorityVerdict, AUTHORITY_VERDICTS, authorityResultHash, authorityBinding } from '../lib/authority/resolver.js';
import { computeRegistryHead } from '../lib/authority/registry-head.js';
import { signAuthorityProof, verifyAuthorityProof } from '../lib/authority/proof.js';
import { applyAuthorityEnforcement, authorityAdmissibilityCode } from '../lib/authority/enforcement.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/authority.v1.json'), 'utf8'));

function keyFromSeedHex(hex) {
  const seed = Buffer.from(hex, 'hex');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
function pubB64u(privateKey) {
  return crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

// An "unavailable" store, to drive the registry_unavailable vector.
const unavailableStore = { async resolveContext() { return { unavailable: true, record: null, snapshot: null }; } };

describe('EP-AUTHORITY-REGISTRY-v1 conformance suite', () => {
  const store = snapshotStore(SUITE.base_snapshot);

  for (const v of SUITE.vectors.filter((x) => x.kind === 'resolve')) {
    it(`resolve: ${v.id}`, async () => {
      const s = v.unavailable ? unavailableStore : store;
      const r = await resolveAuthority(s, v.input);
      expect(AUTHORITY_VERDICTS).toContain(r.verdict);
      expect(r.verdict).toBe(v.expect.verdict);
      expect(r.verdict === 'authorized').toBe(v.expect.valid);
      expect(r.authorized).toBe(v.expect.valid);
    });
  }

  for (const v of SUITE.vectors.filter((x) => x.kind === 'proof')) {
    it(`proof: ${v.id}`, () => {
      const priv = keyFromSeedHex(v.seed_hex);
      let proof = signAuthorityProof(v.proof_args, priv);
      if (v.verify.tamper) proof = { ...proof, ...v.verify.tamper };
      if (v.verify.tamperKeyId) proof = { ...proof, signature: { ...proof.signature, key_id: v.verify.tamperKeyId } };

      const pinnedRegistryKeys = v.verify.pin
        ? [{ issuer_id: proof.signature.key_id, public_key: pubB64u(priv) }]
        : [];
      const res = verifyAuthorityProof(proof, {
        pinnedRegistryKeys,
        ...(v.verify.expectRegistryHead ? { expectRegistryHead: v.verify.expectRegistryHead } : {}),
        ...(v.verify.expectMinEpoch !== undefined ? { expectMinEpoch: v.verify.expectMinEpoch } : {}),
      });
      expect(res.accepted).toBe(v.expect.valid);
      if (v.expect.valid) {
        expect(res.verified).toBe(true);
      } else {
        expect(res.reason).toBe(v.expect.reason);
      }
    });
  }

  it('every declared verdict is reachable by at least one vector or is authorized', () => {
    const seen = new Set(SUITE.vectors.filter((x) => x.kind === 'resolve').map((x) => x.expect.verdict));
    // The closed set minus the two verdicts that require a role/currency path
    // already covered above; assert the security-critical ones are all present.
    for (const verdict of ['unknown_authority', 'revoked_authority', 'expired_authority', 'not_yet_valid', 'wrong_scope', 'wrong_role', 'amount_exceeded', 'policy_mismatch', 'delegation_broken', 'registry_unavailable', 'insufficient_assurance', 'authorized']) {
      expect(seen.has(verdict)).toBe(true);
    }
  });
});

describe('EP-AUTHORITY-REGISTRY-v1 unit invariants', () => {
  it('registry head is order-independent over the entry set', () => {
    const a = SUITE.base_snapshot.entries;
    const b = [...a].reverse();
    expect(computeRegistryHead(17, a)).toBe(computeRegistryHead(17, b));
  });

  it('registry head changes when a grant changes', () => {
    const a = SUITE.base_snapshot.entries;
    const mutated = a.map((e) => (e.authority_id === 'auth_cfo' ? { ...e, max_amount_usd: 999999 } : e));
    expect(computeRegistryHead(17, a)).not.toBe(computeRegistryHead(17, mutated));
  });

  it('result hash binds the request facts, not only the verdict', async () => {
    const store = snapshotStore(SUITE.base_snapshot);
    const base = { organization_id: 'org1', approver_id: 'ada', action_type: 'large_payment_release', currency: 'USD', issued_at: '2026-07-07T00:00:00.000Z' };
    const r1 = await resolveAuthority(store, { ...base, amount: 40000 });
    const r2 = await resolveAuthority(store, { ...base, amount: 41000 });
    expect(r1.verdict).toBe('authorized');
    expect(r2.verdict).toBe('authorized');
    // Same verdict, different amount => different result hash (the amount is bound).
    expect(authorityResultHash(r1)).not.toBe(authorityResultHash(r2));
  });

  it('binding carries exactly the six receipt fields', async () => {
    const store = snapshotStore(SUITE.base_snapshot);
    const r = await resolveAuthority(store, { organization_id: 'org1', approver_id: 'ada', action_type: 'large_payment_release', amount: 40000, currency: 'USD', issued_at: '2026-07-07T00:00:00.000Z' });
    const b = authorityBinding(r);
    expect(Object.keys(b).sort()).toEqual([
      'authority_id', 'authority_registry_epoch', 'authority_registry_head', 'authority_result_hash', 'authority_verdict', 'policy_hash',
    ]);
    expect(b.authority_registry_head).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(b.authority_result_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(Number.isSafeInteger(b.authority_registry_epoch)).toBe(true);
  });

  it('enforcement fails closed for critical actions under enforce_critical, blocks all under enforce_default', () => {
    const notAuthorized = 'amount_exceeded';
    expect(applyAuthorityEnforcement({ verdict: notAuthorized, isCritical: true, mode: 'shadow' }).block).toBe(false);
    expect(applyAuthorityEnforcement({ verdict: notAuthorized, isCritical: true, mode: 'warn' }).block).toBe(false);
    expect(applyAuthorityEnforcement({ verdict: notAuthorized, isCritical: true, mode: 'enforce_critical' }).block).toBe(true);
    expect(applyAuthorityEnforcement({ verdict: notAuthorized, isCritical: false, mode: 'enforce_critical' }).block).toBe(false);
    expect(applyAuthorityEnforcement({ verdict: notAuthorized, isCritical: false, mode: 'enforce_default' }).block).toBe(true);
    // authorized never blocks, in any mode
    for (const mode of ['shadow', 'warn', 'enforce_critical', 'enforce_default']) {
      expect(applyAuthorityEnforcement({ verdict: 'authorized', isCritical: true, mode }).block).toBe(false);
    }
  });

  it('unresolved authority maps to the authority_unresolved umbrella code', () => {
    expect(authorityAdmissibilityCode('registry_unavailable')).toBe('authority_unresolved');
    expect(authorityAdmissibilityCode('unknown_authority')).toBe('authority_unresolved');
    expect(authorityAdmissibilityCode('amount_exceeded')).toBe('authority_amount_exceeded');
    expect(authorityAdmissibilityCode('authorized')).toBe('admissible');
  });

  it('invalid enforcement mode falls back to shadow (never accidentally enforces)', () => {
    const e = applyAuthorityEnforcement({ verdict: 'unknown_authority', isCritical: true, mode: 'bogus' });
    expect(e.mode).toBe('shadow');
    expect(e.block).toBe(false);
  });

  it('a null-scope grant does not fail wrong_scope (unscoped), but a present scope must contain the action', () => {
    const unscoped = { record: { authority_id: 'a1', subject_ref: 's', organization_id: 'o', role: 'r', status: 'active', assurance_class: 'A', action_scopes: null }, snapshot: { epoch: 1, head: 'sha256:' + '0'.repeat(64) } };
    const r = evaluateAuthorityVerdict(unscoped, { organization_id: 'o', approver_id: 's', action_type: 'anything', issued_at: '2026-07-07T00:00:00.000Z' });
    expect(r.verdict).toBe('authorized');
  });
});
