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
import { evaluateAuthorityVerdict, AUTHORITY_VERDICTS, authorityResultHash, authorityBinding, normalizeAuthorityRecord } from '../lib/authority/resolver.js';
import { computeRegistryHead } from '../lib/authority/registry-head.js';
import { signAuthorityProof, verifyAuthorityProof } from '../lib/authority/proof.js';
import { applyAuthorityEnforcement, authorityAdmissibilityCode } from '../lib/authority/enforcement.js';
import { canonicalize } from '../lib/canonical-json.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/authority.v1.json'), 'utf8'));
const COMPLETE_RESULT_DIGESTS = Object.freeze({
  authorized_within_scope_and_limit: '77761fbb35d71604a7d5cceb3654bfe385972608aee81031bf810c9614d52459',
  reject_amount_exceeded: '1a26c1d10b15a691943573c845d8562e414fd6a0620e7bca7d2fab40880de8cf',
  reject_currency_mismatch: 'd622c695b9565d03b1c371aa631cfd093cb623d888afbb0121b607281088f728',
  reject_wrong_scope: '5d954b16c5258b9e5faeb9944af47264b8a2c296c95886bf19e9284d28062893',
  reject_wrong_role: '09d307b19c1cd261ff735dd1c30bd972847df149a2c31ea6efcd6e40fe30ee4f',
  reject_unknown_authority: '8746818c36c3d83013f5b4eb7679727e8bd746ff416bf9b0ef3a51ad3d8b16c9',
  reject_revoked_authority: '93bc5b09857497b1497de7b02e3b7dee1b92e15f33fdea6bbebadc361712888e',
  reject_expired_authority: 'aff52fb751d551b8ef956e88230b85900a8145ce0f72badb0b87f00a7d17297a',
  reject_not_yet_valid: '860eba870eea5d69bdad3e29f16a903767ae4d29afa9a61a5964ef6e54b74667',
  reject_policy_mismatch: '9c08139ade209eaec7aed981c6c39795b6ba255130794aa81339563f207d1828',
  reject_delegation_widened_amount: '974a0f61449c72cca56d11f02d89bc83bc1d68d382e74e7d1fd5510683908eb9',
  reject_delegation_parent_missing: '7917b81d104e12937c68f7f43fc76116a6a3448b868b8e579bb2bee40b6f1cd8',
  reject_insufficient_assurance: '844676cbc02a372a01bd592ae0a6791a22f6763af02c44c62eb1660139530c33',
  reject_policy_omitted: '09e477cbbd3357a19ee46f6d39ccd645577450ee0b21817df5fc4b80b78977d0',
  reject_capped_amount_omitted: '64e911605c8f6fad7b7ba642b3737ffdfc8a3c1173d03df8dee532947e02f1c8',
  reject_capped_currency_omitted: 'e35aff9b69bb3bff26f0717460155846693c88d8f9ebff2e7460da1cbede7b68',
  reject_malformed_issued_at: 'b774fef09a2c4b26ba6b6baa243e57236ce8919176241b7fb0b5ce310f2695da',
  reject_impossible_calendar_date: 'bf846fb6b15c97e8423958b1ec411b66fff3bc831f01debebc3095dbff879aef',
  reject_unknown_assurance_label: '1f91e6b55be9d28ad267a8012a3bc9b4f1a35c2651e20bd99f6d1395b8dca9a6',
  reject_registry_unavailable: '2e50aba2187b40466a59db11c2548e545e308e84419007728dbd169da673fd77',
  reject_stale_registry: 'ce36cab7a58887bb480e4ee0d139a9c143a85cc2dd3eedbbe53fa7b4d9640b46',
  proof_accepted_when_pinned: 'a9f64e8d766bf15d9a367722683a9f8573fc90ebaf69302dc8f416c03ca8df36',
  reject_proof_unpinned_key: '75c1017fd5d55710afc1b191364da0490066e8a3df1325d1717d0dd5954476c1',
  reject_proof_tampered_role: 'bbd3599e3b2898e1b37e54dd2591a771fb22df77cac5857513f28ca92350c5db',
  reject_proof_registry_head_mismatch: '3bf462f69cd4ee1ebf36ccfee53ec42deeea6c7428604c3070e33b12f13139e3',
  reject_proof_stale_epoch: '65d39a7340106f6a8ac1bf4b6d3dbc0d50d0897af4c40097cb58d3257903d7b7',
  reject_proof_forged_key_id: '4e1cc9a0dc410ed9ed0d2a8ecab512cd9dbb0605038cd1fba4273074bc090e70',
});

function keyFromSeedHex(hex) {
  const seed = Buffer.from(hex, 'hex');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
function pubB64u(privateKey) {
  return crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}
const resultDigest = (value) => crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');

function runProofVector(v) {
  const priv = keyFromSeedHex(v.seed_hex);
  let proof = signAuthorityProof(v.proof_args, priv);
  if (v.verify.tamper) proof = { ...proof, ...v.verify.tamper };
  if (v.verify.tamperKeyId) proof = { ...proof, signature: { ...proof.signature, key_id: v.verify.tamperKeyId } };
  const pinnedRegistryKeys = v.verify.pin
    ? [{ issuer_id: proof.authority_id, public_key: pubB64u(priv) }]
    : [];
  return verifyAuthorityProof(proof, {
    pinnedRegistryKeys,
    ...(v.verify.expectRegistryHead ? { expectRegistryHead: v.verify.expectRegistryHead } : {}),
    ...(v.verify.expectMinEpoch !== undefined ? { expectMinEpoch: v.verify.expectMinEpoch } : {}),
  });
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
      const res = runProofVector(v);
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

  it('pins the complete resolver and proof result for every vector', async () => {
    const store = snapshotStore(SUITE.base_snapshot);
    const digests = {};
    for (const v of SUITE.vectors) {
      const result = v.kind === 'resolve'
        ? await resolveAuthority(v.unavailable ? unavailableStore : store, v.input)
        : runProofVector(v);
      digests[v.id] = resultDigest(result);
    }
    expect(digests).toEqual(COMPLETE_RESULT_DIGESTS);
  });
});

describe('EP-AUTHORITY-REGISTRY-v1 unit invariants', () => {
  it('does not let a key pinned for one issuer authenticate another issuer', () => {
    const priv = keyFromSeedHex('d4'.repeat(32));
    const proof = signAuthorityProof({
      authority_id: 'auth_cfo',
      subject: 'ep:approver:cfo',
      role: 'cfo',
      scope: ['wire.release'],
      registry_head: `sha256:${'11'.repeat(32)}`,
      registry_epoch: 1,
      issued_at: '2026-07-07T00:00:00.000Z',
    }, priv);
    const result = verifyAuthorityProof(proof, {
      pinnedRegistryKeys: [{ issuer_id: 'auth_other', public_key: pubB64u(priv) }],
    });

    expect(result.verified).toBe(false);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('pin_mismatched_issuer');
  });

  it('does not let a key-only pin establish registry identity', () => {
    const priv = keyFromSeedHex('d5'.repeat(32));
    const proof = signAuthorityProof({
      authority_id: 'auth_cfo',
      subject: 'ep:approver:cfo',
      role: 'cfo',
      scope: ['wire.release'],
      registry_head: `sha256:${'11'.repeat(32)}`,
      registry_epoch: 1,
      issued_at: '2026-07-07T00:00:00.000Z',
    }, priv);
    const result = verifyAuthorityProof(proof, {
      pinnedRegistryKeys: [{ public_key: pubB64u(priv) }],
    });

    expect(result.verified).toBe(false);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('pin_mismatched_issuer');
  });

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

  it('joins the resolved grant back to the requested subject and organization', () => {
    const record = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
    };
    const ctx = { record, snapshot: { epoch: 1, head: 'sha256:' + '0'.repeat(64) } };
    const input = { organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release', issued_at: '2026-07-07T00:00:00.000Z' };
    expect(evaluateAuthorityVerdict(ctx, { ...input, approver_id: 'mallory' }).verdict).toBe('unknown_authority');
    expect(evaluateAuthorityVerdict(ctx, { ...input, organization_id: 'org-b' }).verdict).toBe('unknown_authority');
  });

  it('does not fall back to a cached snapshot when the authority store reports unavailable', () => {
    const record = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
    };
    const result = evaluateAuthorityVerdict(
      { unavailable: true, record, snapshot: { epoch: 99, head: 'sha256:' + '9'.repeat(64) } },
      { organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release', issued_at: '2026-07-07T00:00:00.000Z' },
    );
    expect(result.verdict).toBe('registry_unavailable');
    expect(result.authorized).toBe(false);
    expect(result.registry_epoch).toBe(null);
    expect(result.registry_head).toBe(null);
  });

  it('refuses non-active status and malformed grant validity even under a fresh snapshot', () => {
    const baseRecord = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
    };
    const snapshot = { epoch: 1, head: 'sha256:' + '0'.repeat(64) };
    const input = { organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release', issued_at: '2026-07-07T00:00:00.000Z' };
    expect(evaluateAuthorityVerdict({ record: { ...baseRecord, status: 'suspended' }, snapshot }, input).verdict).toBe('revoked_authority');
    expect(evaluateAuthorityVerdict({ record: { ...baseRecord, valid_to: '2026-02-30T00:00:00.000Z' }, snapshot }, input).verdict).toBe('expired_authority');
  });

  it('fails closed on an omitted policy, amount, currency, or malformed time', () => {
    const record = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 50000, currency: 'USD', policy_hash: 'sha256:policy-a',
      valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
    };
    const ctx = { record, snapshot: { epoch: 1, head: 'sha256:' + '0'.repeat(64) } };
    const input = {
      organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release',
      amount: 50000, currency: 'USD', policy_hash: 'sha256:policy-a',
      issued_at: '2026-07-07T00:00:00.000Z', requiredAssurance: 'A',
    };
    expect(evaluateAuthorityVerdict(ctx, { ...input, policy_hash: undefined }).verdict).toBe('policy_mismatch');
    expect(evaluateAuthorityVerdict(ctx, { ...input, amount: undefined }).verdict).toBe('amount_exceeded');
    expect(evaluateAuthorityVerdict(ctx, { ...input, currency: undefined }).verdict).toBe('amount_exceeded');
    expect(evaluateAuthorityVerdict(ctx, { ...input, issued_at: 'not-a-time' }).verdict).toBe('expired_authority');
  });

  it('refuses unknown assurance labels and accepts exact amount/time boundaries', () => {
    const record = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 50000, currency: 'USD',
      valid_from: '2026-07-07T00:00:00.000Z', valid_to: '2026-07-07T00:00:00.000Z',
    };
    const ctx = { record, snapshot: { epoch: 1, head: 'sha256:' + '0'.repeat(64) } };
    const input = {
      organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release',
      amount: 50000, currency: 'USD', issued_at: '2026-07-07T00:00:00.000Z',
    };
    expect(evaluateAuthorityVerdict(ctx, { ...input, requiredAssurance: 'CLASS_A' }).verdict).toBe('insufficient_assurance');
    const accepted = evaluateAuthorityVerdict(ctx, { ...input, requiredAssurance: 'A' });
    expect(accepted).toMatchObject({
      action_type: 'wire.release', amount: 50000, currency: 'USD', issued_at: input.issued_at,
      subject_ref: 'alice', registry_epoch: 1, authority_id: 'a1', role: 'cfo',
      scope: ['wire.release'], max_amount_usd: 50000, verdict: 'authorized',
      authorized: true, detail: 'ok', assurance_class: 'A',
    });
  });

  it('delegation cannot widen by omitting scope, ceiling, currency, policy, assurance, lifecycle, or organization', () => {
    const snapshot = { epoch: 1, head: 'sha256:' + '0'.repeat(64) };
    const input = {
      organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release',
      amount: 100, currency: 'USD', policy_hash: 'sha256:policy-a',
      issued_at: '2026-07-07T00:00:00.000Z', requiredAssurance: 'A',
    };
    const parent = {
      authority_id: 'parent', subject_ref: 'director', organization_id: 'org-a',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 1000, currency: 'USD', policy_hash: 'sha256:policy-a',
      valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
    };
    const child = {
      authority_id: 'child', subject_ref: 'alice', organization_id: 'org-a',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 500, currency: 'USD', policy_hash: 'sha256:policy-a',
      valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
      delegation_parent: 'parent',
    };
    const evaluate = (childOverride = {}, parentOverride = {}, resolve = true, inputOverride = {}) => evaluateAuthorityVerdict(
      {
        record: { ...child, ...childOverride }, snapshot,
        resolveParent: resolve ? () => ({ ...parent, ...parentOverride }) : () => null,
      },
      { ...input, ...inputOverride },
    );

    expect(evaluate().verdict).toBe('authorized');
    for (const result of [
      evaluate({ action_scopes: null }),
      evaluate({ action_scopes: ['wire.release', 'admin.delete'] }),
      evaluate({ max_amount_usd: null }),
      evaluate({ max_amount_usd: 1001 }),
      evaluate({ currency: 'EUR' }, {}, true, { currency: 'EUR' }),
      evaluate({ policy_hash: null }),
      evaluate({ assurance_class: 'A' }, { assurance_class: 'B' }),
      evaluate({ assurance_class: 'UNKNOWN' }),
      evaluate({}, { assurance_class: 'UNKNOWN' }),
      evaluate({}, { organization_id: 'org-b' }),
      evaluate({}, { status: 'suspended' }),
      evaluate({}, { revoked_at: '2026-07-01T00:00:00.000Z' }),
      evaluate({}, { max_amount_usd: Number.POSITIVE_INFINITY }),
      evaluate({}, { valid_from: 'not-a-date' }),
      evaluate({}, { valid_to: '2026-02-30T00:00:00.000Z' }),
      evaluate({}, { valid_from: '2026-08-01T00:00:00.000Z' }),
      evaluate({}, { valid_to: '2026-06-01T00:00:00.000Z' }),
      evaluate({}, {}, false),
      evaluate({}, { authority_id: 'child' }),
    ]) {
      expect(result.verdict).toBe('delegation_broken');
      expect(result.authorized).toBe(false);
    }

    expect(evaluate({ max_amount_usd: 1000 }).verdict).toBe('authorized');
  });

  it('fails closed on over-deep delegation and normalizes legacy scalar fields deterministically', () => {
    const normalized = normalizeAuthorityRecord({
      authority_id: 'legacy', subject_ref: 'alice', organization_id: 'org-a',
      scope: 'wire.release', max_amount_usd: '500', currency: null,
    });
    expect(normalized).toMatchObject({
      authority_id: 'legacy', action_scopes: ['wire.release'], max_amount_usd: 500,
      currency: 'USD', status: 'active', delegation_parent: null,
    });
    expect(normalizeAuthorityRecord(null)).toBe(null);

    let depth = 0;
    const result = evaluateAuthorityVerdict({
      record: {
        authority_id: 'leaf', subject_ref: 'alice', organization_id: 'org-a', status: 'active',
        assurance_class: 'A', action_scopes: ['wire.release'], max_amount_usd: 100,
        currency: 'USD', delegation_parent: 'p0',
      },
      resolveParent: () => {
        const id = `p${depth++}`;
        return {
          authority_id: id, subject_ref: id, organization_id: 'org-a', status: 'active',
          assurance_class: 'A', action_scopes: ['wire.release'], max_amount_usd: 100,
          currency: 'USD', delegation_parent: `p${depth}`,
        };
      },
      snapshot: { epoch: 1, head: 'sha256:' + '0'.repeat(64) },
    }, {
      organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release',
      amount: 1, currency: 'USD', issued_at: '2026-07-07T00:00:00.000Z',
    });
    expect(result.verdict).toBe('delegation_broken');
    expect(result.detail).toBe('delegation_too_deep');
  });

  it('strictly validates authority instants, leap years, offsets, epoch, and zero boundaries', () => {
    const record = {
      authority_id: 'a1', subject_ref: 'alice', organization_id: 'org-a', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 0, currency: 'USD',
    };
    const ctx = { record, snapshot: { epoch: 7, head: 'sha256:' + '0'.repeat(64) } };
    const base = {
      organization_id: 'org-a', approver_id: 'alice', action_type: 'wire.release',
      amount: 0, currency: 'USD', expected_min_epoch: 7, requiredAssurance: 'A',
    };
    for (const issued_at of [
      null, 0, [], {}, '2026-00-01T00:00:00Z', '2026-13-01T00:00:00Z',
      '2026-01-00T00:00:00Z', '2026-04-31T00:00:00Z', '1900-02-29T00:00:00Z',
      '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z', '2026-01-01T00:00:60Z',
      '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60',
      '2026-01-01T00:00:00',
    ]) {
      expect(evaluateAuthorityVerdict(ctx, { ...base, issued_at }).verdict).toBe('expired_authority');
    }
    for (const issued_at of ['2000-02-29T00:00:00Z', '2024-02-29T23:59:59+23:59']) {
      expect(evaluateAuthorityVerdict(ctx, { ...base, issued_at }).verdict).toBe('authorized');
    }
    expect(evaluateAuthorityVerdict(ctx, { ...base, issued_at: '2026-01-01T00:00:00Z', expected_min_epoch: 8 }).verdict).toBe('registry_unavailable');
    expect(evaluateAuthorityVerdict(ctx, { ...base, issued_at: '2026-01-01T00:00:00Z', amount: -1 }).verdict).toBe('amount_exceeded');
  });
});
