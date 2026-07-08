// SPDX-License-Identifier: Apache-2.0
// EP-RELIANCE-KERNEL-v1 — conformance + unit tests.
//
// Assembles a fully-valid reliance packet (valid trust receipt with a Class-A
// device signoff + a portable authority proof + fresh revocation + an
// unconsumed gate), then drives conformance/vectors/reliance.v1.json: each
// vector names a `break` applied to the base packet, and we assert the closed
// reliance verdict. Signatures are live (reproduced in-process), never embedded.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { evaluateReliance, RELIANCE_VERDICTS } from '../packages/verify/reliance.js';
import { signAuthorityProof } from '../lib/authority/proof.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/reliance.v1.json'), 'utf8'));

// ── canonicalization + hashing (byte-identical to the verifier) ──────────────
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafHashV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(p, 'utf8')])).digest('hex');
const hashPairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function p256() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function keyFromSeedHex(hex) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(hex, 'hex')]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

const logKey = ed25519();
const approverB = ed25519();
const approverB2 = ed25519();
const approverA = p256();
const registryKey = keyFromSeedHex('c1'.repeat(32));
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');

function signBWith(priv, digestHex) {
  return crypto.sign(null, Buffer.from(digestHex, 'hex'), priv).toString('base64url');
}
function signA(digestHex, { rpId = 'www.emiliaprotocol.ai', flags = 0x05 } = {}) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, approverA.privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}

// Build a valid trust receipt. classAForCfo=false makes both signoffs Class-B.
function buildReceipt({ classAForCfo = true } = {}) {
  const action = {
    ep_version: '1.0', action_type: 'wire.release',
    target: { system: 'treasury.example', resource: 'wire/8841' },
    parameters: { amount: '50000.00', currency: 'USD' },
    initiator: 'ep:entity:agent-recon-7', policy_id: 'ep:policy:wires-over-100k@v12',
    requested_at: '2026-06-09T17:21:04Z',
  };
  const action_hash = `sha256:${sha256hex(canonicalize(action))}`;
  const baseCtx = {
    ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash,
    policy_id: 'ep:policy:wires-over-100k@v12', policy_hash: 'sha256:77ab1234',
    initiator: action.initiator, required_approvals: 2,
    issued_at: '2026-06-09T17:21:05Z', expires_at: '2026-06-09T17:36:05Z',
  };
  const ctx1 = { ...baseCtx, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1' };
  const ctx2 = { ...baseCtx, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2' };
  const d1 = sha256hex(canonicalize(ctx1));
  const d2 = sha256hex(canonicalize(ctx2));
  const signoffs = classAForCfo
    ? [
      { context_hash: `sha256:${d1}`, signature: signBWith(approverB.privateKey, d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
      { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
    ]
    : [
      { context_hash: `sha256:${d1}`, signature: signBWith(approverB.privateKey, d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
      { context_hash: `sha256:${d2}`, signature: signBWith(approverB2.privateKey, d2), key_class: 'B', approver_key_id: 'ep:key:controller#2', signed_at: '2026-06-09T17:25:01Z' },
    ];
  const receipt = { receipt_id: 'ep:receipt:01JTEST', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: '2026-06-09T17:25:02Z' } };
  const leaf = leafHashV2(canonicalize(receipt));
  const sibling1 = sha256hex('other-leaf-1');
  const sibling2 = sha256hex('other-subtree');
  const root = hashPairV2(hashPairV2(leaf, sibling1), sibling2);
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sibling1, position: 'right' }, { hash: sibling2, position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

const KEYS = {
  'ep:key:controller#1': { public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:controller#2': { public_key: approverB2.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};

const NOW = Date.parse('2026-07-07T00:00:00.000Z');

function baseAuthorityProofArgs(receipt) {
  return {
    authority_id: 'auth_cfo', subject: 'ep:approver:mrios-cfo', organization_id: 'acme', role: 'cfo',
    scope: ['wire.release'], limits: { max_amount_usd: 50000, currency: 'USD' },
    validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
    revocation: { status: 'not_revoked', checked_at: '2026-07-06T23:59:00.000Z' },
    registry_head: 'sha256:' + '11'.repeat(32), registry_epoch: 17, policy_hash: 'sha256:77ab1234',
    issued_at: '2026-07-06T23:59:00.000Z',
  };
}

// Assemble a packet + apply a break, return { input, opts }.
function assemble(brk) {
  const receipt = buildReceipt({ classAForCfo: brk !== 'class_b_only' });
  const opts = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai' };
  const action = { action_type: 'wire.release', amount: 50000, currency: 'USD', policy_hash: 'sha256:77ab1234', action_hash: receipt.action_hash };
  let proofArgs = baseAuthorityProofArgs(receipt);
  const profile = {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    required_assurance: 'class_a',
    required_authority: true,
    max_revocation_staleness_sec: 300,
    accepted_registry_keys: [{ issuer_id: 'auth_cfo', public_key: registryPub }],
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: ['sha256:77ab1234'],
    required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
  };
  const revocation_state = { checked_at: '2026-07-06T23:58:00.000Z' };
  let consumption = { consumed: false };
  let authorityIncluded = true;

  switch (brk) {
    case 'none': break;
    case 'no_profile':
      delete profile['@type']; // present object, but not a pinned EP-RELIANCE-PROFILE-v1
      break;
    case 'authority_subject_not_signer':
      proofArgs = { ...proofArgs, subject: 'ep:approver:eve-not-a-signer' }; // valid authority, wrong human
      break;
    case 'tamper_signoff':
      receipt.signoffs[0].signature = crypto.sign(null, Buffer.from('00'.repeat(32), 'hex'), ed25519().privateKey).toString('base64url');
      break;
    case 'unpinned_issuer':
      profile.accepted_issuer_keys = [ed25519().pub];
      break;
    case 'class_b_only':
      break; // receipt built Class-B only; profile still demands class_a
    case 'require_quorum_absent':
      profile.required_assurance = 'quorum'; // no quorum doc supplied
      break;
    case 'no_authority_proof':
      authorityIncluded = false;
      break;
    case 'authority_revoked':
      proofArgs = { ...proofArgs, revocation: { status: 'revoked', checked_at: '2026-07-06T23:59:00.000Z', revoked_at: '2026-07-05T00:00:00.000Z' } };
      break;
    case 'authority_expired':
      proofArgs = { ...proofArgs, validity: { from: '2025-01-01T00:00:00.000Z', to: '2026-06-01T00:00:00.000Z' } };
      break;
    case 'authority_scope_wrong':
      proofArgs = { ...proofArgs, scope: ['production_delete'] };
      break;
    case 'amount_over_ceiling':
      action.amount = 90000; // ceiling is 50000
      break;
    case 'policy_not_accepted':
      action.policy_hash = 'sha256:deadbeef';
      break;
    case 'revocation_stale':
      revocation_state.checked_at = '2026-01-01T00:00:00.000Z'; // far older than 300s
      break;
    case 'already_consumed':
      consumption = { consumed: true };
      break;
    case 'registry_key_unpinned':
      profile.accepted_registry_keys = []; // proof valid but no pinned registry key
      break;
    default: throw new Error(`unknown break: ${brk}`);
  }

  const authority_proof = authorityIncluded ? signAuthorityProof(proofArgs, registryKey) : undefined;
  return { input: { action, receipt, authority_proof, revocation_state, consumption, relying_party_profile: profile, now: NOW }, opts };
}

describe('EP-RELIANCE-KERNEL-v1 conformance suite', () => {
  for (const v of SUITE.vectors) {
    it(`${v.id} → ${v.expect.verdict}`, () => {
      const { input, opts } = assemble(v.break);
      const r = evaluateReliance(input, opts);
      expect(RELIANCE_VERDICTS).toContain(r.verdict);
      expect(r.verdict).toBe(v.expect.verdict);
      expect(r.rely).toBe(v.expect.valid);
    });
  }

  it('covers every closed verdict at least once', () => {
    const covered = new Set(SUITE.vectors.map((v) => v.expect.verdict));
    for (const verdict of RELIANCE_VERDICTS) expect(covered.has(verdict)).toBe(true);
  });
});

describe('EP-RELIANCE-KERNEL-v1 unit invariants', () => {
  it('rely is the ONLY success verdict; every other is fail-closed', () => {
    const { input, opts } = assemble('none');
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.rely).toBe(true);
  });

  it('no pinned profile → no reliance (verification can pass, reliance cannot)', () => {
    const { input, opts } = assemble('none');
    // Absent profile: even a fully-valid packet must NOT rely without a pinned rule.
    const r = evaluateReliance({ ...input, relying_party_profile: undefined }, opts);
    expect(r.verdict).toBe('do_not_rely_no_profile');
    expect(r.rely).toBe(false);
    // A present object that is not an EP-RELIANCE-PROFILE-v1 is equally unpinned.
    const r2 = evaluateReliance({ ...input, relying_party_profile: { required_assurance: 'signed' } }, opts);
    expect(r2.verdict).toBe('do_not_rely_no_profile');
  });

  it('authority must be BOUND to the actual signer (no compose-across-humans)', () => {
    // Alice signs (Class-A), but the packet carries an authority proof for a
    // different subject. This must never compose to rely.
    const { input, opts } = assemble('authority_subject_not_signer');
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_authority_subject_mismatch');
    expect(r.rely).toBe(false);
  });

  it('authority is an INPUT: same receipt, stricter profile can flip rely→do_not_rely', () => {
    const { input, opts } = assemble('none');
    const relaxed = evaluateReliance({ ...input, relying_party_profile: { '@type': 'EP-RELIANCE-PROFILE-v1', required_assurance: 'signed', required_evidence: [] } }, opts);
    expect(relaxed.verdict).toBe('rely');
    const strict = evaluateReliance({ ...input, action: { ...input.action, amount: 999999 } }, opts);
    expect(strict.verdict).toBe('do_not_rely_amount_exceeded');
  });
});
