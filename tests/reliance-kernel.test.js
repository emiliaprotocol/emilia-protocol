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

import { evaluateReliance, RELIANCE_VERDICTS, validateRelianceProfile } from '../packages/verify/reliance.js';
import { authorityProofDigest, signAuthorityProof } from '../lib/authority/proof.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/reliance.v1.json'), 'utf8'));
const CONSUMPTION_SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/consumption-proof.v1.json'), 'utf8'));
const COMPLETE_RESULT_DIGESTS = Object.freeze({
  rely_full_packet_composes: 'a4c6d44742247dd1228da471ef0f1a02217a6a5ae6c9ee93f9a060133b9a88f3',
  reject_no_profile: '2c7acaa1fbf071aba461959dea04e7d4f3d19924d6d23fba06a6f18697cea144',
  reject_unsigned_receipt: '5080d5a7c78cbbc50fba629f9c234f16617608eef8ecbd00aa68c38826bce4ba',
  reject_untrusted_issuer: '9daf22097be3329ba38354b52a022e9b62dfe18264a0e762bd738ab4f69df0a9',
  reject_no_class_a: 'acb2df48b7019c925c8b85394e21097911e81b83ba084f919313f3bf76d005a6',
  reject_quorum_unsatisfied: 'e8718cd9994076148a5edfe34b6c0aa03ab2eb5948a549eada805023fe0c4b34',
  reject_authority_missing: '7763522aee01f451ac2047ad2f6ce138a48830e46ed6c1ee32c49736eadb1b0b',
  reject_authority_subject_not_signer: 'c42775973e07caf04cf0b8480bd753b4b81866f05cfbccab046e5594907bfb66',
  reject_authority_organization_mismatch: 'b505a6afb77e0eff54549a94ce376b50b87acf3d6429278122fb3684d8af6e2c',
  reject_authority_revoked: '46a997d08d86349425b8674aff80e3d475070be5a8c30b26c28b4a5af9ed234a',
  reject_authority_expired: '3ccb46bb8a4a852dbf66666e42eb1a14c0a36effd24837e6786122d202bdf490',
  reject_scope_mismatch: '1026a380c8b3423b86019701d4657fcee43b5bc05c9310e2fd0d5fa6d0099670',
  reject_amount_exceeded: 'a328e14d7cc8a7bd4318f1b9b31f68b7074ba30ade0fc9f6137bb8de68a2ae13',
  reject_policy_mismatch: '117aa427e46eca13426a24e63c88ef2809241f41836e21d32a18d9a4d69f6047',
  reject_stale_revocation: '6c74a3c8e915bab595f7fb1db6e52d7a4888a05c8da416c5842ea31f597eb898',
  reject_already_consumed: '629deee2388215ca02f80553c9f062ca0dc49c1a615b158c033c601c740370b6',
  reject_registry_unavailable: '05865b85e6342ca874e311889effcabf7e567b06405f8524bf8066b571cca875',
});

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
function webauthnForDigest(privateKey, digestHex, { rpId = 'www.emiliaprotocol.ai', flags = 0x05 } = {}) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}
function signA(digestHex, options) {
  return webauthnForDigest(approverA.privateKey, digestHex, options);
}

function buildQuorum(actionHash) {
  const first = p256();
  const second = p256();
  const contexts = [
    {
      ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: actionHash,
      policy_hash: 'sha256:77ab1234', nonce: 'q-1', approver: 'ep:approver:quorum-one',
      initiator: 'ep:entity:agent-recon-7', issued_at: '2026-06-09T17:24:00Z', expires_at: '2026-06-09T17:36:00Z',
    },
    {
      ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: actionHash,
      policy_hash: 'sha256:77ab1234', nonce: 'q-2', approver: 'ep:approver:quorum-two',
      initiator: 'ep:entity:agent-recon-7', issued_at: '2026-06-09T17:25:00Z', expires_at: '2026-06-09T17:36:00Z',
    },
  ];
  const member = (role, context, key) => ({
    role,
    approver_public_key: key.pub,
    signoff: {
      '@type': 'ep.signoff.webauthn', context,
      webauthn: webauthnForDigest(key.privateKey, sha256hex(canonicalize(context))),
    },
  });
  return {
    '@type': 'ep.quorum', action_hash: actionHash,
    policy: {
      mode: 'threshold', required: 2, distinct_humans: true, window_sec: 300,
      approvers: [
        { role: 'controller', approver: contexts[0].approver },
        { role: 'treasurer', approver: contexts[1].approver },
      ],
    },
    members: [member('controller', contexts[0], first), member('treasurer', contexts[1], second)],
  };
}

function buildRevocationStatement(target, signer) {
  const fields = {
    '@version': 'EP-REVOCATION-v1', action_hash: target.action_hash,
    reason: 'authority withdrawn', revoked_at: '2026-07-06T23:59:30.000Z',
    revoker_id: 'ep:revoker:test', target_id: target.target_id, target_type: target.target_type,
  };
  return {
    ...fields,
    proof: {
      algorithm: 'Ed25519', revoker_key_id: 'revoker-key-1', public_key: signer.pub,
      signature_b64u: crypto.sign(null, Buffer.from(canonicalize(fields), 'utf8'), signer.privateKey).toString('base64url'),
    },
  };
}

// Build a valid trust receipt. classAForCfo=false makes both signoffs Class-B.
function buildReceipt({ classAForCfo = true, amount = '50000.00', currency = 'USD', policyHash = 'sha256:77ab1234', actionOverrides = {} } = {}) {
  const baseAction = {
    ep_version: '1.0', action_type: 'wire.release',
    organization_id: 'acme',
    target: { system: 'treasury.example', resource: 'wire/8841' },
    parameters: { amount, currency },
    initiator: 'ep:entity:agent-recon-7', policy_id: 'ep:policy:wires-over-100k@v12',
    requested_at: '2026-06-09T17:21:04Z',
  };
  const action = { ...baseAction, ...actionOverrides };
  const action_hash = `sha256:${sha256hex(canonicalize(action))}`;
  const baseCtx = {
    ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash,
    policy_id: 'ep:policy:wires-over-100k@v12', policy_hash: policyHash,
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
  'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:controller#2': { approver_id: 'ep:approver:mrios-cfo', public_key: approverB2.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
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

function resignAuthorityProof(proof, overrides) {
  const { signature, ...originalBody } = structuredClone(proof);
  const body = { ...originalBody, ...overrides };
  const proofDigest = authorityProofDigest(body);
  const signingBytes = Buffer.from(`EP-AUTHORITY-PROOF-v1\0${canonicalize(body)}`, 'utf8');
  return {
    ...body,
    signature: {
      ...signature,
      proof_digest: proofDigest,
      signature_b64u: crypto.sign(null, signingBytes, registryKey).toString('base64url'),
    },
  };
}

// Assemble a packet + apply a break, return { input, opts }.
function assemble(brk) {
  const signedAmount = brk === 'amount_over_ceiling' ? '90000.00' : '50000.00';
  const signedPolicy = brk === 'policy_not_accepted' ? 'sha256:deadbeef' : 'sha256:77ab1234';
  const receipt = buildReceipt({
    classAForCfo: brk !== 'class_b_only',
    amount: signedAmount,
    policyHash: signedPolicy,
  });
  const opts = {
    approverKeys: KEYS,
    logPublicKey: logKey.pub,
    rpId: 'www.emiliaprotocol.ai',
    isConsumed: () => false,
  };
  const action = { action_type: 'wire.release', amount: Number(signedAmount), currency: 'USD', organization_id: 'acme', policy_hash: signedPolicy, action_hash: receipt.action_hash };
  let proofArgs = baseAuthorityProofArgs(receipt);
  if (brk === 'policy_not_accepted') proofArgs = { ...proofArgs, policy_hash: signedPolicy };
  const profile = {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    required_assurance: 'class_a',
    required_authority: true,
    max_revocation_staleness_sec: 300,
    accepted_registry_keys: [{ issuer_id: 'auth_cfo', organization_id: 'acme', public_key: registryPub, min_epoch: 17, registry_head: 'sha256:' + '11'.repeat(32) }],
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
    case 'authority_organization_wrong':
      proofArgs = { ...proofArgs, organization_id: 'attacker-org' };
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
    case 'policy_not_accepted':
      break; // signed receipt material was selected before assembly
    case 'revocation_stale':
      proofArgs = {
        ...proofArgs,
        revocation: { ...proofArgs.revocation, checked_at: '2026-01-01T00:00:00.000Z' },
      };
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

  it('pins the complete result shape for every conformance vector', () => {
    const digests = {};
    for (const v of SUITE.vectors) {
      const { input, opts } = assemble(v.break);
      digests[v.id] = sha256hex(canonicalize(evaluateReliance(input, opts)));
    }
    expect(digests).toEqual(COMPLETE_RESULT_DIGESTS);
  });
});

describe('EP-RELIANCE-KERNEL-v1 unit invariants', () => {
  it('rely is the ONLY success verdict; every other is fail-closed', () => {
    const { input, opts } = assemble('none');
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.rely).toBe(true);
    expect(r.checks).toEqual({
      receipt: true,
      issuer: true,
      assurance: 'class_a',
      authority: { accepted: true, authority_id: 'auth_cfo', subject: 'ep:approver:mrios-cfo', bound_to: 'class_a' },
      policy: true,
      revocation: 'fresh',
      consumption: 'unconsumed',
    });
    expect(r.profile).toEqual({
      id: 'EP-RELIANCE-PROFILE-v1',
      required_assurance: 'class_a',
      required_authority: true,
    });
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

  it('reports a missing authority proof through the exact closed refusal contract', () => {
    const { input, opts } = assemble('no_authority_proof');
    const r = evaluateReliance(input, opts);
    expect(r).toMatchObject({ verdict: 'do_not_rely_authority_missing', rely: false });
    expect(r.reasons.at(-1)).toBe('scoped authority is required but no EP-AUTHORITY-PROOF-v1 was supplied');
    expect(r.checks.authority).toBe(null);
  });

  it('binds authority organization to signed action material and the pinned registry key', () => {
    const { input, opts } = assemble('authority_organization_wrong');
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_authority_organization_mismatch');

    const missingPinScope = assemble('none');
    delete missingPinScope.input.relying_party_profile.accepted_registry_keys[0].organization_id;
    expect(evaluateReliance(missingPinScope.input, missingPinScope.opts).verdict).toBe('do_not_rely_no_profile');

    const missingSignedOrganization = assemble('none');
    const receipt = buildReceipt({ actionOverrides: { organization_id: null } });
    missingSignedOrganization.input.receipt = receipt;
    missingSignedOrganization.input.action.action_hash = receipt.action_hash;
    delete missingSignedOrganization.input.action.organization_id;
    missingSignedOrganization.input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
    expect(evaluateReliance(missingSignedOrganization.input, missingSignedOrganization.opts).verdict)
      .toBe('do_not_rely_authority_organization_mismatch');
  });

  it('pins the authority registry head and minimum epoch at reliance time', () => {
    const wrongHead = assemble('none');
    wrongHead.input.relying_party_profile.accepted_registry_keys[0].registry_head = 'sha256:' + '22'.repeat(32);
    expect(evaluateReliance(wrongHead.input, wrongHead.opts).verdict).toBe('do_not_rely_registry_unavailable');

    const staleEpoch = assemble('none');
    staleEpoch.input.relying_party_profile.accepted_registry_keys[0].min_epoch = 18;
    expect(evaluateReliance(staleEpoch.input, staleEpoch.opts).verdict).toBe('do_not_rely_registry_unavailable');
  });

  it('selects the exact registry pin despite same-key and same-issuer decoys', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.accepted_registry_keys.unshift(
      {
        issuer_id: 'wrong-authority', organization_id: 'acme', public_key: registryPub,
        min_epoch: 999, registry_head: 'sha256:' + '99'.repeat(32),
      },
      {
        issuer_id: 'auth_cfo', organization_id: 'acme', public_key: ed25519().pub,
        min_epoch: 999, registry_head: 'sha256:' + '88'.repeat(32),
      },
    );
    expect(evaluateReliance(input, opts).verdict).toBe('rely');
  });

  it('authority is an INPUT: same receipt, stricter profile can flip rely→do_not_rely', () => {
    const { input, opts } = assemble('none');
    const relaxed = evaluateReliance({
      ...input,
      relying_party_profile: {
        '@type': 'EP-RELIANCE-PROFILE-v1',
        required_assurance: 'signed',
        accepted_issuer_keys: [logKey.pub],
        required_evidence: [],
      },
    }, opts);
    expect(relaxed.verdict).toBe('rely');
    const strict = evaluateReliance({
      ...input,
      authority_proof: signAuthorityProof({
        ...baseAuthorityProofArgs(input.receipt),
        limits: { max_amount_usd: 1000, currency: 'USD' },
      }, registryKey),
    }, opts);
    expect(strict.verdict).toBe('do_not_rely_amount_exceeded');
  });

  it('binds every pinned signing key to the approver named by its context', () => {
    const { input, opts } = assemble('none');
    const receipt = buildReceipt({ classAForCfo: false });
    input.receipt = receipt;
    input.action.action_hash = receipt.action_hash;
    input.relying_party_profile.required_assurance = 'signed';
    input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
    opts.approverKeys = {
      ...opts.approverKeys,
      'ep:key:controller#2': {
        ...opts.approverKeys['ep:key:controller#2'],
        approver_id: 'ep:approver:low-privilege-operator',
      },
    };

    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_unsigned');
    expect(r.rely).toBe(false);
  });

  it('requires the relying action hash instead of treating the join as optional', () => {
    const { input, opts } = assemble('none');
    delete input.action.action_hash;
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_unsigned');
    expect(r.rely).toBe(false);
  });

  it('will not accept a machine policy decision record in the receipt slot', () => {
    // Honest scope: the reliance kernel expects an EP trust receipt (action +
    // signoffs). A machine decision record — "decision": "allow",
    // "approval_state": "granted" — is not a well-formed trust receipt, so the
    // kernel refuses it at the receipt gate rather than weighing it as human
    // authorization. This asserts the kernel does NOT have a code path that
    // accepts a decision record here; the role-substitution proof against a
    // *composed* artifact lives in tests/role-non-substitution.test.js, and the
    // cross-language version-gate refusal is the boundary suite vector.
    const boundary = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/boundary.v1.json'), 'utf8'));
    const vector = boundary.vectors.find((v) => v.id === 'policy_decision_presented_as_human_authorization');
    expect(vector).toBeDefined();
    expect(vector.document.payload.decision).toBe('allow');
    expect(vector.document.payload.approval_state).toBe('granted');

    const { input, opts } = assemble('none');
    input.receipt = vector.document;
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_unsigned');
    expect(r.rely).toBe(false);
  });

  it('reaches the same refusal whether or not an unrelated machine decision is attached', () => {
    // The kernel weighs only the receipt, its signoffs, and the pinned inputs —
    // never a free-floating artifact a presenter attaches. Prove that directly:
    // with a valid but Class-B-only receipt under a class_a profile, the verdict
    // is do_not_rely_no_class_a, and it is BYTE-IDENTICAL with or without a
    // signed machine decision attached. A machine ALLOW cannot buy a Class-A
    // seat, and there is no side channel that even looks at it.
    const boundary = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/boundary.v1.json'), 'utf8'));
    const decision = boundary.vectors.find((v) => v.id === 'policy_decision_presented_as_human_authorization').document;

    const build = (attach) => {
      const { input, opts } = assemble('none');
      const receipt = buildReceipt({ classAForCfo: false });
      input.receipt = receipt;
      input.action.action_hash = receipt.action_hash;
      input.relying_party_profile.required_assurance = 'class_a';
      if (attach) input.presented_evidence = [decision];
      return evaluateReliance(input, opts);
    };
    const without = build(false);
    const withDecision = build(true);
    expect(without.verdict).toBe('do_not_rely_no_class_a');
    expect(withDecision.verdict).toBe('do_not_rely_no_class_a');
    expect(withDecision).toEqual(without);
  });

  it('does not skip an authority ceiling when the JSON amount is a decimal string', () => {
    const { input, opts } = assemble('amount_over_ceiling');
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_amount_exceeded');
    expect(r.rely).toBe(false);
  });

  it('derives authority material fields from the signed receipt when the caller summary omits them', () => {
    const { input, opts } = assemble('none');
    delete input.action.amount;
    delete input.action.currency;
    delete input.action.action_type;
    delete input.action.policy_hash;
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.rely).toBe(true);
  });

  it('refuses caller material fields that disagree with the signed receipt', () => {
    for (const override of [
      { amount: 1 },
      { currency: 'EUR' },
      { action_type: 'wire.preview' },
      { policy_hash: 'sha256:attacker-policy' },
    ]) {
      const { input, opts } = assemble('none');
      input.action = { ...input.action, ...override };
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_unsigned');
      expect(r.rely).toBe(false);
    }
  });

  it('refuses ambiguous or malformed material inside the signed receipt itself', () => {
    for (const actionOverrides of [
      { amount: '50000.00', parameters: { amount: '1.00', currency: 'USD' } },
      { currency: 'EUR', parameters: { amount: '50000.00', currency: 'USD' } },
      { policy_hash: 'sha256:different-from-signed-context' },
      { parameters: { amount: '-1', currency: 'USD' } },
      { parameters: { amount: '01', currency: 'USD' } },
      { action_type: null },
    ]) {
      const { input, opts } = assemble('none');
      const receipt = buildReceipt({ actionOverrides });
      input.receipt = receipt;
      input.action.action_hash = receipt.action_hash;
      input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_unsigned');
      expect(r.rely).toBe(false);
    }
  });

  it('accepts a signed amount_usd material field only as USD', () => {
    const { input, opts } = assemble('none');
    const receipt = buildReceipt({ actionOverrides: { parameters: { amount_usd: '50000.00' } } });
    input.receipt = receipt;
    input.action = {
      action_type: 'wire.release', amount: 50000, currency: 'USD',
      policy_hash: 'sha256:77ab1234', action_hash: receipt.action_hash,
    };
    input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');

    input.action.currency = 'EUR';
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_unsigned');
  });

  it('compares decimal material exactly without exponent, prefix, or suffix smuggling', () => {
    for (const amount of ['50000', '50000.0', '50000.0000']) {
      const { input, opts } = assemble('none');
      input.action.amount = amount;
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }
    for (const amount of ['x50000', '50000x', '5e4', '-50000', Number.NaN, Number.POSITIVE_INFINITY]) {
      const { input, opts } = assemble('none');
      input.action.amount = amount;
      expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_unsigned');
    }

    const { input, opts } = assemble('none');
    const receipt = buildReceipt({
      actionOverrides: { amount: '50000.0', parameters: { amount: '50000.00', currency: 'USD' } },
    });
    input.receipt = receipt;
    input.action.action_hash = receipt.action_hash;
    input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');
  });

  it('accepts numeric zero as exact signed material and rejects isolated invalid signed decimals', () => {
    const zero = assemble('none');
    const zeroReceipt = buildReceipt({ amount: 0 });
    zero.input.receipt = zeroReceipt;
    zero.input.action = { ...zero.input.action, amount: 0, action_hash: zeroReceipt.action_hash };
    zero.input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(zeroReceipt), registryKey);
    expect(evaluateReliance(zero.input, zero.opts).verdict).toBe('rely');

    for (const amount of ['-1', '01', '1e2', 'x1', '1x']) {
      const isolated = assemble('none');
      const receipt = buildReceipt({ amount });
      isolated.input.receipt = receipt;
      isolated.input.action = { ...isolated.input.action, amount, action_hash: receipt.action_hash };
      isolated.input.authority_proof = signAuthorityProof({
        ...baseAuthorityProofArgs(receipt), limits: { max_amount_usd: null, currency: 'USD' },
      }, registryKey);
      const result = evaluateReliance(isolated.input, isolated.opts);
      expect(result.verdict).toBe('do_not_rely_unsigned');
      expect(result.reasons.at(-1)).toMatch(/inconsistent signed action material/);
    }
  });

  it('cannot substitute an accepted authority and policy over a receipt signed under another policy', () => {
    const { input, opts } = assemble('none');
    const substituted = 'sha256:substituted-policy';
    input.action.policy_hash = substituted;
    input.relying_party_profile.accepted_policy_hashes = [substituted];
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      policy_hash: substituted,
    }, registryKey);
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_unsigned');
    expect(r.rely).toBe(false);
  });

  it('enforces an authority policy pin independently of profile policy admission', () => {
    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      policy_hash: 'sha256:different-authority-policy',
    }, registryKey);
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_policy_mismatch');
    expect(r.rely).toBe(false);
  });

  it('binds authority to the ceremony that actually satisfied class_a_or_quorum', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.required_assurance = 'signed';
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      subject: 'ep:approver:jchen-controller',
    }, registryKey);
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_authority_subject_mismatch');
    expect(r.rely).toBe(false);
  });

  it('a checkpointed receipt cannot rely when the profile pins no issuer key', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.accepted_issuer_keys = [];
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_untrusted_issuer');
    expect(r.rely).toBe(false);
  });

  it('rejects malformed and impossible signed authority validity windows', () => {
    for (const to of ['not-a-date', '2026-02-30T00:00:00.000Z']) {
      const { input, opts } = assemble('none');
      input.authority_proof = signAuthorityProof({
        ...baseAuthorityProofArgs(input.receipt),
        validity: { from: '2026-01-01T00:00:00.000Z', to },
      }, registryKey);
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_authority_expired');
      expect(r.rely).toBe(false);
    }
  });

  it('accepts optional and exact-boundary authority windows but rejects inverted windows', () => {
    for (const validity of [
      {}, { from: null, to: null },
      { from: '2026-01-01T00:00:00.000Z' },
      { to: '2027-01-01T00:00:00.000Z' },
      {
      from: '2026-07-07T00:00:00.000Z', to: '2026-07-07T00:00:00.000Z',
      },
    ]) {
      const { input, opts } = assemble('none');
      input.authority_proof = signAuthorityProof({ ...baseAuthorityProofArgs(input.receipt), validity }, registryKey);
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }

    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      validity: { from: '2026-08-01T00:00:00.000Z', to: '2026-01-01T00:00:00.000Z' },
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_authority_expired');
  });

  it('fails closed on validly signed malformed authority shapes and accepts genuinely unbounded limits', () => {
    for (const scope of [null, [], 'wire.release']) {
      const { input, opts } = assemble('none');
      input.authority_proof = resignAuthorityProof(input.authority_proof, { scope });
      const result = evaluateReliance(input, opts);
      expect(result.verdict).toBe('do_not_rely_scope_mismatch');
      expect(result.reasons.at(-1)).toMatch(/not within the authority scope/);
    }
    for (const limits of [null, {}]) {
      const { input, opts } = assemble('none');
      input.authority_proof = resignAuthorityProof(input.authority_proof, { limits });
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }
    for (const validity of [null, {}]) {
      const { input, opts } = assemble('none');
      input.authority_proof = resignAuthorityProof(input.authority_proof, { validity });
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }

    const euro = assemble('none');
    const euroReceipt = buildReceipt({ currency: 'EUR' });
    euro.input.receipt = euroReceipt;
    euro.input.action = { ...euro.input.action, currency: 'EUR', action_hash: euroReceipt.action_hash };
    euro.input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(euroReceipt), registryKey);
    expect(evaluateReliance(euro.input, euro.opts).verdict).toBe('do_not_rely_amount_exceeded');
  });

  it('strictly rejects malformed reliance instants and calendar rollovers', () => {
    const invalid = [
      null, Number.NaN, Number.POSITIVE_INFINITY, [], {}, '2026-00-01T00:00:00Z', '2026-13-01T00:00:00Z',
      '2026-01-00T00:00:00Z', '2026-04-31T00:00:00Z', '1900-02-29T00:00:00Z',
      '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z', '2026-01-01T00:00:60Z',
      '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60',
      '2026-01-01T00:00:00',
    ];
    for (const now of invalid) {
      const { input, opts } = assemble('none');
      input.now = now;
      expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_unsigned');
    }

    for (const from of ['2000-02-29T00:00:00Z', '2024-02-29T00:00:00+23:59']) {
      const { input, opts } = assemble('none');
      input.authority_proof = signAuthorityProof({
        ...baseAuthorityProofArgs(input.receipt), validity: { from, to: '2027-01-01T00:00:00Z' },
      }, registryKey);
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }
  });

  it('rejects an invalid assurance label instead of downgrading it to signed', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.required_assurance = 'CLASS_A';
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_no_profile');
    expect(r.rely).toBe(false);
  });

  it('rejects malformed and unknown required-evidence policy', () => {
    for (const required_evidence of [{}, ['receipt', 'made_up_proof']]) {
      const { input, opts } = assemble('none');
      input.relying_party_profile.required_evidence = required_evidence;
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_no_profile');
      expect(r.rely).toBe(false);
    }
  });

  it('validates every security-bearing reliance profile field fail-closed', () => {
    const { input } = assemble('none');
    const valid = input.relying_party_profile;
    expect(validateRelianceProfile(valid)).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...valid, max_revocation_staleness_sec: 0 }).ok).toBe(true);

    const withoutFreshnessBound = { ...valid };
    delete withoutFreshnessBound.max_revocation_staleness_sec;
    const invalid = [
      null,
      [],
      { ...valid, '@type': 'wrong' },
      { ...valid, required_assurance: 'CLASS_A' },
      { ...valid, required_authority: 'true' },
      { ...valid, required_evidence: {} },
      { ...valid, required_evidence: [1] },
      { ...valid, required_evidence: ['unknown_evidence'] },
      { ...valid, accepted_issuer_keys: {} },
      { ...valid, accepted_issuer_keys: [null] },
      { ...valid, accepted_issuer_keys: [{ public_key: 1 }] },
      { ...valid, accepted_registry_keys: {} },
      { ...valid, accepted_registry_keys: [null] },
      { ...valid, accepted_registry_keys: [{ public_key: 1 }] },
      { ...valid, accepted_registry_keys: [{ issuer_id: 'auth_cfo', organization_id: 'acme', public_key: registryPub, min_epoch: -1, registry_head: 'sha256:' + '11'.repeat(32) }] },
      { ...valid, accepted_registry_keys: [{ issuer_id: 'auth_cfo', organization_id: 'acme', public_key: registryPub, min_epoch: 17, registry_head: 'not-a-head' }] },
      { ...valid, accepted_policy_hashes: {} },
      { ...valid, accepted_policy_hashes: [null] },
      { ...valid, accepted_policy_hashes: [''] },
      { ...valid, max_revocation_staleness_sec: -1 },
      { ...valid, max_revocation_staleness_sec: Number.POSITIVE_INFINITY },
      withoutFreshnessBound,
    ];
    for (const profile of invalid) {
      const result = validateRelianceProfile(profile);
      expect(result.ok).toBe(false);
      expect(result.issues.length).toBeGreaterThan(0);
    }
  });

  it('returns exact profile-validation issues for each malformed field family', () => {
    const { input } = assemble('none');
    const valid = input.relying_party_profile;
    const cases = [
      [null, 'profile is not an object'],
      [{ ...valid, '@type': 'wrong' }, '@type must be EP-RELIANCE-PROFILE-v1'],
      [{ ...valid, required_assurance: 'CLASS_A' }, 'required_assurance must be one of signed, class_a, quorum'],
      [{ ...valid, required_authority: 'true' }, 'required_authority must be a boolean'],
      [{ ...valid, required_evidence: {} }, 'required_evidence must be an array'],
      [{ ...valid, required_evidence: ['unknown'] }, 'unsupported required_evidence entry: unknown'],
      [{ ...valid, accepted_issuer_keys: {} }, 'accepted_issuer_keys must be an array'],
      [{ ...valid, accepted_issuer_keys: [null] }, 'accepted_issuer_keys contains an invalid key entry'],
      [{ ...valid, accepted_registry_keys: [null] }, 'accepted_registry_keys contains an invalid key entry'],
      [{ ...valid, accepted_policy_hashes: [null] }, 'accepted_policy_hashes contains an invalid policy hash'],
      [{ ...valid, max_revocation_staleness_sec: -1 }, 'max_revocation_staleness_sec must be a finite non-negative number'],
      [{ ...valid, max_revocation_staleness_sec: undefined }, 'revocation_freshness requires max_revocation_staleness_sec'],
    ];
    for (const [profile, issue] of cases) {
      expect(validateRelianceProfile(profile).issues).toContain(issue);
    }
  });

  it('honors class_a_or_quorum even when required_assurance is misconfigured lower', () => {
    const { input, opts } = assemble('none');
    const receipt = buildReceipt({ classAForCfo: false });
    input.receipt = receipt;
    input.action.action_hash = receipt.action_hash;
    input.authority_proof = signAuthorityProof(baseAuthorityProofArgs(receipt), registryKey);
    input.relying_party_profile.required_assurance = 'signed';
    input.relying_party_profile.required_evidence = ['receipt', 'class_a_or_quorum', 'authority_proof'];

    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_no_class_a');
    expect(r.rely).toBe(false);
  });

  it('accepts a real two-device quorum and binds authority to a counted member', () => {
    const { input, opts } = assemble('none');
    input.quorum = buildQuorum(input.receipt.action_hash);
    input.relying_party_profile.required_assurance = 'quorum';
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt), subject: 'ep:approver:quorum-one',
    }, registryKey);
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.checks.assurance).toBe('quorum');
    expect(r.checks.authority).toMatchObject({ subject: 'ep:approver:quorum-one', bound_to: 'quorum' });
  });

  it('uses a valid quorum as the class_a_or_quorum fallback for a Class-B receipt', () => {
    const { input, opts } = assemble('none');
    const receipt = buildReceipt({ classAForCfo: false });
    input.receipt = receipt;
    input.action.action_hash = receipt.action_hash;
    input.quorum = buildQuorum(receipt.action_hash);
    input.relying_party_profile.required_assurance = 'signed';
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(receipt), subject: 'ep:approver:quorum-two',
    }, registryKey);
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.checks.assurance).toBe('quorum');
    expect(r.checks.authority).toMatchObject({ subject: 'ep:approver:quorum-two', bound_to: 'quorum' });
  });

  it('refuses a valid quorum whose document is not bound to the receipt action', () => {
    const { input, opts } = assemble('none');
    input.quorum = buildQuorum(input.receipt.action_hash);
    input.quorum.action_hash = 'sha256:' + '9'.repeat(64);
    input.relying_party_profile.required_assurance = 'quorum';
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_quorum_unsatisfied');
  });

  it('does not accept a presenter-supplied revocation timestamp as authenticated freshness', () => {
    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      revocation: { status: 'unknown', checked_at: new Date(NOW).toISOString() },
    }, registryKey);
    input.revocation_state = { checked_at: new Date(NOW).toISOString() };
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_stale_revocation');
    expect(r.rely).toBe(false);
  });

  it('requires relying-party-owned consumption state; presenter false is not proof', () => {
    const { input, opts } = assemble('none');
    delete opts.isConsumed;
    input.consumption = { consumed: false };
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('do_not_rely_already_consumed');
    expect(r.rely).toBe(false);
    expect(r.reasons.at(-1)).toBe('relying-party consumption state is unavailable');
  });

  it('fails closed for consumed, indeterminate, throwing, and async consumption lookups', () => {
    for (const [isConsumed, reason] of [
      [() => true, 'relying-party consumption state is consumed or indeterminate'],
      [() => undefined, 'relying-party consumption state is consumed or indeterminate'],
      [() => { throw new Error('store down'); }, 'relying-party consumption lookup failed'],
      [async () => false, 'relying-party consumption state is consumed or indeterminate'],
    ]) {
      const { input, opts } = assemble('none');
      opts.isConsumed = isConsumed;
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_already_consumed');
      expect(r.rely).toBe(false);
      expect(r.reasons.at(-1)).toBe(reason);
    }
  });

  it('passes the exact stable receipt/action identity to the local consumption lookup', () => {
    const { input, opts } = assemble('none');
    let key;
    opts.isConsumed = (presented) => { key = presented; return false; };
    input.consumption = undefined;
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(key).toEqual({ receipt_id: input.receipt.receipt_id, action_hash: input.receipt.action_hash.slice('sha256:'.length) });
  });

  it('refuses malformed or positive presenter consumption evidence', () => {
    for (const consumption of [{ proof: null }, { proof: {} }, { consumed: true }]) {
      const { input, opts } = assemble('none');
      input.consumption = consumption;
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_already_consumed');
      expect(r.rely).toBe(false);
      if (Object.hasOwn(consumption, 'proof')) {
        const reason = consumption.proof === null ? 'bundle_missing' : 'nonce_missing';
        expect(r.reasons.at(-1)).toBe(`consumption evidence did not verify: ${reason}`);
      }
    }
  });

  it('refuses partial or invalid signed revocation artifacts instead of ignoring them', () => {
    for (const revocation_state of [
      { statement: {} },
      { target: {} },
      { statement: {}, target: {} },
    ]) {
      const { input, opts } = assemble('none');
      input.revocation_state = revocation_state;
      const r = evaluateReliance(input, opts);
      expect(r.verdict).toBe('do_not_rely_stale_revocation');
      expect(r.rely).toBe(false);
      if (!revocation_state.statement || !revocation_state.target) {
        expect(r.reasons.at(-1)).toBe('revocation evidence is incomplete');
      }
    }
  });

  it('recognizes an authentic pinned revocation artifact as a positive revocation', () => {
    const { input, opts } = assemble('none');
    const signer = ed25519();
    const target = {
      target_type: 'receipt', target_id: input.receipt.receipt_id,
      action_hash: input.receipt.action_hash,
    };
    input.revocation_state = { target, statement: buildRevocationStatement(target, signer) };
    opts.revokerKeys = { 'ep:revoker:test': { public_key: signer.pub } };
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_authority_revoked');

    input.revocation_state.target = { ...target, target_id: 'different-receipt' };
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_stale_revocation');
  });

  it('reports every optional reliance leg as not required under a minimal pinned profile', () => {
    const { input, opts } = assemble('none');
    delete input.authority_proof;
    delete input.revocation_state;
    delete input.consumption;
    input.relying_party_profile = {
      '@type': 'EP-RELIANCE-PROFILE-v1', required_assurance: 'signed',
      accepted_issuer_keys: [logKey.pub], required_evidence: [],
    };
    const r = evaluateReliance(input, opts);
    expect(r.verdict).toBe('rely');
    expect(r.checks).toMatchObject({
      assurance: 'signed', authority: 'not_required', policy: 'not_pinned',
      revocation: 'not_required', consumption: 'not_required',
    });
  });

  it('treats the authenticated revocation freshness boundary as inclusive and future checks as invalid', () => {
    const atBoundary = new Date(NOW - 300_000).toISOString();
    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      revocation: { status: 'not_revoked', checked_at: atBoundary },
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');

    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      revocation: { status: 'not_revoked', checked_at: new Date(NOW + 1).toISOString() },
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('do_not_rely_stale_revocation');
  });

  it('treats primitive optional evidence as absent, never as an implicit positive claim', () => {
    for (const revocation_state of [null, false, 0, '', 'not-an-evidence-object']) {
      const { input, opts } = assemble('none');
      input.revocation_state = revocation_state;
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }
    for (const consumption of [null, false, 0, '', 'not-an-evidence-object']) {
      const { input, opts } = assemble('none');
      input.consumption = consumption;
      expect(evaluateReliance(input, opts).verdict).toBe('rely');
    }
  });

  it('distinguishes a valid positive consumption proof from malformed evidence', () => {
    const validProof = CONSUMPTION_SUITE.vectors.find((vector) => vector.expect.valid).consumption_proof;
    const { input, opts } = assemble('none');
    input.consumption = { proof: validProof };
    const result = evaluateReliance(input, opts);
    expect(result).toMatchObject({
      verdict: 'do_not_rely_already_consumed', rely: false,
      checks: { consumption: 'consumed' },
    });
    expect(result.reasons.at(-1)).toBe('the authorization has already been consumed');
  });

  it('accepts a revocation check performed at the exact reliance instant', () => {
    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt),
      revocation: { status: 'not_revoked', checked_at: new Date(NOW).toISOString() },
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');
  });

  it('defaults an authority ceiling currency to USD only when the signed action is USD', () => {
    const { input, opts } = assemble('none');
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt), limits: { max_amount_usd: 50000 },
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');

    const euro = assemble('none');
    const receipt = buildReceipt({ currency: 'EUR' });
    euro.input.receipt = receipt;
    euro.input.action = { ...euro.input.action, currency: 'EUR', action_hash: receipt.action_hash };
    euro.input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(receipt), limits: { max_amount_usd: 50000 },
    }, registryKey);
    expect(evaluateReliance(euro.input, euro.opts).verdict).toBe('do_not_rely_amount_exceeded');
  });

  it('normalizes hostile top-level argument shapes to a closed refusal', () => {
    for (const input of [null, false, 0, 'packet']) {
      const result = evaluateReliance(input, null);
      expect(result).toEqual({
        verdict: 'do_not_rely_no_profile', rely: false,
        reasons: ['no pinned EP-RELIANCE-PROFILE-v1 supplied; verification can pass but reliance cannot'],
        checks: {
          receipt: false, issuer: null, assurance: null, authority: null,
          policy: null, revocation: null, consumption: null,
        },
        profile: { id: 'EP-RELIANCE-PROFILE-v1', pinned: false },
      });
    }
  });

  it('refuses a receipt without a transparency checkpoint before reliance can downgrade issuer trust', () => {
    const { input, opts } = assemble('none');
    delete input.receipt.log_proof;
    const result = evaluateReliance(input, opts);
    expect(result.verdict).toBe('do_not_rely_unsigned');
    expect(result.checks).toMatchObject({ receipt: false, issuer: null });
    expect(result.reasons.at(-1)).toMatch(/missing log_proof/);
  });

  it('returns the exact no-pinned-issuer refusal for a checkpointed receipt', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.accepted_issuer_keys = [];
    const result = evaluateReliance(input, opts);
    expect(result).toMatchObject({
      verdict: 'do_not_rely_untrusted_issuer', rely: false,
      checks: { receipt: true, issuer: false },
    });
    expect(result.reasons.at(-1)).toBe(
      'receipt has a transparency checkpoint but the profile pins no accepted issuer key',
    );
  });

  it('refuses a correctly action-bound quorum whose threshold is unsatisfied', () => {
    const { input, opts } = assemble('none');
    input.quorum = buildQuorum(input.receipt.action_hash);
    input.quorum.policy.required = 3;
    input.relying_party_profile.required_assurance = 'quorum';
    const result = evaluateReliance(input, opts);
    expect(result).toMatchObject({
      verdict: 'do_not_rely_quorum_unsatisfied', rely: false,
      checks: { assurance: false },
    });
  });

  it('requires authority when the evidence list requests it even if the boolean is false', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.required_authority = false;
    input.relying_party_profile.required_evidence = ['authority_proof'];
    delete input.authority_proof;
    const result = evaluateReliance(input, opts);
    expect(result.verdict).toBe('do_not_rely_authority_missing');
    expect(result.reasons.at(-1)).toBe(
      'scoped authority is required but no EP-AUTHORITY-PROOF-v1 was supplied',
    );
  });

  it('never accepts a registry key pinned for another organization', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.accepted_registry_keys[0].organization_id = 'other-org';
    const result = evaluateReliance(input, opts);
    expect(result).toMatchObject({ verdict: 'do_not_rely_registry_unavailable', rely: false });
    expect(result.reasons.at(-1)).toBe(
      'no authority registry key is pinned for the signed action organization',
    );
  });

  it('classifies a tampered authority signature as missing authority, not a registry outage', () => {
    const { input, opts } = assemble('none');
    input.authority_proof.signature.signature_b64u = 'AA';
    const result = evaluateReliance(input, opts);
    expect(result).toMatchObject({ verdict: 'do_not_rely_authority_missing', rely: false });
    expect(result.reasons.at(-1)).toMatch(/^authority proof did not verify:/);
  });

  it('allows an optional revocation field to be absent when freshness is not required', () => {
    const { input, opts } = assemble('none');
    input.relying_party_profile.required_evidence = ['receipt', 'authority_proof', 'consumption_proof'];
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(input.receipt), revocation: null,
    }, registryKey);
    expect(evaluateReliance(input, opts).verdict).toBe('rely');
  });

  it('binds signed assurance authority to any verified signer, including Class-B', () => {
    const { input, opts } = assemble('none');
    const receipt = buildReceipt({ classAForCfo: false });
    input.receipt = receipt;
    input.action.action_hash = receipt.action_hash;
    input.relying_party_profile.required_assurance = 'signed';
    input.relying_party_profile.required_evidence = ['receipt', 'authority_proof', 'consumption_proof'];
    input.authority_proof = signAuthorityProof({
      ...baseAuthorityProofArgs(receipt), subject: 'ep:approver:jchen-controller',
    }, registryKey);
    const result = evaluateReliance(input, opts);
    expect(result.verdict).toBe('rely');
    expect(result.checks.authority).toMatchObject({
      subject: 'ep:approver:jchen-controller', bound_to: 'signed',
    });
  });
});
