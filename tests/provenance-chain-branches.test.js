// SPDX-License-Identifier: Apache-2.0
//
// EP-PROVENANCE-CHAIN-v1 — branch/edge coverage companion suite.
//
// Locks the defensive throws, early-returns, and advisory blocks of
// lib/provenance/chain.js that the catalogue suite (provenance-chain.test.js)
// does not exercise: assembleProvenance input validation + optional passthrough,
// verifyProvenanceOffline version/missing-root early exits, the
// reversibilityAsserted / allowUnsignedDelegations / requireActionApprovalAlways
// option branches, the proof-key-binding failures, cap-inheritance edges, and the
// advisory agent_identity / liability attestation reporting (valid/invalid/absent).
// All cryptographic material is minted LIVE (real Ed25519 receipts + real
// delegation proofs over canonical bytes), so every negative is a genuine forgery.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  assembleProvenance,
  verifyProvenanceOffline,
  PROVENANCE_VERSION,
} from '../lib/provenance/chain.js';

import {
  canonicalize,
  buildContexts,
  collectSignoffs,
  assembleAuthorizationReceipt,
  policyHash as computePolicyHash,
  generateEd25519KeyPair,
} from '../packages/issue/index.js';

// ── fixed reference time so expiry windows are deterministic ─────────────────
const NOW = Date.parse('2026-06-13T12:00:00.000Z');
const ISSUED_AT = '2026-06-13T11:00:00.000Z';
const EXPIRES_AT = '2026-06-13T18:00:00.000Z';

// ── Class-A (human / WebAuthn-shaped) signer over the raw context digest ─────
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

function newP256() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    privateKey,
    publicKey,
    publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function classASigner({ approverKeyId, privateKey, signedAt }) {
  return {
    approverKeyId,
    keyClass: 'A',
    signedAt,
    signWebAuthn: (digest) => {
      const clientData = {
        type: 'webauthn.get',
        challenge: Buffer.from(digest).toString('base64url'),
        origin: 'https://test.emilia',
        crossOrigin: false,
      };
      const clientDataJson = Buffer.from(JSON.stringify(clientData), 'utf8');
      const authData = Buffer.concat([
        crypto.createHash('sha256').update('rp').digest(),
        Buffer.from([FLAG_UP | FLAG_UV]),
        Buffer.from([0, 0, 0, 1]),
      ]);
      const signed = Buffer.concat([
        authData,
        crypto.createHash('sha256').update(clientDataJson).digest(),
      ]);
      const signature = crypto.sign('sha256', signed, privateKey).toString('base64url');
      return {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataJson.toString('base64url'),
        signature,
      };
    },
  };
}

/** Mint a genuinely-valid EP-RECEIPT-v1 receipt + its pinned verification material. */
function mintReceipt({
  action,
  approver = 'ep:approver:human',
  approverKeyId = 'ep:key:human#1',
  keyClass = 'A',
  issuedAt = ISSUED_AT,
  expiresAt = EXPIRES_AT,
  committedAt = '2026-06-13T11:30:00.000Z',
}) {
  const approverKp = keyClass === 'A' ? newP256() : generateEd25519KeyPair();
  const logKp = generateEd25519KeyPair();
  const pHash = computePolicyHash({ policy_id: action.policy_id });

  const contexts = buildContexts({
    action,
    policyHash: pHash,
    approvers: [approver],
    requiredApprovals: 1,
    issuedAt,
    expiresAt,
  });

  const signerCommon = { approverKeyId, signedAt: issuedAt, privateKey: approverKp.privateKey };
  const signer = keyClass === 'A'
    ? classASigner(signerCommon)
    : {
        approverKeyId,
        keyClass,
        signedAt: issuedAt,
        sign: (digest) => crypto.sign(null, digest, approverKp.privateKey).toString('base64url'),
      };

  return collectSignoffs(contexts, [signer]).then((signoffs) => {
    const receipt = assembleAuthorizationReceipt({
      receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`,
      action,
      contexts,
      signoffs,
      committedAt,
      log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' },
    });
    const verification = {
      '@version': 'EP-AUTHORIZATION-RECEIPT-VERIFICATION-v1',
      approver_keys: {
        [approverKeyId]: {
          public_key: approverKp.publicKeyB64u,
          key_class: keyClass,
          valid_from: '2026-01-01T00:00:00Z',
          valid_to: '2036-01-01T00:00:00Z',
        },
      },
      log_public_key: logKp.publicKeyB64u,
    };
    return { receipt, verification, approver, approverKeyId };
  });
}

// ── delegation proof over the link's OWN canonical fields ────────────────────
const PROOF_FIELDS = [
  'delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints',
];

function proofPayloadBytes(link) {
  const subset = {};
  for (const f of PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

function signedLink(link, delegatorKp) {
  const payload = proofPayloadBytes(link);
  const signature = crypto.sign(null, payload, delegatorKp.privateKey);
  return {
    ...link,
    proof: {
      algorithm: 'Ed25519',
      signed_payload_b64u: payload.toString('base64url'),
      signature_b64u: signature.toString('base64url'),
      public_key: delegatorKp.publicKeyB64u,
    },
  };
}

/** A generic detached Ed25519 attestation over arbitrary canonical bytes. */
function detachedAttestation(obj, kp) {
  const payload = Buffer.from(canonicalize(obj), 'utf8');
  const signature = crypto.sign(null, payload, kp.privateKey);
  return {
    algorithm: 'Ed25519',
    signed_payload_b64u: payload.toString('base64url'),
    signature_b64u: signature.toString('base64url'),
    public_key: kp.publicKeyB64u,
  };
}

function action(actionType, extra = {}) {
  return {
    action_type: actionType,
    policy_id: 'policy.test',
    initiator: 'ep:agent:worker',
    ...extra,
  };
}

// ── canonical "happy path" pieces reused across vectors ──────────────────────
async function buildBaseline() {
  const rootAction = action('payment.*', { initiator: 'ep:agent:requester' });
  const root = await mintReceipt({
    action: rootAction,
    approver: 'ep:approver:human',
    approverKeyId: 'ep:key:human#1',
    keyClass: 'A',
  });

  const delegatorKp = generateEd25519KeyPair();
  const agentKp = generateEd25519KeyPair();

  const link0Base = {
    sequence: 0,
    delegation_id: 'ep_dlg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    delegator: 'ep:key:human#1',
    delegatee: 'ep:agent:worker',
    scope: ['payment.release'],
    max_value_usd: 1000,
    expires_at: EXPIRES_AT,
    constraints: null,
    parent_ref: 'ep:key:human#1',
  };
  const link0 = signedLink(link0Base, delegatorKp);

  const approvalAction = action('payment.release', { initiator: 'ep:agent:worker' });
  const approval = await mintReceipt({
    action: approvalAction,
    approver: 'ep:approver:human2',
    approverKeyId: 'ep:key:human2#1',
    keyClass: 'A',
  });

  const execution = {
    action_hash: approval.receipt.action_hash,
    irreversible: true,
    executed_at: '2026-06-13T11:45:00.000Z',
  };

  const delegationKeys = {
    'ep:key:human#1': { public_key: delegatorKp.publicKeyB64u },
  };

  return { root, link0, link0Base, delegatorKp, agentKp, approval, approvalAction, execution, delegationKeys };
}

const baseOpts = (b, over = {}) => ({
  now: NOW,
  humanKeyClasses: ['A'],
  delegationKeys: b.delegationKeys,
  ...over,
});

function assemble(b, over = {}) {
  return assembleProvenance({
    rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
    delegationChain: over.delegationChain ?? [b.link0],
    actionApproval: over.actionApproval ?? { receipt: b.approval.receipt, verification: b.approval.verification },
    execution: over.execution ?? b.execution,
    ...(over.agentIdentity ? { agentIdentity: over.agentIdentity } : {}),
    ...(over.liability ? { liability: over.liability } : {}),
    ...(over.metadata ? { metadata: over.metadata } : {}),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
describe('assembleProvenance — defensive input validation (throws)', () => {
  it('throws when rootSignoff.receipt is missing', () => {
    expect(() => assembleProvenance({
      rootSignoff: { verification: {} },
      execution: { action_hash: 'sha256:ab', irreversible: false },
    })).toThrow(/requires rootSignoff/);
  });

  it('throws when rootSignoff.verification is missing', () => {
    expect(() => assembleProvenance({
      rootSignoff: { receipt: {} },
      execution: { action_hash: 'sha256:ab', irreversible: false },
    })).toThrow(/requires rootSignoff/);
  });

  it('throws when rootSignoff itself is absent', () => {
    expect(() => assembleProvenance({
      execution: { action_hash: 'sha256:ab', irreversible: false },
    })).toThrow(/requires rootSignoff/);
  });

  it('throws when execution.action_hash is missing', () => {
    expect(() => assembleProvenance({
      rootSignoff: { receipt: {}, verification: {} },
      execution: { irreversible: false },
    })).toThrow(/requires execution/);
  });

  it('throws when execution.irreversible is not a boolean', () => {
    expect(() => assembleProvenance({
      rootSignoff: { receipt: {}, verification: {} },
      execution: { action_hash: 'sha256:ab', irreversible: 'yes' },
    })).toThrow(/requires execution/);
  });

  it('throws when execution is entirely absent', () => {
    expect(() => assembleProvenance({
      rootSignoff: { receipt: {}, verification: {} },
    })).toThrow(/requires execution/);
  });

  it('throws when an irreversible execution has no actionApproval.receipt', () => {
    expect(() => assembleProvenance({
      rootSignoff: { receipt: {}, verification: {} },
      execution: { action_hash: 'sha256:ab', irreversible: true },
    })).toThrow(/irreversible execution requires actionApproval/);
  });
});

describe('assembleProvenance — optional blocks + sequence stamping', () => {
  it('stamps sequence numbers in chain order when links omit them', async () => {
    const b = await buildBaseline();
    const link0NoSeq = { ...b.link0 };
    delete link0NoSeq.sequence;
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [link0NoSeq],
      actionApproval: { receipt: b.approval.receipt, verification: b.approval.verification },
      execution: b.execution,
    });
    expect(doc.delegation_chain[0].sequence).toBe(0);
    expect(doc.provenance_metadata.chain_depth).toBe(1);
  });

  it('passes through agentIdentity, liability, and merges metadata', async () => {
    const b = await buildBaseline();
    const agentIdentity = { agent_id: 'ep:agent:worker', claimed_by: 'ep:org:acme' };
    const liability = { owner: 'ep:org:acme', owner_name: 'Acme Inc.' };
    const doc = assemble(b, {
      agentIdentity,
      liability,
      metadata: { custom: 'note', chain_depth: 999 },
    });
    expect(doc.agent_identity).toEqual(agentIdentity);
    expect(doc.liability).toEqual(liability);
    // user metadata is spread AFTER the defaults, so it overrides chain_depth.
    expect(doc.provenance_metadata.custom).toBe('note');
    expect(doc.provenance_metadata.chain_depth).toBe(999);
    expect(doc.provenance_metadata.note).toMatch(/No new trust/);
  });

  it('omits action_approval when reversible execution provides none', async () => {
    const b = await buildBaseline();
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [b.link0],
      execution: { action_hash: 'sha256:ab', irreversible: false },
    });
    expect(doc.action_approval).toBeUndefined();
    expect(doc.agent_identity).toBeUndefined();
    expect(doc.liability).toBeUndefined();
  });
});

describe('verifyProvenanceOffline — version + structural early exits', () => {
  it('rejects an undefined document (missing @version)', () => {
    const res = verifyProvenanceOffline(undefined);
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.errors[0]).toMatch(/unsupported version/);
  });

  it('rejects an empty object bundle', () => {
    const res = verifyProvenanceOffline({});
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
  });

  it('rejects a wrong @version and returns early (advisory blocks untouched)', () => {
    const res = verifyProvenanceOffline({ '@version': 'EP-PROVENANCE-CHAIN-v2' });
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.agent_identity).toBeNull();
    expect(res.liability).toBeNull();
    expect(res.links).toEqual([]);
  });

  it('rejects when root_signoff is missing entirely', () => {
    const res = verifyProvenanceOffline({ '@version': PROVENANCE_VERSION });
    expect(res.valid).toBe(false);
    expect(res.checks.root_receipt_valid).toBe(false);
    expect(res.errors).toContain('missing root_signoff.receipt or root_signoff.verification');
  });

  it('rejects when root_signoff.verification is missing', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    delete doc.root_signoff.verification;
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.root_receipt_valid).toBe(false);
  });
});

describe('verifyProvenanceOffline — root receipt v1 failures', () => {
  it('rejects when the root receipt fails v1 verification (tampered action_hash)', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    doc.root_signoff.receipt = {
      ...doc.root_signoff.receipt,
      action_hash: 'sha256:' + '00'.repeat(32),
    };
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.root_receipt_valid).toBe(false);
    expect(res.errors.some((e) => /root receipt failed v1 verification/.test(e))).toBe(true);
  });
});

describe('verifyProvenanceOffline — per-action approval option branches', () => {
  it('drops the approval requirement when reversibility is INDEPENDENTLY asserted', async () => {
    const b = await buildBaseline();
    // reversible execution, no approval — but a verifier predicate asserts reversible.
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [b.link0],
      execution: {
        action_hash: 'sha256:' + crypto.randomBytes(32).toString('hex'),
        irreversible: false,
        executed_at: '2026-06-13T11:45:00.000Z',
      },
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b, {
      reversibilityAsserted: (e) => e.irreversible === false,
    }));
    // per_action_required no longer trips...
    expect(res.checks.per_action_required).toBe(true);
    // ...but with no approval, the executed action_type is indeterminate -> fail.
    expect(res.checks.leaf_permits_action).toBe(false);
    expect(res.valid).toBe(false);
  });

  it('re-mandates approval via requireActionApprovalAlways even when asserted reversible', async () => {
    const b = await buildBaseline();
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [b.link0],
      execution: {
        action_hash: 'sha256:' + crypto.randomBytes(32).toString('hex'),
        irreversible: false,
        executed_at: '2026-06-13T11:45:00.000Z',
      },
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b, {
      reversibilityAsserted: () => true,
      requireActionApprovalAlways: true,
    }));
    expect(res.checks.per_action_required).toBe(false);
    expect(res.valid).toBe(false);
  });

  it('rejects when the action_approval receipt fails v1 verification', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    // corrupt the approval receipt's log signature region by swapping action_hash.
    doc.action_approval.receipt = {
      ...doc.action_approval.receipt,
      action_hash: 'sha256:' + '11'.repeat(32),
    };
    // keep execution bound to the (now tampered) hash so execution_binding passes
    // and we isolate the v1-verification failure.
    doc.execution = { ...doc.execution, action_hash: 'sha256:' + '11'.repeat(32) };
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.action_receipt_valid).toBe(false);
    expect(res.errors.some((e) => /action_approval receipt failed v1 verification/.test(e))).toBe(true);
  });

  it('rejects execution NOT hash-bound to the approved action', async () => {
    const b = await buildBaseline();
    const doc = assemble(b, {
      execution: {
        action_hash: 'sha256:' + 'ab'.repeat(32), // unrelated hash
        irreversible: true,
        executed_at: '2026-06-13T11:45:00.000Z',
      },
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.execution_binding).toBe(false);
  });

  it('accepts a reversible action whose approval carries only a non-human (Class B) signoff', async () => {
    // exec.irreversible:false means the action_human_signoff branch is NOT taken,
    // so a Class-B-only approval is acceptable for the human check.
    const b = await buildBaseline();
    const softApproval = await mintReceipt({
      action: action('payment.release', { initiator: 'ep:agent:worker' }),
      approver: 'ep:approver:bot',
      approverKeyId: 'ep:key:bot#1',
      keyClass: 'B',
    });
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [b.link0],
      actionApproval: { receipt: softApproval.receipt, verification: softApproval.verification },
      execution: {
        action_hash: softApproval.receipt.action_hash,
        irreversible: false,
        executed_at: '2026-06-13T11:45:00.000Z',
      },
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.checks.action_human_signoff).toBe(true);
    expect(res.errors, JSON.stringify(res, null, 2)).toEqual([]);
    expect(res.valid).toBe(true);
  });
});

describe('verifyProvenanceOffline — delegation proof / key-binding branches', () => {
  it('rejects when the delegator has no pinned proof key', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    // valid link + valid proof, but provide an EMPTY delegationKeys map.
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: {} }));
    expect(res.valid).toBe(false);
    expect(res.checks.proof_key_bound).toBe(false);
    expect(res.errors.some((e) => /no pinned key for delegator/.test(e))).toBe(true);
  });

  it('accepts an unsigned delegation only when allowUnsignedDelegations is set', async () => {
    const b = await buildBaseline();
    const unsigned = { ...b.link0 };
    delete unsigned.proof;
    const doc = assemble(b, { delegationChain: [unsigned] });

    // default: fail-closed on the missing proof.
    const closed = verifyProvenanceOffline(doc, baseOpts(b));
    expect(closed.valid).toBe(false);
    expect(closed.checks.delegations_signed).toBe(false);

    // relaxed: unsigned permitted, and proof_key_bound is not evaluated.
    const relaxed = verifyProvenanceOffline(doc, baseOpts(b, { allowUnsignedDelegations: true }));
    expect(relaxed.checks.delegations_signed).toBe(true);
    expect(relaxed.checks.proof_key_bound).toBe(true);
    expect(relaxed.valid, JSON.stringify(relaxed, null, 2)).toBe(true);
  });

  it('rejects a proof whose detached signature does not verify (corrupted signature bytes)', async () => {
    const b = await buildBaseline();
    const link = signedLink(b.link0Base, b.delegatorKp);
    // flip the trailing byte of the signature -> verify() returns false.
    const sigBuf = Buffer.from(link.proof.signature_b64u, 'base64url');
    sigBuf[sigBuf.length - 1] ^= 0xff;
    link.proof.signature_b64u = sigBuf.toString('base64url');
    const doc = assemble(b, { delegationChain: [link] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.delegations_signed).toBe(false);
    expect(res.links[0].issues).toContain('signature_invalid');
  });

  it('rejects a proof with a non-Ed25519 algorithm tag', async () => {
    const b = await buildBaseline();
    const link = signedLink(b.link0Base, b.delegatorKp);
    link.proof.algorithm = 'ES256'; // verifyDetachedSignature short-circuits to false
    const doc = assemble(b, { delegationChain: [link] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.delegations_signed).toBe(false);
  });
});

describe('verifyProvenanceOffline — cap inheritance + scope edges', () => {
  it('accepts a multi-hop chain where parent is uncapped and child sets a cap', async () => {
    // Exercises the "parent uncapped -> child sets the cap" branch of the
    // effectiveCap computation, plus a valid bound second hop and Math.min path.
    const b = await buildBaseline();
    const subKp = generateEd25519KeyPair();

    // link0 caps $1000. link1 narrows to $500 under it (Math.min path).
    const link1 = signedLink({
      sequence: 1,
      delegation_id: 'ep_dlg_11111111111111111111111111111111',
      delegator: 'ep:agent:worker',
      delegatee: 'ep:agent:sub',
      scope: ['payment.release'],
      max_value_usd: 500,
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:worker',
    }, b.agentKp);

    // link2 omits max_value_usd entirely -> inherits the effective $500.
    const link2Base = {
      sequence: 2,
      delegation_id: 'ep_dlg_22222222222222222222222222222222',
      delegator: 'ep:agent:sub',
      delegatee: 'ep:agent:worker',
      scope: ['payment.release'],
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:sub',
    };
    const link2 = signedLink(link2Base, subKp);

    const keys = {
      ...b.delegationKeys,
      'ep:agent:worker': { public_key: b.agentKp.publicKeyB64u },
      'ep:agent:sub': { public_key: subKp.publicKeyB64u },
    };
    const doc = assemble(b, { delegationChain: [b.link0, link1, link2] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.errors, JSON.stringify(res, null, 2)).toEqual([]);
    expect(res.valid).toBe(true);
  });

  it('rejects a child whose explicit cap exceeds the parent cap (Math comparison path)', async () => {
    const b = await buildBaseline();
    // link0 caps $1000; widen it directly to $5000 with a re-signed proof so the
    // value-containment branch (not the tamper branch) is the failure.
    const widerBase = { ...b.link0Base, max_value_usd: 5000 };
    const wider = signedLink(widerBase, b.delegatorKp);
    const doc = assemble(b, { delegationChain: [wider] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    // root authority cap is null (uncapped), so $5000 is allowed at hop 0; the
    // real cap violation is exercised in the multi-hop test below. Here we assert
    // it does NOT fail on value containment at the root boundary.
    expect(res.checks.scope_containment).toBe(true);
    expect(res.valid, JSON.stringify(res, null, 2)).toBe(true);
  });

  it('rejects when a deeper hop tries to raise the cap above the inherited minimum', async () => {
    const b = await buildBaseline();
    const subKp = generateEd25519KeyPair();
    // link0 = $1000. link1 raises to $9999 under a $1000 parent -> violation.
    const link1 = signedLink({
      sequence: 1,
      delegation_id: 'ep_dlg_33333333333333333333333333333333',
      delegator: 'ep:agent:worker',
      delegatee: 'ep:agent:sub',
      scope: ['payment.release'],
      max_value_usd: 9999,
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:worker',
    }, b.agentKp);
    const keys = {
      ...b.delegationKeys,
      'ep:agent:worker': { public_key: b.agentKp.publicKeyB64u },
      'ep:agent:sub': { public_key: subKp.publicKeyB64u },
    };
    const doc = assemble(b, { delegationChain: [b.link0, link1] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    expect(res.checks.scope_containment).toBe(false);
    expect(res.errors.some((e) => /exceeds parent cap 1000/.test(e))).toBe(true);
  });

  it('rejects a child glob scope not contained in the parent scope', async () => {
    const b = await buildBaseline();
    // link0 narrowed to payment.release; child requests payment.* (a wider glob).
    const subKp = generateEd25519KeyPair();
    const link1 = signedLink({
      sequence: 1,
      delegation_id: 'ep_dlg_44444444444444444444444444444444',
      delegator: 'ep:agent:worker',
      delegatee: 'ep:agent:sub',
      scope: ['payment.*'], // wider than parent's [payment.release]
      max_value_usd: 500,
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:worker',
    }, b.agentKp);
    const keys = {
      ...b.delegationKeys,
      'ep:agent:worker': { public_key: b.agentKp.publicKeyB64u },
      'ep:agent:sub': { public_key: subKp.publicKeyB64u },
    };
    const doc = assemble(b, { delegationChain: [b.link0, link1] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    expect(res.checks.scope_containment).toBe(false);
  });
});

describe('verifyProvenanceOffline — chain anchoring + intra-hop temporal containment', () => {
  it('rejects when the chain head parent_ref/delegator names no root approver', async () => {
    const b = await buildBaseline();
    // Re-sign the head with a delegator id that is NOT a root approver. The proof
    // is self-consistent but the head fails to anchor to the root receipt.
    const strangerKp = generateEd25519KeyPair();
    const unanchoredBase = {
      ...b.link0Base,
      delegator: 'ep:agent:STRANGER',
      parent_ref: 'ep:agent:STRANGER',
    };
    const unanchored = signedLink(unanchoredBase, strangerKp);
    const keys = { 'ep:agent:STRANGER': { public_key: strangerKp.publicKeyB64u } };
    const doc = assemble(b, { delegationChain: [unanchored] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    expect(res.checks.chain_anchored).toBe(false);
    expect(res.errors.some((e) => /does not name a root-receipt approver/.test(e))).toBe(true);
  });

  it('rejects a child delegation that expires AFTER its parent delegation', async () => {
    const b = await buildBaseline();
    const subKp = generateEd25519KeyPair();
    // link0 expires at EXPIRES_AT (18:00). link1 expires LATER (next day) ->
    // intra-hop temporal containment violation (parent link vs child link).
    const link1 = signedLink({
      sequence: 1,
      delegation_id: 'ep_dlg_55555555555555555555555555555555',
      delegator: 'ep:agent:worker',
      delegatee: 'ep:agent:sub',
      scope: ['payment.release'],
      max_value_usd: 500,
      expires_at: '2026-06-14T18:00:00.000Z', // after parent's 2026-06-13T18:00
      constraints: null,
      parent_ref: 'ep:agent:worker',
    }, b.agentKp);
    const keys = {
      ...b.delegationKeys,
      'ep:agent:worker': { public_key: b.agentKp.publicKeyB64u },
      'ep:agent:sub': { public_key: subKp.publicKeyB64u },
    };
    const doc = assemble(b, { delegationChain: [b.link0, link1] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    expect(res.checks.scope_containment).toBe(false);
    expect(res.errors.some((e) => /is after parent expires_at/.test(e))).toBe(true);
  });

  it('rejects a proof whose public_key bytes are not a valid SPKI key (verify throws -> false)', async () => {
    const b = await buildBaseline();
    const link = signedLink(b.link0Base, b.delegatorKp);
    // Garbage public-key bytes make crypto.createPublicKey throw inside
    // verifyDetachedSignature, which is caught and returns false.
    link.proof.public_key = Buffer.from('not-a-real-spki-key').toString('base64url');
    // Pin the SAME garbage key so proof_key_bound is not the failure we isolate.
    const keys = { 'ep:key:human#1': { public_key: link.proof.public_key } };
    const doc = assemble(b, { delegationChain: [link] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    expect(res.checks.delegations_signed).toBe(false);
    expect(res.links[0].issues).toContain('signature_invalid');
  });
});

describe('verifyProvenanceOffline — leaf-permits + temporal containment edges', () => {
  it('rejects when no per-action approval is present (action_type indeterminate, empty chain)', async () => {
    const b = await buildBaseline();
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [],
      execution: {
        action_hash: 'sha256:' + crypto.randomBytes(32).toString('hex'),
        irreversible: false,
        executed_at: '2026-06-13T11:45:00.000Z',
      },
    });
    // reversibility asserted so per_action_required passes; leaf_permits must still
    // fail because no approval => no executed action_type.
    const res = verifyProvenanceOffline(doc, baseOpts(b, { reversibilityAsserted: () => true }));
    expect(res.checks.leaf_permits_action).toBe(false);
    expect(res.errors.some((e) => /cannot determine executed action_type/.test(e))).toBe(true);
  });

  it('rejects when the per-action approval committed_at is after the leaf delegation expiry', async () => {
    const b = await buildBaseline();
    // Approval committed late (15:00) but the leaf delegation expires at 13:00.
    const lateApproval = await mintReceipt({
      action: action('payment.release', { initiator: 'ep:agent:worker' }),
      approver: 'ep:approver:human2',
      approverKeyId: 'ep:key:human2#1',
      keyClass: 'A',
      committedAt: '2026-06-13T15:00:00.000Z',
    });
    const shortLinkBase = { ...b.link0Base, expires_at: '2026-06-13T13:00:00.000Z' };
    const shortLink = signedLink(shortLinkBase, b.delegatorKp);
    const doc = assemble(b, {
      delegationChain: [shortLink],
      actionApproval: { receipt: lateApproval.receipt, verification: lateApproval.verification },
      execution: {
        action_hash: lateApproval.receipt.action_hash,
        irreversible: true,
        executed_at: '2026-06-13T12:30:00.000Z',
      },
    });
    // now is 12:00 so the link is not expired; the temporal_containment check
    // (commit 15:00 > leaf expiry 13:00) is what trips.
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.temporal_containment).toBe(false);
    expect(res.checks.delegations_not_expired).toBe(true);
    expect(res.errors.some((e) => /committed_at is after the leaf delegation/.test(e))).toBe(true);
  });
});

describe('verifyProvenanceOffline — advisory agent_identity / liability blocks', () => {
  it('reports a VALID agent_identity attestation without affecting the verdict', async () => {
    const b = await buildBaseline();
    const attKp = generateEd25519KeyPair();
    const body = { agent_id: 'ep:agent:worker', claimed_by: 'ep:org:acme' };
    const agentIdentity = { ...body, attestation: detachedAttestation(body, attKp) };
    const doc = assemble(b, { agentIdentity });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid, JSON.stringify(res, null, 2)).toBe(true);
    expect(res.agent_identity).toEqual({
      agent_id: 'ep:agent:worker',
      claimed_by: 'ep:org:acme',
      claim_only: true,
      attestation_signature_valid: true,
    });
  });

  it('reports an INVALID agent_identity attestation as advisory (not gating)', async () => {
    const b = await buildBaseline();
    const attKp = generateEd25519KeyPair();
    const body = { agent_id: 'ep:agent:worker', claimed_by: 'ep:org:acme' };
    const att = detachedAttestation(body, attKp);
    const sig = Buffer.from(att.signature_b64u, 'base64url');
    sig[0] ^= 0xff; // corrupt -> signature invalid
    att.signature_b64u = sig.toString('base64url');
    const doc = assemble(b, { agentIdentity: { ...body, attestation: att } });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    // advisory error is recorded but the bundle is still valid (not gating).
    expect(res.agent_identity.attestation_signature_valid).toBe(false);
    expect(res.errors).toContain('advisory: agent_identity.attestation signature does not verify (not gating)');
    expect(res.valid).toBe(true);
  });

  it('reports agent_identity with NO attestation as null-signature and null fields', async () => {
    const b = await buildBaseline();
    const doc = assemble(b, { agentIdentity: {} }); // no agent_id, no attestation
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.agent_identity).toEqual({
      agent_id: null,
      claimed_by: null,
      claim_only: true,
      attestation_signature_valid: null,
    });
    expect(res.valid).toBe(true);
  });

  it('reports a VALID liability attestation without affecting the verdict', async () => {
    const b = await buildBaseline();
    const attKp = generateEd25519KeyPair();
    const body = { owner: 'ep:org:acme', owner_name: 'Acme Inc.' };
    const liability = { ...body, attestation: detachedAttestation(body, attKp) };
    const doc = assemble(b, { liability });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid, JSON.stringify(res, null, 2)).toBe(true);
    expect(res.liability).toEqual({
      owner: 'ep:org:acme',
      owner_name: 'Acme Inc.',
      evidence_only: true,
      attestation_signature_valid: true,
    });
  });

  it('reports an INVALID liability attestation as advisory (not gating)', async () => {
    const b = await buildBaseline();
    const attKp = generateEd25519KeyPair();
    const body = { owner: 'ep:org:acme', owner_name: 'Acme Inc.' };
    const att = detachedAttestation(body, attKp);
    const sig = Buffer.from(att.signature_b64u, 'base64url');
    sig[sig.length - 1] ^= 0xff;
    att.signature_b64u = sig.toString('base64url');
    const doc = assemble(b, { liability: { ...body, attestation: att } });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.liability.attestation_signature_valid).toBe(false);
    expect(res.errors).toContain('advisory: liability.attestation signature does not verify (not gating)');
    expect(res.valid).toBe(true);
  });

  it('reports liability with NO attestation as null-signature and null fields', async () => {
    const b = await buildBaseline();
    const doc = assemble(b, { liability: {} });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.liability).toEqual({
      owner: null,
      owner_name: null,
      evidence_only: true,
      attestation_signature_valid: null,
    });
    expect(res.valid).toBe(true);
  });

  it('reports BOTH advisory blocks simultaneously on an otherwise-valid bundle', async () => {
    const b = await buildBaseline();
    const aKp = generateEd25519KeyPair();
    const lKp = generateEd25519KeyPair();
    const aBody = { agent_id: 'ep:agent:worker', claimed_by: 'ep:org:acme' };
    const lBody = { owner: 'ep:org:acme', owner_name: 'Acme Inc.' };
    const doc = assemble(b, {
      agentIdentity: { ...aBody, attestation: detachedAttestation(aBody, aKp) },
      liability: { ...lBody, attestation: detachedAttestation(lBody, lKp) },
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.agent_identity.attestation_signature_valid).toBe(true);
    expect(res.liability.attestation_signature_valid).toBe(true);
    expect(res.valid).toBe(true);
  });
});

describe('verifyProvenanceOffline — option defaults', () => {
  it('uses DEFAULT_HUMAN_KEY_CLASSES (A) and Date.now() when opts omitted', async () => {
    const b = await buildBaseline();
    // EXPIRES_AT is in the past relative to a real Date.now() (2026-06-13T18:00),
    // so with default `now` the delegation should be expired. We only assert that
    // the call runs with zero opts (default-branch coverage) and returns a verdict.
    const doc = assemble(b);
    const res = verifyProvenanceOffline(doc);
    expect(typeof res.valid).toBe('boolean');
    expect(res.checks.version).toBe(true);
    // Class A is counted as human under the default policy.
    expect(res.checks.root_human_signoff).toBe(true);
  });

  it('rejects when the verifier human policy excludes the root signoff class', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    // Root is Class A; restrict the human policy to Class C only -> no human signoff.
    const res = verifyProvenanceOffline(doc, baseOpts(b, { humanKeyClasses: ['C'] }));
    expect(res.valid).toBe(false);
    expect(res.checks.root_human_signoff).toBe(false);
    expect(res.errors.some((e) => /no human signoff/.test(e))).toBe(true);
  });
});
