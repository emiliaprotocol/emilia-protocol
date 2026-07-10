/**
 * EP-PROVENANCE-CHAIN-v1 — adversarial conformance suite.
 *
 * For each attack catalogued in conformance/vectors/provenance-chains.v1.json we
 * build a bundle that MUST verify { valid:false }, plus one well-formed bundle
 * that MUST verify { valid:true }. The cryptographic material is minted LIVE
 * here (real Ed25519 receipts + real delegation proofs over canonical bytes) so
 * the negatives are genuine forgery attempts, not hand-edited JSON that would
 * have failed v1 verification for an unrelated reason.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(path.join(__dirname, '..', 'conformance', 'vectors', 'provenance-chains.v1.json'), 'utf8'),
);

// ── Class-A (human / WebAuthn-shaped) signer over the raw context digest ─────
// verifyClassAOverDigest (packages/verify) checks: clientData.type=='webauthn.get',
// clientData.challenge==base64url(digest), authData UV flag set, and an ECDSA
// P-256/SHA-256 signature over authData||sha256(clientDataJSON). Class-A keys are
// P-256 (ES256), NOT Ed25519. We reproduce exactly that.
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
      // 32-byte rpIdHash + 1 flag byte (UP|UV) + 4 counter bytes = 37 bytes.
      const authData = Buffer.concat([
        crypto.createHash('sha256').update('rp').digest(), // 32
        Buffer.from([FLAG_UP | FLAG_UV]),                  // flags (user verified)
        Buffer.from([0, 0, 0, 1]),                         // counter
      ]);
      const signed = Buffer.concat([
        authData,
        crypto.createHash('sha256').update(clientDataJson).digest(),
      ]);
      const signature = crypto.sign('sha256', signed, privateKey).toString('base64url'); // DER ECDSA
      return {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataJson.toString('base64url'),
        signature,
      };
    },
  };
}

/**
 * Mint a genuinely-valid EP-RECEIPT-v1 receipt with a Class-A human signoff,
 * plus the verification material a verifier pins. keyClass is configurable so we
 * can also mint a Class-B (non-human) signoff for the human-override vector.
 */
function mintReceipt({
  action,
  approver = 'ep:approver:human',
  approverKeyId = 'ep:key:human#1',
  keyClass = 'A',
  issuedAt = ISSUED_AT,
  expiresAt = EXPIRES_AT,
  committedAt = '2026-06-13T11:30:00.000Z',
}) {
  // Class A approver keys are P-256 (ES256); Class B/C are Ed25519.
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

  // collectSignoffs is async (Class A awaits signWebAuthn) — but we resolve it
  // synchronously here via a deasync-free trick: it returns a Promise, so the
  // caller must await. Keep mintReceipt async.
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
          approver_id: approver,
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

// ── delegation proof: sign the CANONICAL bytes of the link's OWN fields ──────
// This mirrors what the hardened verifier independently recomputes. The signed
// material is exactly the proof-covered subset of the link.
const PROOF_FIELDS = [
  'delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints',
];

function proofPayloadBytes(link) {
  const subset = {};
  for (const f of PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

/** Build a delegation link and attach a valid proof signed by `delegatorKp`. */
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

// Action factory — policy_id + initiator are required by buildContexts.
function action(actionType, extra = {}) {
  return {
    action_type: actionType,
    policy_id: 'policy.test',
    initiator: 'ep:agent:worker',
    ...extra,
  };
}

// ── canonical "happy path" pieces reused across vectors ──────────────────────
// Root authorizes payment.* ; one delegation narrows to payment.release ;
// per-action approval + execution are for payment.release.
async function buildBaseline() {
  const rootAction = action('payment.*', { initiator: 'ep:agent:requester' });
  const root = await mintReceipt({
    action: rootAction,
    approver: 'ep:approver:human',
    approverKeyId: 'ep:key:human#1',
    keyClass: 'A',
  });

  // delegator key is bound to the root approver id via the keyMap below.
  const delegatorKp = generateEd25519KeyPair();
  const agentKp = generateEd25519KeyPair();

  const link0Base = {
    sequence: 0,
    delegation_id: 'ep_dlg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    delegator: 'ep:key:human#1',     // names the root approver_key_id
    delegatee: 'ep:agent:worker',
    scope: ['payment.release'],
    max_value_usd: 1000,
    expires_at: EXPIRES_AT,           // within the root context window
    constraints: null,
    parent_ref: 'ep:key:human#1',    // sequence 0 binds to a root approver
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

  // key map: proof key for each delegator id (mirrors approver_keys shape).
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
    ...(over.metadata ? { metadata: over.metadata } : {}),
  });
}

describe('EP-PROVENANCE-CHAIN-v1 — vectors catalogue', () => {
  it('catalogue is the expected wire tag and version', () => {
    expect(PROVENANCE_VERSION).toBe('EP-PROVENANCE-CHAIN-v1');
    expect(VECTORS.wire_tag).toBe('EP-PROVENANCE-CHAIN-v1');
    expect(VECTORS.must_reject).toHaveLength(9);
    expect(VECTORS.must_accept).toHaveLength(1);
  });
});

describe('EP-PROVENANCE-CHAIN-v1 — positive (MUST verify valid:true)', () => {
  it('z_well_formed_positive', async () => {
    const b = await buildBaseline();
    const doc = assemble(b);
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.errors, JSON.stringify(res, null, 2)).toEqual([]);
    expect(res.valid).toBe(true);
  });
});

describe('EP-PROVENANCE-CHAIN-v1 — negatives (each MUST verify valid:false)', () => {
  // (a) broken inter-hop link: chain[1] does not bind to chain[0].delegatee
  it('a_broken_inter_hop_link', async () => {
    const b = await buildBaseline();

    // second hop signed by its own key, but parent_ref/delegator do NOT equal
    // link0.delegatee ('ep:agent:worker'); they point at an unrelated id.
    const hop1Kp = generateEd25519KeyPair();
    const link1Base = {
      sequence: 1,
      delegation_id: 'ep_dlg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      delegator: 'ep:agent:STRANGER',   // != link0.delegatee
      delegatee: 'ep:agent:subworker',
      scope: ['payment.release'],
      max_value_usd: 500,
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:STRANGER',  // != link0.delegatee
    };
    const link1 = signedLink(link1Base, hop1Kp);
    const keys = { ...b.delegationKeys, 'ep:agent:STRANGER': { public_key: hop1Kp.publicKeyB64u } };

    const doc = assemble(b, { delegationChain: [b.link0, link1] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid).toBe(false);
    // head IS anchored to root; the SECOND hop fails to bind to the prior delegatee.
    expect(res.checks.chain_links_bound).toBe(false);
  });

  // (b) tampered delegation: visible scope/cap/expiry != the signed canonical bytes
  it('b_tampered_delegation_fields', async () => {
    const b = await buildBaseline();
    // Take the validly-signed link, then WIDEN scope + cap after signing.
    const tampered = {
      ...b.link0,
      scope: ['payment.*', 'admin.*'],   // widened
      max_value_usd: 1_000_000,          // widened
      // proof unchanged — still over the original narrow fields.
    };
    const doc = assemble(b, { delegationChain: [tampered] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.delegations_signed).toBe(false);
  });

  // (c) key-substituted proof: signature verifies under a key NOT bound to delegator
  it('c_key_substituted_proof', async () => {
    const b = await buildBaseline();
    const attackerKp = generateEd25519KeyPair();
    // Re-sign the SAME canonical payload with the attacker key and swap the key.
    const link = signedLink(b.link0Base, attackerKp); // proof self-consistent...
    // ...but delegationKeys still maps delegator -> the LEGITIMATE key.
    const doc = assemble(b, { delegationChain: [link] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    // signature math is self-consistent over the right bytes; the KEY is wrong.
    expect(res.checks.proof_key_bound).toBe(false);
  });

  // (d) out-of-root-scope action (root authorizes payment.* only)
  it('d_out_of_root_scope_action', async () => {
    const b = await buildBaseline();
    // Leaf delegation + approval + execution are all for admin.delete — outside
    // root's payment.* authority. The delegation is internally self-consistent.
    const delegatorKp = b.delegatorKp;
    const evilLinkBase = {
      ...b.link0Base,
      scope: ['admin.delete'],   // child of root? root only granted payment.*
    };
    const evilLink = signedLink(evilLinkBase, delegatorKp);

    const evilApprovalAction = action('admin.delete', { initiator: 'ep:agent:worker' });
    const evilApproval = await mintReceipt({
      action: evilApprovalAction,
      approver: 'ep:approver:human2',
      approverKeyId: 'ep:key:human2#1',
      keyClass: 'A',
    });
    const execution = { action_hash: evilApproval.receipt.action_hash, irreversible: true, executed_at: '2026-06-13T11:45:00.000Z' };

    const doc = assemble(b, {
      delegationChain: [evilLink],
      actionApproval: { receipt: evilApproval.receipt, verification: evilApproval.verification },
      execution,
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    // either the link is not contained in root scope, or the leaf does not sit
    // under the derived root authority — both are gating failures.
    expect(res.checks.scope_containment === false || res.checks.leaf_permits_action === false).toBe(true);
  });

  // (e) empty delegation_chain, executed action outside root authority
  it('e_empty_chain_out_of_root_authority', async () => {
    const b = await buildBaseline();
    // Root authorizes payment.* ; approve+execute admin.delete with NO chain.
    const evilApprovalAction = action('admin.delete', { initiator: 'ep:agent:worker' });
    const evilApproval = await mintReceipt({
      action: evilApprovalAction,
      approver: 'ep:approver:human2',
      approverKeyId: 'ep:key:human2#1',
      keyClass: 'A',
    });
    const execution = { action_hash: evilApproval.receipt.action_hash, irreversible: true, executed_at: '2026-06-13T11:45:00.000Z' };

    const doc = assemble(b, {
      delegationChain: [],
      actionApproval: { receipt: evilApproval.receipt, verification: evilApproval.verification },
      execution,
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.leaf_permits_action).toBe(false);
  });

  // (f) irreversible action mislabeled execution.irreversible:false (drops approval)
  it('f_irreversible_mislabeled_false', async () => {
    const b = await buildBaseline();
    // No per-action approval at all, and producer claims irreversible:false to
    // try to skip it. Reversibility is NOT independently asserted, so approval
    // is required by default. Built WITHOUT assemble() so no approval is injected.
    const execution = {
      action_hash: 'sha256:' + crypto.randomBytes(32).toString('hex'),
      irreversible: false,   // the lie
      executed_at: '2026-06-13T11:45:00.000Z',
    };
    const doc = assembleProvenance({
      rootSignoff: { receipt: b.root.receipt, verification: b.root.verification },
      delegationChain: [],
      actionApproval: undefined,
      execution,
    });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.per_action_required).toBe(false);
  });

  // (g) per-document human-class override widening 'human' to include 'B'
  it('g_human_class_override_widening', async () => {
    const b = await buildBaseline();
    // Mint a root whose ONLY signoff is Class B (software, non-human).
    const rootAction = action('payment.*', { initiator: 'ep:agent:requester' });
    const softRoot = await mintReceipt({
      action: rootAction,
      approver: 'ep:approver:bot',
      approverKeyId: 'ep:key:bot#1',
      keyClass: 'B',
    });

    // Producer tries to widen the human set via the per-document field.
    const doc = assembleProvenance({
      rootSignoff: { receipt: softRoot.receipt, verification: softRoot.verification },
      delegationChain: [],
      actionApproval: { receipt: b.approval.receipt, verification: b.approval.verification },
      execution: b.execution,
    });
    doc.root_signoff.human_key_classes = ['A', 'B']; // the override attempt

    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.root_human_signoff).toBe(false);
  });

  // (h) expired delegation link
  it('h_expired_delegation_link', async () => {
    const b = await buildBaseline();
    const expiredBase = { ...b.link0Base, expires_at: '2020-01-01T00:00:00.000Z' };
    const expiredLink = signedLink(expiredBase, b.delegatorKp);
    const doc = assemble(b, { delegationChain: [expiredLink] });
    const res = verifyProvenanceOffline(doc, baseOpts(b));
    expect(res.valid).toBe(false);
    expect(res.checks.delegations_not_expired).toBe(false);
  });

  // (i) value-cap escalation via a null cap on a MIDDLE hop (depth>=2).
  // Root uncapped -> l0 caps $1,000 -> l1 cap=null (MUST inherit $1,000, not uncap)
  // -> l2 grants $10,000,000. The leaf cap must be rejected against the effective
  // inherited $1,000, not the raw null. Regression guard for the cross-hop fix.
  it('i_value_cap_escalation_null_mid_chain', async () => {
    const b = await buildBaseline();
    const subKp = generateEd25519KeyPair();

    const link1 = signedLink({
      sequence: 1,
      delegation_id: 'ep_dlg_cccccccccccccccccccccccccccccccc',
      delegator: 'ep:agent:worker',     // == link0.delegatee
      delegatee: 'ep:agent:sub',
      scope: ['payment.release'],
      max_value_usd: null,              // inherits $1,000 — must NOT uncap
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:worker',
    }, b.agentKp);

    const link2 = signedLink({
      sequence: 2,
      delegation_id: 'ep_dlg_dddddddddddddddddddddddddddddddd',
      delegator: 'ep:agent:sub',        // == link1.delegatee
      delegatee: 'ep:agent:worker',
      scope: ['payment.release'],
      max_value_usd: 10_000_000,        // 10,000x the effective $1,000 cap
      expires_at: EXPIRES_AT,
      constraints: null,
      parent_ref: 'ep:agent:sub',
    }, subKp);

    const keys = {
      ...b.delegationKeys,
      'ep:agent:worker': { public_key: b.agentKp.publicKeyB64u },
      'ep:agent:sub': { public_key: subKp.publicKeyB64u },
    };

    const doc = assemble(b, { delegationChain: [b.link0, link1, link2] });
    const res = verifyProvenanceOffline(doc, baseOpts(b, { delegationKeys: keys }));
    expect(res.valid, JSON.stringify(res, null, 2)).toBe(false);
    // the $10M leaf must fail value containment against the inherited $1,000 cap
    expect(res.checks.scope_containment).toBe(false);
  });
});
