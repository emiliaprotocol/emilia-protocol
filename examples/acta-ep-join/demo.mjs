#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

import { issueTrustReceipt } from '../../lib/trust-receipt/issuer.js';
import { canonicalize } from '../../packages/verify/index.js';
import { actionDigest } from '../../packages/verify/evidence-chain.js';
import {
  ACTA_COMPONENT_TYPE,
  PAYMENT_RELEASE_MAPPING_PROFILE,
  PAYMENT_RELEASE_MAPPING_PROFILE_HASH,
  artifactDigest,
  computeActaActionRef,
  mapPaymentReleaseCaid,
} from './acta-profile.mjs';
import { ACTA_EP_REQUIREMENT, createActaEpExecutionGate } from './gate.mjs';

const RP_ID = 'treasury.example';
const ORIGIN = 'https://treasury.example';
const VERIFY_AT = '2026-07-14T18:00:30Z';
const EP_POLICY_HASH = `sha256:${crypto.createHash('sha256').update('ep:wires-over-100k:v12').digest('hex')}`;
const ACTA_POLICY_DIGEST = `sha256:${crypto.createHash('sha256').update('cedar:wire-release:v4').digest('hex')}`;
const ACTA_KID = 'sb:issuer:treasury-policy-engine-01';

function clone(value) {
  return structuredClone(value);
}

function digestText(value) {
  return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

/**
 * @returns {{
 *   approverKeyId: string,
 *   approverId: string,
 *   keyEntry: { approver_id: string, public_key: string, key_class: 'A', status: string, valid_from: string, valid_to: string, revoked_at: null },
 *   signer: {
 *     approverKeyId: string,
 *     keyClass: 'A',
 *     signedAt: string,
 *     signWebAuthn: (digest: Buffer) => { authenticator_data: string, client_data_json: string, signature: string },
 *   },
 * }}
 */
function classASigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const approverKeyId = 'ep:key:cfo-mrios#1';
  const approverId = 'ep:approver:mrios-cfo';
  return {
    approverKeyId,
    approverId,
    keyEntry: {
      approver_id: approverId,
      public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      key_class: 'A',
      status: 'active',
      valid_from: '2026-01-01T00:00:00Z',
      valid_to: '2027-01-01T00:00:00Z',
      revoked_at: null,
    },
    signer: {
      approverKeyId,
      keyClass: 'A',
      signedAt: '2026-07-14T18:00:18Z',
      signWebAuthn: (digest) => {
        const clientDataJSON = Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: digest.toString('base64url'),
          origin: ORIGIN,
        }), 'utf8');
        const authenticatorData = Buffer.concat([
          crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
          Buffer.from([0x05]),
          Buffer.from([0, 0, 0, 1]),
        ]);
        const signedData = Buffer.concat([
          authenticatorData,
          crypto.createHash('sha256').update(clientDataJSON).digest(),
        ]);
        return {
          authenticator_data: authenticatorData.toString('base64url'),
          client_data_json: clientDataJSON.toString('base64url'),
          signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
        };
      },
    },
  };
}

function logSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    logKeyId: 'ep:log:treasury-demo#1',
  };
}

function actaSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

export function signActaPayload(payload, privateKey) {
  return {
    payload: clone(payload),
    signature: {
      alg: 'EdDSA',
      kid: payload.issuer_id,
      sig: crypto.sign(
        null,
        Buffer.from(canonicalize(payload), 'utf8'),
        privateKey,
      ).toString('hex'),
    },
  };
}

function buildChain(action, actaReceipt, epReceipt) {
  return {
    '@version': 'EP-AEC-v1',
    action: clone(action),
    action_digest: `sha256:${actionDigest(action)}`,
    components: [
      { type: ACTA_COMPONENT_TYPE, label: 'machine policy decision', evidence: clone(actaReceipt) },
      { type: 'ep-receipt', label: 'named-human authorization', evidence: clone(epReceipt) },
    ],
    requirement: ACTA_EP_REQUIREMENT,
  };
}

export async function buildActaEpFixture() {
  const action = {
    ep_version: '1.0',
    action_type: 'payment.release.1',
    amount: '2400000.00',
    currency: 'USD',
    beneficiary_account: digestText('USABA021000021:9876543210'),
    payment_instruction_id: 'wire-8841',
    policy_id: 'ep:policy:wires-over-100k@v12',
    initiator: 'urn:agent:treasury:recon-7',
    requested_at: '2026-07-14T18:00:00Z',
  };
  const expectedActaEvaluation = {
    agentId: action.initiator,
    actionType: action.action_type,
    scopeRequired: [
      'payment.release',
      `payment.instruction:${action.payment_instruction_id}`,
      `payment.amount:${action.amount}:${action.currency}`,
    ],
    timestamp: action.requested_at,
  };

  const approver = classASigner();
  const log = logSigner();
  const machine = actaSigner();

  const issueEpReceipt = (receiptId) => issueTrustReceipt({
    receiptId,
    action,
    policyHash: EP_POLICY_HASH,
    approvers: [approver.approverId],
    requiredApprovals: 1,
    issuedAt: '2026-07-14T18:00:05Z',
    expiresAt: '2026-07-14T18:05:00Z',
    committedAt: '2026-07-14T18:00:22Z',
    signers: [approver.signer],
    log,
  });

  const epReceipt = await issueEpReceipt('ep:receipt:acta-join-001');
  const mapped = mapPaymentReleaseCaid(action);
  if (!mapped.ok) throw new Error(`CAID mapping failed: ${mapped.reasons.join(', ')}`);
  const actaPayload = {
    type: 'protectmcp:decision',
    tool_name: 'release_payment',
    decision: 'allow',
    policy_digest: ACTA_POLICY_DIGEST,
    action_ref: computeActaActionRef(expectedActaEvaluation),
    caid: mapped.caid,
    ep_action_digest: `sha256:${actionDigest(action)}`,
    human_authorization_ref: {
      format: 'EP-RECEIPT-v1',
      digest: artifactDigest(epReceipt),
    },
    issued_at: '2026-07-14T18:00:24Z',
    issuer_id: ACTA_KID,
  };
  const actaReceipt = signActaPayload(actaPayload, machine.privateKey);

  const actaPolicy = {
    expected_tool_name: 'release_payment',
    expected_decision: 'allow',
    expected_policy_digest: ACTA_POLICY_DIGEST,
    max_age_sec: 300,
    registry_checked_at: '2026-07-14T17:59:30Z',
    max_registry_age_sec: 300,
    mapping_profile: PAYMENT_RELEASE_MAPPING_PROFILE,
    mapping_profile_hash: PAYMENT_RELEASE_MAPPING_PROFILE_HASH,
    source_descriptor: PAYMENT_RELEASE_MAPPING_PROFILE.source_format,
  };
  const actaIssuerKeys = {
    [ACTA_KID]: {
      issuer_id: ACTA_KID,
      public_key: machine.publicKey,
      status: 'active',
      valid_from: '2026-01-01T00:00:00Z',
      valid_to: '2027-01-01T00:00:00Z',
      revoked_at: null,
    },
  };
  const epReceiptProfile = {
    approver_keys: { [approver.approverKeyId]: approver.keyEntry },
    log_public_key: log.pub,
    rp_id: RP_ID,
    allowed_origins: [ORIGIN],
    expected_policy_hash: EP_POLICY_HASH,
    max_age_sec: 300,
    registry_checked_at: '2026-07-14T17:59:30Z',
    max_registry_age_sec: 300,
  };

  return {
    action,
    expectedActaEvaluation,
    epReceipt,
    issueEpReceipt,
    actaReceipt,
    actaPayload,
    actaPrivateKey: machine.privateKey,
    chain: buildChain(action, actaReceipt, epReceipt),
    trust: { actaIssuerKeys, actaPolicy, epReceiptProfile },
    verificationTime: VERIFY_AT,
  };
}

export function gateFor(fixture, overrides = {}) {
  return createActaEpExecutionGate({
    ...fixture.trust,
    allowEphemeralState: true,
    now: () => new Date(fixture.verificationTime),
    ...overrides,
  });
}

async function mustNotExecute() {
  throw new Error('refused scenario reached the protected effect');
}

export async function runActaEpJoinDemo() {
  const fixture = await buildActaEpFixture();
  const request = {
    chain: fixture.chain,
    expectedAction: fixture.action,
    expectedActaEvaluation: fixture.expectedActaEvaluation,
  };

  let executions = 0;
  const liveGate = gateFor(fixture);
  const accepted = await liveGate.run(request, async () => {
    executions += 1;
    return { settlement_id: 'fedwire:20260714:8841' };
  });
  const replay = await liveGate.run(request, mustNotExecute);

  const changedAction = { ...fixture.action, amount: '24000000.00' };
  const changedChain = { ...clone(fixture.chain), action: changedAction };
  changedChain.action_digest = `sha256:${actionDigest(changedAction)}`;
  const actionSubstitution = await gateFor(fixture).run({
    chain: changedChain,
    expectedAction: changedAction,
    expectedActaEvaluation: fixture.expectedActaEvaluation,
  }, mustNotExecute);

  const unpinnedIssuer = await gateFor(fixture, { actaIssuerKeys: {} }).run(request, mustNotExecute);

  const roleSubstitutionChain = clone(fixture.chain);
  roleSubstitutionChain.components[1] = {
    type: 'ep-receipt',
    label: 'machine receipt relabeled as human evidence',
    evidence: clone(fixture.actaReceipt),
  };
  const roleSubstitution = await gateFor(fixture).run({
    ...request,
    chain: roleSubstitutionChain,
  }, mustNotExecute);

  const stale = await gateFor(fixture, {
    now: () => new Date('2026-07-14T18:10:00Z'),
  }).run(request, mustNotExecute);

  const otherEpReceipt = await fixture.issueEpReceipt('ep:receipt:acta-join-002');
  const swappedReceiptChain = clone(fixture.chain);
  swappedReceiptChain.components[1].evidence = otherEpReceipt;
  const receiptSwap = await gateFor(fixture).run({
    ...request,
    chain: swappedReceiptChain,
  }, mustNotExecute);

  const embeddedKeyPayload = {
    ...fixture.actaPayload,
    public_key: fixture.trust.actaIssuerKeys[ACTA_KID].public_key,
  };
  const embeddedKeyChain = clone(fixture.chain);
  embeddedKeyChain.components[0].evidence = signActaPayload(
    embeddedKeyPayload,
    fixture.actaPrivateKey,
  );
  const embeddedKey = await gateFor(fixture).run({
    ...request,
    chain: embeddedKeyChain,
  }, mustNotExecute);

  const result = {
    valid_pair: accepted.allow === true && executions === 1 ? 'executed_once' : accepted.reason,
    replay: replay.reason,
    action_substitution: actionSubstitution.reason,
    unpinned_acta_key: unpinnedIssuer.reason,
    machine_as_human: roleSubstitution.reason,
    stale_human_approval: stale.reason,
    different_ep_receipt: receiptSwap.reason,
    embedded_acta_key: embeddedKey.reason,
  };
  const expected = {
    valid_pair: 'executed_once',
    replay: 'replay_refused',
    action_substitution: 'aec_refused',
    unpinned_acta_key: 'aec_refused',
    machine_as_human: 'aec_refused',
    stale_human_approval: 'aec_refused',
    different_ep_receipt: 'aec_refused',
    embedded_acta_key: 'aec_refused',
  };
  if (JSON.stringify(result) !== JSON.stringify(expected)) {
    throw new Error(`unexpected ACTA + EP result: ${JSON.stringify(result)}`);
  }
  return result;
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const result = await runActaEpJoinDemo();
  console.log('ACTA + EP: machine policy allowed AND a named human approved the exact action.');
  console.log(JSON.stringify(result, null, 2));
}
