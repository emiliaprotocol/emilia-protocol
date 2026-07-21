// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildPortableSignoffDecision } from '../lib/signoff/decision-evidence.ts';
import {
  buildAuthorizationContext,
  contextHashBytes,
  contextHashHex,
} from '../lib/webauthn.js';
import { verifyWebAuthnSignoff } from '../packages/verify/index.js';

const RP_ID = 'emiliaprotocol.ai';
const SIGNOFF_ID = `sig_${'d'.repeat(32)}`;
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;

function signedEvent({ signedDecision = 'denied', eventType = 'guard.signoff.rejected' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = buildAuthorizationContext({
    actionHash: ACTION_HASH,
    policyId: 'policy_wire_release',
    policyHash: `sha256:${'b'.repeat(64)}`,
    initiatorId: 'agent_treasury',
    approverId: 'cfo@example.com',
    signoffId: SIGNOFF_ID,
    issuedAt: '2026-07-13T20:00:00.000Z',
    expiresAt: '2026-07-13T20:05:00.000Z',
    decision: signedDecision,
    displayHash: `sha256:${'c'.repeat(64)}`,
  });
  const challenge = contextHashBytes(context).toString('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: 'https://www.emiliaprotocol.ai',
  }), 'utf8');
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signedBytes = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  const signature = crypto.sign('sha256', signedBytes, privateKey);

  return {
    event: {
      event_type: eventType,
      actor_id: 'cfo@example.com',
      created_at: '2026-07-13T20:01:00.000Z',
      after_state: {
        signoff_id: SIGNOFF_ID,
        approver_id: 'cfo@example.com',
        approved_action_hash: ACTION_HASH,
        decided_at: '2026-07-13T20:01:00.000Z',
        key_class: 'A',
        context,
        context_hash: contextHashHex(context),
        webauthn: {
          credential_id: 'cred_cfo_1',
          authenticator_data: authenticatorData.toString('base64url'),
          client_data_json: clientData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
      },
    },
    approverPublicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

describe('portable Class-A signoff decision evidence', () => {
  it('exports a device-signed denial that verifies offline under a pinned approver key', () => {
    const { event, approverPublicKey } = signedEvent();
    const record = buildPortableSignoffDecision(event);

    expect(record).toMatchObject({
      decision: 'denied',
      signoff_id: SIGNOFF_ID,
      approver_id: 'cfo@example.com',
      action_hash: ACTION_HASH,
      key_class: 'A',
      credential_id: 'cred_cfo_1',
    });
    expect(verifyWebAuthnSignoff(record.signoff, approverPublicKey, { rpId: RP_ID }).valid).toBe(true);
  });

  it('refuses to export an approval event carrying a signed denial', () => {
    const { event } = signedEvent({ eventType: 'guard.signoff.approved' });
    expect(buildPortableSignoffDecision(event)).toBeNull();
  });

  it('refuses internally substituted context, actor, action, hash, and bearer-only evidence', () => {
    const mutations = [
      (event) => { event.after_state.context.nonce = `sig_${'e'.repeat(32)}`; },
      (event) => { event.actor_id = 'operator@example.com'; },
      (event) => { event.after_state.approved_action_hash = `sha256:${'f'.repeat(64)}`; },
      (event) => { event.after_state.context_hash = '0'.repeat(64); },
      (event) => { event.after_state.key_class = 'C'; delete event.after_state.webauthn; },
    ];

    for (const mutate of mutations) {
      const { event } = signedEvent();
      mutate(event);
      expect(buildPortableSignoffDecision(event)).toBeNull();
    }
  });
});
