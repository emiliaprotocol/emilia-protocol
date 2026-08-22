// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { afterEach, describe, expect, it } from 'vitest';

import {
  AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION,
  AGENT_MAILBOX_ENVELOPE_VERSION,
  admitMailboxActionProposal,
  agentMailboxDigest,
  createAgentMailbox,
  createAgentMailboxEnvelope,
  createFileAgentMailboxStore,
  createMemoryAgentMailboxStore,
  extractMailboxActionProposal,
  verifyAgentMailboxDeliveryReceipt,
  verifyAgentMailboxEnvelope,
} from '../lib/agent-mailbox.js';
import { createCurtailmentAction, graceDigest } from '../lib/grace/mobile-grid.js';

const NOW = '2026-08-22T20:00:00.000Z';
const LATER = '2026-08-22T21:00:00.000Z';

function keyPair(keyId: string) {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    keyId,
    privateKey: pair.privateKey,
    publicKeySpkiB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const smith = keyPair('agent-smith-signing-1');
const iman = keyPair('agent-iman-signing-1');
const mailboxService = keyPair('nomadic-mailbox-signing-1');

function senderDirectory(overrides: Record<string, unknown> = {}) {
  return {
    'agent:smith': {
      key_id: smith.keyId,
      public_key_spki_b64u: smith.publicKeySpkiB64u,
      status: 'active',
    },
    'agent:iman': {
      key_id: iman.keyId,
      public_key_spki_b64u: iman.publicKeySpkiB64u,
      status: 'active',
    },
    ...overrides,
  };
}

function noteEnvelope(input: Record<string, unknown> = {}) {
  return createAgentMailboxEnvelope({
    senderId: 'agent:smith',
    recipientId: 'agent:iman',
    threadId: 'thread:smith-iman-demo',
    sequence: 1,
    messageType: 'note',
    payload: { text: 'The GRACE test proposal is ready.' },
    createdAt: NOW,
    expiresAt: LATER,
    privateKey: smith.privateKey,
    keyId: smith.keyId,
    ...input,
  });
}

function mailbox(store = createMemoryAgentMailboxStore()) {
  return createAgentMailbox({
    mailboxId: 'mailbox:nomadic-demo',
    store,
    senderDirectory: senderDirectory(),
    privateKey: mailboxService.privateKey,
    keyId: mailboxService.keyId,
    now: () => NOW,
  });
}

const tempDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(tempDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('EP agent mailbox envelope', () => {
  it('matches the closed interoperability schema', async () => {
    const schema = JSON.parse(await readFile(
      new URL('../conformance/schemas/agent-mailbox-envelope.v0.1.schema.json', import.meta.url),
      'utf8',
    ));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    expect(validate(noteEnvelope()), JSON.stringify(validate.errors)).toBe(true);
  });

  it('signs and verifies one recipient-bound envelope under a pinned sender key', () => {
    const envelope = noteEnvelope();
    expect(envelope['@version']).toBe(AGENT_MAILBOX_ENVELOPE_VERSION);
    expect(envelope.authority).toEqual({ authorizes: false });
    expect(envelope.payload_digest).toBe(agentMailboxDigest(envelope.payload));

    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(),
      expectedRecipientId: 'agent:iman',
      asOf: NOW,
    })).toMatchObject({
      verified: true,
      accepted: true,
      reason: null,
      envelope_digest: agentMailboxDigest(envelope),
      authorizes: false,
    });
  });

  it('refuses payload tampering even if the attacker recomputes the unsigned payload digest', () => {
    const envelope: any = structuredClone(noteEnvelope());
    envelope.payload.text = 'Dispatch immediately.';
    envelope.payload_digest = agentMailboxDigest(envelope.payload);
    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    })).toMatchObject({ accepted: false, reason: 'signature_invalid' });
  });

  it('refuses an unpinned sender, wrong recipient, expired message, unknown member, and symbol member', () => {
    const envelope: any = noteEnvelope();
    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: {}, expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('sender_key_not_pinned');
    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:mallory', asOf: NOW,
    }).reason).toBe('recipient_mismatch');
    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: '2026-08-22T21:00:00.001Z',
    }).reason).toBe('envelope_expired');
    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: '2026-08-22T19:59:59.999Z',
    }).reason).toBe('envelope_not_yet_valid');

    const widened: any = structuredClone(envelope);
    widened.hidden_authority = true;
    expect(verifyAgentMailboxEnvelope(widened, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('envelope_shape_invalid');

    const symbolized: any = structuredClone(envelope);
    symbolized.payload[Symbol('hidden')] = 'dispatch';
    expect(verifyAgentMailboxEnvelope(symbolized, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('envelope_not_canonical');
  });

  it('refuses oversized inline content before signature work', () => {
    expect(() => noteEnvelope({ payload: { text: 'x'.repeat(262_145) } })).toThrow(/payload_too_large/);
  });
});

describe('durable mailbox and delivery receipts', () => {
  it('emits a delivery receipt matching the closed interoperability schema', async () => {
    const schema = JSON.parse(await readFile(
      new URL('../conformance/schemas/agent-mailbox-delivery-receipt.v0.1.schema.json', import.meta.url),
      'utf8',
    ));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    const receipt = await mailbox().deliver(noteEnvelope(), { recipientId: 'agent:iman' });
    expect(validate(receipt), JSON.stringify(validate.errors)).toBe(true);
  });

  it('stores a new envelope once, emits one metadata-only chime, and signs a non-authorizing delivery receipt', async () => {
    const service = mailbox();
    const chimes: any[] = [];
    service.subscribe('agent:iman', (notification) => chimes.push(notification));

    const envelope = noteEnvelope();
    const first = await service.deliver(envelope, { recipientId: 'agent:iman' });
    const duplicate = await service.deliver(envelope, { recipientId: 'agent:iman' });

    expect(first).toMatchObject({
      '@version': AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION,
      delivery_status: 'ACCEPTED',
      authorizes: false,
    });
    expect(duplicate).toMatchObject({ delivery_status: 'DUPLICATE', authorizes: false });
    expect(chimes).toEqual([{
      mailbox_id: 'mailbox:nomadic-demo',
      recipient_id: 'agent:iman',
      envelope_id: envelope.envelope_id,
      envelope_digest: agentMailboxDigest(envelope),
      message_type: 'note',
      received_at: NOW,
    }]);
    expect(JSON.stringify(chimes)).not.toContain('GRACE test proposal');

    expect(verifyAgentMailboxDeliveryReceipt(first, {
      mailboxId: 'mailbox:nomadic-demo',
      publicKeySpkiB64u: mailboxService.publicKeySpkiB64u,
      keyId: mailboxService.keyId,
      expectedEnvelopeDigest: agentMailboxDigest(envelope),
    })).toMatchObject({ verified: true, accepted: true, reason: null, authorizes: false });

    const listed = await service.list('agent:iman');
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ read_at: null, envelope });
    expect(await service.acknowledge({ recipientId: 'agent:iman', envelopeId: envelope.envelope_id }))
      .toMatchObject({ acknowledged: true, authorizes: false });
    expect((await service.list('agent:iman'))[0].read_at).toBe(NOW);
  });

  it('refuses same envelope ID with different signed bytes instead of overwriting the first message', async () => {
    const service = mailbox();
    const first = noteEnvelope({ envelopeId: 'message:fixed-conflict-id' });
    const conflicting = noteEnvelope({
      envelopeId: 'message:fixed-conflict-id',
      sequence: 2,
      payload: { text: 'Different signed content.' },
    });
    expect((await service.deliver(first, { recipientId: 'agent:iman' })).delivery_status).toBe('ACCEPTED');
    expect(await service.deliver(conflicting, { recipientId: 'agent:iman' }))
      .toMatchObject({ delivery_status: 'REFUSED', reason: 'envelope_id_conflict' });
    expect(await service.list('agent:iman')).toHaveLength(1);
  });

  it('refuses sender equivocation at the same recipient, thread, and sequence even under different IDs', async () => {
    const service = mailbox();
    const first = noteEnvelope({ envelopeId: 'message:first-sequence-body' });
    const conflicting = noteEnvelope({
      envelopeId: 'message:second-sequence-body',
      payload: { text: 'A different statement at sequence one.' },
    });
    expect((await service.deliver(first, { recipientId: 'agent:iman' })).delivery_status).toBe('ACCEPTED');
    expect(await service.deliver(conflicting, { recipientId: 'agent:iman' }))
      .toMatchObject({ delivery_status: 'REFUSED', reason: 'thread_sequence_conflict' });
    expect(await service.list('agent:iman')).toHaveLength(1);
  });

  it('persists accepted envelopes across a new filesystem store instance', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-'));
    tempDirectories.push(directory);
    const envelope = noteEnvelope();
    const firstService = mailbox(createFileAgentMailboxStore({ directory }));
    expect((await firstService.deliver(envelope, { recipientId: 'agent:iman' })).delivery_status).toBe('ACCEPTED');

    const restarted = mailbox(createFileAgentMailboxStore({ directory }));
    const listed = await restarted.list('agent:iman');
    expect(listed).toHaveLength(1);
    expect(listed[0].envelope_digest).toBe(agentMailboxDigest(envelope));
    expect((await restarted.deliver(envelope, { recipientId: 'agent:iman' })).delivery_status).toBe('DUPLICATE');
  });
});

describe('GRACE action proposal composition', () => {
  function graceProposalEnvelope() {
    const action = createCurtailmentAction({
      actionId: 'curtailment:region1:20260822:01',
      facility: 'datacenter:vs-m32q:selab',
      targetDeltaKw: '5000',
      notBefore: '2026-08-22T20:10:00.000Z',
      notAfter: '2026-08-22T21:10:00.000Z',
      issuedAt: NOW,
      baselineMethodHash: `sha256:${'a'.repeat(64)}`,
      controlMode: 'human_in_the_loop',
      envelopeId: 'grid-envelope:region1:01',
      requestedBy: 'agent:smith',
    });
    const envelope = createAgentMailboxEnvelope({
      senderId: 'agent:smith',
      recipientId: 'agent:iman',
      threadId: 'thread:grace-curtailment-01',
      sequence: 1,
      messageType: 'action_proposal',
      payload: {
        action_profile: action['@version'],
        action_digest: graceDigest(action),
        action,
      },
      createdAt: NOW,
      expiresAt: LATER,
      privateKey: smith.privateKey,
      keyId: smith.keyId,
    });
    return { action, envelope };
  }

  it('extracts a signed GRACE proposal as context that explicitly authorizes nothing', () => {
    const { action, envelope } = graceProposalEnvelope();
    const verified = verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    });
    const proposal = extractMailboxActionProposal(envelope, { verifiedEnvelope: verified });
    expect(proposal).toMatchObject({
      valid: true,
      authorizes: false,
      action_profile: action['@version'],
      action_digest: graceDigest(action),
      envelope_digest: agentMailboxDigest(envelope),
    });
  });

  it('requires a separately verified exact-action EMILIA admission before executor readiness', async () => {
    const { action, envelope } = graceProposalEnvelope();
    const verified = verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    });
    const proposal = extractMailboxActionProposal(envelope, { verifiedEnvelope: verified });

    expect(await admitMailboxActionProposal({ proposal })).toMatchObject({
      admitted: false, ready_for_executor: false, reason: 'admission_verifier_required', mailbox_authorizes: false,
    });
    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => ({
        verified: true,
        accepted: true,
        action_digest: agentMailboxDigest({ substituted: true }),
        admission_digest: `sha256:${'b'.repeat(64)}`,
      }),
    })).toMatchObject({ admitted: false, reason: 'admission_action_mismatch' });
    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => { throw new Error('registry unavailable'); },
    })).toMatchObject({ admitted: false, state: 'INDETERMINATE', reason: 'admission_verification_indeterminate' });

    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => ({
        verified: true,
        accepted: true,
        action_digest: graceDigest(action),
        admission_digest: `sha256:${'c'.repeat(64)}`,
      }),
    })).toEqual({
      admitted: true,
      state: 'ADMITTED',
      ready_for_executor: true,
      reason: null,
      action,
      action_digest: graceDigest(action),
      envelope_digest: agentMailboxDigest(envelope),
      admission_digest: `sha256:${'c'.repeat(64)}`,
      authority_source: 'external_emilia_admission',
      mailbox_authorizes: false,
    });
  });
});
