// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
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

function mailboxOptions(overrides: Record<string, unknown> = {}) {
  return {
    mailboxId: 'mailbox:nomadic-demo',
    store: createMemoryAgentMailboxStore(),
    senderDirectory: senderDirectory(),
    privateKey: mailboxService.privateKey,
    keyId: mailboxService.keyId,
    now: () => NOW,
    ...overrides,
  } as any;
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

  it('refuses malformed envelope construction inputs before signing', () => {
    expect(() => noteEnvelope({ senderId: 'x' })).toThrow(/mailbox_identifier_invalid/);
    expect(() => noteEnvelope({ sequence: 0 })).toThrow(/mailbox_sequence_invalid/);
    expect(() => noteEnvelope({ messageType: 'dispatch' })).toThrow(/mailbox_message_type_invalid/);
    expect(() => noteEnvelope({ createdAt: 'not-an-instant' })).toThrow(/mailbox_time_window_invalid/);
    expect(() => noteEnvelope({ expiresAt: NOW })).toThrow(/mailbox_time_window_invalid/);
    expect(() => noteEnvelope({ payload: { count: 1n } })).toThrow(/payload_not_canonical/);
    expect(() => noteEnvelope({ privateKey: 'not-a-private-key' })).toThrow(/mailbox_ed25519_private_key_required/);
    expect(() => noteEnvelope({ envelopeId: 'x' })).toThrow(/mailbox_envelope_id_invalid/);
  });

  it('fails closed on malformed times, payloads, sender state, keys, and signatures', () => {
    const envelope: any = structuredClone(noteEnvelope());

    const invalidTime = structuredClone(envelope);
    invalidTime.created_at = 'not-an-instant';
    expect(verifyAgentMailboxEnvelope(invalidTime, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('envelope_time_invalid');

    const payloadMismatch = structuredClone(envelope);
    payloadMismatch.payload.text = 'Different unsigned bytes.';
    expect(verifyAgentMailboxEnvelope(payloadMismatch, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('payload_digest_mismatch');

    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory({
        'agent:smith': {
          key_id: smith.keyId,
          public_key_spki_b64u: smith.publicKeySpkiB64u,
          status: 'revoked',
        },
      }),
      expectedRecipientId: 'agent:iman',
      asOf: NOW,
    }).reason).toBe('sender_key_not_active');

    expect(verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory({
        'agent:smith': {
          key_id: smith.keyId,
          public_key_spki_b64u: 'not-a-der-key',
          status: 'active',
        },
      }),
      expectedRecipientId: 'agent:iman',
      asOf: NOW,
    }).reason).toBe('sender_key_invalid');

    const malformedSignature = structuredClone(envelope);
    malformedSignature.signature.value = '*';
    expect(verifyAgentMailboxEnvelope(malformedSignature, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    }).reason).toBe('signature_invalid');
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

  it('durably sorts, acknowledges once, and refuses same-ID replacement', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-'));
    tempDirectories.push(directory);
    const service = mailbox(createFileAgentMailboxStore({ directory }));
    const second = noteEnvelope({ sequence: 2 });
    const first = noteEnvelope();
    expect((await service.deliver(second, { recipientId: 'agent:iman' })).delivery_status).toBe('ACCEPTED');
    expect((await service.deliver(first, { recipientId: 'agent:iman' })).delivery_status).toBe('ACCEPTED');
    expect((await service.list('agent:iman')).map((record) => record.envelope.sequence)).toEqual([1, 2]);

    expect(await service.acknowledge({ recipientId: 'agent:iman', envelopeId: first.envelope_id }))
      .toEqual({ acknowledged: true, authorizes: false });
    expect(await service.acknowledge({ recipientId: 'agent:iman', envelopeId: first.envelope_id }))
      .toEqual({ acknowledged: true, authorizes: false });
    expect(await service.acknowledge({ recipientId: 'agent:iman', envelopeId: 'message:missing-record' }))
      .toEqual({ acknowledged: false, authorizes: false });

    const sameId = noteEnvelope({
      envelopeId: second.envelope_id,
      sequence: 3,
      payload: { text: 'Replacement bytes must not overwrite.' },
    });
    expect(await service.deliver(sameId, { recipientId: 'agent:iman' }))
      .toMatchObject({ delivery_status: 'REFUSED', reason: 'envelope_id_conflict' });
  });

  it('serializes same-sequence equivocation across filesystem store instances', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-'));
    tempDirectories.push(directory);
    const firstService = mailbox(createFileAgentMailboxStore({ directory }));
    const secondService = mailbox(createFileAgentMailboxStore({ directory }));
    const first = noteEnvelope({
      envelopeId: 'message:concurrent-sequence-first',
      payload: { text: 'First statement at sequence one.' },
    });
    const conflicting = noteEnvelope({
      envelopeId: 'message:concurrent-sequence-second',
      payload: { text: 'Conflicting statement at sequence one.' },
    });

    const receipts = await Promise.all([
      firstService.deliver(first, { recipientId: 'agent:iman' }),
      secondService.deliver(conflicting, { recipientId: 'agent:iman' }),
    ]);
    expect(receipts.map((receipt) => receipt.delivery_status).sort()).toEqual(['ACCEPTED', 'REFUSED']);
    expect(receipts.find((receipt) => receipt.delivery_status === 'REFUSED')).toMatchObject({
      reason: 'thread_sequence_conflict',
      authorizes: false,
    });
    expect(await firstService.list('agent:iman')).toHaveLength(1);
  });

  it('serializes identical concurrent deliveries across filesystem store instances', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-'));
    tempDirectories.push(directory);
    const firstService = mailbox(createFileAgentMailboxStore({ directory }));
    const secondService = mailbox(createFileAgentMailboxStore({ directory }));
    const envelope = noteEnvelope();

    const receipts = await Promise.all([
      firstService.deliver(envelope, { recipientId: 'agent:iman' }),
      secondService.deliver(envelope, { recipientId: 'agent:iman' }),
    ]);
    expect(receipts.map((receipt) => receipt.delivery_status).sort()).toEqual(['ACCEPTED', 'DUPLICATE']);
    expect(await secondService.list('agent:iman')).toHaveLength(1);
  });

  it('refuses relative storage paths and surfaces corrupted durable records', async () => {
    expect(() => createFileAgentMailboxStore({ directory: 'relative/mailbox' }))
      .toThrow(/mailbox_store_directory_must_be_absolute/);

    const directory = await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-'));
    tempDirectories.push(directory);
    const service = mailbox(createFileAgentMailboxStore({ directory }));
    await service.deliver(noteEnvelope(), { recipientId: 'agent:iman' });
    const recordsDirectory = path.join(directory, 'records');
    const [recordName] = await readdir(recordsDirectory);
    await writeFile(path.join(recordsDirectory, recordName), '{"truncated":', 'utf8');
    await expect(service.list('agent:iman')).rejects.toThrow(/mailbox_store_record_corrupt/);
  });

  it('verifies receipt refusals without treating delivery as authority', async () => {
    const service = mailbox();
    const envelope = noteEnvelope();
    const accepted: any = await service.deliver(envelope, { recipientId: 'agent:iman' });
    const verificationOptions = {
      mailboxId: 'mailbox:nomadic-demo',
      publicKeySpkiB64u: mailboxService.publicKeySpkiB64u,
      keyId: mailboxService.keyId,
      expectedEnvelopeDigest: agentMailboxDigest(envelope),
    };

    expect(verifyAgentMailboxDeliveryReceipt(null, verificationOptions).reason)
      .toBe('delivery_receipt_shape_invalid');

    const nonCanonical = structuredClone(accepted);
    nonCanonical.reason = '\ud800';
    expect(verifyAgentMailboxDeliveryReceipt(nonCanonical, verificationOptions).reason)
      .toBe('delivery_receipt_not_canonical');

    const wrongMailbox = structuredClone(accepted);
    wrongMailbox.mailbox_id = 'mailbox:other-service';
    expect(verifyAgentMailboxDeliveryReceipt(wrongMailbox, verificationOptions).reason)
      .toBe('delivery_receipt_shape_invalid');

    expect(verifyAgentMailboxDeliveryReceipt(accepted, {
      ...verificationOptions,
      expectedEnvelopeDigest: `sha256:${'f'.repeat(64)}`,
    }).reason).toBe('delivery_receipt_envelope_mismatch');
    expect(verifyAgentMailboxDeliveryReceipt(accepted, {
      ...verificationOptions,
      publicKeySpkiB64u: 'not-a-der-key',
    }).reason).toBe('delivery_receipt_key_invalid');

    const badSignature = structuredClone(accepted);
    badSignature.signature.value = `${badSignature.signature.value[0] === 'A' ? 'B' : 'A'}${badSignature.signature.value.slice(1)}`;
    expect(verifyAgentMailboxDeliveryReceipt(badSignature, verificationOptions).reason)
      .toBe('delivery_receipt_signature_invalid');

    const wrongReceiptId = structuredClone(accepted);
    wrongReceiptId.receipt_id = 'delivery:content-derived-id-mismatch';
    expect(verifyAgentMailboxDeliveryReceipt(wrongReceiptId, verificationOptions).reason)
      .toBe('delivery_receipt_id_mismatch');

    const refused = await service.deliver({}, { recipientId: 'agent:iman' });
    expect(verifyAgentMailboxDeliveryReceipt(refused, {
      mailboxId: 'mailbox:nomadic-demo',
      publicKeySpkiB64u: mailboxService.publicKeySpkiB64u,
      keyId: mailboxService.keyId,
    })).toMatchObject({
      verified: true,
      accepted: false,
      delivery_status: 'REFUSED',
      reason: 'envelope_shape_invalid',
      authorizes: false,
    });

    const acceptedWithReason = structuredClone(accepted);
    acceptedWithReason.reason = 'accepted receipts cannot carry refusal reasons';
    expect(verifyAgentMailboxDeliveryReceipt(acceptedWithReason, verificationOptions).reason)
      .toBe('delivery_receipt_shape_invalid');

    for (const invalidReason of [null, '', 'x'.repeat(257)]) {
      const malformedRefusal = structuredClone(refused);
      malformedRefusal.reason = invalidReason;
      expect(verifyAgentMailboxDeliveryReceipt(malformedRefusal, {
        mailboxId: 'mailbox:nomadic-demo',
        publicKeySpkiB64u: mailboxService.publicKeySpkiB64u,
        keyId: mailboxService.keyId,
      }).reason).toBe('delivery_receipt_shape_invalid');
    }
  });

  it('does not let a throwing chime listener suppress an accepted receipt', async () => {
    const service = mailbox();
    service.subscribe('agent:iman', () => { throw new Error('subscriber failed'); });
    const envelope = noteEnvelope();

    expect(await service.deliver(envelope, { recipientId: 'agent:iman' }))
      .toMatchObject({ delivery_status: 'ACCEPTED', authorizes: false });
    expect(await service.list('agent:iman')).toHaveLength(1);
    expect(await service.deliver(envelope, { recipientId: 'agent:iman' }))
      .toMatchObject({ delivery_status: 'DUPLICATE', authorizes: false });
  });

  it('validates service configuration and recipient-facing method inputs', async () => {
    expect(() => createAgentMailbox(mailboxOptions({ mailboxId: 'x' })))
      .toThrow(/mailbox_service_identifier_invalid/);
    expect(() => createAgentMailbox(mailboxOptions({ store: {} })))
      .toThrow(/mailbox_store_contract_invalid/);
    expect(() => createAgentMailbox(mailboxOptions({ privateKey: 'not-a-private-key' })))
      .toThrow(/mailbox_service_ed25519_key_required/);
    expect(() => createAgentMailbox(mailboxOptions({ senderDirectory: [] })))
      .toThrow(/mailbox_service_configuration_invalid/);

    const service = mailbox();
    expect(() => service.subscribe('x', () => {})).toThrow(/mailbox_subscription_invalid/);
    await expect(service.deliver(noteEnvelope(), { recipientId: 'x' })).rejects
      .toThrow(/mailbox_recipient_invalid/);
    await expect(service.list('x')).rejects.toThrow(/mailbox_recipient_invalid/);
    await expect(service.acknowledge({ recipientId: 'agent:iman', envelopeId: 'x' })).rejects
      .toThrow(/mailbox_acknowledgement_invalid/);

    const notifications: unknown[] = [];
    const unsubscribe = service.subscribe('agent:iman', (notification) => notifications.push(notification));
    unsubscribe();
    await service.deliver(noteEnvelope(), { recipientId: 'agent:iman' });
    expect(notifications).toEqual([]);

    const noTime = createAgentMailbox(mailboxOptions({ now: () => 'not-an-instant' }));
    await expect(noTime.deliver(noteEnvelope(), { recipientId: 'agent:iman' })).rejects
      .toThrow(/mailbox_trusted_time_unavailable/);
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

  it('refuses unverified, malformed, and digest-substituted action proposals', () => {
    const note = noteEnvelope();
    expect(extractMailboxActionProposal(note, {
      verifiedEnvelope: { accepted: true, envelope_digest: agentMailboxDigest(note) },
    })).toMatchObject({ valid: false, reason: 'not_an_action_proposal', authorizes: false });

    const { envelope } = graceProposalEnvelope();
    expect(extractMailboxActionProposal(envelope, {
      verifiedEnvelope: { accepted: false, envelope_digest: agentMailboxDigest(envelope) },
    })).toMatchObject({ valid: false, reason: 'verified_envelope_required' });

    const malformed: any = structuredClone(envelope);
    delete malformed.payload.action_profile;
    expect(extractMailboxActionProposal(malformed, {
      verifiedEnvelope: { accepted: true, envelope_digest: agentMailboxDigest(malformed) },
    })).toMatchObject({ valid: false, reason: 'action_proposal_shape_invalid' });

    const substituted: any = structuredClone(envelope);
    substituted.payload.action_digest = `sha256:${'0'.repeat(64)}`;
    expect(extractMailboxActionProposal(substituted, {
      verifiedEnvelope: { accepted: true, envelope_digest: agentMailboxDigest(substituted) },
    })).toMatchObject({ valid: false, reason: 'action_digest_mismatch' });

    const cyclic: any = { message_type: 'action_proposal' };
    cyclic.payload = cyclic;
    expect(() => extractMailboxActionProposal(cyclic, {
      verifiedEnvelope: { accepted: true, envelope_digest: `sha256:${'0'.repeat(64)}` },
    })).not.toThrow();
    expect(extractMailboxActionProposal(cyclic, {
      verifiedEnvelope: { accepted: true, envelope_digest: `sha256:${'0'.repeat(64)}` },
    })).toMatchObject({ valid: false, reason: 'verified_envelope_required' });

    const symbolBearing: any = structuredClone(envelope);
    symbolBearing.payload.action[Symbol('hidden')] = 'dispatch';
    expect(extractMailboxActionProposal(symbolBearing, {
      verifiedEnvelope: { accepted: true, envelope_digest: `sha256:${'0'.repeat(64)}` },
    })).toMatchObject({ valid: false, reason: 'verified_envelope_required' });

    const oversized: any = structuredClone(envelope);
    oversized.payload.action.oversized = 'x'.repeat(262_145);
    expect(extractMailboxActionProposal(oversized, {
      verifiedEnvelope: { accepted: true, envelope_digest: `sha256:${'0'.repeat(64)}` },
    })).toMatchObject({ valid: false, reason: 'verified_envelope_required' });
  });

  it('snapshots the exact action across the asynchronous admission boundary', async () => {
    const { action, envelope } = graceProposalEnvelope();
    const verified = verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    });
    const extracted = extractMailboxActionProposal(envelope, { verifiedEnvelope: verified });
    const tampered: any = structuredClone(extracted);
    tampered.action.action_id = 'curtailment:attacker-substitution';
    let verifierCalled = false;
    expect(await admitMailboxActionProposal({
      proposal: tampered,
      verifyAdmission: async () => {
        verifierCalled = true;
        throw new Error('must not be called');
      },
    })).toMatchObject({
      admitted: false,
      ready_for_executor: false,
      reason: 'proposal_action_digest_mismatch',
    });
    expect(verifierCalled).toBe(false);

    const admitted = await admitMailboxActionProposal({
      proposal: extracted,
      verifyAdmission: async (detachedProposal) => {
        detachedProposal.action.action_id = 'curtailment:mutated-inside-verifier';
        return {
          verified: true,
          accepted: true,
          action_digest: extracted.action_digest,
          admission_digest: `sha256:${'d'.repeat(64)}`,
        };
      },
    });
    expect(admitted).toMatchObject({
      admitted: true,
      ready_for_executor: true,
      action,
      action_digest: graceDigest(action),
    });
    expect(admitted.action.action_id).toBe(action.action_id);
    expect(Object.isFrozen(admitted.action)).toBe(true);
  });

  it('refuses every incomplete external admission state', async () => {
    const { envelope } = graceProposalEnvelope();
    const verified = verifyAgentMailboxEnvelope(envelope, {
      senderDirectory: senderDirectory(), expectedRecipientId: 'agent:iman', asOf: NOW,
    });
    const proposal = extractMailboxActionProposal(envelope, { verifiedEnvelope: verified });

    expect(await admitMailboxActionProposal({ proposal: null }))
      .toMatchObject({ admitted: false, reason: 'valid_action_proposal_required' });
    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => ({ verified: false, accepted: true }),
    })).toMatchObject({ admitted: false, reason: 'admission_not_verified' });
    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => ({ verified: true, accepted: false }),
    })).toMatchObject({ admitted: false, reason: 'admission_not_accepted' });
    expect(await admitMailboxActionProposal({
      proposal,
      verifyAdmission: async () => ({
        verified: true,
        accepted: true,
        action_digest: proposal.action_digest,
        admission_digest: 'not-a-digest',
      }),
    })).toMatchObject({ admitted: false, reason: 'admission_digest_invalid' });
  });
});
