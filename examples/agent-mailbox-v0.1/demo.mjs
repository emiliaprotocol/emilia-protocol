// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { admitMailboxActionProposal, agentMailboxDigest, createAgentMailbox, createAgentMailboxEnvelope, createFileAgentMailboxStore, extractMailboxActionProposal, verifyAgentMailboxDeliveryReceipt, verifyAgentMailboxEnvelope, } from '../../lib/agent-mailbox.js';
import { createCurtailmentAction, graceDigest } from '../../lib/grace/mobile-grid.js';
const NOW = '2026-08-22T20:00:00.000Z';
const EXPIRES = '2026-08-22T21:00:00.000Z';
function signer(keyId) {
    const pair = crypto.generateKeyPairSync('ed25519');
    return Object.freeze({
        keyId,
        privateKey: pair.privateKey,
        publicKeySpkiB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
}
export async function runDemo({ directory } = {}) {
    const smith = signer('agent-smith-signing-1');
    const mailboxSigner = signer('nomadic-mailbox-signing-1');
    const workingDirectory = directory ?? await mkdtemp(path.join(os.tmpdir(), 'ep-agent-mailbox-demo-'));
    const removeWhenDone = directory === undefined;
    try {
        const senderDirectory = {
            'agent:smith': {
                key_id: smith.keyId,
                public_key_spki_b64u: smith.publicKeySpkiB64u,
                status: 'active',
            },
        };
        const serviceOptions = {
            mailboxId: 'mailbox:nomadic-reference',
            senderDirectory,
            privateKey: mailboxSigner.privateKey,
            keyId: mailboxSigner.keyId,
            now: () => NOW,
        };
        const mailbox = createAgentMailbox({
            ...serviceOptions,
            store: createFileAgentMailboxStore({ directory: workingDirectory }),
        });
        const chimes = [];
        mailbox.subscribe('agent:iman', (notification) => chimes.push(notification));
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
            expiresAt: EXPIRES,
            privateKey: smith.privateKey,
            keyId: smith.keyId,
        });
        const deliveryReceipt = await mailbox.deliver(envelope, { recipientId: 'agent:iman' });
        const deliveryVerification = verifyAgentMailboxDeliveryReceipt(deliveryReceipt, {
            mailboxId: serviceOptions.mailboxId,
            publicKeySpkiB64u: mailboxSigner.publicKeySpkiB64u,
            keyId: mailboxSigner.keyId,
            expectedRecipientId: 'agent:iman',
            expectedEnvelopeId: envelope.envelope_id,
            expectedEnvelopeDigest: agentMailboxDigest(envelope),
        });
        const envelopeVerification = verifyAgentMailboxEnvelope(envelope, {
            senderDirectory,
            expectedRecipientId: 'agent:iman',
            asOf: NOW,
        });
        const proposal = extractMailboxActionProposal(envelope, { verifiedEnvelope: envelopeVerification });
        const beforeAdmission = await admitMailboxActionProposal({ proposal });
        const afterAdmission = await admitMailboxActionProposal({
            proposal,
            verifyAdmission: async () => ({
                verified: true,
                accepted: true,
                authorized: true,
                action_digest: graceDigest(action),
                admission_digest: `sha256:${'c'.repeat(64)}`,
                authority_source: 'emilia_gate',
            }),
        });
        if (!afterAdmission.admitted) {
            throw new Error(`reference admission failed: ${afterAdmission.reason}`);
        }
        const restarted = createAgentMailbox({
            ...serviceOptions,
            store: createFileAgentMailboxStore({ directory: workingDirectory }),
        });
        const persisted = await restarted.list('agent:iman');
        const duplicateReceipt = await restarted.deliver(envelope, { recipientId: 'agent:iman' });
        return Object.freeze({
            delivery_status: deliveryReceipt.delivery_status,
            delivery_receipt_verified: deliveryVerification.verified,
            chime_count: chimes.length,
            chime_contains_payload: JSON.stringify(chimes).includes('curtailment'),
            persisted_after_restart: persisted.length === 1,
            duplicate_status: duplicateReceipt.delivery_status,
            mailbox_authorizes: proposal.authorizes,
            before_admission: {
                ready_for_executor: beforeAdmission.ready_for_executor,
                reason: beforeAdmission.reason,
            },
            after_admission: {
                ready_for_executor: afterAdmission.ready_for_executor,
                authority_source: afterAdmission.authority_source,
                exact_action_bound: afterAdmission.action_digest === graceDigest(action),
            },
        });
    }
    finally {
        if (removeWhenDone)
            await rm(workingDirectory, { recursive: true, force: true });
    }
}
const invokedDirectly = process.argv[1]
    && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
    const result = await runDemo();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
