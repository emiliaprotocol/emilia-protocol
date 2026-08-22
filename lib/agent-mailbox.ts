// SPDX-License-Identifier: Apache-2.0

/**
 * Signed store-and-forward envelopes for agent-to-agent communication.
 *
 * The mailbox is a delivery surface. An envelope can carry context or an
 * action proposal, but it never carries execution authority. Consequential
 * actions become executor-ready only after a separately verified EMILIA
 * admission bound to the exact proposed action digest.
 */
import crypto from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  readdir,
  rename,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeStrictJson, strictJsonGate } from './strict-json.js';

export const AGENT_MAILBOX_ENVELOPE_VERSION = 'EP-AGENT-MAILBOX-ENVELOPE-v0.1';
export const AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION = 'EP-AGENT-MAILBOX-DELIVERY-RECEIPT-v0.1';

const ENVELOPE_DOMAIN = Buffer.from(`${AGENT_MAILBOX_ENVELOPE_VERSION}\0`, 'utf8');
const RECEIPT_DOMAIN = Buffer.from(`${AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION}\0`, 'utf8');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const MESSAGE_TYPES = new Set(['note', 'context_handoff', 'action_proposal', 'result']);
const DELIVERY_STATUSES = new Set(['ACCEPTED', 'DUPLICATE', 'REFUSED']);
const ENVELOPE_KEYS = new Set([
  '@version',
  'envelope_id',
  'sender_id',
  'recipient_id',
  'thread_id',
  'sequence',
  'message_type',
  'payload',
  'payload_digest',
  'created_at',
  'expires_at',
  'authority',
  'signer_key_id',
  'signature',
]);
const SIGNATURE_KEYS = new Set(['algorithm', 'value']);
const AUTHORITY_KEYS = new Set(['authorizes']);
const RECEIPT_KEYS = new Set([
  '@version',
  'receipt_id',
  'mailbox_id',
  'envelope_id',
  'envelope_digest',
  'recipient_id',
  'received_at',
  'delivery_status',
  'reason',
  'authorizes',
  'signer_key_id',
  'signature',
]);
const MAX_CANONICAL_NODES = 10_000;
const MAX_CANONICAL_STRING_BYTES = 262_144;

type JsonRecord = Record<string, any>;

type StoredEnvelope = {
  recipient_id: string;
  envelope_id: string;
  envelope_digest: string;
  envelope: JsonRecord;
  received_at: string;
  read_at: string | null;
};

type AgentMailboxStore = {
  durable: boolean;
  deliveryAtomicity: 'single_process' | 'shared_durable';
  bodyBound: boolean;
  put(record: StoredEnvelope): Promise<{
    outcome: 'stored' | 'duplicate' | 'envelope_id_conflict' | 'thread_sequence_conflict';
    record: StoredEnvelope;
  }>;
  list(recipientId: string): Promise<StoredEnvelope[]>;
  acknowledge(recipientId: string, envelopeId: string, readAt: string): Promise<boolean>;
};

function isRecord(value: unknown): value is JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, keys: Set<string>): value is JsonRecord {
  if (!isRecord(value)) return false;
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.size
    && ownKeys.every((key) => typeof key === 'string' && keys.has(key));
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function canonicalInstant(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonical = new Date(parsed).toISOString();
  return canonical === value ? canonical : null;
}

function canonical(value: unknown): string {
  return canonicalizeStrictJson(value, {
    maxDepth: 32,
    maxNodes: MAX_CANONICAL_NODES,
    maxStringBytes: MAX_CANONICAL_STRING_BYTES,
  });
}

export function agentMailboxDigest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`;
}

function privateEd25519(value: unknown): crypto.KeyObject | null {
  try {
    const key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value as any);
    return key.type === 'private' && key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function publicEd25519(value: unknown): crypto.KeyObject | null {
  if (typeof value !== 'string' || !BASE64URL.test(value)) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function sign(domain: Buffer, value: JsonRecord, privateKey: crypto.KeyObject): string {
  const bytes = Buffer.concat([domain, Buffer.from(canonical(value), 'utf8')]);
  return crypto.sign(null, bytes, privateKey).toString('base64url');
}

function verify(domain: Buffer, value: JsonRecord, signature: unknown, publicKey: crypto.KeyObject): boolean {
  if (typeof signature !== 'string' || !BASE64URL.test(signature)) return false;
  try {
    const bytes = Buffer.concat([domain, Buffer.from(canonical(value), 'utf8')]);
    return crypto.verify(null, bytes, publicKey, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonical(value));
}

export function createAgentMailboxEnvelope(input: {
  envelopeId?: string;
  senderId: string;
  recipientId: string;
  threadId: string;
  sequence: number;
  messageType: 'note' | 'context_handoff' | 'action_proposal' | 'result';
  payload: unknown;
  createdAt: string;
  expiresAt: string;
  privateKey: unknown;
  keyId: string;
}): JsonRecord {
  if (!identifier(input?.senderId) || !identifier(input?.recipientId)
      || !identifier(input?.threadId) || !identifier(input?.keyId)) {
    throw new TypeError('mailbox_identifier_invalid');
  }
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) {
    throw new TypeError('mailbox_sequence_invalid');
  }
  if (!MESSAGE_TYPES.has(input.messageType)) throw new TypeError('mailbox_message_type_invalid');
  const createdAt = canonicalInstant(input.createdAt);
  const expiresAt = canonicalInstant(input.expiresAt);
  if (!createdAt || !expiresAt || Date.parse(expiresAt) <= Date.parse(createdAt)) {
    throw new TypeError('mailbox_time_window_invalid');
  }
  let payload: unknown;
  let payloadDigest: string;
  try {
    payload = canonicalCopy(input.payload);
    payloadDigest = agentMailboxDigest(payload);
  } catch (error) {
    if (error instanceof Error && /string bytes exceed|node count exceeds|nesting depth exceeds/.test(error.message)) {
      throw new TypeError('payload_too_large');
    }
    throw new TypeError('payload_not_canonical');
  }
  const privateKey = privateEd25519(input.privateKey);
  if (!privateKey) throw new TypeError('mailbox_ed25519_private_key_required');
  const core = {
    '@version': AGENT_MAILBOX_ENVELOPE_VERSION,
    sender_id: input.senderId,
    recipient_id: input.recipientId,
    thread_id: input.threadId,
    sequence: input.sequence,
    message_type: input.messageType,
    payload,
    payload_digest: payloadDigest,
    created_at: createdAt,
    expires_at: expiresAt,
    authority: { authorizes: false },
    signer_key_id: input.keyId,
  };
  const envelopeId = input.envelopeId ?? `message:${agentMailboxDigest(core).slice('sha256:'.length)}`;
  if (!identifier(envelopeId)) throw new TypeError('mailbox_envelope_id_invalid');
  const unsigned = { ...core, envelope_id: envelopeId };
  return Object.freeze({
    ...canonicalCopy(unsigned),
    signature: Object.freeze({ algorithm: 'Ed25519', value: sign(ENVELOPE_DOMAIN, unsigned, privateKey) }),
  });
}

function envelopeRefusal(reason: string, envelopeDigest: string | null = null) {
  return Object.freeze({
    verified: false,
    accepted: false,
    reason,
    envelope_digest: envelopeDigest,
    authorizes: false as const,
  });
}

export function verifyAgentMailboxEnvelope(envelope: unknown, options: {
  senderDirectory: Record<string, unknown>;
  expectedRecipientId: string;
  asOf: string;
}) {
  if (!exactKeys(envelope, ENVELOPE_KEYS)) return envelopeRefusal('envelope_shape_invalid');
  let envelopeDigest: string;
  try {
    envelopeDigest = agentMailboxDigest(envelope);
  } catch {
    return envelopeRefusal('envelope_not_canonical');
  }
  if (envelope['@version'] !== AGENT_MAILBOX_ENVELOPE_VERSION
      || !identifier(envelope.envelope_id)
      || !identifier(envelope.sender_id)
      || !identifier(envelope.recipient_id)
      || !identifier(envelope.thread_id)
      || !Number.isSafeInteger(envelope.sequence) || envelope.sequence < 1
      || !MESSAGE_TYPES.has(envelope.message_type)
      || !DIGEST.test(envelope.payload_digest)
      || !exactKeys(envelope.authority, AUTHORITY_KEYS)
      || envelope.authority.authorizes !== false
      || !identifier(envelope.signer_key_id)
      || !exactKeys(envelope.signature, SIGNATURE_KEYS)
      || envelope.signature.algorithm !== 'Ed25519') {
    return envelopeRefusal('envelope_shape_invalid', envelopeDigest);
  }
  if (envelope.recipient_id !== options?.expectedRecipientId) {
    return envelopeRefusal('recipient_mismatch', envelopeDigest);
  }
  const createdAt = canonicalInstant(envelope.created_at);
  const expiresAt = canonicalInstant(envelope.expires_at);
  const asOf = canonicalInstant(options?.asOf);
  if (!createdAt || !expiresAt || !asOf || Date.parse(expiresAt) <= Date.parse(createdAt)) {
    return envelopeRefusal('envelope_time_invalid', envelopeDigest);
  }
  if (Date.parse(asOf) > Date.parse(expiresAt)) return envelopeRefusal('envelope_expired', envelopeDigest);
  if (Date.parse(asOf) < Date.parse(createdAt)) return envelopeRefusal('envelope_not_yet_valid', envelopeDigest);
  try {
    if (agentMailboxDigest(envelope.payload) !== envelope.payload_digest) {
      return envelopeRefusal('payload_digest_mismatch', envelopeDigest);
    }
  } catch {
    return envelopeRefusal('envelope_not_canonical', envelopeDigest);
  }
  const directory = isRecord(options?.senderDirectory) ? options.senderDirectory : {};
  const sender = directory[envelope.sender_id];
  if (!isRecord(sender) || sender.key_id !== envelope.signer_key_id) {
    return envelopeRefusal('sender_key_not_pinned', envelopeDigest);
  }
  if (sender.status !== 'active') return envelopeRefusal('sender_key_not_active', envelopeDigest);
  const publicKey = publicEd25519(sender.public_key_spki_b64u);
  if (!publicKey) return envelopeRefusal('sender_key_invalid', envelopeDigest);
  const { signature, ...unsigned } = envelope;
  if (!verify(ENVELOPE_DOMAIN, unsigned, signature.value, publicKey)) {
    return envelopeRefusal('signature_invalid', envelopeDigest);
  }
  return Object.freeze({
    verified: true,
    accepted: true,
    reason: null,
    envelope_digest: envelopeDigest,
    authorizes: false as const,
  });
}

function copyRecord(record: StoredEnvelope): StoredEnvelope {
  return structuredClone(record);
}

export function createMemoryAgentMailboxStore(): AgentMailboxStore {
  const records = new Map<string, StoredEnvelope>();
  const key = (recipientId: string, envelopeId: string) => `${recipientId}\0${envelopeId}`;
  return Object.freeze({
    durable: false,
    deliveryAtomicity: 'single_process',
    bodyBound: true,
    async put(record) {
      const recordKey = key(record.recipient_id, record.envelope_id);
      const existing = records.get(recordKey);
      if (existing) {
        return {
          outcome: existing.envelope_digest === record.envelope_digest ? 'duplicate' : 'envelope_id_conflict',
          record: copyRecord(existing),
        };
      }
      const sameSequence = [...records.values()].find((candidate) => (
        candidate.recipient_id === record.recipient_id
        && candidate.envelope.sender_id === record.envelope.sender_id
        && candidate.envelope.thread_id === record.envelope.thread_id
        && candidate.envelope.sequence === record.envelope.sequence
      ));
      if (sameSequence) {
        return {
          outcome: sameSequence.envelope_digest === record.envelope_digest ? 'duplicate' : 'thread_sequence_conflict',
          record: copyRecord(sameSequence),
        };
      }
      records.set(recordKey, copyRecord(record));
      return { outcome: 'stored', record: copyRecord(record) };
    },
    async list(recipientId) {
      return [...records.values()]
        .filter((record) => record.recipient_id === recipientId)
        .sort((left, right) => left.envelope.sequence - right.envelope.sequence)
        .map(copyRecord);
    },
    async acknowledge(recipientId, envelopeId, readAt) {
      const record = records.get(key(recipientId, envelopeId));
      if (!record) return false;
      record.read_at = record.read_at ?? readAt;
      return true;
    },
  });
}

function storageKey(recipientId: string, envelopeId: string): string {
  return crypto.createHash('sha256').update(`${recipientId}\0${envelopeId}`, 'utf8').digest('hex');
}

function parseStoredEnvelope(raw: string): StoredEnvelope {
  const gate = strictJsonGate(raw);
  if (!gate.ok) throw new Error('mailbox_store_record_corrupt');
  const record = JSON.parse(raw);
  if (!isRecord(record)
      || !identifier(record.recipient_id)
      || !identifier(record.envelope_id)
      || !DIGEST.test(record.envelope_digest)
      || !canonicalInstant(record.received_at)
      || (record.read_at !== null && !canonicalInstant(record.read_at))
      || !isRecord(record.envelope)
      || record.envelope.envelope_id !== record.envelope_id
      || record.envelope.recipient_id !== record.recipient_id
      || agentMailboxDigest(record.envelope) !== record.envelope_digest) {
    throw new Error('mailbox_store_record_corrupt');
  }
  return record as StoredEnvelope;
}

async function writeNewRecord(filename: string, record: StoredEnvelope): Promise<'stored' | 'exists'> {
  let handle;
  try {
    handle = await open(filename, 'wx', 0o600);
    await handle.writeFile(canonical(record), 'utf8');
    await handle.sync();
    return 'stored';
  } catch (error: any) {
    if (error?.code === 'EEXIST') return 'exists';
    throw error;
  } finally {
    await handle?.close();
  }
}

export function createFileAgentMailboxStore({ directory }: { directory: string }): AgentMailboxStore {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    throw new TypeError('mailbox_store_directory_must_be_absolute');
  }
  const recordsDirectory = path.join(directory, 'records');
  const ready = mkdir(recordsDirectory, { recursive: true, mode: 0o700 });
  const filename = (recipientId: string, envelopeId: string) => path.join(recordsDirectory, `${storageKey(recipientId, envelopeId)}.json`);
  let putQueue = Promise.resolve();
  async function serializePut<T>(operation: () => Promise<T>): Promise<T> {
    const previous = putQueue;
    let release!: () => void;
    putQueue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
  return Object.freeze({
    durable: true,
    deliveryAtomicity: 'single_process',
    bodyBound: true,
    async put(record) {
      return serializePut(async () => {
        await ready;
        const target = filename(record.recipient_id, record.envelope_id);
        let names = (await readdir(recordsDirectory)).filter((name) => name.endsWith('.json'));
        const existingRecords = await Promise.all(names.map(async (name) => parseStoredEnvelope(
          await readFile(path.join(recordsDirectory, name), 'utf8'),
        )));
        const sameSequence = existingRecords.find((candidate) => (
          candidate.recipient_id === record.recipient_id
          && candidate.envelope.sender_id === record.envelope.sender_id
          && candidate.envelope.thread_id === record.envelope.thread_id
          && candidate.envelope.sequence === record.envelope.sequence
        ));
        if (sameSequence) {
          return {
            outcome: sameSequence.envelope_digest === record.envelope_digest ? 'duplicate' as const : 'thread_sequence_conflict' as const,
            record: copyRecord(sameSequence),
          };
        }
        const outcome = await writeNewRecord(target, record);
        if (outcome === 'stored') return { outcome, record: copyRecord(record) };
        const existing = parseStoredEnvelope(await readFile(target, 'utf8'));
        return {
          outcome: existing.envelope_digest === record.envelope_digest ? 'duplicate' as const : 'envelope_id_conflict' as const,
          record: copyRecord(existing),
        };
      });
    },
    async list(recipientId) {
      await ready;
      const names = (await readdir(recordsDirectory)).filter((name) => name.endsWith('.json'));
      const records = await Promise.all(names.map(async (name) => parseStoredEnvelope(
        await readFile(path.join(recordsDirectory, name), 'utf8'),
      )));
      return records
        .filter((record) => record.recipient_id === recipientId)
        .sort((left, right) => left.envelope.sequence - right.envelope.sequence)
        .map(copyRecord);
    },
    async acknowledge(recipientId, envelopeId, readAt) {
      await ready;
      const target = filename(recipientId, envelopeId);
      let record: StoredEnvelope;
      try {
        record = parseStoredEnvelope(await readFile(target, 'utf8'));
      } catch (error: any) {
        if (error?.code === 'ENOENT') return false;
        throw error;
      }
      if (record.read_at !== null) return true;
      record.read_at = readAt;
      const temporary = path.join(recordsDirectory, `.${storageKey(recipientId, envelopeId)}.${crypto.randomUUID()}.tmp`);
      let handle;
      try {
        handle = await open(temporary, 'wx', 0o600);
        await handle.writeFile(canonical(record), 'utf8');
        await handle.sync();
      } finally {
        await handle?.close();
      }
      await rename(temporary, target);
      return true;
    },
  });
}

function createDeliveryReceipt(input: {
  mailboxId: string;
  envelopeId: string | null;
  envelopeDigest: string | null;
  recipientId: string;
  receivedAt: string;
  deliveryStatus: 'ACCEPTED' | 'DUPLICATE' | 'REFUSED';
  reason: string | null;
  keyId: string;
  privateKey: crypto.KeyObject;
}) {
  const core = {
    '@version': AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION,
    mailbox_id: input.mailboxId,
    envelope_id: input.envelopeId,
    envelope_digest: input.envelopeDigest,
    recipient_id: input.recipientId,
    received_at: input.receivedAt,
    delivery_status: input.deliveryStatus,
    reason: input.reason,
    authorizes: false,
    signer_key_id: input.keyId,
  };
  const receiptId = `delivery:${agentMailboxDigest(core).slice('sha256:'.length)}`;
  const unsigned = { ...core, receipt_id: receiptId };
  return Object.freeze({
    ...canonicalCopy(unsigned),
    signature: Object.freeze({ algorithm: 'Ed25519', value: sign(RECEIPT_DOMAIN, unsigned, input.privateKey) }),
  });
}

export function verifyAgentMailboxDeliveryReceipt(receipt: unknown, options: {
  mailboxId: string;
  publicKeySpkiB64u: string;
  keyId: string;
  expectedEnvelopeDigest?: string;
}) {
  const refusal = (reason: string) => Object.freeze({
    verified: false, accepted: false, reason, authorizes: false as const,
  });
  if (!exactKeys(receipt, RECEIPT_KEYS)) return refusal('delivery_receipt_shape_invalid');
  try {
    canonical(receipt);
  } catch {
    return refusal('delivery_receipt_not_canonical');
  }
  if (receipt['@version'] !== AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION
      || !identifier(receipt.receipt_id)
      || receipt.mailbox_id !== options?.mailboxId
      || !identifier(receipt.mailbox_id)
      || (receipt.envelope_id !== null && !identifier(receipt.envelope_id))
      || (receipt.envelope_digest !== null && !DIGEST.test(receipt.envelope_digest))
      || !identifier(receipt.recipient_id)
      || !canonicalInstant(receipt.received_at)
      || !DELIVERY_STATUSES.has(receipt.delivery_status)
      || (receipt.reason !== null && typeof receipt.reason !== 'string')
      || receipt.authorizes !== false
      || receipt.signer_key_id !== options?.keyId
      || !exactKeys(receipt.signature, SIGNATURE_KEYS)
      || receipt.signature.algorithm !== 'Ed25519') {
    return refusal('delivery_receipt_shape_invalid');
  }
  if (options.expectedEnvelopeDigest !== undefined
      && receipt.envelope_digest !== options.expectedEnvelopeDigest) {
    return refusal('delivery_receipt_envelope_mismatch');
  }
  const publicKey = publicEd25519(options?.publicKeySpkiB64u);
  if (!publicKey) return refusal('delivery_receipt_key_invalid');
  const { signature, ...unsigned } = receipt;
  if (!verify(RECEIPT_DOMAIN, unsigned, signature.value, publicKey)) {
    return refusal('delivery_receipt_signature_invalid');
  }
  return Object.freeze({
    verified: true,
    accepted: receipt.delivery_status === 'ACCEPTED' || receipt.delivery_status === 'DUPLICATE',
    reason: receipt.delivery_status === 'REFUSED' ? receipt.reason : null,
    delivery_status: receipt.delivery_status,
    envelope_digest: receipt.envelope_digest,
    authorizes: false as const,
  });
}

export function createAgentMailbox(options: {
  mailboxId: string;
  store: AgentMailboxStore;
  senderDirectory: Record<string, unknown>;
  privateKey: unknown;
  keyId: string;
  now: () => string;
}) {
  if (!identifier(options?.mailboxId) || !identifier(options?.keyId)) {
    throw new TypeError('mailbox_service_identifier_invalid');
  }
  if (!options?.store || typeof options.store.put !== 'function'
      || typeof options.store.list !== 'function' || typeof options.store.acknowledge !== 'function'
      || !['single_process', 'shared_durable'].includes(options.store.deliveryAtomicity)
      || options.store.bodyBound !== true) {
    throw new TypeError('mailbox_store_contract_invalid');
  }
  const privateKey = privateEd25519(options.privateKey);
  if (!privateKey) throw new TypeError('mailbox_service_ed25519_key_required');
  if (typeof options.now !== 'function' || !isRecord(options.senderDirectory)) {
    throw new TypeError('mailbox_service_configuration_invalid');
  }
  const listeners = new Map<string, Set<(notification: JsonRecord) => void>>();
  const timestamp = () => {
    const value = canonicalInstant(options.now());
    if (!value) throw new Error('mailbox_trusted_time_unavailable');
    return value;
  };
  const receipt = (input: {
    envelopeId: string | null;
    envelopeDigest: string | null;
    recipientId: string;
    receivedAt: string;
    deliveryStatus: 'ACCEPTED' | 'DUPLICATE' | 'REFUSED';
    reason: string | null;
  }) => createDeliveryReceipt({
    mailboxId: options.mailboxId,
    keyId: options.keyId,
    privateKey,
    ...input,
  });
  return Object.freeze({
    mailbox_id: options.mailboxId,
    durable: options.store.durable,
    subscribe(recipientId: string, listener: (notification: JsonRecord) => void) {
      if (!identifier(recipientId) || typeof listener !== 'function') {
        throw new TypeError('mailbox_subscription_invalid');
      }
      const group = listeners.get(recipientId) ?? new Set();
      group.add(listener);
      listeners.set(recipientId, group);
      return () => group.delete(listener);
    },
    async deliver(envelope: unknown, { recipientId }: { recipientId: string }) {
      if (!identifier(recipientId)) throw new TypeError('mailbox_recipient_invalid');
      const receivedAt = timestamp();
      const verification = verifyAgentMailboxEnvelope(envelope, {
        senderDirectory: options.senderDirectory,
        expectedRecipientId: recipientId,
        asOf: receivedAt,
      });
      const candidate = isRecord(envelope) ? envelope : {};
      if (!verification.accepted) {
        return receipt({
          envelopeId: identifier(candidate.envelope_id) ? candidate.envelope_id : null,
          envelopeDigest: verification.envelope_digest,
          recipientId,
          receivedAt,
          deliveryStatus: 'REFUSED',
          reason: verification.reason,
        });
      }
      const stored: StoredEnvelope = {
        recipient_id: recipientId,
        envelope_id: candidate.envelope_id,
        envelope_digest: verification.envelope_digest,
        envelope: canonicalCopy(candidate),
        received_at: receivedAt,
        read_at: null,
      };
      const result = await options.store.put(stored);
      if (result.outcome === 'envelope_id_conflict' || result.outcome === 'thread_sequence_conflict') {
        return receipt({
          envelopeId: candidate.envelope_id,
          envelopeDigest: verification.envelope_digest,
          recipientId,
          receivedAt,
          deliveryStatus: 'REFUSED',
          reason: result.outcome,
        });
      }
      if (result.outcome === 'stored') {
        const notification = Object.freeze({
          mailbox_id: options.mailboxId,
          recipient_id: recipientId,
          envelope_id: candidate.envelope_id,
          envelope_digest: verification.envelope_digest,
          message_type: candidate.message_type,
          received_at: receivedAt,
        });
        for (const listener of listeners.get(recipientId) ?? []) listener(notification);
      }
      return receipt({
        envelopeId: candidate.envelope_id,
        envelopeDigest: verification.envelope_digest,
        recipientId,
        receivedAt,
        deliveryStatus: result.outcome === 'stored' ? 'ACCEPTED' : 'DUPLICATE',
        reason: null,
      });
    },
    async list(recipientId: string) {
      if (!identifier(recipientId)) throw new TypeError('mailbox_recipient_invalid');
      return options.store.list(recipientId);
    },
    async acknowledge({ recipientId, envelopeId }: { recipientId: string; envelopeId: string }) {
      if (!identifier(recipientId) || !identifier(envelopeId)) {
        throw new TypeError('mailbox_acknowledgement_invalid');
      }
      const acknowledged = await options.store.acknowledge(recipientId, envelopeId, timestamp());
      return Object.freeze({ acknowledged, authorizes: false as const });
    },
  });
}

export function extractMailboxActionProposal(envelope: unknown, options: {
  verifiedEnvelope: { accepted?: boolean; envelope_digest?: string | null };
}) {
  const refusal = (reason: string) => Object.freeze({ valid: false, authorizes: false as const, reason });
  if (!isRecord(envelope) || envelope.message_type !== 'action_proposal') {
    return refusal('not_an_action_proposal');
  }
  if (options?.verifiedEnvelope?.accepted !== true
      || options.verifiedEnvelope.envelope_digest !== agentMailboxDigest(envelope)) {
    return refusal('verified_envelope_required');
  }
  const payload = envelope.payload;
  if (!exactKeys(payload, new Set(['action_profile', 'action_digest', 'action']))
      || !identifier(payload.action_profile) || !DIGEST.test(payload.action_digest)
      || !isRecord(payload.action)) {
    return refusal('action_proposal_shape_invalid');
  }
  let actionDigest;
  try {
    actionDigest = agentMailboxDigest(payload.action);
  } catch {
    return refusal('action_not_canonical');
  }
  if (actionDigest !== payload.action_digest) return refusal('action_digest_mismatch');
  return Object.freeze({
    valid: true,
    authorizes: false as const,
    reason: null,
    action_profile: payload.action_profile,
    action_digest: payload.action_digest,
    action: canonicalCopy(payload.action),
    envelope_digest: options.verifiedEnvelope.envelope_digest,
  });
}

function admissionRefusal(reason: string, state: 'REFUSED' | 'INDETERMINATE' = 'REFUSED') {
  return Object.freeze({
    admitted: false,
    state,
    ready_for_executor: false,
    reason,
    mailbox_authorizes: false as const,
  });
}

export async function admitMailboxActionProposal(input: {
  proposal: any;
  verifyAdmission?: (proposal: any) => Promise<{
    verified: boolean;
    accepted: boolean;
    action_digest?: string;
    admission_digest?: string;
  }>;
}) {
  if (!input?.proposal?.valid || input.proposal.authorizes !== false) {
    return admissionRefusal('valid_action_proposal_required');
  }
  if (typeof input.verifyAdmission !== 'function') {
    return admissionRefusal('admission_verifier_required');
  }
  let admission;
  try {
    admission = await input.verifyAdmission(input.proposal);
  } catch {
    return admissionRefusal('admission_verification_indeterminate', 'INDETERMINATE');
  }
  if (!isRecord(admission) || admission.verified !== true) {
    return admissionRefusal('admission_not_verified');
  }
  if (admission.accepted !== true) return admissionRefusal('admission_not_accepted');
  if (admission.action_digest !== input.proposal.action_digest) {
    return admissionRefusal('admission_action_mismatch');
  }
  if (!DIGEST.test(admission.admission_digest ?? '')) {
    return admissionRefusal('admission_digest_invalid');
  }
  return Object.freeze({
    admitted: true,
    state: 'ADMITTED' as const,
    ready_for_executor: true,
    reason: null,
    action: canonicalCopy(input.proposal.action),
    action_digest: input.proposal.action_digest,
    envelope_digest: input.proposal.envelope_digest,
    admission_digest: admission.admission_digest,
    authority_source: 'external_emilia_admission' as const,
    mailbox_authorizes: false as const,
  });
}
