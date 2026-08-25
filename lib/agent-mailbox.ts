// SPDX-License-Identifier: Apache-2.0

/**
 * Signed store-and-forward envelopes for agent-to-agent communication.
 *
 * The mailbox is a delivery surface. An envelope can carry context or an
 * action proposal, but it never carries execution authority. Consequential
 * actions become executor-ready only after a separate EMILIA Gate adapter
 * reports authorization bound to the exact proposed action digest. The
 * mailbox action digest is a content binding, not a CAID or authority token.
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
export const AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE = 'EP-AGENT-MAILBOX-ENVELOPE-VERIFICATION-v0.1';
export const AGENT_MAILBOX_DELIVERY_VERIFICATION_PROFILE = 'EP-AGENT-MAILBOX-DELIVERY-VERIFICATION-v0.1';
export const AGENT_MAILBOX_STORED_DELIVERY_VERSION = 'EP-AGENT-MAILBOX-STORED-DELIVERY-v0.1';
export const AGENT_MAILBOX_READ_ACKNOWLEDGEMENT_VERSION = 'EP-AGENT-MAILBOX-READ-ACKNOWLEDGEMENT-v0.1';

const ENVELOPE_DOMAIN = Buffer.from(`${AGENT_MAILBOX_ENVELOPE_VERSION}\0`, 'utf8');
const RECEIPT_DOMAIN = Buffer.from(`${AGENT_MAILBOX_DELIVERY_RECEIPT_VERSION}\0`, 'utf8');
const STORED_DELIVERY_DOMAIN = Buffer.from(`${AGENT_MAILBOX_STORED_DELIVERY_VERSION}\0`, 'utf8');
const READ_ACKNOWLEDGEMENT_DOMAIN = Buffer.from(`${AGENT_MAILBOX_READ_ACKNOWLEDGEMENT_VERSION}\0`, 'utf8');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const CANONICAL_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const ED25519_SIGNATURE_BYTES = 64;
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
const ACTION_PROPOSAL_KEYS = new Set([
  'valid',
  'authorizes',
  'reason',
  'action_profile',
  'action_digest',
  'action',
  'envelope_digest',
]);
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
const SENDER_VERIFICATION_KEYS = new Set([
  'verification_profile',
  'sender_id',
  'signer_key_id',
  'public_key_spki_b64u',
  'verified_at',
  'authorizes',
]);
const DELIVERY_BINDING_KEYS = new Set([
  '@version',
  'mailbox_id',
  'signer_key_id',
  'authorizes',
  'signature',
]);
const READ_ACKNOWLEDGEMENT_KEYS = new Set([
  '@version',
  'mailbox_id',
  'recipient_id',
  'envelope_id',
  'envelope_digest',
  'delivery_binding_digest',
  'read_at',
  'authorizes',
  'signer_key_id',
  'signature',
]);
const STORED_ENVELOPE_KEYS = new Set([
  'recipient_id',
  'envelope_id',
  'envelope_digest',
  'envelope',
  'received_at',
  'read_acknowledgement',
  'sender_verification',
  'delivery_binding',
]);
const STORE_PUT_RESULT_KEYS = new Set(['outcome', 'record']);
const ADMISSION_RESULT_KEYS = new Set([
  'verified',
  'accepted',
  'authorized',
  'action_digest',
  'admission_digest',
  'authority_source',
]);
const MAX_CANONICAL_NODES = 10_000;
const MAX_CANONICAL_STRING_BYTES = 262_144;
const FILE_STORE_QUEUES = new Map<string, Promise<void>>();
type SenderVerification = {
  verification_profile: typeof AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE;
  sender_id: string;
  signer_key_id: string;
  public_key_spki_b64u: string;
  verified_at: string;
  authorizes: false;
};

type DeliveryBinding = {
  '@version': typeof AGENT_MAILBOX_STORED_DELIVERY_VERSION;
  mailbox_id: string;
  signer_key_id: string;
  authorizes: false;
  signature: {
    algorithm: 'Ed25519';
    value: string;
  };
};

type ReadAcknowledgement = {
  '@version': typeof AGENT_MAILBOX_READ_ACKNOWLEDGEMENT_VERSION;
  mailbox_id: string;
  recipient_id: string;
  envelope_id: string;
  envelope_digest: string;
  delivery_binding_digest: string;
  read_at: string;
  authorizes: false;
  signer_key_id: string;
  signature: {
    algorithm: 'Ed25519';
    value: string;
  };
};

const VERIFIED_ENVELOPE_RESULTS = new WeakMap<object, SenderVerification>();

type JsonRecord = Record<string, any>;

type StoredEnvelope = {
  recipient_id: string;
  envelope_id: string;
  envelope_digest: string;
  envelope: JsonRecord;
  received_at: string;
  read_acknowledgement: ReadAcknowledgement | null;
  sender_verification: SenderVerification;
  delivery_binding: DeliveryBinding;
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
  acknowledge(
    recipientId: string,
    envelopeId: string,
    acknowledgement: ReadAcknowledgement,
  ): Promise<StoredEnvelope | null>;
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
  if (typeof value !== 'string' || !CANONICAL_INSTANT.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonical = new Date(parsed).toISOString();
  return canonical === value ? canonical : null;
}

function canonicalBase64url(value: unknown): Buffer | null {
  if (typeof value !== 'string' || !BASE64URL.test(value)) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.toString('base64url') === value ? bytes : null;
  } catch {
    return null;
  }
}

function ed25519Signature(value: unknown): value is string {
  return canonicalBase64url(value)?.length === ED25519_SIGNATURE_BYTES;
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
  const bytes = canonicalBase64url(value);
  if (!bytes) return null;
  try {
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
  if (!ed25519Signature(signature)) return false;
  try {
    const bytes = Buffer.concat([domain, Buffer.from(canonical(value), 'utf8')]);
    return crypto.verify(null, bytes, publicKey, canonicalBase64url(signature)!);
  } catch {
    return false;
  }
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonical(value));
}

function deepFreeze<T>(value: T): T {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else if (isRecord(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return Object.freeze(value);
}

async function serializeFileStore<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = FILE_STORE_QUEUES.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => { release = resolve; });
  const tail = previous.then(() => current);
  FILE_STORE_QUEUES.set(key, tail);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (FILE_STORE_QUEUES.get(key) === tail) FILE_STORE_QUEUES.delete(key);
  }
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
    verification_profile: AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE,
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
      || envelope.signature.algorithm !== 'Ed25519'
      || !ed25519Signature(envelope.signature.value)) {
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
  const publicKeySpkiB64u = sender.public_key_spki_b64u;
  const publicKey = publicEd25519(publicKeySpkiB64u);
  if (!publicKey) return envelopeRefusal('sender_key_invalid', envelopeDigest);
  const { signature, ...unsigned } = envelope;
  if (!verify(ENVELOPE_DOMAIN, unsigned, signature.value, publicKey)) {
    return envelopeRefusal('signature_invalid', envelopeDigest);
  }
  const result = Object.freeze({
    verification_profile: AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE,
    verified: true,
    accepted: true,
    reason: null,
    envelope_digest: envelopeDigest,
    authorizes: false as const,
  });
  VERIFIED_ENVELOPE_RESULTS.set(result, deepFreeze({
    verification_profile: AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE,
    sender_id: envelope.sender_id,
    signer_key_id: envelope.signer_key_id,
    public_key_spki_b64u: publicKeySpkiB64u,
    verified_at: asOf,
    authorizes: false as const,
  }));
  return result;
}

function copyRecord(record: StoredEnvelope): StoredEnvelope {
  return structuredClone(record);
}

function sameStoredDelivery(left: StoredEnvelope, right: StoredEnvelope): boolean {
  return canonical({ ...left, read_acknowledgement: null })
    === canonical({ ...right, read_acknowledgement: null });
}

function storedDeliverySigningValue(
  record: Pick<StoredEnvelope,
    'recipient_id' | 'envelope_id' | 'envelope_digest' | 'envelope'
    | 'received_at' | 'sender_verification'>,
  binding: Omit<DeliveryBinding, 'signature'>,
): JsonRecord {
  // Read acknowledgement is a separate signed first-write-wins record. The
  // delivery binding covers every immutable delivery field, including the
  // exact delivery-time sender key, and remains non-authorizing.
  return {
    ...binding,
    stored_delivery: {
      recipient_id: record.recipient_id,
      envelope_id: record.envelope_id,
      envelope_digest: record.envelope_digest,
      envelope: record.envelope,
      received_at: record.received_at,
      sender_verification: record.sender_verification,
    },
  };
}

function createReadAcknowledgement(record: StoredEnvelope, input: {
  mailboxId: string;
  keyId: string;
  readAt: string;
  privateKey: crypto.KeyObject;
}): ReadAcknowledgement {
  const unsigned: Omit<ReadAcknowledgement, 'signature'> = {
    '@version': AGENT_MAILBOX_READ_ACKNOWLEDGEMENT_VERSION,
    mailbox_id: input.mailboxId,
    recipient_id: record.recipient_id,
    envelope_id: record.envelope_id,
    envelope_digest: record.envelope_digest,
    delivery_binding_digest: agentMailboxDigest(record.delivery_binding),
    read_at: input.readAt,
    authorizes: false,
    signer_key_id: input.keyId,
  };
  return deepFreeze({
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      value: sign(READ_ACKNOWLEDGEMENT_DOMAIN, unsigned, input.privateKey),
    },
  });
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
    async acknowledge(recipientId, envelopeId, acknowledgement) {
      const record = records.get(key(recipientId, envelopeId));
      if (!record) return null;
      if (record.read_acknowledgement === null) {
        const updated = checkedStoredEnvelope({
          ...record,
          read_acknowledgement: acknowledgement,
        });
        if (!updated) throw new Error('mailbox_store_acknowledgement_invalid');
        records.set(key(recipientId, envelopeId), updated);
        return copyRecord(updated);
      }
      return copyRecord(record);
    },
  });
}

function storageKey(recipientId: string, envelopeId: string): string {
  return crypto.createHash('sha256').update(`${recipientId}\0${envelopeId}`, 'utf8').digest('hex');
}

function shapedReadAcknowledgement(value: unknown): value is ReadAcknowledgement {
  return exactKeys(value, READ_ACKNOWLEDGEMENT_KEYS)
    && value['@version'] === AGENT_MAILBOX_READ_ACKNOWLEDGEMENT_VERSION
    && identifier(value.mailbox_id)
    && identifier(value.recipient_id)
    && identifier(value.envelope_id)
    && DIGEST.test(value.envelope_digest)
    && DIGEST.test(value.delivery_binding_digest)
    && canonicalInstant(value.read_at) !== null
    && value.authorizes === false
    && identifier(value.signer_key_id)
    && exactKeys(value.signature, SIGNATURE_KEYS)
    && value.signature.algorithm === 'Ed25519'
    && ed25519Signature(value.signature.value);
}

function checkedStoredEnvelope(value: unknown): StoredEnvelope | null {
  try {
    canonical(value);
  } catch {
    return null;
  }
  if (!exactKeys(value, STORED_ENVELOPE_KEYS)) return null;
  const record = value;
  if (!identifier(record.recipient_id)
      || !identifier(record.envelope_id)
      || !DIGEST.test(record.envelope_digest)
      || !canonicalInstant(record.received_at)
      || (record.read_acknowledgement !== null
        && !shapedReadAcknowledgement(record.read_acknowledgement))
      || !exactKeys(record.sender_verification, SENDER_VERIFICATION_KEYS)
      || record.sender_verification.verification_profile !== AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE
      || !identifier(record.sender_verification.sender_id)
      || !identifier(record.sender_verification.signer_key_id)
      || !publicEd25519(record.sender_verification.public_key_spki_b64u)
      || record.sender_verification.verified_at !== record.received_at
      || record.sender_verification.authorizes !== false
      || !exactKeys(record.delivery_binding, DELIVERY_BINDING_KEYS)
      || record.delivery_binding['@version'] !== AGENT_MAILBOX_STORED_DELIVERY_VERSION
      || !identifier(record.delivery_binding.mailbox_id)
      || !identifier(record.delivery_binding.signer_key_id)
      || record.delivery_binding.authorizes !== false
      || !exactKeys(record.delivery_binding.signature, SIGNATURE_KEYS)
      || record.delivery_binding.signature.algorithm !== 'Ed25519'
      || !ed25519Signature(record.delivery_binding.signature.value)
      || !exactKeys(record.envelope, ENVELOPE_KEYS)
      || record.envelope.envelope_id !== record.envelope_id
      || record.envelope.recipient_id !== record.recipient_id
      || record.envelope['@version'] !== AGENT_MAILBOX_ENVELOPE_VERSION
      || !identifier(record.envelope.sender_id)
      || !identifier(record.envelope.thread_id)
      || !Number.isSafeInteger(record.envelope.sequence) || record.envelope.sequence < 1
      || !MESSAGE_TYPES.has(record.envelope.message_type)
      || !DIGEST.test(record.envelope.payload_digest)
      || !exactKeys(record.envelope.authority, AUTHORITY_KEYS)
      || record.envelope.authority.authorizes !== false
      || !identifier(record.envelope.signer_key_id)
      || record.sender_verification.sender_id !== record.envelope.sender_id
      || record.sender_verification.signer_key_id !== record.envelope.signer_key_id
      || !exactKeys(record.envelope.signature, SIGNATURE_KEYS)
      || record.envelope.signature.algorithm !== 'Ed25519'
      || !ed25519Signature(record.envelope.signature.value)) {
    return null;
  }
  try {
    if (agentMailboxDigest(record.envelope.payload) !== record.envelope.payload_digest
        || agentMailboxDigest(record.envelope) !== record.envelope_digest) return null;
    const acknowledgement = record.read_acknowledgement;
    if (acknowledgement !== null && (
      acknowledgement.mailbox_id !== record.delivery_binding.mailbox_id
      || acknowledgement.recipient_id !== record.recipient_id
      || acknowledgement.envelope_id !== record.envelope_id
      || acknowledgement.envelope_digest !== record.envelope_digest
      || acknowledgement.delivery_binding_digest !== agentMailboxDigest(record.delivery_binding)
      || Date.parse(acknowledgement.read_at) < Date.parse(record.received_at)
    )) return null;
  } catch {
    return null;
  }
  return canonicalCopy(record) as StoredEnvelope;
}

function verifyStoredEnvelope(record: StoredEnvelope, options: {
  mailboxId: string;
  verificationKeys: ReadonlyMap<string, crypto.KeyObject>;
  asOf: string;
}): boolean {
  if (record.delivery_binding.mailbox_id !== options.mailboxId) return false;
  const publicKey = options.verificationKeys.get(record.delivery_binding.signer_key_id);
  if (!publicKey) return false;
  const { signature, ...binding } = record.delivery_binding;
  if (!verify(
    STORED_DELIVERY_DOMAIN,
    storedDeliverySigningValue(record, binding),
    signature.value,
    publicKey,
  )) return false;

  const senderDirectory: JsonRecord = Object.create(null);
  senderDirectory[record.sender_verification.sender_id] = {
    key_id: record.sender_verification.signer_key_id,
    public_key_spki_b64u: record.sender_verification.public_key_spki_b64u,
    status: 'active',
  };
  const verification = verifyAgentMailboxEnvelope(record.envelope, {
    senderDirectory,
    expectedRecipientId: record.recipient_id,
    asOf: record.sender_verification.verified_at,
  });
  if (verification.accepted !== true
      || verification.envelope_digest !== record.envelope_digest
      || verification.authorizes !== false) return false;

  const acknowledgement = record.read_acknowledgement;
  if (acknowledgement === null) return true;
  if (Date.parse(acknowledgement.read_at) > Date.parse(options.asOf)) return false;
  const acknowledgementKey = options.verificationKeys.get(acknowledgement.signer_key_id);
  if (!acknowledgementKey) return false;
  const { signature: acknowledgementSignature, ...unsignedAcknowledgement } = acknowledgement;
  return verify(
    READ_ACKNOWLEDGEMENT_DOMAIN,
    unsignedAcknowledgement,
    acknowledgementSignature.value,
    acknowledgementKey,
  )
    && acknowledgement.authorizes === false;
}

function parseStoredEnvelope(raw: string): StoredEnvelope {
  const gate = strictJsonGate(raw);
  if (!gate.ok) throw new Error('mailbox_store_record_corrupt');
  const record = checkedStoredEnvelope(JSON.parse(raw));
  if (!record) throw new Error('mailbox_store_record_corrupt');
  return record;
}

function checkedStorePutResult(value: unknown, pending: StoredEnvelope) {
  if (!exactKeys(value, STORE_PUT_RESULT_KEYS)
      || !['stored', 'duplicate', 'envelope_id_conflict', 'thread_sequence_conflict'].includes(value.outcome)) {
    return null;
  }
  const record = checkedStoredEnvelope(value.record);
  if (!record || record.recipient_id !== pending.recipient_id) return null;
  if (value.outcome === 'stored') {
    if (canonical(record) !== canonical(pending)) return null;
  } else if (value.outcome === 'duplicate') {
    if (record.envelope_id !== pending.envelope_id
        || record.envelope_digest !== pending.envelope_digest
        || canonical(record.envelope) !== canonical(pending.envelope)) return null;
  } else if (value.outcome === 'envelope_id_conflict') {
    if (record.envelope_id !== pending.envelope_id
        || record.envelope_digest === pending.envelope_digest) return null;
  } else if (record.envelope_digest === pending.envelope_digest
      || record.envelope.sender_id !== pending.envelope.sender_id
      || record.envelope.thread_id !== pending.envelope.thread_id
      || record.envelope.sequence !== pending.envelope.sequence) {
    return null;
  }
  return { outcome: value.outcome, record } as const;
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

async function readStoredEnvelopeFile(recordsDirectory: string, name: string): Promise<StoredEnvelope> {
  const record = parseStoredEnvelope(await readFile(path.join(recordsDirectory, name), 'utf8'));
  if (name !== `${storageKey(record.recipient_id, record.envelope_id)}.json`) {
    throw new Error('mailbox_store_record_corrupt');
  }
  return record;
}

export function createFileAgentMailboxStore({ directory }: { directory: string }): AgentMailboxStore {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    throw new TypeError('mailbox_store_directory_must_be_absolute');
  }
  const recordsDirectory = path.resolve(directory, 'records');
  const ready = mkdir(recordsDirectory, { recursive: true, mode: 0o700 });
  const filename = (recipientId: string, envelopeId: string) => path.join(recordsDirectory, `${storageKey(recipientId, envelopeId)}.json`);
  return Object.freeze({
    durable: true,
    deliveryAtomicity: 'single_process',
    bodyBound: true,
    async put(record) {
      return serializeFileStore(recordsDirectory, async () => {
        await ready;
        const target = filename(record.recipient_id, record.envelope_id);
        const names = (await readdir(recordsDirectory)).filter((name) => name.endsWith('.json'));
        const existingRecords = await Promise.all(names.map((name) => (
          readStoredEnvelopeFile(recordsDirectory, name)
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
        const existing = await readStoredEnvelopeFile(recordsDirectory, path.basename(target));
        return {
          outcome: existing.envelope_digest === record.envelope_digest ? 'duplicate' as const : 'envelope_id_conflict' as const,
          record: copyRecord(existing),
        };
      });
    },
    async list(recipientId) {
      return serializeFileStore(recordsDirectory, async () => {
        await ready;
        const names = (await readdir(recordsDirectory)).filter((name) => name.endsWith('.json'));
        const records = await Promise.all(names.map((name) => (
          readStoredEnvelopeFile(recordsDirectory, name)
        )));
        return records
          .filter((record) => record.recipient_id === recipientId)
          .sort((left, right) => left.envelope.sequence - right.envelope.sequence)
          .map(copyRecord);
      });
    },
    async acknowledge(recipientId, envelopeId, acknowledgement) {
      return serializeFileStore(recordsDirectory, async () => {
        await ready;
        const target = filename(recipientId, envelopeId);
        let record: StoredEnvelope;
        try {
          record = await readStoredEnvelopeFile(recordsDirectory, path.basename(target));
        } catch (error: any) {
          if (error?.code === 'ENOENT') return null;
          throw error;
        }
        if (record.read_acknowledgement !== null) return copyRecord(record);
        const updated = checkedStoredEnvelope({
          ...record,
          read_acknowledgement: acknowledgement,
        });
        if (!updated) throw new Error('mailbox_store_acknowledgement_invalid');
        const temporary = path.join(recordsDirectory, `.${storageKey(recipientId, envelopeId)}.${crypto.randomUUID()}.tmp`);
        let handle;
        try {
          handle = await open(temporary, 'wx', 0o600);
          await handle.writeFile(canonical(updated), 'utf8');
          await handle.sync();
        } finally {
          await handle?.close();
        }
        await rename(temporary, target);
        return copyRecord(await readStoredEnvelopeFile(recordsDirectory, path.basename(target)));
      });
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
  expectedRecipientId: string;
  expectedEnvelopeId?: string;
  expectedEnvelopeDigest?: string;
}) {
  const refusal = (reason: string) => Object.freeze({
    verification_profile: AGENT_MAILBOX_DELIVERY_VERIFICATION_PROFILE,
    verified: false, accepted: false, duplicate: false, reason, authorizes: false as const,
  });
  if (!identifier(options?.expectedRecipientId)) return refusal('delivery_receipt_recipient_required');
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
      || (receipt.delivery_status === 'REFUSED'
        ? typeof receipt.reason !== 'string' || receipt.reason.length < 1 || [...receipt.reason].length > 256
        : receipt.reason !== null)
      || receipt.authorizes !== false
      || !identifier(receipt.signer_key_id)
      || receipt.signer_key_id !== options?.keyId
      || !exactKeys(receipt.signature, SIGNATURE_KEYS)
      || receipt.signature.algorithm !== 'Ed25519'
      || !ed25519Signature(receipt.signature.value)
      || (receipt.delivery_status !== 'REFUSED'
        && (receipt.envelope_id === null || receipt.envelope_digest === null))) {
    return refusal('delivery_receipt_shape_invalid');
  }
  if (receipt.recipient_id !== options.expectedRecipientId) {
    return refusal('delivery_receipt_recipient_mismatch');
  }
  if (options.expectedEnvelopeId !== undefined
      && receipt.envelope_id !== options.expectedEnvelopeId) {
    return refusal('delivery_receipt_envelope_mismatch');
  }
  if (options.expectedEnvelopeDigest !== undefined
      && receipt.envelope_digest !== options.expectedEnvelopeDigest) {
    return refusal('delivery_receipt_envelope_mismatch');
  }
  const publicKey = publicEd25519(options?.publicKeySpkiB64u);
  if (!publicKey) return refusal('delivery_receipt_key_invalid');
  const { signature, ...unsigned } = receipt;
  const { receipt_id: receiptId, ...core } = unsigned;
  const expectedReceiptId = `delivery:${agentMailboxDigest(core).slice('sha256:'.length)}`;
  if (receiptId !== expectedReceiptId) return refusal('delivery_receipt_id_mismatch');
  if (!verify(RECEIPT_DOMAIN, unsigned, signature.value, publicKey)) {
    return refusal('delivery_receipt_signature_invalid');
  }
  return Object.freeze({
    verification_profile: AGENT_MAILBOX_DELIVERY_VERIFICATION_PROFILE,
    verified: true,
    accepted: receipt.delivery_status === 'ACCEPTED',
    duplicate: receipt.delivery_status === 'DUPLICATE',
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
  mailboxVerificationKeys?: Record<string, unknown>;
}) {
  if (!identifier(options?.mailboxId) || !identifier(options?.keyId)) {
    throw new TypeError('mailbox_service_identifier_invalid');
  }
  if (!options?.store || typeof options.store.put !== 'function'
      || typeof options.store.list !== 'function' || typeof options.store.acknowledge !== 'function'
      || typeof options.store.durable !== 'boolean'
      || !['single_process', 'shared_durable'].includes(options.store.deliveryAtomicity)
      || options.store.bodyBound !== true) {
    throw new TypeError('mailbox_store_contract_invalid');
  }
  const privateKey = privateEd25519(options.privateKey);
  if (!privateKey) throw new TypeError('mailbox_service_ed25519_key_required');
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeySpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const configuredVerificationKeys = options.mailboxVerificationKeys === undefined
    ? {}
    : options.mailboxVerificationKeys;
  if (!isRecord(configuredVerificationKeys)) {
    throw new TypeError('mailbox_service_verification_keys_invalid');
  }
  const mailboxVerificationKeys = new Map<string, crypto.KeyObject>();
  for (const keyId of Reflect.ownKeys(configuredVerificationKeys)) {
    if (typeof keyId !== 'string' || !identifier(keyId)) {
      throw new TypeError('mailbox_service_verification_keys_invalid');
    }
    const encodedKey = configuredVerificationKeys[keyId];
    if (keyId === options.keyId && encodedKey !== publicKeySpkiB64u) {
      throw new TypeError('mailbox_service_verification_key_mismatch');
    }
    const verificationKey = publicEd25519(encodedKey);
    if (!verificationKey) throw new TypeError('mailbox_service_verification_keys_invalid');
    mailboxVerificationKeys.set(keyId, keyId === options.keyId ? publicKey : verificationKey);
  }
  mailboxVerificationKeys.set(options.keyId, publicKey);
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
  const verifiedList = async (recipientId: string, asOf: string): Promise<StoredEnvelope[]> => {
    const listed = await options.store.list(recipientId);
    if (!Array.isArray(listed)) throw new Error('mailbox_store_result_invalid');
    const records: StoredEnvelope[] = [];
    const byEnvelopeId = new Map<string, string>();
    const byThreadSequence = new Map<string, string>();
    for (const candidate of listed) {
      const record = checkedStoredEnvelope(candidate);
      if (!record || record.recipient_id !== recipientId || !verifyStoredEnvelope(record, {
        mailboxId: options.mailboxId,
        verificationKeys: mailboxVerificationKeys,
        asOf,
      })) throw new Error('mailbox_store_result_invalid');

      const recordBytes = canonical(record);
      const envelopeKey = `${record.recipient_id}\0${record.envelope_id}`;
      const sequenceKey = [
        record.recipient_id,
        record.envelope.sender_id,
        record.envelope.thread_id,
        record.envelope.sequence,
      ].join('\0');
      const envelopeMatch = byEnvelopeId.get(envelopeKey);
      const sequenceMatch = byThreadSequence.get(sequenceKey);
      if (envelopeMatch !== undefined || sequenceMatch !== undefined) {
        if (envelopeMatch === recordBytes && sequenceMatch === recordBytes) continue;
        throw new Error('mailbox_store_result_invalid');
      }
      byEnvelopeId.set(envelopeKey, recordBytes);
      byThreadSequence.set(sequenceKey, recordBytes);
      records.push(copyRecord(record));
    }
    return records;
  };
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
      const senderVerification = VERIFIED_ENVELOPE_RESULTS.get(verification);
      if (!senderVerification) {
        return receipt({
          envelopeId: candidate.envelope_id,
          envelopeDigest: verification.envelope_digest,
          recipientId,
          receivedAt,
          deliveryStatus: 'REFUSED',
          reason: 'mailbox_sender_verification_unavailable',
        });
      }
      const storedDelivery = {
        recipient_id: recipientId,
        envelope_id: candidate.envelope_id,
        envelope_digest: verification.envelope_digest,
        envelope: canonicalCopy(candidate),
        received_at: receivedAt,
        read_acknowledgement: null,
        sender_verification: canonicalCopy(senderVerification),
      };
      const deliveryBinding: Omit<DeliveryBinding, 'signature'> = {
        '@version': AGENT_MAILBOX_STORED_DELIVERY_VERSION,
        mailbox_id: options.mailboxId,
        signer_key_id: options.keyId,
        authorizes: false as const,
      };
      const stored: StoredEnvelope = {
        ...storedDelivery,
        delivery_binding: {
          ...deliveryBinding,
          signature: {
            algorithm: 'Ed25519',
            value: sign(
              STORED_DELIVERY_DOMAIN,
              storedDeliverySigningValue(storedDelivery, deliveryBinding),
              privateKey,
            ),
          },
        },
      };
      const result = checkedStorePutResult(await options.store.put(stored), stored);
      if (!result || !verifyStoredEnvelope(result.record, {
        mailboxId: options.mailboxId,
        verificationKeys: mailboxVerificationKeys,
        asOf: receivedAt,
      })) {
        return receipt({
          envelopeId: candidate.envelope_id,
          envelopeDigest: verification.envelope_digest,
          recipientId,
          receivedAt,
          deliveryStatus: 'REFUSED',
          reason: 'mailbox_store_result_invalid',
        });
      }
      if (result.outcome === 'envelope_id_conflict' || result.outcome === 'thread_sequence_conflict') {
        return receipt({
          envelopeId: stored.envelope_id,
          envelopeDigest: stored.envelope_digest,
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
          envelope_id: stored.envelope_id,
          envelope_digest: stored.envelope_digest,
          message_type: stored.envelope.message_type,
          received_at: receivedAt,
        });
        for (const listener of listeners.get(recipientId) ?? []) {
          try {
            listener(notification);
          } catch {
            // Delivery is already durable. A local chime cannot suppress its receipt.
          }
        }
      }
      return receipt({
        envelopeId: stored.envelope_id,
        envelopeDigest: stored.envelope_digest,
        recipientId,
        receivedAt,
        deliveryStatus: result.outcome === 'stored' ? 'ACCEPTED' : 'DUPLICATE',
        reason: null,
      });
    },
    async list(recipientId: string) {
      if (!identifier(recipientId)) throw new TypeError('mailbox_recipient_invalid');
      return verifiedList(recipientId, timestamp());
    },
    async acknowledge({ recipientId, envelopeId }: { recipientId: string; envelopeId: string }) {
      if (!identifier(recipientId) || !identifier(envelopeId)) {
        throw new TypeError('mailbox_acknowledgement_invalid');
      }
      const readAt = timestamp();
      const before = await verifiedList(recipientId, readAt);
      const existing = before.find((record) => record.envelope_id === envelopeId);
      if (!existing) return Object.freeze({ acknowledgement: null, authorizes: false as const });
      if (existing.read_acknowledgement !== null) {
        return deepFreeze({
          acknowledgement: canonicalCopy(existing.read_acknowledgement),
          authorizes: false as const,
        });
      }

      const pendingAcknowledgement = createReadAcknowledgement(existing, {
        mailboxId: options.mailboxId,
        keyId: options.keyId,
        readAt,
        privateKey,
      });
      const returnedValue = await options.store.acknowledge(
        recipientId,
        envelopeId,
        pendingAcknowledgement,
      );
      if (returnedValue === null) {
        const afterMissing = await verifiedList(recipientId, readAt);
        if (afterMissing.some((record) => record.envelope_id === envelopeId)) {
          throw new Error('mailbox_store_result_invalid');
        }
        return Object.freeze({ acknowledgement: null, authorizes: false as const });
      }
      const returned = checkedStoredEnvelope(returnedValue);
      if (!returned
          || returned.recipient_id !== recipientId
          || returned.envelope_id !== envelopeId
          || returned.read_acknowledgement === null
          || !sameStoredDelivery(returned, existing)
          || !verifyStoredEnvelope(returned, {
            mailboxId: options.mailboxId,
            verificationKeys: mailboxVerificationKeys,
            asOf: readAt,
          })) throw new Error('mailbox_store_result_invalid');

      const after = await verifiedList(recipientId, readAt);
      const persisted = after.find((record) => record.envelope_id === envelopeId);
      if (!persisted
          || persisted.read_acknowledgement === null
          || canonical(persisted.read_acknowledgement) !== canonical(returned.read_acknowledgement)) {
        throw new Error('mailbox_store_result_invalid');
      }
      return deepFreeze({
        acknowledgement: canonicalCopy(persisted.read_acknowledgement),
        authorizes: false as const,
      });
    },
  });
}

export function extractMailboxActionProposal(envelope: unknown, options: {
  verifiedEnvelope: {
    verification_profile?: string;
    verified?: boolean;
    accepted?: boolean;
    envelope_digest?: string | null;
  };
}) {
  const refusal = (reason: string) => Object.freeze({ valid: false, authorizes: false as const, reason });
  if (!isRecord(envelope) || envelope.message_type !== 'action_proposal') {
    return refusal('not_an_action_proposal');
  }
  let envelopeDigest: string;
  try {
    envelopeDigest = agentMailboxDigest(envelope);
  } catch {
    return refusal('verified_envelope_required');
  }
  if (options?.verifiedEnvelope?.verification_profile !== AGENT_MAILBOX_ENVELOPE_VERIFICATION_PROFILE
      || options.verifiedEnvelope.verified !== true
      || options.verifiedEnvelope.accepted !== true
      || !VERIFIED_ENVELOPE_RESULTS.has(options.verifiedEnvelope)
      || options.verifiedEnvelope.envelope_digest !== envelopeDigest) {
    return refusal('verified_envelope_required');
  }
  const payload = envelope.payload;
  if (!exactKeys(payload, new Set(['action_profile', 'action_digest', 'action']))
      || !identifier(payload.action_profile) || !DIGEST.test(payload.action_digest)
      || !isRecord(payload.action)) {
    return refusal('action_proposal_shape_invalid');
  }
  if (payload.action['@version'] !== payload.action_profile) {
    return refusal('action_profile_mismatch');
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
    action: deepFreeze(canonicalCopy(payload.action)),
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
    authorized?: boolean;
    action_digest?: string;
    admission_digest?: string;
    authority_source?: string;
  }>;
}) {
  let proposalSnapshot: JsonRecord;
  try {
    proposalSnapshot = canonicalCopy(input?.proposal);
  } catch {
    return admissionRefusal('valid_action_proposal_required');
  }
  if (!exactKeys(proposalSnapshot, ACTION_PROPOSAL_KEYS)
      || proposalSnapshot.valid !== true
      || proposalSnapshot.authorizes !== false
      || proposalSnapshot.reason !== null
      || !identifier(proposalSnapshot.action_profile)
      || !DIGEST.test(proposalSnapshot.action_digest)
      || !DIGEST.test(proposalSnapshot.envelope_digest)
      || !isRecord(proposalSnapshot.action)) {
    return admissionRefusal('valid_action_proposal_required');
  }
  if (typeof input.verifyAdmission !== 'function') {
    return admissionRefusal('admission_verifier_required');
  }
  let actionSnapshot: JsonRecord;
  try {
    actionSnapshot = canonicalCopy(proposalSnapshot.action);
  } catch {
    return admissionRefusal('proposal_action_not_canonical');
  }
  if (agentMailboxDigest(actionSnapshot) !== proposalSnapshot.action_digest) {
    return admissionRefusal('proposal_action_digest_mismatch');
  }
  const verifierProposal = canonicalCopy({
    ...proposalSnapshot,
    action: actionSnapshot,
  });
  let admission;
  try {
    admission = await input.verifyAdmission(verifierProposal);
  } catch {
    return admissionRefusal('admission_verification_indeterminate', 'INDETERMINATE');
  }
  let checkedAdmission: JsonRecord;
  try {
    checkedAdmission = canonicalCopy(admission);
  } catch {
    return admissionRefusal('admission_not_verified');
  }
  if (!isRecord(checkedAdmission) || checkedAdmission.verified !== true) {
    return admissionRefusal('admission_not_verified');
  }
  if (checkedAdmission.accepted !== true) return admissionRefusal('admission_not_accepted');
  if (checkedAdmission.authorized !== true || checkedAdmission.authority_source !== 'emilia_gate') {
    return admissionRefusal('admission_not_authorized');
  }
  if (!exactKeys(checkedAdmission, ADMISSION_RESULT_KEYS)) {
    return admissionRefusal('admission_shape_invalid');
  }
  if (checkedAdmission.action_digest !== proposalSnapshot.action_digest) {
    return admissionRefusal('admission_action_mismatch');
  }
  if (!DIGEST.test(checkedAdmission.admission_digest ?? '')) {
    return admissionRefusal('admission_digest_invalid');
  }
  return Object.freeze({
    admitted: true,
    state: 'ADMITTED' as const,
    ready_for_executor: true,
    reason: null,
    action: deepFreeze(actionSnapshot),
    action_digest: proposalSnapshot.action_digest,
    envelope_digest: proposalSnapshot.envelope_digest,
    admission_digest: checkedAdmission.admission_digest,
    authority_source: 'emilia_gate' as const,
    mailbox_authorizes: false as const,
  });
}
