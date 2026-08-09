// SPDX-License-Identifier: Apache-2.0
/**
 * A2A v1.0 carrier binding for an EMILIA receipt.
 *
 * A2A supplies task, context, message, and extension semantics; it does not
 * make an unsigned Task a proof of authority. This module therefore carries a
 * separately signed companion artifact on A2A's namespaced Message extension
 * point. The artifact binds the complete receipt, exact semantic action,
 * initiating Message, server-issued Task snapshot, proof Message, selected
 * Agent Card, and target interface. Receipt verification and local execution
 * authorization remain separate relying-party decisions.
 */
import crypto, { KeyObject } from 'node:crypto';

import { digestAeb, type AebDigest } from './aeb-adapter-contract.js';
import { canonicalizeStrictJson } from './strict-json.js';

type Obj = Record<string, any>;

export const A2A_PROTOCOL_VERSION = '1.0';
export const A2A_ACTION_MEDIA_TYPE = 'application/vnd.emilia.action+json';
export const A2A_RECEIPT_EXTENSION_URI = 'https://emiliaprotocol.ai/extensions/a2a/receipt-binding/v1';
export const A2A_RECEIPT_EXTENSION_NAME = 'ai.emiliaprotocol.a2a.receipt-binding.v1';
export const A2A_RECEIPT_BINDING_VERSION = 'EP-A2A-RECEIPT-BINDING-v1';
export const A2A_RECEIPT_BINDING_DOMAIN = `${A2A_RECEIPT_BINDING_VERSION}\0`;
export const A2A_RECEIPT_PRESENTATION_VERSION = 'EP-A2A-RECEIPT-PRESENTATION-v1';
export const RECEIPT_EXTENSIONS_VERSION = 'EP-RECEIPT-EXTENSIONS-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9._-]{0,126}:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const ID_RE = /^[^\u0000-\u001f\u007f]{1,512}$/;
const MESSAGE_KEYS = new Set([
  'messageId', 'contextId', 'taskId', 'role', 'parts', 'metadata', 'extensions',
  'referenceTaskIds',
]);
const PART_KEYS = new Set(['text', 'raw', 'url', 'data', 'metadata', 'filename', 'mediaType']);
const TASK_KEYS = new Set(['id', 'contextId', 'status', 'artifacts', 'history', 'metadata']);
const STATUS_KEYS = new Set(['state', 'message', 'timestamp']);
const BINDING_KEYS = new Set([
  '@version', 'extension_name', 'protocol_version', 'target_interface_url',
  'agent_card_digest', 'task_id', 'context_id', 'task_snapshot_digest',
  'initiating_message_id', 'initiating_message_digest', 'proof_message_id',
  'proof_message_digest', 'base_receipt_digest', 'base_action_digest', 'caid',
  'issued_at', 'expires_at', 'signature',
]);
const SIGNATURE_KEYS = new Set(['algorithm', 'key_id', 'value']);
const PRESENTATION_KEYS = new Set([
  '@version', 'action', 'receipt', 'receipt_extensions', 'binding_artifact',
]);
const COMPANION_KEYS = new Set([
  'version', 'base_receipt_digest', 'base_action_digest', 'entries',
]);
const COMPANION_ENTRY_KEYS = new Set([
  'name', 'operation_id', 'consequence_digest', 'artifact_digest',
]);
const TRUST_ROOT_KEYS = new Set(['key_id', 'public_key']);

export interface A2AMessage {
  messageId: string;
  contextId?: string;
  taskId?: string;
  role: 'ROLE_USER' | 'ROLE_AGENT';
  parts: readonly unknown[];
  metadata?: Readonly<Record<string, unknown>>;
  extensions?: readonly string[];
  referenceTaskIds?: readonly string[];
}

export interface A2ATask {
  id: string;
  contextId: string;
  status: { state: string; message?: unknown; timestamp?: string };
  artifacts?: readonly unknown[];
  history?: readonly unknown[];
  metadata?: Readonly<Record<string, unknown>>;
}

export interface A2AReceiptBindingBody {
  '@version': typeof A2A_RECEIPT_BINDING_VERSION;
  extension_name: typeof A2A_RECEIPT_EXTENSION_NAME;
  protocol_version: typeof A2A_PROTOCOL_VERSION;
  target_interface_url: string;
  agent_card_digest: AebDigest;
  task_id: string;
  context_id: string;
  task_snapshot_digest: AebDigest;
  initiating_message_id: string;
  initiating_message_digest: AebDigest;
  proof_message_id: string;
  proof_message_digest: AebDigest;
  base_receipt_digest: AebDigest;
  base_action_digest: AebDigest;
  caid: string;
  issued_at: string;
  expires_at: string;
}

export interface A2AReceiptBindingArtifact extends A2AReceiptBindingBody {
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
}

export interface A2AReceiptExtensionsCompanion {
  version: typeof RECEIPT_EXTENSIONS_VERSION;
  base_receipt_digest: AebDigest;
  base_action_digest: AebDigest;
  entries: readonly [{
    name: typeof A2A_RECEIPT_EXTENSION_NAME;
    operation_id: string;
    consequence_digest: null;
    artifact_digest: AebDigest;
  }];
}

export interface A2AReceiptPresentationPayload {
  '@version': typeof A2A_RECEIPT_PRESENTATION_VERSION;
  action: unknown;
  receipt: unknown;
  receipt_extensions: A2AReceiptExtensionsCompanion;
  binding_artifact: A2AReceiptBindingArtifact;
}

export interface A2AReceiptPresentation {
  message: A2AMessage & { metadata: Record<string, unknown>; extensions: string[] };
  artifact: A2AReceiptBindingArtifact;
  companion: A2AReceiptExtensionsCompanion;
}

export interface A2AReceiptSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface A2AReceiptTrustRoot {
  key_id: string;
  public_key: string;
}

export interface VerifiedReceiptBinding {
  valid: boolean;
  action_digest: string | null;
  caid: string | null;
}

export interface A2AReceiptPresentationVerification {
  valid: boolean;
  checks: {
    shape: boolean;
    protocol: boolean;
    extension: boolean;
    target: boolean;
    task: boolean;
    initiating_message: boolean;
    presentation_message: boolean;
    companion: boolean;
    signature: boolean;
    validity: boolean;
    receipt: boolean;
  };
  reasons: string[];
  decision_scope: {
    correlation_only: true;
    receipt_verified: boolean;
    a2a_server_authenticated: false;
    authorization_granted: false;
    execution_proven: false;
  };
}

export interface CreateA2AReceiptPresentationInput {
  protocol_version: string;
  target_interface_url: string;
  agent_card: unknown;
  task: unknown;
  initiating_message: unknown;
  proof_message: unknown;
  base_receipt: unknown;
  receipt_binding: { caid: string; action_digest: string };
  issued_at: string;
  expires_at: string;
  signer: A2AReceiptSigner;
}

export interface VerifyA2AReceiptPresentationInput {
  protocol_version: string;
  target_interface_url: string;
  agent_card: unknown;
  task: unknown;
  initiating_message: unknown;
  presentation_message: unknown;
  negotiated_extensions: readonly string[];
  trust_roots: readonly A2AReceiptTrustRoot[];
  expected_action: unknown;
  expected_caid: string;
  now: string;
  verify_receipt?: (receipt: unknown) => VerifiedReceiptBinding;
}

function isObject(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Obj, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}

function onlyKeys(value: Obj, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => keys.has(key));
}

function exactString(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value);
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function strictClone<T>(value: T): T {
  return JSON.parse(canonicalizeStrictJson(value)) as T;
}

function instant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_RE);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const milliseconds = Number(fraction.padEnd(3, '0'));
  const timestamp = Date.UTC(
    Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), milliseconds,
  );
  const date = new Date(timestamp);
  if (date.getUTCFullYear() !== Number(year)
      || date.getUTCMonth() !== Number(month) - 1
      || date.getUTCDate() !== Number(day)
      || date.getUTCHours() !== Number(hour)
      || date.getUTCMinutes() !== Number(minute)
      || date.getUTCSeconds() !== Number(second)
      || date.getUTCMilliseconds() !== milliseconds) return NaN;
  return timestamp;
}

function validHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' && parsed.hash === '';
  } catch {
    return false;
  }
}

function agentCardSupportsReceiptExtension(card: unknown, interfaceUrl: string): boolean {
  if (!isObject(card) || !Array.isArray(card.supportedInterfaces)
      || !isObject(card.capabilities) || !Array.isArray(card.capabilities.extensions)) return false;
  const interfaceMatch = card.supportedInterfaces.some((candidate: unknown) => isObject(candidate)
    && candidate.url === interfaceUrl
    && candidate.protocolVersion === A2A_PROTOCOL_VERSION
    && ['HTTP+JSON', 'JSONRPC', 'GRPC'].includes(String(candidate.protocolBinding)));
  const extensionMatch = card.capabilities.extensions.some((candidate: unknown) => isObject(candidate)
    && candidate.uri === A2A_RECEIPT_EXTENSION_URI);
  return interfaceMatch && extensionMatch;
}

function validStringArray(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.every(exactString)
    && new Set(value).size === value.length;
}

function validPart(value: unknown): boolean {
  if (!isObject(value) || !onlyKeys(value, PART_KEYS)) return false;
  const content = ['text', 'raw', 'url', 'data'].filter((key) => Object.hasOwn(value, key));
  if (content.length !== 1) return false;
  if (Object.hasOwn(value, 'text') && typeof value.text !== 'string') return false;
  if (Object.hasOwn(value, 'raw') && typeof value.raw !== 'string') return false;
  if (Object.hasOwn(value, 'url') && typeof value.url !== 'string') return false;
  if (value.filename !== undefined && typeof value.filename !== 'string') return false;
  if (value.mediaType !== undefined && typeof value.mediaType !== 'string') return false;
  return value.metadata === undefined || isObject(value.metadata);
}

function validMessage(value: unknown): value is A2AMessage {
  if (!isObject(value) || !onlyKeys(value, MESSAGE_KEYS)
      || !exactString(value.messageId)
      || !['ROLE_USER', 'ROLE_AGENT'].includes(String(value.role))
      || !Array.isArray(value.parts) || value.parts.length === 0 || value.parts.length > 64
      || !value.parts.every(validPart)) return false;
  if (value.contextId !== undefined && !exactString(value.contextId)) return false;
  if (value.taskId !== undefined && !exactString(value.taskId)) return false;
  if (value.metadata !== undefined && !isObject(value.metadata)) return false;
  if (value.extensions !== undefined && !validStringArray(value.extensions)) return false;
  return value.referenceTaskIds === undefined || validStringArray(value.referenceTaskIds);
}

function validTask(value: unknown): value is A2ATask {
  if (!isObject(value) || !onlyKeys(value, TASK_KEYS)
      || !exactString(value.id) || !exactString(value.contextId)
      || !isObject(value.status) || !onlyKeys(value.status, STATUS_KEYS)
      || value.status.state !== 'TASK_STATE_AUTH_REQUIRED') return false;
  if (value.status.timestamp !== undefined || value.status.message !== undefined) {
    if (value.status.timestamp !== undefined && !Number.isFinite(instant(value.status.timestamp))) return false;
    if (value.status.message !== undefined && !validMessage(value.status.message)) return false;
  }
  if (value.artifacts !== undefined && !Array.isArray(value.artifacts)) return false;
  if (value.history !== undefined && !Array.isArray(value.history)) return false;
  return value.metadata === undefined || isObject(value.metadata);
}

function actionFromInitiatingMessage(message: A2AMessage): unknown {
  const matches = message.parts.filter((part) => isObject(part)
    && Object.hasOwn(part, 'data') && part.mediaType === A2A_ACTION_MEDIA_TYPE);
  if (matches.length !== 1) {
    throw new TypeError(`initiating A2A Message must contain exactly one ${A2A_ACTION_MEDIA_TYPE} data Part`);
  }
  return strictClone((matches[0] as Obj).data);
}

function messageProjection(message: A2AMessage): Obj {
  const metadata = strictClone(message.metadata ?? {}) as Obj;
  delete metadata[A2A_RECEIPT_EXTENSION_URI];
  return {
    profile: 'A2A-v1.0-Message',
    message_id: message.messageId,
    context_id: message.contextId ?? null,
    task_id: message.taskId ?? null,
    role: message.role,
    parts: strictClone(message.parts),
    metadata,
    extensions: [...(message.extensions ?? [])]
      .filter((uri) => uri !== A2A_RECEIPT_EXTENSION_URI),
    reference_task_ids: [...(message.referenceTaskIds ?? [])],
  };
}

function messageDigest(message: A2AMessage): AebDigest {
  return digestAeb(messageProjection(message));
}

function bindingBody(artifact: A2AReceiptBindingArtifact): A2AReceiptBindingBody {
  const { signature: _signature, ...body } = artifact;
  return body;
}

function signingBytes(body: A2AReceiptBindingBody): Buffer {
  return Buffer.from(`${A2A_RECEIPT_BINDING_DOMAIN}${canonicalizeStrictJson(body)}`, 'utf8');
}

function validSignature(value: unknown): boolean {
  if (!isObject(value) || !exactKeys(value, SIGNATURE_KEYS)
      || value.algorithm !== 'Ed25519' || !exactString(value.key_id)
      || typeof value.value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value.value)) return false;
  try {
    const bytes = Buffer.from(value.value, 'base64url');
    return bytes.length === 64 && bytes.toString('base64url') === value.value;
  } catch {
    return false;
  }
}

function validBindingArtifact(value: unknown): value is A2AReceiptBindingArtifact {
  return isObject(value) && exactKeys(value, BINDING_KEYS)
    && value['@version'] === A2A_RECEIPT_BINDING_VERSION
    && value.extension_name === A2A_RECEIPT_EXTENSION_NAME
    && value.protocol_version === A2A_PROTOCOL_VERSION
    && validHttpsUrl(value.target_interface_url)
    && validDigest(value.agent_card_digest)
    && exactString(value.task_id) && exactString(value.context_id)
    && validDigest(value.task_snapshot_digest)
    && exactString(value.initiating_message_id) && validDigest(value.initiating_message_digest)
    && exactString(value.proof_message_id) && validDigest(value.proof_message_digest)
    && validDigest(value.base_receipt_digest) && validDigest(value.base_action_digest)
    && typeof value.caid === 'string' && CAID_RE.test(value.caid)
    && Number.isFinite(instant(value.issued_at)) && Number.isFinite(instant(value.expires_at))
    && instant(value.issued_at) < instant(value.expires_at)
    && validSignature(value.signature);
}

function validCompanion(value: unknown): value is A2AReceiptExtensionsCompanion {
  if (!isObject(value) || !exactKeys(value, COMPANION_KEYS)
      || value.version !== RECEIPT_EXTENSIONS_VERSION
      || !validDigest(value.base_receipt_digest) || !validDigest(value.base_action_digest)
      || !Array.isArray(value.entries) || value.entries.length !== 1) return false;
  const entry = value.entries[0];
  return isObject(entry) && exactKeys(entry, COMPANION_ENTRY_KEYS)
    && entry.name === A2A_RECEIPT_EXTENSION_NAME
    && exactString(entry.operation_id)
    && entry.consequence_digest === null
    && validDigest(entry.artifact_digest);
}

function validPresentationPayload(value: unknown): value is A2AReceiptPresentationPayload {
  return isObject(value) && exactKeys(value, PRESENTATION_KEYS)
    && value['@version'] === A2A_RECEIPT_PRESENTATION_VERSION
    && validCompanion(value.receipt_extensions)
    && validBindingArtifact(value.binding_artifact);
}

function isEd25519PrivateKey(key: unknown): key is KeyObject {
  return key instanceof KeyObject && key.type === 'private' && key.asymmetricKeyType === 'ed25519';
}

function trustedPublicKey(root: A2AReceiptTrustRoot): KeyObject | null {
  if (!isObject(root) || !exactKeys(root, TRUST_ROOT_KEYS)
      || !exactString(root.key_id) || typeof root.public_key !== 'string') return null;
  try {
    const bytes = Buffer.from(root.public_key, 'base64url');
    if (bytes.toString('base64url') !== root.public_key) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function signBinding(body: A2AReceiptBindingBody, signer: A2AReceiptSigner): A2AReceiptBindingArtifact {
  if (!exactString(signer?.key_id) || !isEd25519PrivateKey(signer?.private_key)) {
    throw new TypeError('Ed25519 A2A receipt-binding signer required');
  }
  const detached = strictClone(body);
  const value = crypto.sign(null, signingBytes(detached), signer.private_key).toString('base64url');
  return Object.freeze({
    ...detached,
    signature: { algorithm: 'Ed25519' as const, key_id: signer.key_id, value },
  });
}

function verifyBindingSignature(
  artifact: A2AReceiptBindingArtifact,
  roots: readonly A2AReceiptTrustRoot[],
): boolean {
  const root = roots.find((candidate) => isObject(candidate)
    && candidate.key_id === artifact.signature.key_id);
  if (!root) return false;
  const key = trustedPublicKey(root);
  if (!key) return false;
  try {
    return crypto.verify(
      null,
      signingBytes(bindingBody(artifact)),
      key,
      Buffer.from(artifact.signature.value, 'base64url'),
    );
  } catch {
    return false;
  }
}

/**
 * Create one A2A proof retry carrying the base receipt plus its signed,
 * receipt-extension-compatible A2A correlation artifact.
 */
export function createA2AReceiptPresentation(
  input: CreateA2AReceiptPresentationInput,
): A2AReceiptPresentation {
  if (input.protocol_version !== A2A_PROTOCOL_VERSION) {
    throw new TypeError(`A2A protocol version ${A2A_PROTOCOL_VERSION} required`);
  }
  if (!validHttpsUrl(input.target_interface_url)) throw new TypeError('canonical HTTPS A2A target required');
  const agentCard = strictClone(input.agent_card);
  const task = strictClone(input.task);
  const initiatingMessage = strictClone(input.initiating_message);
  const proofMessage = strictClone(input.proof_message);
  const receipt = strictClone(input.base_receipt);
  const receiptBinding = strictClone(input.receipt_binding);
  if (!agentCardSupportsReceiptExtension(agentCard, input.target_interface_url)) {
    throw new TypeError('Agent Card must advertise the selected A2A v1.0 interface and EMILIA receipt extension');
  }
  if (!validTask(task)) throw new TypeError('closed A2A auth-required Task required');
  if (!validMessage(initiatingMessage) || initiatingMessage.role !== 'ROLE_USER') {
    throw new TypeError('closed initiating A2A user Message required');
  }
  if (!validMessage(proofMessage) || proofMessage.role !== 'ROLE_USER') {
    throw new TypeError('closed A2A proof user Message required');
  }
  if (proofMessage.taskId !== task.id || proofMessage.contextId !== task.contextId) {
    throw new TypeError('proof Message must bind the supplied Task id and contextId');
  }
  if ((proofMessage.extensions ?? []).some((uri) => uri === A2A_RECEIPT_EXTENSION_URI)
      || Object.hasOwn(proofMessage.metadata ?? {}, A2A_RECEIPT_EXTENSION_URI)) {
    throw new TypeError('proof Message already carries the EMILIA A2A extension');
  }
  if (!isObject(receiptBinding)
      || !exactKeys(receiptBinding, new Set(['caid', 'action_digest']))
      || typeof receiptBinding.caid !== 'string' || !CAID_RE.test(receiptBinding.caid)
      || !validDigest(receiptBinding.action_digest)) {
    throw new TypeError('valid receipt CAID and action digest required');
  }
  const action = actionFromInitiatingMessage(initiatingMessage);
  const actionDigest = digestAeb(action);
  if (actionDigest !== receiptBinding.action_digest) {
    throw new TypeError('receipt action digest does not match the initiating A2A action Part');
  }
  if (!Number.isFinite(instant(input.issued_at)) || !Number.isFinite(instant(input.expires_at))
      || instant(input.issued_at) >= instant(input.expires_at)) {
    throw new TypeError('bounded millisecond-precision A2A binding validity required');
  }
  const body: A2AReceiptBindingBody = {
    '@version': A2A_RECEIPT_BINDING_VERSION,
    extension_name: A2A_RECEIPT_EXTENSION_NAME,
    protocol_version: A2A_PROTOCOL_VERSION,
    target_interface_url: input.target_interface_url,
    agent_card_digest: digestAeb(agentCard),
    task_id: task.id,
    context_id: task.contextId,
    task_snapshot_digest: digestAeb(task),
    initiating_message_id: initiatingMessage.messageId,
    initiating_message_digest: messageDigest(initiatingMessage),
    proof_message_id: proofMessage.messageId,
    proof_message_digest: messageDigest(proofMessage),
    base_receipt_digest: digestAeb(receipt),
    base_action_digest: actionDigest,
    caid: receiptBinding.caid,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
  };
  const artifact = signBinding(body, input.signer);
  const companion: A2AReceiptExtensionsCompanion = Object.freeze({
    version: RECEIPT_EXTENSIONS_VERSION,
    base_receipt_digest: artifact.base_receipt_digest,
    base_action_digest: artifact.base_action_digest,
    entries: Object.freeze([Object.freeze({
      name: A2A_RECEIPT_EXTENSION_NAME,
      operation_id: artifact.task_id,
      consequence_digest: null,
      artifact_digest: digestAeb(artifact),
    })]) as unknown as A2AReceiptExtensionsCompanion['entries'],
  });
  const payload: A2AReceiptPresentationPayload = {
    '@version': A2A_RECEIPT_PRESENTATION_VERSION,
    action,
    receipt,
    receipt_extensions: companion,
    binding_artifact: artifact,
  };
  const message = strictClone({
    ...proofMessage,
    extensions: [...(proofMessage.extensions ?? []), A2A_RECEIPT_EXTENSION_URI],
    metadata: { ...(proofMessage.metadata ?? {}), [A2A_RECEIPT_EXTENSION_URI]: payload },
  }) as A2AReceiptPresentation['message'];
  return Object.freeze({ message, artifact, companion });
}

function blankVerification(): A2AReceiptPresentationVerification {
  return {
    valid: false,
    checks: {
      shape: false,
      protocol: false,
      extension: false,
      target: false,
      task: false,
      initiating_message: false,
      presentation_message: false,
      companion: false,
      signature: false,
      validity: false,
      receipt: false,
    },
    reasons: [],
    decision_scope: {
      correlation_only: true,
      receipt_verified: false,
      a2a_server_authenticated: false,
      authorization_granted: false,
      execution_proven: false,
    },
  };
}

function addReason(result: A2AReceiptPresentationVerification, reason: string): void {
  if (!result.reasons.includes(reason)) result.reasons.push(reason);
}

/**
 * Verify the portable A2A/receipt correlation. A caller-supplied receipt
 * verifier is mandatory and must return the action digest and CAID it verified.
 * Success remains evidence correlation; it never grants execution authority.
 */
export function verifyA2AReceiptPresentation(
  input: VerifyA2AReceiptPresentationInput,
): A2AReceiptPresentationVerification {
  const result = blankVerification();
  let agentCard: unknown;
  let task: A2ATask;
  let initiatingMessage: A2AMessage;
  let presentationMessage: A2AMessage;
  let expectedAction: unknown;
  let negotiatedExtensions: string[];
  let trustRoots: A2AReceiptTrustRoot[];
  try {
    agentCard = strictClone(input.agent_card);
    task = strictClone(input.task) as A2ATask;
    initiatingMessage = strictClone(input.initiating_message) as A2AMessage;
    presentationMessage = strictClone(input.presentation_message) as A2AMessage;
    expectedAction = strictClone(input.expected_action);
    negotiatedExtensions = strictClone(input.negotiated_extensions) as string[];
    trustRoots = strictClone(input.trust_roots) as A2AReceiptTrustRoot[];
  } catch {
    addReason(result, 'presentation_malformed');
    return result;
  }
  if (!validTask(task) || !validMessage(initiatingMessage)
      || initiatingMessage.role !== 'ROLE_USER'
      || !validMessage(presentationMessage) || presentationMessage.role !== 'ROLE_USER') {
    addReason(result, 'presentation_malformed');
    return result;
  }
  const extensions = presentationMessage.extensions ?? [];
  const payload = isObject(presentationMessage.metadata)
    ? presentationMessage.metadata[A2A_RECEIPT_EXTENSION_URI]
    : undefined;
  if (extensions.filter((uri) => uri === A2A_RECEIPT_EXTENSION_URI).length !== 1
      || !validPresentationPayload(payload)) {
    addReason(result, 'presentation_malformed');
    return result;
  }
  result.checks.shape = true;
  const artifact = payload.binding_artifact;
  const companion = payload.receipt_extensions;

  result.checks.protocol = input.protocol_version === A2A_PROTOCOL_VERSION
    && artifact.protocol_version === A2A_PROTOCOL_VERSION;
  if (!result.checks.protocol) addReason(result, 'protocol_version_mismatch');

  const negotiated = Array.isArray(negotiatedExtensions)
    && negotiatedExtensions.every((uri) => typeof uri === 'string')
    && new Set(negotiatedExtensions).size === negotiatedExtensions.length
    && negotiatedExtensions.some((uri) => uri === A2A_RECEIPT_EXTENSION_URI);
  result.checks.extension = negotiated;
  if (!negotiated) addReason(result, 'extension_not_negotiated');

  result.checks.target = validHttpsUrl(input.target_interface_url)
    && artifact.target_interface_url === input.target_interface_url
    && artifact.agent_card_digest === digestAeb(agentCard)
    && agentCardSupportsReceiptExtension(agentCard, input.target_interface_url);
  if (!result.checks.target) addReason(result, 'target_binding_mismatch');

  const taskIdMatches = artifact.task_id === task.id
    && presentationMessage.taskId === task.id;
  const contextMatches = artifact.context_id === task.contextId
    && presentationMessage.contextId === task.contextId;
  result.checks.task = taskIdMatches && contextMatches
    && artifact.task_snapshot_digest === digestAeb(task);
  if (!taskIdMatches) addReason(result, 'task_binding_mismatch');
  if (!contextMatches) addReason(result, 'context_binding_mismatch');
  if (artifact.task_snapshot_digest !== digestAeb(task)) addReason(result, 'task_snapshot_digest_mismatch');

  let initiatingAction: unknown = null;
  try {
    initiatingAction = actionFromInitiatingMessage(initiatingMessage);
  } catch {
    addReason(result, 'initiating_action_part_invalid');
  }
  const expectedActionDigest = digestAeb(expectedAction);
  result.checks.initiating_message = artifact.initiating_message_id === initiatingMessage.messageId
    && artifact.initiating_message_digest === messageDigest(initiatingMessage)
    && initiatingAction !== null
    && digestAeb(initiatingAction) === expectedActionDigest;
  if (artifact.initiating_message_id !== initiatingMessage.messageId) {
    addReason(result, 'initiating_message_id_mismatch');
  }
  if (artifact.initiating_message_digest !== messageDigest(initiatingMessage)) {
    addReason(result, 'initiating_message_digest_mismatch');
  }
  if (initiatingAction === null || digestAeb(initiatingAction) !== expectedActionDigest) {
    addReason(result, 'initiating_action_mismatch');
  }

  result.checks.presentation_message = artifact.proof_message_id === presentationMessage.messageId
    && artifact.proof_message_digest === messageDigest(presentationMessage);
  if (artifact.proof_message_id !== presentationMessage.messageId) addReason(result, 'proof_message_id_mismatch');
  if (artifact.proof_message_digest !== messageDigest(presentationMessage)) addReason(result, 'proof_message_digest_mismatch');

  const expectedArtifactDigest = digestAeb(artifact);
  result.checks.companion = companion.base_receipt_digest === artifact.base_receipt_digest
    && companion.base_action_digest === artifact.base_action_digest
    && companion.entries[0].operation_id === artifact.task_id
    && companion.entries[0].artifact_digest === expectedArtifactDigest;
  if (!result.checks.companion) addReason(result, 'receipt_companion_mismatch');

  result.checks.signature = verifyBindingSignature(artifact, trustRoots);
  if (!result.checks.signature) addReason(result, 'binding_signature_invalid');

  const now = instant(input.now);
  result.checks.validity = Number.isFinite(now)
    && now >= instant(artifact.issued_at) && now < instant(artifact.expires_at);
  if (!result.checks.validity) addReason(result, 'binding_outside_validity');

  const receiptDigestMatches = digestAeb(payload.receipt) === artifact.base_receipt_digest;
  const actionMatches = digestAeb(payload.action) === artifact.base_action_digest
    && artifact.base_action_digest === expectedActionDigest;
  const caidMatches = typeof input.expected_caid === 'string'
    && CAID_RE.test(input.expected_caid)
    && artifact.caid === input.expected_caid;
  if (!receiptDigestMatches) addReason(result, 'base_receipt_digest_mismatch');
  if (!actionMatches) addReason(result, 'base_action_digest_mismatch');
  if (!caidMatches) addReason(result, 'caid_mismatch');
  if (canonicalizeStrictJson(payload.action) !== canonicalizeStrictJson(expectedAction)) {
    addReason(result, 'presented_action_mismatch');
  }
  if (typeof input.verify_receipt !== 'function') {
    addReason(result, 'receipt_verifier_required');
  }
  let verifiedReceipt: VerifiedReceiptBinding | null = null;
  if (typeof input.verify_receipt === 'function') {
    try {
      verifiedReceipt = strictClone(input.verify_receipt(strictClone(payload.receipt)));
    } catch {
      verifiedReceipt = null;
    }
  }
  const receiptVerified = isObject(verifiedReceipt)
    && verifiedReceipt.valid === true
    && verifiedReceipt.action_digest === artifact.base_action_digest
    && verifiedReceipt.caid === artifact.caid;
  if (typeof input.verify_receipt === 'function' && !receiptVerified) {
    addReason(result, 'receipt_verification_failed');
  }
  result.checks.receipt = receiptDigestMatches && actionMatches && caidMatches
    && canonicalizeStrictJson(payload.action) === canonicalizeStrictJson(expectedAction)
    && receiptVerified;
  result.decision_scope.receipt_verified = result.checks.receipt;

  result.valid = Object.values(result.checks).every(Boolean) && result.reasons.length === 0;
  return result;
}
