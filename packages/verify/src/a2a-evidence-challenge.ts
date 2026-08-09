// SPDX-License-Identifier: Apache-2.0

/** Transport-neutral AE-CHALLENGE carrier for the released A2A v1.0 flow. */
import { digestAeb } from './aeb-adapter-contract.js';
import { canonicalizeStrictJson } from './strict-json.js';

type Obj = Record<string, any>;

export const A2A_AE_CHALLENGE_EXTENSION_URI =
  'https://emiliaprotocol.ai/extensions/a2a/authorization-evidence-challenge/v1';
export const A2A_AE_CHALLENGE_PART_PROFILE = 'AE-CHALLENGE-v1';
export const A2A_AP2_NATIVE_PRESENTATION_METHOD = 'ap2-native';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ID_RE = /^[^\u0000-\u001f\u007f]{1,512}$/;
const TASK_KEYS = new Set(['id', 'contextId', 'status']);
const STATUS_KEYS = new Set(['state', 'message', 'timestamp']);
const MESSAGE_KEYS = new Set(['messageId', 'contextId', 'taskId', 'role', 'parts', 'extensions', 'metadata']);
const PART_KEYS = new Set(['text']);

export interface A2AAuthorizationChallengeTaskInput {
  task_id: string;
  context_id: string;
  message_id: string;
  timestamp: string;
  challenge: unknown;
}

export interface A2AAuthorizationChallengeVerification {
  valid: boolean;
  task_id: string | null;
  context_id: string | null;
  challenge: unknown | null;
  reasons: string[];
  authorization_granted: false;
  admission_transferred: false;
}

function isObject(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, keys: ReadonlySet<string>, optional: ReadonlySet<string> = new Set()): boolean {
  const required = [...keys].filter((key) => !optional.has(key));
  return Object.keys(value).every((key) => keys.has(key))
    && required.every((key) => Object.hasOwn(value, key));
}

function clone<T>(value: T): T {
  return JSON.parse(canonicalizeStrictJson(value)) as T;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value);
}

function instant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function validChallenge(value: unknown): value is Obj {
  return isObject(value)
    && value['@version'] === A2A_AE_CHALLENGE_PART_PROFILE
    && identifier(value.challenge_id)
    && typeof value.nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(value.nonce)
    && typeof value.action_digest === 'string' && DIGEST_RE.test(value.action_digest)
    && identifier(value.action_profile)
    && (value.audience === undefined || identifier(value.audience))
    && Array.isArray(value.required_evidence) && value.required_evidence.length > 0
    && Array.isArray(value.present_as) && value.present_as.length > 0
    && Number.isFinite(instant(value.expires_at));
}

function validPart(value: unknown): value is Obj {
  return isObject(value) && exactKeys(value, PART_KEYS)
    && value.text === 'Authorization evidence required.';
}

function baseResult(): A2AAuthorizationChallengeVerification {
  return {
    valid: false,
    task_id: null,
    context_id: null,
    challenge: null,
    reasons: [],
    authorization_granted: false,
    admission_transferred: false,
  };
}

export function createA2AAuthorizationChallengeTask(
  input: A2AAuthorizationChallengeTaskInput,
): Readonly<Obj> {
  if (!identifier(input?.task_id) || !identifier(input?.context_id)
      || !identifier(input?.message_id) || !Number.isFinite(instant(input?.timestamp))
      || !validChallenge(input?.challenge)) {
    throw new TypeError('closed A2A authorization-challenge task input required');
  }
  return Object.freeze(clone({
    id: input.task_id,
    contextId: input.context_id,
    status: {
      state: 'TASK_STATE_AUTH_REQUIRED',
      timestamp: input.timestamp,
      message: {
        messageId: input.message_id,
        contextId: input.context_id,
        taskId: input.task_id,
        role: 'ROLE_AGENT',
        parts: [{
          text: 'Authorization evidence required.',
        }],
        extensions: [A2A_AE_CHALLENGE_EXTENSION_URI],
        metadata: { [A2A_AE_CHALLENGE_EXTENSION_URI]: input.challenge },
      },
    },
  }));
}

export function verifyA2AAuthorizationChallengeTask(
  candidate: unknown,
  expectedAction: unknown,
  now: string,
): A2AAuthorizationChallengeVerification {
  const result = baseResult();
  let task: unknown;
  try {
    task = clone(candidate);
    canonicalizeStrictJson(expectedAction);
  } catch {
    result.reasons.push('malformed_a2a_challenge_input');
    return result;
  }
  if (!isObject(task) || !exactKeys(task, TASK_KEYS)
      || !identifier(task.id) || !identifier(task.contextId)
      || !isObject(task.status) || !exactKeys(task.status, STATUS_KEYS)) {
    result.reasons.push('malformed_a2a_task');
    return result;
  }
  result.task_id = task.id;
  result.context_id = task.contextId;
  if (task.status.state !== 'TASK_STATE_AUTH_REQUIRED') {
    result.reasons.push('task_not_auth_required');
  }
  if (!Number.isFinite(instant(task.status.timestamp))) result.reasons.push('task_timestamp_invalid');
  const message = task.status.message;
  if (!isObject(message) || !exactKeys(message, MESSAGE_KEYS)
      || !identifier(message.messageId) || message.contextId !== task.contextId
      || message.taskId !== task.id || message.role !== 'ROLE_AGENT'
      || !Array.isArray(message.extensions)
      || message.extensions.length !== 1
      || message.extensions[0] !== A2A_AE_CHALLENGE_EXTENSION_URI
      || !Array.isArray(message.parts) || message.parts.length !== 1
      || !validPart(message.parts[0])
      || !isObject(message.metadata)
      || Object.keys(message.metadata).length !== 1
      || !validChallenge(message.metadata[A2A_AE_CHALLENGE_EXTENSION_URI])) {
    result.reasons.push('malformed_a2a_challenge_message');
    return result;
  }
  const challenge = message.metadata[A2A_AE_CHALLENGE_EXTENSION_URI];
  result.challenge = clone(challenge);
  let expectedDigest: string;
  try {
    expectedDigest = digestAeb(expectedAction);
  } catch {
    result.reasons.push('expected_action_invalid');
    return result;
  }
  if (challenge.action_digest !== expectedDigest) result.reasons.push('challenge_action_mismatch');
  const nowMs = instant(now);
  if (!Number.isFinite(nowMs)) result.reasons.push('verification_time_invalid');
  else if (instant(challenge.expires_at) <= nowMs) result.reasons.push('challenge_expired');
  result.reasons = [...new Set(result.reasons)].sort();
  result.valid = result.reasons.length === 0;
  return result;
}
