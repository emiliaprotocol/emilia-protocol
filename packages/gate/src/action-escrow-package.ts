// SPDX-License-Identifier: Apache-2.0
/**
 * Strict adapter from one exact Action Escrow kernel snapshot to the portable
 * Action Escrow evidence-package profile.
 *
 * This module does not accept package-field overrides. Every package field is
 * either derived from the durable record or occupies one of the four external
 * artifact slots that the kernel intentionally does not own.
 */
import crypto from 'node:crypto';

import {
  ACTION_ESCROW_PROFILE_VERSION,
  ACTION_ESCROW_STATE_VERSION,
  ACTION_ESCROW_STATES,
  ACTION_ESCROW_TRANSITIONS,
  computeActionEscrowReleaseBindingMomentDigest,
  computeActionEscrowResolutionNonce,
} from './action-escrow.js';
import { buildActionEscrowEvidencePackage } from './action-escrow-evidence.js';
import {
  ACTION_ESCROW_STATE_STATEMENT_DOMAIN,
  ACTION_ESCROW_STATE_STATEMENT_VERSION,
} from './action-escrow-state.js';
import {
  ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
  computeActionEscrowAgreementDigest,
  validateActionEscrowReleaseTemplate,
} from './action-escrow-verifiers.js';
import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  computeDocumentActionBindingDigest,
  computeDocumentSha256,
  computeReleaseActionDigest,
} from '@emilia-protocol/verify/document-action-binding';

const HASH = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_RECORD_NODES = 50_000;
const MAX_RECORD_DEPTH = 64;
const MAX_STRING_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_DOCUMENT_BYTES = 50 * 1024 * 1024;

const INPUT_KEYS = new Set([
  'kernelRecord',
  'finalPdfBytes',
  'documentFileName',
  'documentExecution',
  'operatorStateStatement',
  'verificationProfile',
]);
const CONTRACTOR_INPUT_KEYS = new Set([
  ...INPUT_KEYS,
  'projectRecordBytes',
  'projectRecordFileName',
  'projectRecordProvider',
  'projectRecordSnapshotDigest',
]);
const OPTION_KEYS = new Set(['now', 'maxDocumentBytes']);
const CONTRACTOR_OPTION_KEYS = new Set([
  ...OPTION_KEYS,
  'maxProjectRecordBytes',
]);
const RECORD_KEYS = new Set([
  '@version',
  'escrow_key',
  'revision',
  'state',
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties',
  'parties_digest',
  'profile',
  'profile_digest',
  'document_action_binding',
  'agreement_acceptances',
  'funding',
  'milestone_evidence',
  'release_approvals',
  'release',
  'dispute',
  'cancellation',
  'completion',
  'pending_amendment',
  'superseded_bindings',
  'operations',
  'history',
  'created_at',
  'updated_at',
]);
const PROFILE_KEYS = new Set([
  '@version',
  'profile_id',
  'provider_id',
  'required_acceptance_party_ids',
  'required_release_approver_party_ids',
  'prohibit_self_approval',
]);
const PARTY_KEYS = new Set(['party_id', 'role']);
const CONTAINER_KEYS = new Set(['artifact', 'verification']);
const ACCEPTANCE_KEYS = new Set(['party_id', 'artifact', 'verification']);
const RELEASE_APPROVAL_KEYS = new Set(['party_id', 'resolution', 'verification']);
const CORE_VERIFICATION_KEYS = [
  'valid',
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties_digest',
  'profile_digest',
];
const BINDING_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'verification_digest',
  'document_digest',
  'agreement_id',
  'binding_id',
  'release_action_template',
  'supersedes_document_action_binding_digest',
]);
const ACCEPTANCE_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'party_id',
  'principal_key_id',
  'acceptance_digest',
]);
const FUNDING_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authenticated',
  'provider_id',
  'statement_type',
  'status',
  'provider_transaction_id',
  'provider_milestone_id',
  'amount',
  'currency',
  'destination_id',
  'statement_digest',
]);
const MILESTONE_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'evidence_digest',
  'submitter_party_id',
  'observed_at',
]);
const RELEASE_APPROVAL_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authorizes_action',
  'outcome',
  'party_role',
  'principal_key_id',
  'nonce',
  'issued_at',
  'expires_at',
  'resolution_digest',
  'evidence_digest',
]);
const PROVIDER_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authenticated',
  'provider_id',
  'provider_idempotency_key',
  'provider_request_digest',
  'provider_transaction_id',
  'provider_milestone_id',
  'amount',
  'currency',
  'destination_id',
  'statement_type',
  'status',
  'statement_digest',
]);
const COMMAND_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authorizes_command',
  'command',
  'party_id',
  'details_digest',
  'command_digest',
]);
const OPERATION_KEYS = new Set([
  'idempotency_key',
  'operation',
  'request_digest',
  'code',
  'ok',
  'outcome',
  'state',
  'at',
]);
const HISTORY_KEYS = new Set([
  'from',
  'to',
  'operation',
  'idempotency_key',
  'at',
]);
const SUPERSESSION_KEYS = new Set([
  'document_action_binding_digest',
  'release_action_digest',
  'superseded_by_binding_digest',
  'superseded_at',
]);
const RELEASE_KEYS = new Set([
  'release_key',
  'provider_idempotency_key',
  'operation_idempotency_key',
  'status',
  'reserved_at',
  'reconciled_at',
  'provider_request',
  'provider_statement',
  'provider_verification',
]);
const PROVIDER_REQUEST_KEYS = new Set([
  'method',
  'provider_id',
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties',
  'parties_digest',
  'profile',
  'profile_digest',
  'agreement_id',
  'binding_id',
  'document_digest',
  'release_action_template',
  'release_key',
  'idempotency_key',
  'request_digest',
]);
const PENDING_AMENDMENT_KEYS = new Set([
  'from_state',
  'document_action_binding_digest',
  'release_action_digest',
  'document_action_binding',
  'agreement_acceptances',
  'proposer_party_id',
  'proposal_authorization',
  'proposed_at',
]);
const COMMAND_CONTAINER_KEYS = new Set(['artifact', 'verification']);
const DISPUTE_KEYS = new Set(['party_id', 'reason', 'authorization', 'opened_at']);
const CANCELLATION_KEYS = new Set([
  'party_id',
  'reason',
  'authorization',
  'cancelled_at',
]);
const COMPLETION_KEYS = new Set([
  'party_id',
  'meaning',
  'authorization',
  'completed_at',
]);
const STATE_STATEMENT_KEYS = new Set([
  'version',
  'issuer',
  'payload',
  'statement_digest',
  'signature',
]);
const STATE_ISSUER_KEYS = new Set(['operator_id', 'key_id']);
const STATE_PAYLOAD_KEYS = new Set([
  'statement_id',
  'agreement_id',
  'binding_digest',
  'action_digest',
  'profile_digest',
  'state',
  'revision',
  'amendment_digests',
  'state_record_digest',
  'previous_statement_digest',
  'occurred_at',
]);
const STATE_SIGNATURE_KEYS = new Set(['algorithm', 'signature_b64u']);
const PROFILE_REFERENCE_KEYS = new Set(['id', 'digest']);

const EXECUTED_AGREEMENT_STATES = new Set([
  'effective',
  'awaiting_funding',
  'funded',
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'amendment_pending',
  'completed',
  'release_indeterminate',
]);
const FUNDING_STATES = new Set([
  'funded',
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'completed',
  'release_indeterminate',
]);
const MILESTONE_STATES = new Set([
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'completed',
  'release_indeterminate',
]);
const RELEASE_APPROVAL_STATES = new Set([
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'completed',
  'release_indeterminate',
]);
const COMPLETE_RELEASE_APPROVAL_STATES = new Set([
  'release_reserved',
  'released',
  'completed',
  'release_indeterminate',
]);
const REQUIRED_RELEASE_STATES = new Set([
  'release_reserved',
  'released',
  'completed',
  'release_indeterminate',
]);
const OPTIONAL_RELEASE_STATES = new Set([
  'milestone_submitted',
  'disputed',
]);
const KERNEL_OPERATIONS = new Set([
  'create',
  'begin_acceptance',
  'accept_agreement',
  'request_funding',
  'record_funding',
  'submit_milestone',
  'approve_release',
  'release',
  'reconcile_release',
  'open_dispute',
  'propose_amendment',
  'accept_amendment',
  'cancel',
  'complete',
]);

const SECRET_FIELD_NAMES = new Set([
  'api_key',
  'api_token',
  'api_secret',
  'access_key',
  'access_key_id',
  'access_token',
  'refresh_token',
  'session_token',
  'oauth_token',
  'bearer_token',
  'client_secret',
  'client_password',
  'password',
  'passwd',
  'private_key',
  'private_key_pem',
  'secret',
  'secret_key',
  'secret_access_key',
  'signing_secret',
  'webhook_secret',
  'credential',
  'credentials',
  'provider_credentials',
  'authorization_header',
  'cookie',
  'set_cookie',
  'request_headers',
  'http_headers',
  'headers',
  'connection_string',
  'database_url',
]);

function fail(reason): never {
  throw new TypeError(`action-escrow package: ${reason}`);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, allowed, required = allowed) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function validString(value, max = 512) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validDigest(value) {
  return typeof value === 'string' && HASH.test(value);
}

function validInstant(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function canonicalCopy(value, label) {
  let nodes = 0;
  let stringBytes = 0;
  const seen = new WeakSet();

  function copy(current, depth) {
    nodes += 1;
    if (nodes > MAX_RECORD_NODES || depth > MAX_RECORD_DEPTH) {
      fail(`${label} exceeds resource limits`);
    }
    if (current === null || typeof current === 'boolean') return current;
    if (typeof current === 'string') {
      stringBytes += Buffer.byteLength(current, 'utf8');
      if (stringBytes > MAX_STRING_BYTES) fail(`${label} exceeds string limits`);
      return current;
    }
    if (typeof current === 'number') {
      if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
        fail(`${label} contains a non-canonical number`);
      }
      return current;
    }
    if (!isRecord(current) && !Array.isArray(current)) {
      fail(`${label} is not canonical JSON`);
    }
    if (seen.has(current)) fail(`${label} contains an alias or cycle`);
    seen.add(current);
    if (Array.isArray(current)) {
      return current.map((entry) => copy(entry, depth + 1));
    }
    return Object.fromEntries(
      Object.entries(current).map(([key, entry]) => [key, copy(entry, depth + 1)]),
    );
  }

  return copy(value, 0);
}

function canonicalDigest(value) {
  return `sha256:${hashCanonical(value)}`;
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function normalizeFieldName(value) {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function assertNoSecrets(value, label) {
  const stack = [{ value, path: label }];
  while (stack.length > 0) {
    const current = stack.pop();
    // stack.length > 0 guarantees pop() returns an entry; TS can't see that.
    if (!current) break;
    if (typeof current.value === 'string') {
      if (/-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/.test(current.value)
        || /^\s*Bearer\s+\S+/i.test(current.value)
        || /^[a-z][a-z0-9+.-]*:\/\/[^/\s]*@/i.test(current.value)) {
        fail(`${current.path} contains provider credentials or secrets`);
      }
      continue;
    }
    if (current.value === null || typeof current.value !== 'object') continue;
    for (const [key, child] of Object.entries(current.value)) {
      const normalized = normalizeFieldName(key);
      if (SECRET_FIELD_NAMES.has(normalized)
        || normalized.endsWith('_client_secret')
        || normalized.endsWith('_private_key')
        || normalized.endsWith('_access_token')
        || normalized.endsWith('_refresh_token')
        || normalized.endsWith('_password')) {
        fail(`${current.path}.${key} contains provider credentials or secrets`);
      }
      stack.push({ value: child, path: `${current.path}.${key}` });
    }
  }
}

function expectedCore(
  record,
  overrides: { document_action_binding_digest?: any; release_action_digest?: any } = {},
) {
  return {
    agreement_digest: record.agreement_digest,
    document_action_binding_digest:
      overrides.document_action_binding_digest ?? record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: overrides.release_action_digest ?? record.release_action_digest,
    parties_digest: record.parties_digest,
    profile_digest: record.profile_digest,
  };
}

function verificationMatchesCore(value, expected) {
  return isRecord(value)
    && value.valid === true
    && Object.entries(expected).every(([key, entry]) => value[key] === entry);
}

function validateStringArray(value, allowed, label) {
  if (!Array.isArray(value)
    || value.length === 0
    || value.some((entry) => !validString(entry, 256))
    || new Set(value).size !== value.length
    || value.some((entry) => !allowed.has(entry))) {
    fail(`${label} is invalid`);
  }
}

function partyIdentity(party) {
  return `${party.role}\u0000${party.party_id}`;
}

function sameParties(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  const expected = new Set(left.map(partyIdentity));
  return expected.size === left.length && right.every((party) => (
    exactKeys(party, PARTY_KEYS) && expected.has(partyIdentity(party))
  ));
}

function validatePartiesAndProfile(record) {
  if (!Array.isArray(record.parties)
    || record.parties.length < 2
    || record.parties.length > 16) {
    fail('kernel record parties are invalid');
  }
  const ids = new Set();
  for (const party of record.parties) {
    if (!exactKeys(party, PARTY_KEYS)
      || !validString(party.party_id, 256)
      || !validString(party.role, 128)
      || ids.has(party.party_id)) {
      fail('kernel record party is malformed or duplicated');
    }
    ids.add(party.party_id);
  }
  if (record.parties_digest !== canonicalDigest(record.parties)) {
    fail('kernel record parties digest mismatch');
  }
  if (!exactKeys(record.profile, PROFILE_KEYS)
    || record.profile['@version'] !== ACTION_ESCROW_PROFILE_VERSION
    || !validString(record.profile.profile_id, 256)
    || !validString(record.profile.provider_id, 256)
    || typeof record.profile.prohibit_self_approval !== 'boolean') {
    fail('kernel record profile is malformed');
  }
  validateStringArray(
    record.profile.required_acceptance_party_ids,
    ids,
    'required acceptance party roster',
  );
  validateStringArray(
    record.profile.required_release_approver_party_ids,
    ids,
    'required release party roster',
  );
  if (record.profile.required_acceptance_party_ids.length !== record.parties.length) {
    fail('required acceptance party roster does not cover the exact parties');
  }
  if (record.profile_digest !== canonicalDigest(record.profile)) {
    fail('kernel record profile digest mismatch');
  }
}

function validateHistory(record) {
  if (!Array.isArray(record.operations)
    || record.operations.length === 0
    || !Array.isArray(record.history)
    || record.history.length === 0) {
    fail('kernel operation or state history is malformed');
  }
  const operationIds = new Set();
  const operationsById = new Map();
  let previousOperationTime = Number.NEGATIVE_INFINITY;
  for (const operation of record.operations) {
    if (!exactKeys(operation, OPERATION_KEYS)
      || !validString(operation.idempotency_key, 512)
      || operationIds.has(operation.idempotency_key)
      || !validString(operation.operation, 128)
      || !KERNEL_OPERATIONS.has(operation.operation)
      || !validDigest(operation.request_digest)
      || !validString(operation.code, 256)
      || typeof operation.ok !== 'boolean'
      || !validString(operation.outcome, 128)
      || !ACTION_ESCROW_STATES.includes(operation.state)
      || !validInstant(operation.at)) {
      fail('kernel operation history is malformed');
    }
    const operationTime = Date.parse(operation.at);
    if (operationTime < previousOperationTime) {
      fail('kernel operation history is not time-monotonic');
    }
    operationIds.add(operation.idempotency_key);
    operationsById.set(operation.idempotency_key, operation);
    previousOperationTime = operationTime;
  }
  const firstOperation = record.operations[0];
  if (firstOperation.operation !== 'create'
    || firstOperation.state !== 'draft'
    || firstOperation.code !== 'escrow_created'
    || firstOperation.ok !== true) {
    fail('kernel operation history has no valid creation root');
  }

  let previous = null;
  let previousHistoryTime = Number.NEGATIVE_INFINITY;
  const releaseHistoryCounts = new Map();
  for (const [index, entry] of record.history.entries()) {
    if (!exactKeys(entry, HISTORY_KEYS)
      || entry.from !== previous
      || !ACTION_ESCROW_STATES.includes(entry.to)
      || !validString(entry.operation, 128)
      || !validString(entry.idempotency_key, 512)
      || !validInstant(entry.at)) {
      fail('kernel state history is malformed');
    }
    const linkedOperation = operationsById.get(entry.idempotency_key);
    const historyTime = Date.parse(entry.at);
    if (!linkedOperation
      || linkedOperation.operation !== entry.operation
      || historyTime < previousHistoryTime) {
      fail('kernel state history is not bound to its operation log');
    }
    if (entry.operation === 'release') {
      if (historyTime < Date.parse(linkedOperation.at)) {
        fail('kernel release history predates its reservation');
      }
      releaseHistoryCounts.set(
        entry.idempotency_key,
        (releaseHistoryCounts.get(entry.idempotency_key) ?? 0) + 1,
      );
    } else if (entry.at !== linkedOperation.at || entry.to !== linkedOperation.state) {
      fail('kernel state history is inconsistent with its operation');
    }
    if (index === 0) {
      if (entry.from !== null || entry.to !== 'draft' || entry.operation !== 'create') {
        fail('kernel state history has no valid creation root');
      }
    } else if (!ACTION_ESCROW_TRANSITIONS[entry.from]?.includes(entry.to)) {
      fail('kernel state history contains an invalid transition');
    }
    previous = entry.to;
    previousHistoryTime = historyTime;
  }
  if (previous !== record.state) fail('kernel state does not match its history');
  const internalReleaseTransitions = [...releaseHistoryCounts.values()]
    .reduce((total, count) => total + Math.max(0, count - 1), 0);
  if (record.revision !== record.operations.length - 1 + internalReleaseTransitions) {
    fail('kernel revision does not match its complete operation history');
  }

  const eventTimes = [
    ...record.operations.map((entry) => entry.at),
    ...record.history.map((entry) => entry.at),
  ];
  if (record.created_at !== record.operations[0].at
    || Date.parse(record.created_at) > Date.parse(record.updated_at)
    || eventTimes.some((instant) => Date.parse(instant) > Date.parse(record.updated_at))
    || Math.max(...eventTimes.map((instant) => Date.parse(instant)))
      !== Date.parse(record.updated_at)) {
    fail('kernel record timestamps do not match its history');
  }
}

/**
 * @param {any} container
 * @param {any} record
 * @param {{
 *   bindingDigest?: any,
 *   actionDigest?: any,
 *   supersedesDigest?: string|null,
 *   documentDigest?: string|null,
 *   documentLength?: number|null,
 * }} [options]
 */
function validateBindingContainer(container, record, {
  bindingDigest = record.document_action_binding_digest,
  actionDigest = record.release_action_digest,
  supersedesDigest = null,
  documentDigest = null,
  documentLength = null,
}: {
  bindingDigest?: string;
  actionDigest?: string;
  supersedesDigest?: string | null;
  documentDigest?: string | null;
  documentLength?: number | null;
} = {}) {
  if (!exactKeys(container, CONTAINER_KEYS)
    || !isRecord(container.artifact)
    || !isRecord(container.verification)) {
    fail('document-action binding container is malformed');
  }
  const binding = container.artifact;
  const verification = container.verification;
  const computedBindingDigest = computeDocumentActionBindingDigest(binding);
  const computedActionDigest = computeReleaseActionDigest(binding.release_action?.template);
  const bindingDocumentDigest = binding.document?.digest;
  const currentContractorProfile =
    binding.release_action?.template?.action_escrow_template_profile
      === ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION;
  const projectRecordBound = validDigest(
    binding.release_action?.template?.project_record_snapshot_digest,
  );
  // `validateActionEscrowReleaseTemplate` (action-escrow-verifiers.ts, outside
  // this file's scope) still infers its options parameter type from only the
  // one destructured property that carries a default value, so a fresh object
  // literal here trips the excess-property check. Routing through a locally
  // typed variable avoids that without changing what gets passed at runtime.
  const releaseTemplateOptions: {
    profileDigest?: any;
    agreementId?: any;
    agreementDigest?: any;
    milestoneId?: any;
    documentDigest?: any;
    materialTerms?: any;
    contractorProjectSource?: boolean;
  } = {
    profileDigest: record.profile_digest,
    agreementId: binding.agreement_id,
    agreementDigest: record.agreement_digest,
    milestoneId: record.milestone_id,
    documentDigest: bindingDocumentDigest,
    materialTerms: binding.material_terms,
    contractorProjectSource: currentContractorProfile,
  };
  const releaseActionTemplate = validateActionEscrowReleaseTemplate(
    binding.release_action?.template,
    releaseTemplateOptions,
  );
  const requiredVerification = new Set(BINDING_VERIFICATION_KEYS);
  if (supersedesDigest === null) {
    requiredVerification.delete('supersedes_document_action_binding_digest');
  }
  if (!exactKeys(verification, BINDING_VERIFICATION_KEYS, requiredVerification)
    || !verificationMatchesCore(verification, expectedCore(record, {
      document_action_binding_digest: bindingDigest,
      release_action_digest: actionDigest,
    }))
    || computedBindingDigest !== bindingDigest
    || binding.binding_digest !== bindingDigest
    || verification.verification_digest !== bindingDigest
    || computedActionDigest !== actionDigest
    || binding.release_action?.digest !== actionDigest
    || !validDigest(bindingDocumentDigest)
    || verification.document_digest !== bindingDocumentDigest
    || verification.agreement_id !== binding.agreement_id
    || verification.binding_id !== binding.binding_id
    || computeActionEscrowAgreementDigest(binding.agreement_id) !== record.agreement_digest
    || releaseActionTemplate === null
    || !sameCanonical(
      verification.release_action_template,
      releaseActionTemplate,
    )
    || !sameParties(record.parties, binding.parties)
    || !sameParties(record.parties, binding.required_parties)
    || (binding.supersedes_digest ?? null) !== supersedesDigest
    || (verification.supersedes_document_action_binding_digest ?? null)
      !== supersedesDigest) {
    fail('document-action binding is inconsistent with the kernel record');
  }
  if (documentDigest !== null
    && (bindingDocumentDigest !== documentDigest
      || releaseActionTemplate.document_sha256 !== documentDigest)) {
    fail('final PDF does not match the kernel document binding');
  }
  if (documentLength !== null && binding.document?.byte_length !== documentLength) {
    fail('final PDF byte length does not match the kernel document binding');
  }
  return {
    agreementId: binding.agreement_id,
    binding,
    contractorProjectSource: projectRecordBound,
    documentDigest: bindingDocumentDigest,
    projectRecordSnapshotDigest:
      releaseActionTemplate.project_record_snapshot_digest ?? null,
  };
}

function validateAcceptances(
  entries,
  record,
  core,
  {
    requireComplete,
    requireIncomplete = false,
  }: { requireComplete?: boolean; requireIncomplete?: boolean } = {},
) {
  if (!Array.isArray(entries)) fail('agreement acceptances are malformed');
  const parties = new Map<string, { party_id: any; role: any }>(
    record.parties.map((party) => [party.party_id, party]),
  );
  const required = new Set(record.profile.required_acceptance_party_ids);
  const seenParties = new Set();
  const seenKeys = new Set();
  const result: { party_id: any; role: any; evidence: any }[] = [];
  for (const entry of entries) {
    const verification = entry?.verification;
    const party = parties.get(entry?.party_id);
    if (!exactKeys(entry, ACCEPTANCE_KEYS)
      || !party
      || !required.has(entry.party_id)
      || seenParties.has(entry.party_id)
      || !isRecord(entry.artifact)
      || !exactKeys(verification, ACCEPTANCE_VERIFICATION_KEYS)
      || !verificationMatchesCore(verification, core)
      || verification.party_id !== entry.party_id
      || !validString(verification.principal_key_id, 512)
      || seenKeys.has(verification.principal_key_id)
      || verification.acceptance_digest !== canonicalDigest(entry.artifact)) {
      fail('agreement acceptance is malformed or inconsistent');
    }
    seenParties.add(entry.party_id);
    seenKeys.add(verification.principal_key_id);
    result.push({
      party_id: entry.party_id,
      role: party.role,
      evidence: entry.artifact,
    });
  }
  if (requireComplete && seenParties.size !== required.size) {
    fail('required agreement acceptance is missing');
  }
  if (requireIncomplete && seenParties.size >= required.size) {
    fail('agreement acceptance count is inconsistent with the stage');
  }
  return result;
}

function validateFunding(record) {
  const template = record.document_action_binding.verification.release_action_template;
  if (!exactKeys(record.funding, new Set(['statement', 'verification']))
    || !isRecord(record.funding.statement)
    || !exactKeys(record.funding.verification, FUNDING_VERIFICATION_KEYS)
    || !verificationMatchesCore(record.funding.verification, expectedCore(record))
    || record.funding.verification.authenticated !== true
    || record.funding.verification.provider_id !== record.profile.provider_id
    || record.funding.verification.statement_type !== 'funding'
    || record.funding.verification.status !== 'funded'
    || record.funding.verification.provider_transaction_id
      !== template.custodian_transaction_id
    || record.funding.verification.provider_milestone_id
      !== template.custodian_milestone_id
    || record.funding.verification.amount !== template.amount
    || record.funding.verification.currency !== template.currency
    || record.funding.verification.destination_id !== template.destination_id
    || record.funding.verification.statement_digest
      !== canonicalDigest(record.funding.statement)) {
    fail('funding statement is malformed or inconsistent');
  }
  return record.funding.statement;
}

function validateMilestone(record) {
  if (!exactKeys(record.milestone_evidence, CONTAINER_KEYS)
    || !isRecord(record.milestone_evidence.artifact)
    || !exactKeys(
      record.milestone_evidence.verification,
      MILESTONE_VERIFICATION_KEYS,
    )
    || !verificationMatchesCore(
      record.milestone_evidence.verification,
      expectedCore(record),
    )
    || !validDigest(record.milestone_evidence.verification.evidence_digest)
    || !record.parties.some(
      (party) => party.party_id
        === record.milestone_evidence.verification.submitter_party_id,
    )
    || !validInstant(record.milestone_evidence.verification.observed_at)) {
    fail('milestone evidence is malformed or inconsistent');
  }
  const artifact = record.milestone_evidence.artifact;
  const claimedDigest = artifact.evidence_digest
    ?? artifact.payload?.claim?.evidence_manifest_digest;
  if (claimedDigest !== undefined
    && claimedDigest !== record.milestone_evidence.verification.evidence_digest) {
    fail('milestone artifact digest does not match its kernel verification');
  }
  const submission = record.operations.find(
    (operation) => operation.operation === 'submit_milestone',
  );
  if (!submission
    || Date.parse(record.milestone_evidence.verification.observed_at)
      > Date.parse(submission.at)) {
    fail('milestone evidence was not valid at its submission operation');
  }
  return {
    milestone_id: record.milestone_id,
    evidence: artifact,
    resolution: null,
  };
}

function validateReleaseApprovals(record, milestoneVerification) {
  if (!Array.isArray(record.release_approvals)) fail('release approvals are malformed');
  const parties = new Map<string, { party_id: any; role: any }>(
    record.parties.map((party) => [party.party_id, party]),
  );
  const required = new Set(record.profile.required_release_approver_party_ids);
  const bindingInput = {
    agreement_digest: record.agreement_digest,
    document_action_binding_digest: record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: record.release_action_digest,
    profile_digest: record.profile_digest,
    evidence_digest: milestoneVerification.evidence_digest,
    release_action_template:
      record.document_action_binding.verification.release_action_template,
  };
  const bindingMomentDigest = computeActionEscrowReleaseBindingMomentDigest(bindingInput);
  const expectedInitiator = milestoneVerification.submitter_party_id;
  if (!validDigest(bindingMomentDigest) || !validString(expectedInitiator, 256)) {
    fail('release approval binding context is malformed');
  }
  const seenParties = new Set();
  const seenKeys = new Set();
  const result: { party_id: any; role: any; evidence: any }[] = [];
  const approvalOperations = record.operations.filter(
    (operation) => operation.operation === 'approve_release',
  );
  for (const [index, entry] of record.release_approvals.entries()) {
    const party = parties.get(entry?.party_id);
    const verification = entry?.verification;
    const context = entry?.resolution?.signoff?.context;
    if (!exactKeys(entry, RELEASE_APPROVAL_KEYS)
      || !party
      || !required.has(entry.party_id)
      || seenParties.has(entry.party_id)
      || !isRecord(entry.resolution)
      || entry.resolution.profile !== 'EP-RESOLUTION-v1'
      || !isRecord(context)
      || !exactKeys(verification, RELEASE_APPROVAL_VERIFICATION_KEYS)
      || !verificationMatchesCore(verification, expectedCore(record))
      || verification.authorizes_action !== true
      || verification.outcome !== 'approved'
      || verification.party_role !== party.role
      || !validString(verification.principal_key_id, 512)
      || seenKeys.has(verification.principal_key_id)
      || !validString(verification.nonce, 512)
      || !validInstant(verification.issued_at)
      || !validInstant(verification.expires_at)
      || Date.parse(verification.issued_at) < Date.parse(milestoneVerification.observed_at)
      || Date.parse(verification.expires_at) <= Date.parse(verification.issued_at)
      || verification.resolution_digest !== canonicalDigest(entry.resolution)
      || verification.evidence_digest !== milestoneVerification.evidence_digest
      || context.principal !== entry.party_id
      || context.principal_key_id !== verification.principal_key_id
      || context.envelope_hash !== bindingMomentDigest
      || context.action_hash !== record.release_action_digest
      || context.initiator !== expectedInitiator
      || context.nonce !== computeActionEscrowResolutionNonce(bindingInput, entry.party_id)
      || context.nonce !== verification.nonce
      || context.issued_at !== verification.issued_at
      || context.expires_at !== verification.expires_at
      || context.resolution?.outcome !== 'approved'
      || context.resolution?.selected_option !== 0) {
      fail('release approval is malformed or inconsistent');
    }
    const approvalOperation = approvalOperations[index];
    if (!approvalOperation
      || Date.parse(verification.issued_at) > Date.parse(approvalOperation.at)
      || Date.parse(verification.expires_at) <= Date.parse(approvalOperation.at)
      || (
        record.release !== null
        && (
          Date.parse(verification.issued_at) > Date.parse(record.release.reserved_at)
          || Date.parse(verification.expires_at) <= Date.parse(record.release.reserved_at)
        )
      )) {
      fail('release approval was not valid at its operation');
    }
    seenParties.add(entry.party_id);
    seenKeys.add(verification.principal_key_id);
    result.push({
      party_id: entry.party_id,
      role: party.role,
      evidence: entry.resolution,
    });
  }
  return { approvals: result, approvedPartyIds: seenParties };
}

function validateProviderVerification(value, record, release) {
  const template = record.document_action_binding.verification.release_action_template;
  if (!exactKeys(value, PROVIDER_VERIFICATION_KEYS)
    || !verificationMatchesCore(value, expectedCore(record))
    || value.authenticated !== true
    || value.provider_id !== record.profile.provider_id
    || value.provider_idempotency_key !== release.provider_idempotency_key
    || value.provider_request_digest !== release.provider_request.request_digest
    || value.provider_transaction_id !== template.custodian_transaction_id
    || value.provider_milestone_id !== template.custodian_milestone_id
    || value.amount !== template.amount
    || value.currency !== template.currency
    || value.destination_id !== template.destination_id
    || value.statement_type !== 'release'
    || !['released', 'not_released', 'pending'].includes(value.status)
    || !validDigest(value.statement_digest)
    || value.statement_digest !== canonicalDigest(release.provider_statement)) {
    fail('provider release statement is malformed or inconsistent');
  }
}

function validateRelease(record) {
  const release = record.release;
  if (!exactKeys(release, RELEASE_KEYS)
    || !validString(release.release_key, 256)
    || !validString(release.provider_idempotency_key, 256)
    || !validString(release.operation_idempotency_key, 512)
    || !['reserved', 'released', 'not_released', 'indeterminate'].includes(release.status)
    || !validInstant(release.reserved_at)
    || (release.reconciled_at !== null && !validInstant(release.reconciled_at))
    || !exactKeys(release.provider_request, PROVIDER_REQUEST_KEYS)) {
    fail('release record is malformed');
  }
  const expectedReleaseKey = `ep-ae-reservation:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-RELEASE-KEY-v1',
    agreement_digest: record.agreement_digest,
    document_action_binding_digest: record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: record.release_action_digest,
    profile_digest: record.profile_digest,
  })}`;
  const expectedProviderKey = `ep-ae-release:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-PROVIDER-IDEMPOTENCY-v1',
    agreement_digest: record.agreement_digest,
    document_action_binding_digest: record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: record.release_action_digest,
    profile_digest: record.profile_digest,
  })}`;
  if (release.release_key !== expectedReleaseKey
    || release.provider_idempotency_key !== expectedProviderKey) {
    fail('release reservation key mismatch');
  }

  const request = release.provider_request;
  const { request_digest: requestDigest, ...requestScope } = request;
  if (request.method !== 'POST'
    || request.provider_id !== record.profile.provider_id
    || request.agreement_digest !== record.agreement_digest
    || request.document_action_binding_digest
      !== record.document_action_binding_digest
    || request.milestone_id !== record.milestone_id
    || request.release_action_digest !== record.release_action_digest
    || !sameCanonical(request.parties, record.parties)
    || request.parties_digest !== record.parties_digest
    || !sameCanonical(request.profile, record.profile)
    || request.profile_digest !== record.profile_digest
    || request.agreement_id
      !== record.document_action_binding.verification.agreement_id
    || request.binding_id !== record.document_action_binding.verification.binding_id
    || request.document_digest
      !== record.document_action_binding.verification.document_digest
    || !sameCanonical(
      request.release_action_template,
      record.document_action_binding.verification.release_action_template,
    )
    || request.release_key !== release.release_key
    || request.idempotency_key !== release.provider_idempotency_key
    || requestDigest !== canonicalDigest({
      '@version': 'EP-ACTION-ESCROW-PROVIDER-REQUEST-v1',
      ...requestScope,
    })) {
    fail('provider release request is inconsistent with the kernel record');
  }

  const execution = record.operations.find((entry) => (
    entry.operation === 'release'
      && entry.idempotency_key === release.operation_idempotency_key
  ));
  if (!execution) fail('release execution record is missing');
  if (release.reserved_at !== execution.at
    || (
      release.reconciled_at !== null
      && Date.parse(release.reconciled_at) < Date.parse(release.reserved_at)
    )) {
    fail('release timestamps are inconsistent with the execution operation');
  }
  const expectedExecution = {
    reserved: {
      states: new Set(['release_reserved']),
      operationStates: new Set(['release_reserved']),
      codes: new Set(['release_reserved']),
      ok: false,
      outcomes: new Set(['reserved']),
    },
    released: {
      states: new Set(['released', 'completed']),
      operationStates: new Set(['released']),
      codes: new Set(['release_committed', 'release_reconciled_released']),
      ok: true,
      outcomes: new Set(['applied']),
    },
    not_released: {
      states: new Set(['milestone_submitted', 'disputed', 'amendment_pending']),
      operationStates: new Set(['milestone_submitted', 'amendment_pending']),
      codes: new Set([
        'provider_release_not_released',
        'release_reconciled_not_released',
      ]),
      ok: false,
      outcomes: new Set(['refused']),
    },
    indeterminate: {
      states: new Set(['release_indeterminate']),
      operationStates: new Set(['release_indeterminate']),
      codes: new Set([
        'release_effect_indeterminate',
        'release_commit_indeterminate',
        'release_still_indeterminate',
      ]),
      ok: false,
      outcomes: new Set(['indeterminate']),
    },
  }[release.status];
  if (!expectedExecution.states.has(record.state)
    || !expectedExecution.operationStates.has(execution.state)
    || !expectedExecution.codes.has(execution.code)
    || execution.ok !== expectedExecution.ok
    || !expectedExecution.outcomes.has(execution.outcome)) {
    fail('release execution record is inconsistent with the release state');
  }

  if (release.status === 'reserved') {
    if (release.reconciled_at !== null
      || release.provider_statement !== null
      || release.provider_verification !== null) {
      fail('reserved release carries premature provider evidence');
    }
  } else {
    if (release.reconciled_at === null) fail('reconciled release is missing its instant');
    const hasStatement = release.provider_statement !== null;
    const hasVerification = release.provider_verification !== null;
    if (hasStatement !== hasVerification) {
      fail('provider release statement and verification must be paired');
    }
    if (release.status !== 'indeterminate' && !hasStatement) {
      fail('authoritative provider release statement is missing');
    }
    if (hasStatement) {
      if (!isRecord(release.provider_statement)) {
        fail('provider release statement is malformed');
      }
      validateProviderVerification(release.provider_verification, record, release);
      if (release.status !== 'indeterminate'
        && release.provider_verification.status !== release.status) {
        fail('provider release status mismatch');
      }
    }
  }

  return {
    reservation: {
      release_key: release.release_key,
      provider_idempotency_key: release.provider_idempotency_key,
      reserved_at: release.reserved_at,
    },
    provider_request: request,
    provider_statement: release.provider_statement,
    execution_record: execution,
  };
}

function validateCommandAuthorization(container, record, command, partyId, details) {
  if (!exactKeys(container, COMMAND_CONTAINER_KEYS)
    || !isRecord(container.artifact)
    || !exactKeys(container.verification, COMMAND_VERIFICATION_KEYS)
    || !verificationMatchesCore(container.verification, expectedCore(record))) {
    fail(`${command} authorization is malformed`);
  }
  const detailsDigest = canonicalDigest(details);
  const commandDigest = canonicalDigest({
    '@version': 'EP-ACTION-ESCROW-COMMAND-v1',
    ...expectedCore(record),
    command,
    party_id: partyId,
    details_digest: detailsDigest,
  });
  if (container.verification.authorizes_command !== true
    || container.verification.command !== command
    || container.verification.party_id !== partyId
    || container.verification.details_digest !== detailsDigest
    || container.verification.command_digest !== commandDigest) {
    fail(`${command} authorization does not match the state change`);
  }
}

function validateAncillaryState(record) {
  if (record.state === 'disputed') {
    if (!exactKeys(record.dispute, DISPUTE_KEYS)
      || !record.parties.some((party) => party.party_id === record.dispute.party_id)
      || !validString(record.dispute.reason, 2048)
      || !validInstant(record.dispute.opened_at)) {
      fail('dispute state is malformed');
    }
    validateCommandAuthorization(
      record.dispute.authorization,
      record,
      'open_dispute',
      record.dispute.party_id,
      { reason: record.dispute.reason },
    );
  } else if (record.dispute !== null) {
    fail('non-disputed stage carries a dispute');
  }

  if (record.state === 'cancelled') {
    if (!exactKeys(record.cancellation, CANCELLATION_KEYS)
      || !record.parties.some(
        (party) => party.party_id === record.cancellation.party_id,
      )
      || (record.cancellation.reason !== null
        && !validString(record.cancellation.reason, 2048))
      || !validInstant(record.cancellation.cancelled_at)) {
      fail('cancellation state is malformed');
    }
    validateCommandAuthorization(
      record.cancellation.authorization,
      record,
      'cancel',
      record.cancellation.party_id,
      { reason: record.cancellation.reason },
    );
  } else if (record.cancellation !== null) {
    fail('non-cancelled stage carries a cancellation');
  }

  if (record.state === 'completed') {
    if (!exactKeys(record.completion, COMPLETION_KEYS)
      || !record.parties.some((party) => party.party_id === record.completion.party_id)
      || record.completion.meaning !== 'administrative_archive_only'
      || !validInstant(record.completion.completed_at)) {
      fail('completion state is malformed');
    }
    validateCommandAuthorization(
      record.completion.authorization,
      record,
      'complete',
      record.completion.party_id,
      { meaning: 'administrative_archive_only' },
    );
  } else if (record.completion !== null) {
    fail('non-completed stage carries a completion record');
  }
}

/** @param {any} record */
function validateSupersessions(record) {
  if (!Array.isArray(record.superseded_bindings)) {
    fail('superseded binding history is malformed');
  }
  const amendments: any[] = [];
  const amendmentDigests: string[] = [];
  let previousNext = null;
  const seen = new Set();
  for (const entry of record.superseded_bindings) {
    if (!exactKeys(entry, SUPERSESSION_KEYS)
      || !validDigest(entry.document_action_binding_digest)
      || !validDigest(entry.release_action_digest)
      || !validDigest(entry.superseded_by_binding_digest)
      || !validInstant(entry.superseded_at)
      || entry.document_action_binding_digest === entry.superseded_by_binding_digest
      || seen.has(entry.document_action_binding_digest)
      || (previousNext !== null
        && entry.document_action_binding_digest !== previousNext)) {
      fail('superseded binding history is inconsistent');
    }
    seen.add(entry.document_action_binding_digest);
    previousNext = entry.superseded_by_binding_digest;
    amendments.push(entry);
    amendmentDigests.push(canonicalDigest(entry));
  }
  if (previousNext !== null && previousNext !== record.document_action_binding_digest) {
    fail('superseded binding history does not terminate at the current binding');
  }
  return {
    amendments,
    amendmentDigests,
    currentSupersedes: amendments.at(-1)?.document_action_binding_digest ?? null,
  };
}

/** @param {any} record */
function validatePendingAmendment(record) {
  const pendingAllowed = record.state === 'amendment_pending'
    || record.state === 'release_indeterminate'
    || record.state === 'cancelled';
  if (record.pending_amendment === null) {
    if (record.state === 'amendment_pending') fail('pending amendment is missing');
    return;
  }
  if (!pendingAllowed
    || !exactKeys(record.pending_amendment, PENDING_AMENDMENT_KEYS)
    || ![
      'effective',
      'awaiting_funding',
      'funded',
      'milestone_submitted',
      'disputed',
      'release_reserved',
      'release_indeterminate',
    ].includes(record.pending_amendment.from_state)
    || !validDigest(record.pending_amendment.document_action_binding_digest)
    || !validDigest(record.pending_amendment.release_action_digest)
    || record.pending_amendment.document_action_binding_digest
      === record.document_action_binding_digest
    || !record.parties.some(
      (/** @type {{party_id: string}} */ party) => party.party_id
        === record.pending_amendment.proposer_party_id,
    )
    || !validInstant(record.pending_amendment.proposed_at)) {
    fail('pending amendment is malformed');
  }
  if (record.state === 'amendment_pending'
    && ['release_reserved', 'release_indeterminate'].includes(
      record.pending_amendment.from_state,
    )) {
    fail('pending amendment stage is inconsistent with release reconciliation');
  }
  if (record.state === 'release_indeterminate'
    && !['release_reserved', 'release_indeterminate'].includes(
      record.pending_amendment.from_state,
    )) {
    fail('indeterminate amendment does not originate from an uncertain release');
  }

  validateBindingContainer(
    record.pending_amendment.document_action_binding,
    record,
    {
      bindingDigest: record.pending_amendment.document_action_binding_digest,
      actionDigest: record.pending_amendment.release_action_digest,
      supersedesDigest: record.document_action_binding_digest,
    },
  );
  const pendingCore = expectedCore(record, {
    document_action_binding_digest:
      record.pending_amendment.document_action_binding_digest,
    release_action_digest: record.pending_amendment.release_action_digest,
  });
  validateAcceptances(
    record.pending_amendment.agreement_acceptances,
    record,
    pendingCore,
    { requireComplete: false, requireIncomplete: true },
  );
  validateCommandAuthorization(
    record.pending_amendment.proposal_authorization,
    record,
    'propose_amendment',
    record.pending_amendment.proposer_party_id,
    {
      next_document_action_binding_digest:
        record.pending_amendment.document_action_binding_digest,
      next_release_action_digest: record.pending_amendment.release_action_digest,
    },
  );
}

/** @param {any} record */
function validateLifecycle(record) {
  const requiresExecutedAgreement = EXECUTED_AGREEMENT_STATES.has(record.state);
  const agreementAcceptances = validateAcceptances(
    record.agreement_acceptances,
    record,
    expectedCore(record),
    {
      requireComplete: requiresExecutedAgreement,
      requireIncomplete: record.state === 'awaiting_acceptance',
    },
  );
  if (record.state === 'draft' && agreementAcceptances.length !== 0) {
    fail('draft stage carries agreement acceptances');
  }

  const requiresFunding = FUNDING_STATES.has(record.state);
  if (requiresFunding !== (record.funding !== null)) {
    fail(requiresFunding
      ? 'required funding statement is missing'
      : 'stage carries an unexpected funding statement');
  }
  const fundingStatement = record.funding === null ? null : validateFunding(record);

  const requiresMilestone = MILESTONE_STATES.has(record.state);
  if (requiresMilestone !== (record.milestone_evidence !== null)) {
    fail(requiresMilestone
      ? 'required milestone evidence is missing'
      : 'stage carries unexpected milestone evidence');
  }
  const milestone = record.milestone_evidence === null ? null : validateMilestone(record);

  validateLifecycleOperationCoverage(record);
  if (!RELEASE_APPROVAL_STATES.has(record.state)
    && record.release_approvals.length !== 0) {
    fail('stage carries unexpected release approvals');
  }
  if (record.release_approvals.length > 0 && milestone === null) {
    fail('release approval has no milestone evidence');
  }
  const releaseApprovalResult = milestone === null
    ? { approvals: [], approvedPartyIds: new Set() }
    : validateReleaseApprovals(record, record.milestone_evidence.verification);
  if (COMPLETE_RELEASE_APPROVAL_STATES.has(record.state)
    && releaseApprovalResult.approvedPartyIds.size
      !== record.profile.required_release_approver_party_ids.length) {
    fail('required release approval is missing');
  }

  const hasRelease = record.release !== null;
  if (REQUIRED_RELEASE_STATES.has(record.state) && !hasRelease) {
    fail('required release artifacts are missing');
  }
  if (!REQUIRED_RELEASE_STATES.has(record.state)
    && !OPTIONAL_RELEASE_STATES.has(record.state)
    && hasRelease) {
    fail('stage carries unexpected release artifacts');
  }
  const release = hasRelease ? validateRelease(record) : null;

  validateAncillaryState(record);
  validatePendingAmendment(record);

  return {
    requiresExecutedAgreement,
    agreementAcceptances,
    fundingStatement,
    milestones: milestone === null ? [] : [milestone],
    releaseApprovals: releaseApprovalResult.approvals,
    release,
  };
}

/** @param {any} record */
function validateLifecycleOperationCoverage(record) {
  /** @param {string} name */
  const count = (name) => record.operations
    .filter((/** @type {{operation: string}} */ operation) => operation.operation === name)
      .length;
  /**
   * @param {string} name
   * @param {number} expected
   */
  const requireExact = (name, expected) => {
    if (count(name) !== expected) {
      fail(`kernel ${name} operation coverage does not match its artifacts`);
    }
  };
  const acceptanceCount = record.profile.required_acceptance_party_ids.length;
  const expectedInitialAcceptances = record.superseded_bindings.length > 0
    ? acceptanceCount
    : record.agreement_acceptances.length;
  const expectedAmendmentAcceptances =
    record.superseded_bindings.length * acceptanceCount
      + (Array.isArray(record.pending_amendment?.agreement_acceptances)
        ? record.pending_amendment.agreement_acceptances.length
        : 0);

  requireExact('create', 1);
  requireExact(
    'begin_acceptance',
    record.history.some((/** @type {{to: string}} */ entry) => entry.to === 'awaiting_acceptance')
      ? 1 : 0,
  );
  requireExact('accept_agreement', expectedInitialAcceptances);
  requireExact(
    'request_funding',
    record.history.some((/** @type {{to: string}} */ entry) => entry.to === 'awaiting_funding')
      ? 1 : 0,
  );
  requireExact('record_funding', record.funding === null ? 0 : 1);
  requireExact('submit_milestone', record.milestone_evidence === null ? 0 : 1);
  requireExact('approve_release', record.release_approvals.length);
  requireExact(
    'propose_amendment',
    record.superseded_bindings.length + (record.pending_amendment === null ? 0 : 1),
  );
  requireExact('accept_amendment', expectedAmendmentAcceptances);
  requireExact('open_dispute', record.dispute === null ? 0 : 1);
  requireExact('cancel', record.cancellation === null ? 0 : 1);
  requireExact('complete', record.completion === null ? 0 : 1);
  if ((record.release === null) !== (count('release') === 0)) {
    fail('kernel release operation coverage does not match its artifacts');
  }
  if (record.release === null && count('reconcile_release') !== 0) {
    fail('kernel reconciliation operation has no release artifact');
  }
}

/** @param {any} record */
function validateKernelRecord(record) {
  if (!exactKeys(record, RECORD_KEYS)
    || record['@version'] !== ACTION_ESCROW_STATE_VERSION
    || !Number.isSafeInteger(record.revision)
    || record.revision < 0
    || !ACTION_ESCROW_STATES.includes(record.state)
    || !validString(record.escrow_key, 256)
    || !validDigest(record.agreement_digest)
    || !validDigest(record.document_action_binding_digest)
    || !validString(record.milestone_id, 256)
    || !validDigest(record.release_action_digest)
    || !validDigest(record.parties_digest)
    || !validDigest(record.profile_digest)
    || !validInstant(record.created_at)
    || !validInstant(record.updated_at)) {
    fail('kernel record is malformed');
  }
  const expectedEscrowKey = `ep-action-escrow:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-KEY-v1',
    agreement_digest: record.agreement_digest,
    milestone_id: record.milestone_id,
  })}`;
  if (record.escrow_key !== expectedEscrowKey) fail('kernel escrow key mismatch');
  validatePartiesAndProfile(record);
  validateHistory(record);
}

/**
 * @param {any} value
 * @param {{agreementId: string, bindingDigest: string | null, documentDigest: string | null}} expected
 * @param {boolean} required
 */
function validateDocumentExecution(value, expected, required) {
  if (value === null) {
    if (required) fail('required document-execution artifact is missing');
    return null;
  }
  if (!isRecord(value)
    || value.agreement_id !== expected.agreementId
    || value.binding_digest !== expected.bindingDigest
    || value.document_digest !== expected.documentDigest
    || value.authorizes_action !== false
    || (value.state !== undefined && value.state !== 'executed')) {
    fail('document-execution artifact does not match the kernel record');
  }
  return value;
}

/**
 * @param {any} value
 * @param {any} record
 */
function validateProfileReference(value, record) {
  if (!exactKeys(value, PROFILE_REFERENCE_KEYS)
    || value.id !== record.profile.profile_id
    || value.digest !== record.profile_digest) {
    fail('verification-profile reference mismatch');
  }
}

/** @param {any} statement */
function stateStatementDigest(statement) {
  const body = {
    version: statement.version,
    issuer: statement.issuer,
    payload: statement.payload,
  };
  const bytes = Buffer.from(
    ACTION_ESCROW_STATE_STATEMENT_DOMAIN + canonicalize(body),
    'utf8',
  );
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * @param {any} statement
 * @param {any} record
 * @param {string} agreementId
 * @param {string[]} amendmentDigests
 * @param {number} assembledAt
 */
function validateStateStatement(
  statement,
  record,
  agreementId,
  amendmentDigests,
  assembledAt,
) {
  if (!exactKeys(statement, STATE_STATEMENT_KEYS)
    || statement.version !== ACTION_ESCROW_STATE_STATEMENT_VERSION
    || !exactKeys(statement.issuer, STATE_ISSUER_KEYS)
    || !validString(statement.issuer.operator_id, 256)
    || !validString(statement.issuer.key_id, 256)
    || !exactKeys(statement.payload, STATE_PAYLOAD_KEYS)
    || !validString(statement.payload.statement_id, 256)
    || statement.payload.agreement_id !== agreementId
    || statement.payload.binding_digest !== record.document_action_binding_digest
    || statement.payload.action_digest !== record.release_action_digest
    || statement.payload.profile_digest !== record.profile_digest
    || statement.payload.state !== record.state
    || statement.payload.revision !== record.revision
    || !Array.isArray(statement.payload.amendment_digests)
    || statement.payload.amendment_digests.length !== amendmentDigests.length
    || statement.payload.amendment_digests.some(
      (/** @type {string} */ digest, /** @type {number} */ index) => digest
        !== amendmentDigests[index],
    )
    || statement.payload.state_record_digest !== canonicalDigest(record)
    || (statement.payload.previous_statement_digest !== null
      && !validDigest(statement.payload.previous_statement_digest))
    || !validInstant(statement.payload.occurred_at)
    || Date.parse(statement.payload.occurred_at) > assembledAt
    || !exactKeys(statement.signature, STATE_SIGNATURE_KEYS)
    || statement.signature.algorithm !== 'Ed25519'
    || typeof statement.signature.signature_b64u !== 'string'
    || !BASE64URL.test(statement.signature.signature_b64u)
    || statement.signature.signature_b64u.length % 4 === 1
    || !validDigest(statement.statement_digest)
    || statement.statement_digest !== stateStatementDigest(statement)) {
    fail('operator state statement mismatch');
  }
}

/**
 * @param {Buffer|Uint8Array} value
 * @param {number} maxDocumentBytes
 */
function finalPdfBytes(value, maxDocumentBytes) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    fail('finalPdfBytes must be bytes');
  }
  const bytes = Buffer.from(value);
  if (bytes.length === 0 || bytes.length > maxDocumentBytes) {
    fail(`finalPdfBytes must be between 1 and ${maxDocumentBytes} bytes`);
  }
  if (!bytes.subarray(0, 5).equals(Buffer.from('%PDF-', 'ascii'))
    || !bytes.subarray(Math.max(0, bytes.length - 1024)).includes(Buffer.from('%%EOF'))) {
    fail('finalPdfBytes is not a final PDF');
  }
  return bytes;
}

/** @param {number|string|Date|(() => (number|string|Date))} value */
function evaluationInstant(value) {
  const candidate = typeof value === 'function' ? value() : value;
  const parsed = candidate instanceof Date
    ? candidate.getTime()
    : typeof candidate === 'number'
      ? candidate
      : Date.parse(candidate);
  if (!Number.isFinite(parsed)) fail('now must be a valid instant');
  return parsed;
}

/**
 * Assemble an EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1 from one exact durable
 * kernel record and the external artifacts the kernel deliberately does not
 * retain. Invalid local assembly input throws before a package is produced.
 */
function assembleEvidencePackage(
  input,
  options,
  { contractorProjectSource },
) {
  const inputKeys = contractorProjectSource ? CONTRACTOR_INPUT_KEYS : INPUT_KEYS;
  const optionKeys = contractorProjectSource
    ? CONTRACTOR_OPTION_KEYS
    : OPTION_KEYS;
  if (!exactKeys(input, inputKeys)) {
    fail('caller overrides are not accepted; use the closed assembler input');
  }
  if (!exactKeys(options, optionKeys, new Set())) {
    fail('caller overrides are not accepted in assembler options');
  }
  const maxDocumentBytes = options.maxDocumentBytes ?? DEFAULT_MAX_DOCUMENT_BYTES;
  if (!Number.isSafeInteger(maxDocumentBytes) || maxDocumentBytes <= 0) {
    fail('maxDocumentBytes must be a positive safe integer');
  }
  const assembledAt = evaluationInstant(options.now ?? Date.now);
  const bytes = finalPdfBytes(input.finalPdfBytes, maxDocumentBytes);
  const record = canonicalCopy(input.kernelRecord, 'kernelRecord');
  const documentExecution = input.documentExecution === null
    ? null
    : canonicalCopy(input.documentExecution, 'documentExecution');
  const stateStatement = canonicalCopy(
    input.operatorStateStatement,
    'operatorStateStatement',
  );
  const verificationProfile = canonicalCopy(
    input.verificationProfile,
    'verificationProfile',
  );

  assertNoSecrets(record, 'kernelRecord');
  assertNoSecrets(documentExecution, 'documentExecution');
  assertNoSecrets(stateStatement, 'operatorStateStatement');
  assertNoSecrets(verificationProfile, 'verificationProfile');

  validateKernelRecord(record);
  if (Date.parse(record.updated_at) > assembledAt) {
    fail('kernel record is from the future');
  }
  const supersessions = validateSupersessions(record);
  const documentDigest = computeDocumentSha256(bytes);
  const binding = validateBindingContainer(record.document_action_binding, record, {
    supersedesDigest: supersessions.currentSupersedes,
    documentDigest,
    documentLength: bytes.length,
  });
  if (binding.contractorProjectSource !== contractorProjectSource) {
    fail(contractorProjectSource
      ? 'contractor evidence package requires the contractor binding profile'
      : 'contractor binding requires the contractor evidence-package assembler');
  }
  if (contractorProjectSource
    && input.projectRecordSnapshotDigest
      !== binding.projectRecordSnapshotDigest) {
    fail('project-record snapshot digest does not match the document binding');
  }
  const lifecycle = validateLifecycle(record);
  const execution = validateDocumentExecution(
    documentExecution,
    {
      agreementId: binding.agreementId,
      bindingDigest: record.document_action_binding_digest,
      documentDigest,
    },
    lifecycle.requiresExecutedAgreement,
  );
  validateProfileReference(verificationProfile, record);
  validateStateStatement(
    stateStatement,
    record,
    binding.agreementId,
    supersessions.amendmentDigests,
    assembledAt,
  );

  return buildActionEscrowEvidencePackage(/** @type {any} */ ({
    agreementId: binding.agreementId,
    stage: record.state,
    binding: binding.binding,
    documentBytes: bytes,
    documentFileName: input.documentFileName,
    documentExecution: execution,
    agreementAcceptances: lifecycle.agreementAcceptances,
    releaseApprovals: lifecycle.releaseApprovals,
    fundingStatement: lifecycle.fundingStatement,
    milestones: lifecycle.milestones,
    release: lifecycle.release,
    stateRecord: {
      snapshot: record,
      statement: stateStatement,
    },
    amendments: supersessions.amendments,
    verificationProfile,
    ...(contractorProjectSource
      ? {
        projectRecordBytes: input.projectRecordBytes,
        projectRecordFileName: input.projectRecordFileName,
        projectRecordProvider: input.projectRecordProvider,
        projectRecordSnapshotDigest: input.projectRecordSnapshotDigest,
      }
      : {}),
  }), {
    now: assembledAt,
    maxDocumentBytes,
    ...(contractorProjectSource
      ? { maxProjectRecordBytes: options.maxProjectRecordBytes }
      : {}),
  });
}

export function assembleActionEscrowEvidencePackage(input = {}, options = {}) {
  return assembleEvidencePackage(input, options, {
    contractorProjectSource: false,
  });
}

export function assembleActionEscrowContractorEvidencePackage(
  input = {},
  options = {},
) {
  return assembleEvidencePackage(input, options, {
    contractorProjectSource: true,
  });
}

export const buildActionEscrowEvidencePackageFromKernel =
  assembleActionEscrowEvidencePackage;

export default {
  assembleActionEscrowContractorEvidencePackage,
  assembleActionEscrowEvidencePackage,
  buildActionEscrowEvidencePackageFromKernel,
};
