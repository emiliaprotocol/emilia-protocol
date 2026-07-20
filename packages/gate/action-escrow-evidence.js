// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1
 *
 * A content-addressed manifest for the artifacts used by Action Escrow. This
 * module does not decide whether a contract is enforceable and does not move
 * money. Verification replays caller-supplied, relying-party-owned component
 * verifiers so a package cannot make an invalid nested artifact trustworthy by
 * merely hashing it.
 */
import crypto from 'node:crypto';
import { hashCanonical } from './execution-binding.js';
import { strictJsonGate } from './strict-json.js';

export const ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION = 'EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1';
export const ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION =
  'EP-ACTION-ESCROW-CONTRACTOR-EVIDENCE-PACKAGE-v1';
export const ACTION_ESCROW_EVIDENCE_STAGES = Object.freeze([
  'draft',
  'awaiting_acceptance',
  'effective',
  'awaiting_funding',
  'funded',
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'amendment_pending',
  'cancelled',
  'completed',
  'release_indeterminate',
]);

const HASH = /^sha256:[0-9a-f]{64}$/;
const TOP_KEYS = new Set([
  'version',
  'agreement_id',
  'stage',
  'binding',
  'document',
  'document_execution',
  'agreement_acceptances',
  'release_approvals',
  'funding_statement',
  'milestones',
  'release',
  'state_record',
  'amendments',
  'verification_profile',
  'assembled_at',
  'limitations',
  'package_digest',
]);
const CONTRACTOR_TOP_KEYS = new Set([
  ...TOP_KEYS,
  'project_record',
]);
const DOCUMENT_KEYS = new Set(['media_type', 'digest', 'byte_length', 'file_name']);
const PROJECT_RECORD_KEYS = new Set([
  'media_type',
  'digest',
  'byte_length',
  'file_name',
  'provider',
  'snapshot_digest',
]);
const PARTY_EVIDENCE_KEYS = new Set(['party_id', 'role', 'evidence']);
const MILESTONE_KEYS = new Set(['milestone_id', 'evidence', 'resolution']);
const RELEASE_KEYS = new Set([
  'reservation',
  'provider_request',
  'provider_statement',
  'execution_record',
]);
const STATE_RECORD_KEYS = new Set(['snapshot', 'statement']);
const LIMITATIONS = Object.freeze([
  'The package does not establish contract enforceability, comprehension, voluntariness, workmanship, physical truth, or legal compliance.',
  'The package does not establish custodian licensing, solvency, or that no payment path existed outside the integrated release boundary.',
  'A content digest does not upgrade an invalid component; each component must verify under relying-party-pinned trust roots.',
  'An indeterminate provider effect is not proof of failure and must not be retried before authoritative reconciliation.',
]);
const DEFAULT_MAX_DOCUMENT_BYTES = 50 * 1024 * 1024;
const DEFAULT_MAX_PROJECT_RECORD_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_PACKAGE_BYTES = 4 * 1024 * 1024;

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {*} value
 * @param {Set<string>} allowed
 * @param {Set<string>} [required]
 */
function exactKeys(value, allowed, required = allowed) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

/**
 * @param {number|string|Date|(() => (number|string|Date))} value
 */
function toIso(value) {
  const candidate = typeof value === 'function' ? value() : value;
  const date = candidate instanceof Date ? candidate : new Date(candidate ?? 0);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError('action-escrow evidence: assembled_at must be a valid instant');
  }
  return date.toISOString();
}

/**
 * @param {*} value
 */
function portableJsonCopy(value) {
  let nodes = 0;
  let stringBytes = 0;
  const active = new Set();

  /**
   * @param {*} current
   * @param {number} depth
   * @returns {*}
   */
  function copy(current, depth) {
    nodes += 1;
    if (nodes > 50_000 || depth > 64) {
      throw new TypeError('action-escrow evidence: value exceeds resource limits');
    }
    if (current === null || typeof current === 'boolean') return current;
    if (typeof current === 'string') {
      stringBytes += Buffer.byteLength(current, 'utf8');
      if (stringBytes > 4 * 1024 * 1024) {
        throw new TypeError('action-escrow evidence: strings exceed resource limits');
      }
      return current;
    }
    if (typeof current === 'number') {
      if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
        throw new TypeError('action-escrow evidence: numbers must be safe integers');
      }
      return current;
    }
    if (!isRecord(current) && !Array.isArray(current)) {
      throw new TypeError('action-escrow evidence: value is not canonical JSON');
    }
    if (active.has(current)) {
      throw new TypeError('action-escrow evidence: cyclic or aliased value');
    }
    active.add(current);
    try {
      if (Array.isArray(current)) return current.map((entry) => copy(entry, depth + 1));
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError('action-escrow evidence: objects must use a plain prototype');
      }
      return Object.fromEntries(
        Object.entries(current).map(([key, entry]) => [key, copy(entry, depth + 1)]),
      );
    } finally {
      active.delete(current);
    }
  }

  return copy(value, 0);
}

/**
 * @param {*} value
 */
function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

/**
 * @param {*} value
 * @param {number} maxBytes
 */
function documentBytes(value, maxBytes) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    throw new TypeError('action-escrow evidence: documentBytes must be bytes');
  }
  const bytes = Buffer.from(value);
  if (bytes.length === 0 || bytes.length > maxBytes) {
    throw new TypeError(`action-escrow evidence: documentBytes must be between 1 and ${maxBytes} bytes`);
  }
  return bytes;
}

/**
 * @param {*} value
 * @param {number} maxBytes
 */
function projectRecordBytes(value, maxBytes) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    throw new TypeError('action-escrow evidence: projectRecordBytes must be bytes');
  }
  const bytes = Buffer.from(value);
  if (bytes.length === 0 || bytes.length > maxBytes) {
    throw new TypeError(
      `action-escrow evidence: projectRecordBytes must be between 1 and ${maxBytes} bytes`,
    );
  }
  return bytes;
}

/**
 * @param {*} value
 * @param {string} fieldName
 */
function validFileName(value, fieldName) {
  if (value === null) return true;
  if (typeof value !== 'string'
    || value.length === 0
    || value.length > 255
    || /[/\\\u0000]/.test(value)) {
    throw new TypeError(`action-escrow evidence: ${fieldName} is invalid`);
  }
  return true;
}

/**
 * @param {Buffer} bytes
 */
function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * @param {*} value
 */
function validInstant(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

/**
 * @param {*} value
 */
function canonicalSha256(value) {
  return `sha256:${hashCanonical(value)}`;
}

/**
 * @param {*} pkg
 */
function digestScope(pkg) {
  const { package_digest: _digest, ...scope } = pkg;
  return scope;
}

/**
 * Strict raw parser for security-bearing package transport.
 * @param {*} raw
 * @param {{ maxBytes?: number }} [options]
 */
export function parseActionEscrowEvidencePackage(raw, {
  maxBytes = DEFAULT_MAX_PACKAGE_BYTES,
} = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    return { ok: false, reason: 'invalid_package_limit', value: null };
  }
  if (typeof raw !== 'string') {
    return { ok: false, reason: 'package_must_be_json_text', value: null };
  }
  if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
    return { ok: false, reason: 'package_exceeds_size_limit', value: null };
  }
  const gated = strictJsonGate(raw);
  if (!gated.ok) return { ok: false, reason: gated.reason, value: null };
  try {
    return { ok: true, reason: 'parsed', value: JSON.parse(raw) };
  } catch {
    return { ok: false, reason: 'invalid_json_syntax', value: null };
  }
}

/**
 * @param {*} value
 */
function normalizedRequiredParties(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const result = [];
  for (const entry of value) {
    if (typeof entry === 'string' && entry.length > 0) {
      result.push({ party_id: entry, role: null });
      continue;
    }
    if (!isRecord(entry)
      || typeof entry.party_id !== 'string' || entry.party_id.length === 0
      || typeof entry.role !== 'string' || entry.role.length === 0) {
      return null;
    }
    result.push({ party_id: entry.party_id, role: entry.role });
  }
  const identities = result.map((entry) => `${entry.role ?? ''}\u0000${entry.party_id}`);
  return new Set(identities).size === identities.length ? result : null;
}

/**
 * @param {string} stage
 */
function stageRequiresExecutedAgreement(stage) {
  return [
    'effective',
    'awaiting_funding',
    'funded',
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageRequiresReleaseApprovals(stage) {
  return ['release_reserved', 'released', 'completed', 'release_indeterminate'].includes(stage);
}

/**
 * @param {string} stage
 */
function stageRequiresFunding(stage) {
  return [
    'funded',
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageAllowsFunding(stage) {
  return [
    'funded',
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageRequiresMilestone(stage) {
  return [
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageAllowsMilestone(stage) {
  return [
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageAllowsReleaseApprovals(stage) {
  return [
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @param {string} stage
 */
function stageRequiresRelease(stage) {
  return ['release_reserved', 'released', 'completed', 'release_indeterminate'].includes(stage);
}

/**
 * @param {string} stage
 */
function stageAllowsRelease(stage) {
  return [
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'amendment_pending',
    'completed',
    'release_indeterminate',
  ].includes(stage);
}

/**
 * @typedef {Object} EvidencePackageInput
 * @property {string} [agreementId]
 * @property {string} [stage]
 * @property {*} [binding]
 * @property {*} [documentBytes]
 * @property {string|null} [documentFileName]
 * @property {*} [documentExecution]
 * @property {Array<*>} [agreementAcceptances]
 * @property {Array<*>} [releaseApprovals]
 * @property {*} [fundingStatement]
 * @property {Array<*>} [milestones]
 * @property {*} [release]
 * @property {*} [stateRecord]
 * @property {Array<*>} [amendments]
 * @property {*} [verificationProfile]
 * @property {*} [projectRecordBytes]
 * @property {string|null} [projectRecordFileName]
 * @property {string|null} [projectRecordProvider]
 * @property {string|null} [projectRecordSnapshotDigest]
 */

/**
 * Build a portable evidence manifest. The final document bytes are hashed but
 * not embedded; transport them beside the JSON manifest.
 *
 * @param {EvidencePackageInput} [input]
 * @param {{ now?: number, maxDocumentBytes?: number, maxProjectRecordBytes?: number }} [limits]
 */
export function buildActionEscrowEvidencePackage({
  agreementId,
  stage,
  binding,
  documentBytes: rawDocumentBytes,
  documentFileName = null,
  documentExecution = null,
  agreementAcceptances = [],
  releaseApprovals = [],
  fundingStatement = null,
  milestones = [],
  release = null,
  stateRecord,
  amendments = [],
  verificationProfile,
  projectRecordBytes: rawProjectRecordBytes = null,
  projectRecordFileName = null,
  projectRecordProvider = null,
  projectRecordSnapshotDigest = null,
} = {}, {
  now = 0,
  maxDocumentBytes = DEFAULT_MAX_DOCUMENT_BYTES,
  maxProjectRecordBytes = DEFAULT_MAX_PROJECT_RECORD_BYTES,
} = {}) {
  if (typeof agreementId !== 'string' || agreementId.length === 0) {
    throw new TypeError('action-escrow evidence: agreementId is required');
  }
  if (!ACTION_ESCROW_EVIDENCE_STAGES.includes(/** @type {string} */ (stage))) {
    throw new TypeError('action-escrow evidence: stage is not in the closed set');
  }
  if (!Number.isSafeInteger(maxDocumentBytes) || maxDocumentBytes <= 0) {
    throw new TypeError('action-escrow evidence: maxDocumentBytes must be a positive safe integer');
  }
  const bytes = documentBytes(rawDocumentBytes, maxDocumentBytes);
  validFileName(documentFileName, 'documentFileName');
  const hasProjectRecord = rawProjectRecordBytes !== null
    || projectRecordProvider !== null
    || projectRecordSnapshotDigest !== null
    || projectRecordFileName !== null;
  let projectBytes = null;
  if (hasProjectRecord) {
    if (!Number.isSafeInteger(maxProjectRecordBytes)
      || maxProjectRecordBytes <= 0) {
      throw new TypeError(
        'action-escrow evidence: maxProjectRecordBytes must be a positive safe integer',
      );
    }
    if (typeof projectRecordProvider !== 'string'
      || projectRecordProvider.length === 0
      || projectRecordProvider.length > 128
      || !HASH.test(/** @type {string} */ (projectRecordSnapshotDigest))) {
      throw new TypeError(
        'action-escrow evidence: project-record provider and snapshot digest are required',
      );
    }
    validFileName(projectRecordFileName, 'projectRecordFileName');
    projectBytes = projectRecordBytes(
      rawProjectRecordBytes,
      maxProjectRecordBytes,
    );
  }

  const body = portableJsonCopy({
    version: hasProjectRecord
      ? ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION
      : ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION,
    agreement_id: agreementId,
    stage,
    binding,
    document: {
      media_type: 'application/pdf',
      digest: sha256(bytes),
      byte_length: bytes.length,
      ...(documentFileName === null ? {} : { file_name: documentFileName }),
    },
    ...(hasProjectRecord
      ? {
        project_record: {
          media_type: 'application/json',
          digest: sha256(projectBytes),
          byte_length: /** @type {Buffer} */ (projectBytes).length,
          ...(projectRecordFileName === null
            ? {}
            : { file_name: projectRecordFileName }),
          provider: projectRecordProvider,
          snapshot_digest: projectRecordSnapshotDigest,
        },
      }
      : {}),
    document_execution: documentExecution,
    agreement_acceptances: agreementAcceptances,
    release_approvals: releaseApprovals,
    funding_statement: fundingStatement,
    milestones,
    release: release ?? {
      reservation: null,
      provider_request: null,
      provider_statement: null,
      execution_record: null,
    },
    state_record: stateRecord,
    amendments,
    verification_profile: verificationProfile,
    assembled_at: toIso(now),
    limitations: [...LIMITATIONS],
  });

  return deepFreeze({
    ...body,
    package_digest: canonicalSha256(body),
  });
}

function resultFailure(reason, checks, details = {}) {
  return {
    valid: false,
    reason,
    checks,
    ...details,
  };
}

async function callVerifier(verifier, value, context) {
  if (typeof verifier !== 'function') return { valid: false, reason: 'verifier_required' };
  try {
    const result = await verifier(value, context);
    return isRecord(result) ? result : { valid: false, reason: 'malformed_verifier_result' };
  } catch {
    return { valid: false, reason: 'verifier_threw' };
  }
}

/**
 * Re-perform every package join using relying-party-owned component verifiers.
 *
 * Component verifiers are configuration, never read from the package. Their
 * returned binding fields are checked again here so a valid artifact for one
 * agreement, document, party, or action cannot be relabeled into another slot.
 *
 * @param {*} pkg
 * @param {Object} [options]
 * @param {*} [options.documentBytes]
 * @param {*} [options.projectRecordBytes]
 * @param {*} [options.verifyBinding]
 * @param {*} [options.verifyProjectRecord]
 * @param {*} [options.verifyProfile]
 * @param {*} [options.verifyDocumentExecution]
 * @param {*} [options.verifyAgreementAcceptance]
 * @param {*} [options.verifyReleaseApproval]
 * @param {*} [options.verifyFunding]
 * @param {*} [options.verifyMilestone]
 * @param {*} [options.verifyRelease]
 * @param {*} [options.verifyAmendment]
 * @param {*} [options.verifyState]
 * @param {string} [options.expectedAgreementId]
 * @param {Date|number|string} [options.now]
 * @param {number} [options.maxDocumentBytes]
 * @param {number} [options.maxProjectRecordBytes]
 */
export async function verifyActionEscrowEvidencePackage(pkg, {
  documentBytes: rawDocumentBytes,
  projectRecordBytes: rawProjectRecordBytes,
  verifyBinding,
  verifyProjectRecord,
  verifyProfile,
  verifyDocumentExecution,
  verifyAgreementAcceptance,
  verifyReleaseApproval,
  verifyFunding,
  verifyMilestone,
  verifyRelease,
  verifyAmendment,
  verifyState,
  expectedAgreementId,
  now,
  maxDocumentBytes = DEFAULT_MAX_DOCUMENT_BYTES,
  maxProjectRecordBytes = DEFAULT_MAX_PROJECT_RECORD_BYTES,
} = {}) {
  const checks = {
    structure: false,
    package_digest: false,
    time: false,
    document: false,
    project_record: false,
    binding: false,
    profile: false,
    document_execution: false,
    agreement_acceptances: false,
    amendments: false,
    state: false,
    release_approvals: false,
    funding: false,
    milestones: false,
    release: false,
  };

  try {
    const contractorPackage = pkg?.version
      === ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION;
    const allowedTop = contractorPackage ? CONTRACTOR_TOP_KEYS : TOP_KEYS;
    const requiredTop = new Set(allowedTop);
    checks.structure = exactKeys(pkg, allowedTop, requiredTop)
      && (
        pkg.version === ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION
        || contractorPackage
      )
      && typeof pkg.agreement_id === 'string' && pkg.agreement_id.length > 0
      && ACTION_ESCROW_EVIDENCE_STAGES.includes(pkg.stage)
      && HASH.test(pkg.package_digest)
      && exactKeys(pkg.document, DOCUMENT_KEYS, new Set(['media_type', 'digest', 'byte_length']))
      && pkg.document.media_type === 'application/pdf'
      && HASH.test(pkg.document.digest)
      && Number.isSafeInteger(pkg.document.byte_length) && pkg.document.byte_length > 0
      && (!contractorPackage
        || (
          exactKeys(
            pkg.project_record,
            PROJECT_RECORD_KEYS,
            new Set([
              'media_type',
              'digest',
              'byte_length',
              'provider',
              'snapshot_digest',
            ]),
          )
          && pkg.project_record.media_type === 'application/json'
          && HASH.test(pkg.project_record.digest)
          && Number.isSafeInteger(pkg.project_record.byte_length)
          && pkg.project_record.byte_length > 0
          && typeof pkg.project_record.provider === 'string'
          && pkg.project_record.provider.length > 0
          && pkg.project_record.provider.length <= 128
          && HASH.test(pkg.project_record.snapshot_digest)
        ))
      && (pkg.document_execution === null || isRecord(pkg.document_execution))
      && Array.isArray(pkg.agreement_acceptances)
      && Array.isArray(pkg.release_approvals)
      && Array.isArray(pkg.milestones)
      && exactKeys(pkg.release, RELEASE_KEYS)
      && exactKeys(pkg.state_record, STATE_RECORD_KEYS)
      && Array.isArray(pkg.amendments)
      && Array.isArray(pkg.limitations)
      && pkg.limitations.length === LIMITATIONS.length
      && pkg.limitations.every((entry, index) => entry === LIMITATIONS[index]);
    if (!checks.structure) return resultFailure('malformed_evidence_package', checks);

    if (expectedAgreementId !== undefined
      && (typeof expectedAgreementId !== 'string' || pkg.agreement_id !== expectedAgreementId)) {
      return resultFailure('agreement_id_mismatch', checks);
    }

    checks.package_digest = canonicalSha256(digestScope(pkg)) === pkg.package_digest;
    if (!checks.package_digest) return resultFailure('package_digest_mismatch', checks);

    const assembledAt = Date.parse(pkg.assembled_at);
    const evaluation = now === undefined
      ? null
      : (now instanceof Date ? now.getTime() : typeof now === 'number' ? now : Date.parse(now));
    checks.time = Number.isFinite(assembledAt)
      && (evaluation === null || (Number.isFinite(evaluation) && assembledAt <= evaluation));
    if (!checks.time) return resultFailure('invalid_or_future_assembled_at', checks);

    if (!Number.isSafeInteger(maxDocumentBytes) || maxDocumentBytes <= 0) {
      return resultFailure('invalid_document_limit', checks);
    }
    const bytes = documentBytes(rawDocumentBytes, maxDocumentBytes);
    checks.document = bytes.length === pkg.document.byte_length && sha256(bytes) === pkg.document.digest;
    if (!checks.document) return resultFailure('document_bytes_mismatch', checks);

    const bindingResult = await callVerifier(verifyBinding, pkg.binding, {
      expectedAgreementId: pkg.agreement_id,
      expectedDocumentDigest: pkg.document.digest,
    });
    const contractorBinding = HASH.test(
      pkg.binding?.release_action?.template?.project_record_snapshot_digest,
    );
    const requiredParties = normalizedRequiredParties(bindingResult.required_parties);
    checks.binding = bindingResult.valid === true
      && bindingResult.agreement_id === pkg.agreement_id
      && bindingResult.document_digest === pkg.document.digest
      && HASH.test(bindingResult.binding_digest)
      && HASH.test(bindingResult.action_digest)
      && (bindingResult.supersedes_digest === null || HASH.test(bindingResult.supersedes_digest))
      && requiredParties !== null;
    if (!checks.binding) {
      return resultFailure('binding_verification_failed', checks, {
        binding_reason: bindingResult.reason ?? null,
      });
    }
    if (contractorBinding !== contractorPackage) {
      return resultFailure('evidence_profile_mismatch', checks);
    }

    if (contractorPackage) {
      if (!HASH.test(bindingResult.project_record_snapshot_digest)
        || bindingResult.project_record_snapshot_digest
          !== pkg.project_record.snapshot_digest
        || !Number.isSafeInteger(maxProjectRecordBytes)
        || maxProjectRecordBytes <= 0) {
        return resultFailure('project_record_binding_failed', checks);
      }
      let sourceBytes;
      try {
        sourceBytes = projectRecordBytes(
          rawProjectRecordBytes,
          maxProjectRecordBytes,
        );
      } catch {
        return resultFailure('project_record_bytes_mismatch', checks);
      }
      if (sourceBytes.length !== pkg.project_record.byte_length
        || sha256(sourceBytes) !== pkg.project_record.digest) {
        return resultFailure('project_record_bytes_mismatch', checks);
      }
      const gated = strictJsonGate(sourceBytes.toString('utf8'));
      let projectRecord = null;
      if (gated.ok) {
        try {
          projectRecord = JSON.parse(sourceBytes.toString('utf8'));
        } catch {
          projectRecord = null;
        }
      }
      if (!isRecord(projectRecord)) {
        return resultFailure('project_record_json_invalid', checks);
      }
      const projectResult = await callVerifier(
        verifyProjectRecord,
        projectRecord,
        {
          agreementId: pkg.agreement_id,
          bindingDigest: bindingResult.binding_digest,
          actionDigest: bindingResult.action_digest,
          provider: pkg.project_record.provider,
          snapshotDigest: pkg.project_record.snapshot_digest,
        },
      );
      checks.project_record = projectResult.valid === true
        && projectResult.authorizes_action === false
        && projectResult.establishes_acceptance === false
        && projectResult.provider === pkg.project_record.provider
        && projectResult.snapshot_digest === pkg.project_record.snapshot_digest;
      if (!checks.project_record) {
        return resultFailure('project_record_verification_failed', checks, {
          project_record_reason: projectResult.reason ?? null,
        });
      }
    } else {
      checks.project_record = true;
    }

    const profileResult = await callVerifier(verifyProfile, pkg.verification_profile, {
      agreementId: pkg.agreement_id,
      bindingDigest: bindingResult.binding_digest,
      actionDigest: bindingResult.action_digest,
    });
    const requiredReleaseParties = normalizedRequiredParties(
      profileResult.required_release_parties,
    );
    checks.profile = profileResult.valid === true
      && profileResult.agreement_id === pkg.agreement_id
      && profileResult.binding_digest === bindingResult.binding_digest
      && profileResult.action_digest === bindingResult.action_digest
      && HASH.test(profileResult.profile_digest)
      && requiredReleaseParties !== null;
    if (!checks.profile) {
      return resultFailure('verification_profile_failed', checks, {
        profile_reason: profileResult.reason ?? null,
      });
    }

    if (pkg.document_execution !== null) {
      const executionResult = await callVerifier(
        verifyDocumentExecution,
        pkg.document_execution,
        {
          agreementId: pkg.agreement_id,
          bindingDigest: bindingResult.binding_digest,
          documentDigest: pkg.document.digest,
        },
      );
      checks.document_execution = executionResult.valid === true
        && executionResult.authorizes_action === false
        && executionResult.agreement_id === pkg.agreement_id
        && executionResult.binding_digest === bindingResult.binding_digest
        && executionResult.document_digest === pkg.document.digest
        && executionResult.state === 'executed';
    } else {
      checks.document_execution = !stageRequiresExecutedAgreement(pkg.stage);
    }
    if (!checks.document_execution) {
      return resultFailure('document_execution_verification_failed', checks);
    }

    const requiredAgreementByIdentity = new Map(
      /** @type {NonNullable<typeof requiredParties>} */ (requiredParties).map((entry) => [`${entry.role ?? ''}\u0000${entry.party_id}`, entry]),
    );
    const seenAgreementParties = new Set();
    const seenAgreementKeys = new Set();
    let agreementAcceptancesValid = true;
    for (const acceptance of pkg.agreement_acceptances) {
      if (!exactKeys(acceptance, PARTY_EVIDENCE_KEYS)
        || typeof acceptance.party_id !== 'string'
        || typeof acceptance.role !== 'string') {
        agreementAcceptancesValid = false;
        break;
      }
      const identity = `${acceptance.role}\u0000${acceptance.party_id}`;
      if (!requiredAgreementByIdentity.has(identity) || seenAgreementParties.has(identity)) {
        agreementAcceptancesValid = false;
        break;
      }
      const result = await callVerifier(
        verifyAgreementAcceptance,
        acceptance.evidence,
        {
          partyId: acceptance.party_id,
          role: acceptance.role,
          agreementId: pkg.agreement_id,
          bindingDigest: bindingResult.binding_digest,
          documentDigest: pkg.document.digest,
        },
      );
      if (result.valid !== true
        || result.accepts_agreement !== true
        || result.authorizes_action !== false
        || result.agreement_id !== pkg.agreement_id
        || result.party_id !== acceptance.party_id
        || result.role !== acceptance.role
        || result.binding_digest !== bindingResult.binding_digest
        || result.document_digest !== pkg.document.digest
        || typeof result.principal_key_id !== 'string'
        || result.principal_key_id.length === 0
        || seenAgreementKeys.has(result.principal_key_id)) {
        agreementAcceptancesValid = false;
        break;
      }
      seenAgreementParties.add(identity);
      seenAgreementKeys.add(result.principal_key_id);
    }
    if (stageRequiresExecutedAgreement(pkg.stage)) {
      agreementAcceptancesValid = agreementAcceptancesValid
        && seenAgreementParties.size === requiredAgreementByIdentity.size;
    }
    checks.agreement_acceptances = agreementAcceptancesValid;
    if (!checks.agreement_acceptances) {
      return resultFailure('agreement_acceptance_verification_failed', checks);
    }

    const amendmentResults = [];
    let amendmentsValid = true;
    let expectedNextBinding = bindingResult.binding_digest;
    for (let index = pkg.amendments.length - 1; index >= 0; index -= 1) {
      const result = await callVerifier(verifyAmendment, pkg.amendments[index], {
        agreementId: pkg.agreement_id,
        expectedNextBindingDigest: expectedNextBinding,
        profileDigest: profileResult.profile_digest,
      });
      amendmentResults.unshift(result);
      if (result.valid !== true
        || !HASH.test(result.amendment_digest)
        || !HASH.test(result.previous_binding_digest)
        || result.next_binding_digest !== expectedNextBinding) {
        amendmentsValid = false;
        break;
      }
      expectedNextBinding = result.previous_binding_digest;
    }
    if (bindingResult.supersedes_digest === null) {
      amendmentsValid = amendmentsValid && pkg.amendments.length === 0;
    } else {
      const finalAmendment = amendmentResults.at(-1);
      amendmentsValid = amendmentsValid
        && pkg.amendments.length > 0
        && finalAmendment?.previous_binding_digest === bindingResult.supersedes_digest
        && finalAmendment?.next_binding_digest === bindingResult.binding_digest;
    }
    checks.amendments = amendmentsValid;
    if (!checks.amendments) {
      return resultFailure('amendment_chain_verification_failed', checks);
    }
    const amendmentDigests = amendmentResults.map((result) => result.amendment_digest);

    const stateResult = await callVerifier(verifyState, pkg.state_record, {
      agreementId: pkg.agreement_id,
      bindingDigest: bindingResult.binding_digest,
      actionDigest: bindingResult.action_digest,
      profileDigest: profileResult.profile_digest,
      amendmentDigests,
      stage: pkg.stage,
    });
    checks.state = stateResult.valid === true
      && stateResult.agreement_id === pkg.agreement_id
      && stateResult.binding_digest === bindingResult.binding_digest
      && stateResult.action_digest === bindingResult.action_digest
      && stateResult.profile_digest === profileResult.profile_digest
      && stateResult.state === pkg.stage
      && Number.isSafeInteger(stateResult.revision) && stateResult.revision >= 0
      && Array.isArray(stateResult.amendment_digests)
      && stateResult.amendment_digests.length === amendmentDigests.length
      && stateResult.amendment_digests.every((digest, index) => digest === amendmentDigests[index]);
    if (!checks.state) {
      return resultFailure('state_record_verification_failed', checks, {
        state_reason: stateResult.reason ?? null,
      });
    }

    if (pkg.funding_statement !== null) {
      if (!stageAllowsFunding(pkg.stage)) {
        return resultFailure('unexpected_funding_statement', checks);
      }
      const fundingResult = await callVerifier(verifyFunding, pkg.funding_statement, {
        agreementId: pkg.agreement_id,
        bindingDigest: bindingResult.binding_digest,
        actionDigest: bindingResult.action_digest,
      });
      checks.funding = fundingResult.valid === true
        && fundingResult.agreement_id === pkg.agreement_id
        && fundingResult.binding_digest === bindingResult.binding_digest
        && fundingResult.action_digest === bindingResult.action_digest
        && fundingResult.state === 'funded';
      if (!checks.funding) {
        return resultFailure('funding_statement_verification_failed', checks, {
          funding_reason: fundingResult.reason ?? null,
        });
      }
    } else {
      checks.funding = !stageRequiresFunding(pkg.stage);
      if (!checks.funding) return resultFailure('funding_statement_missing', checks);
    }

    let milestonesValid = true;
    const milestoneIds = new Set();
    const milestoneEvidenceDigests = [];
    if (pkg.milestones.length > 0 && !stageAllowsMilestone(pkg.stage)) {
      return resultFailure('unexpected_milestone_evidence', checks);
    }
    for (const milestone of pkg.milestones) {
      if (!exactKeys(milestone, MILESTONE_KEYS)
        || typeof milestone.milestone_id !== 'string' || milestone.milestone_id.length === 0
        || milestoneIds.has(milestone.milestone_id)) {
        milestonesValid = false;
        break;
      }
      milestoneIds.add(milestone.milestone_id);
      const result = await callVerifier(verifyMilestone, milestone, {
        agreementId: pkg.agreement_id,
        bindingDigest: bindingResult.binding_digest,
        actionDigest: bindingResult.action_digest,
      });
      if (result.valid !== true
        || result.agreement_id !== pkg.agreement_id
        || result.milestone_id !== milestone.milestone_id
        || result.binding_digest !== bindingResult.binding_digest
        || result.action_digest !== bindingResult.action_digest
        || !HASH.test(result.evidence_digest)) {
        milestonesValid = false;
        break;
      }
      milestoneEvidenceDigests.push(result.evidence_digest);
    }
    if (stageRequiresMilestone(pkg.stage)) milestonesValid = milestonesValid && milestoneIds.size > 0;
    checks.milestones = milestonesValid;
    if (!checks.milestones) return resultFailure('milestone_verification_failed', checks);

    const requiredReleaseByIdentity = new Map(
      /** @type {NonNullable<typeof requiredReleaseParties>} */ (requiredReleaseParties).map(
        (entry) => [`${entry.role ?? ''}\u0000${entry.party_id}`, entry],
      ),
    );
    const seenReleaseParties = new Set();
    const seenReleaseKeys = new Set();
    let releaseApprovalsValid = true;
    if (pkg.release_approvals.length > 0 && !stageAllowsReleaseApprovals(pkg.stage)) {
      return resultFailure('unexpected_release_approval', checks);
    }
    const releaseExecutionAt = pkg.release.execution_record?.at ?? null;
    for (const [approvalIndex, approval] of pkg.release_approvals.entries()) {
      if (!exactKeys(approval, PARTY_EVIDENCE_KEYS)
        || typeof approval.party_id !== 'string'
        || typeof approval.role !== 'string') {
        releaseApprovalsValid = false;
        break;
      }
      const identity = `${approval.role}\u0000${approval.party_id}`;
      if (!requiredReleaseByIdentity.has(identity) || seenReleaseParties.has(identity)) {
        releaseApprovalsValid = false;
        break;
      }
      const result = await callVerifier(
        verifyReleaseApproval,
        approval.evidence,
        {
          partyId: approval.party_id,
          role: approval.role,
          agreementId: pkg.agreement_id,
          bindingDigest: bindingResult.binding_digest,
          actionDigest: bindingResult.action_digest,
          milestoneEvidenceDigests,
          approvalIndex,
          stateRecord: pkg.state_record,
        },
      );
      if (result.valid !== true
        || result.authorizes_action !== true
        || result.outcome !== 'approved'
        || result.agreement_id !== pkg.agreement_id
        || result.party_id !== approval.party_id
        || result.role !== approval.role
        || result.binding_digest !== bindingResult.binding_digest
        || result.action_digest !== bindingResult.action_digest
        || !Array.isArray(result.milestone_evidence_digests)
        || result.milestone_evidence_digests.length !== milestoneEvidenceDigests.length
        || result.milestone_evidence_digests.some(
          (digest, index) => digest !== milestoneEvidenceDigests[index],
        )
        || typeof result.principal_key_id !== 'string'
        || result.principal_key_id.length === 0
        || !validInstant(result.issued_at)
        || !validInstant(result.expires_at)
        || !validInstant(result.admitted_at)
        || Date.parse(result.issued_at) > Date.parse(result.admitted_at)
        || Date.parse(result.expires_at) <= Date.parse(result.admitted_at)
        || (
          releaseExecutionAt !== null
          && (
            !validInstant(releaseExecutionAt)
            || Date.parse(result.issued_at) > Date.parse(releaseExecutionAt)
            || Date.parse(result.expires_at) <= Date.parse(releaseExecutionAt)
          )
        )
        || seenReleaseKeys.has(result.principal_key_id)) {
        releaseApprovalsValid = false;
        break;
      }
      seenReleaseParties.add(identity);
      seenReleaseKeys.add(result.principal_key_id);
    }
    if (stageRequiresReleaseApprovals(pkg.stage)) {
      releaseApprovalsValid = releaseApprovalsValid
        && seenReleaseParties.size === requiredReleaseByIdentity.size;
    }
    checks.release_approvals = releaseApprovalsValid;
    if (!checks.release_approvals) {
      return resultFailure('release_approval_verification_failed', checks);
    }

    const hasReleaseArtifacts = Object.values(pkg.release).some((entry) => entry !== null);
    if (hasReleaseArtifacts) {
      if (!stageAllowsRelease(pkg.stage)) {
        return resultFailure('release_artifacts_not_allowed_for_stage', checks);
      }
      const releaseResult = await callVerifier(verifyRelease, pkg.release, {
        agreementId: pkg.agreement_id,
        bindingDigest: bindingResult.binding_digest,
        actionDigest: bindingResult.action_digest,
        stage: pkg.stage,
      });
      const expectedReleaseState = pkg.stage === 'release_indeterminate'
        ? 'indeterminate'
        : pkg.stage === 'release_reserved'
          ? 'reserved'
          : ['released', 'completed'].includes(pkg.stage)
            ? 'released'
            : 'not_released';
      checks.release = releaseResult.valid === true
        && releaseResult.agreement_id === pkg.agreement_id
        && releaseResult.binding_digest === bindingResult.binding_digest
        && releaseResult.action_digest === bindingResult.action_digest
        && releaseResult.state === expectedReleaseState;
      if (!checks.release) {
        return resultFailure('release_verification_failed', checks, {
          release_reason: releaseResult.reason ?? null,
        });
      }
    } else {
      checks.release = !stageRequiresRelease(pkg.stage);
      if (!checks.release) return resultFailure('release_artifact_missing', checks);
    }

    return {
      valid: true,
      reason: 'verified',
      checks,
      package_digest: pkg.package_digest,
      agreement_id: pkg.agreement_id,
      binding_digest: bindingResult.binding_digest,
      action_digest: bindingResult.action_digest,
      profile_digest: profileResult.profile_digest,
      project_record_snapshot_digest:
        bindingResult.project_record_snapshot_digest ?? null,
      required_parties: requiredParties,
      required_release_parties: requiredReleaseParties,
    };
  } catch {
    return resultFailure('malformed_evidence_package', checks);
  }
}

export default {
  ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION,
  ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION,
  ACTION_ESCROW_EVIDENCE_STAGES,
  parseActionEscrowEvidencePackage,
  buildActionEscrowEvidencePackage,
  verifyActionEscrowEvidencePackage,
};
