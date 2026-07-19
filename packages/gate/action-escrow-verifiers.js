// SPDX-License-Identifier: Apache-2.0
/**
 * Adapters that turn independently verified protocol artifacts into the exact
 * result contract consumed by the Action Escrow state kernel.
 */
import {
  verifyDocumentActionBinding,
} from '@emilia-protocol/verify/document-action-binding';
import { canonicalize, hashCanonical } from './execution-binding.js';

export const ACTION_ESCROW_AGREEMENT_DIGEST_VERSION =
  'EP-ACTION-ESCROW-AGREEMENT-DIGEST-v1';
export const ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION =
  'EP-ACTION-ESCROW-CONTRACTOR-TEMPLATE-v1';

const HASH = /^sha256:[0-9a-f]{64}$/;
const AMOUNT = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const CURRENCY = /^[A-Z]{3}$/;
export const ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS = Object.freeze([
  'amendment_version',
  'completion_requirements_digest',
  'document_authorizes_payment',
  'milestone_name',
  'payee_id',
  'release.amount',
  'release.destination_id',
  'release.milestone_id',
  'release_requires_mutual_approval',
  'retainage_amount',
]);
export const ACTION_ESCROW_CONTRACTOR_REQUIRED_MATERIAL_TERM_IDS = Object.freeze([
  ...ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS,
  'project_record_snapshot_digest',
]);
const LEGACY_RELEASE_TEMPLATE_KEYS = new Set([
  'action_type',
  'action_escrow_profile_digest',
  'agreement_id',
  'agreement_digest',
  'milestone_id',
  'amount',
  'currency',
  'destination_id',
  'payee_id',
  'custodian_provider',
  'custodian_environment',
  'custodian_transaction_id',
  'custodian_milestone_id',
  'document_sha256',
  'material_terms_sha256',
  'completion_evidence_sha256',
  'amendment_version',
]);
const UNMARKED_PROJECT_RELEASE_TEMPLATE_KEYS = new Set([
  ...LEGACY_RELEASE_TEMPLATE_KEYS,
  'project_record_snapshot_digest',
]);
const CONTRACTOR_RELEASE_TEMPLATE_KEYS = new Set([
  ...LEGACY_RELEASE_TEMPLATE_KEYS,
  'action_escrow_template_profile',
  'project_record_snapshot_digest',
]);

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalCopy(value) {
  return JSON.parse(canonicalize(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function validString(value, max = 256) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function sortedParties(parties) {
  if (!Array.isArray(parties)) return null;
  try {
    return canonicalCopy(parties).sort((left, right) => {
      const leftKey = `${left.role}\u0000${left.party_id}`;
      const rightKey = `${right.role}\u0000${right.party_id}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
  } catch {
    return null;
  }
}

function bytesCopy(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Uint8Array.from(value);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  return null;
}

function refusal(reason) {
  return Object.freeze({
    valid: false,
    reason,
  });
}

export function computeActionEscrowAgreementDigest(agreementId) {
  if (!validString(agreementId)) return null;
  try {
    return `sha256:${hashCanonical({
      '@version': ACTION_ESCROW_AGREEMENT_DIGEST_VERSION,
      agreement_id: agreementId,
    })}`;
  } catch {
    return null;
  }
}

function exactExpected(value) {
  if (!isRecord(value)
    || !HASH.test(value.agreement_digest)
    || !HASH.test(value.document_action_binding_digest)
    || !HASH.test(value.release_action_digest)
    || !HASH.test(value.parties_digest)
    || !HASH.test(value.profile_digest)
    || !validString(value.milestone_id)
    || !Array.isArray(value.parties)) {
    return null;
  }
  const parties = sortedParties(value.parties);
  if (!parties || parties.length < 2) return null;
  return {
    agreement_digest: value.agreement_digest,
    document_action_binding_digest: value.document_action_binding_digest,
    release_action_digest: value.release_action_digest,
    milestone_id: value.milestone_id,
    parties,
    parties_digest: value.parties_digest,
    profile_digest: value.profile_digest,
    supersedes_document_action_binding_digest:
      value.supersedes_document_action_binding_digest ?? null,
  };
}

/**
 * @param {any} template
 * @param {{ profileDigest?: any, agreementId?: any, agreementDigest?: any, milestoneId?: any, documentDigest?: any, materialTerms?: any, contractorProjectSource?: boolean }} [options]
 */
export function validateActionEscrowReleaseTemplate(template, {
  profileDigest,
  agreementId,
  agreementDigest,
  milestoneId,
  documentDigest,
  materialTerms,
  contractorProjectSource = false,
} = {}) {
  const templateKeys = isRecord(template) ? Object.keys(template) : [];
  const allowedKeys = contractorProjectSource
    ? CONTRACTOR_RELEASE_TEMPLATE_KEYS
    : UNMARKED_PROJECT_RELEASE_TEMPLATE_KEYS;
  const requiredKeys = contractorProjectSource
    ? CONTRACTOR_RELEASE_TEMPLATE_KEYS
    : LEGACY_RELEASE_TEMPLATE_KEYS;
  if (!isRecord(template)
    || templateKeys.some((key) => !allowedKeys.has(key))
    || [...requiredKeys].some((key) => !Object.hasOwn(template, key))
    || (contractorProjectSource
      && template.action_escrow_template_profile
        !== ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION)
    || template.action_type !== 'escrow.milestone.release'
    || template.action_escrow_profile_digest !== profileDigest
    || template.agreement_id !== agreementId
    || template.agreement_digest !== agreementDigest
    || template.milestone_id !== milestoneId
    || typeof template.amount !== 'string'
    || !AMOUNT.test(template.amount)
    || typeof template.currency !== 'string'
    || !CURRENCY.test(template.currency)
    || !validString(template.destination_id, 512)
    || !validString(template.payee_id, 512)
    || !validString(template.custodian_provider, 128)
    || !['sandbox', 'production'].includes(template.custodian_environment)
    || !validString(template.custodian_transaction_id, 256)
    || !validString(template.custodian_milestone_id, 256)
    || template.document_sha256 !== documentDigest
    || !HASH.test(template.material_terms_sha256)
    || (materialTerms !== undefined
      && template.material_terms_sha256 !== `sha256:${hashCanonical(materialTerms)}`)
    || (contractorProjectSource
      && !HASH.test(template.project_record_snapshot_digest))
    || (Object.hasOwn(template, 'project_record_snapshot_digest')
      && !HASH.test(template.project_record_snapshot_digest))
    || !HASH.test(template.completion_evidence_sha256)
    || !Number.isSafeInteger(template.amendment_version)
    || template.amendment_version < 1) {
    return null;
  }
  try {
    const copy = canonicalCopy(template);
    return Buffer.byteLength(canonicalize(copy), 'utf8') <= 64 * 1024 ? copy : null;
  } catch {
    return null;
  }
}

function exactActionTemplate(binding, expected, contractorProjectSource) {
  return validateActionEscrowReleaseTemplate(binding?.release_action?.template, {
    profileDigest: expected.profile_digest,
    agreementId: binding?.agreement_id,
    agreementDigest: expected.agreement_digest,
    milestoneId: expected.milestone_id,
    documentDigest: binding?.document?.digest,
    materialTerms: binding?.material_terms,
    contractorProjectSource,
  });
}

function materialTermsMatchAction(binding, template) {
  if (!Array.isArray(binding?.material_terms)) return false;
  const terms = new Map(binding.material_terms.map((term) => [term.term_id, term]));
  const amount = terms.get('release.amount');
  const destination = terms.get('release.destination_id');
  const milestone = terms.get('release.milestone_id');
  const amendment = terms.get('amendment_version');
  const completionRequirements = terms.get('completion_requirements_digest');
  const documentAuthorizesPayment = terms.get('document_authorizes_payment');
  const milestoneName = terms.get('milestone_name');
  const payee = terms.get('payee_id');
  const releaseRequiresMutualApproval = terms.get('release_requires_mutual_approval');
  const retainage = terms.get('retainage_amount');
  const projectRecord = terms.get('project_record_snapshot_digest');
  const projectRecordBound = Object.hasOwn(
    template,
    'project_record_snapshot_digest',
  );
  return amount?.type === 'amount'
    && amount.value === template.amount
    && amount.currency === template.currency
    && ['identifier', 'string'].includes(destination?.type)
    && destination.value === template.destination_id
    && ['identifier', 'string'].includes(milestone?.type)
    && milestone.value === template.milestone_id
    && amendment?.type === 'integer'
    && amendment.value === template.amendment_version
    && completionRequirements?.type === 'digest'
    && HASH.test(completionRequirements.value)
    && documentAuthorizesPayment?.type === 'boolean'
    && documentAuthorizesPayment.value === false
    && milestoneName?.type === 'string'
    && validString(milestoneName.value, 2048)
    && payee?.type === 'identifier'
    && payee.value === template.payee_id
    && releaseRequiresMutualApproval?.type === 'boolean'
    && releaseRequiresMutualApproval.value === true
    && retainage?.type === 'amount'
    && retainage.currency === template.currency
    && (!projectRecordBound
      || (
        projectRecord?.type === 'digest'
        && projectRecord.value === template.project_record_snapshot_digest
      ));
}

/**
 * Create a kernel verifier backed by the public DAB verifier.
 *
 * The document resolver is mandatory: mapping authenticity without checking
 * the final bytes is insufficient for a release decision.
 *
 * @param {{ issuerKeys?: any, resolveDocumentBytes?: any, allowedMediaTypes?: string[], allowedPartyRoles?: string[], now?: () => number }} deps
 * @param {{ contractorProjectSource?: boolean }} params
 */
function createDocumentBindingVerifier({
  issuerKeys,
  resolveDocumentBytes,
  allowedMediaTypes = ['application/pdf'],
  allowedPartyRoles = ['client', 'contractor'],
  now = Date.now,
} = {}, {
  contractorProjectSource,
}) {
  if (!isRecord(issuerKeys)
    || Object.keys(issuerKeys).length === 0
    || typeof resolveDocumentBytes !== 'function'
    || typeof now !== 'function') {
    throw new TypeError('pinned DAB keys, document resolver, and clock are required');
  }
  const pinnedIssuerKeys = deepFreeze(canonicalCopy(issuerKeys));
  const mediaTypes = deepFreeze(canonicalCopy(allowedMediaTypes));
  const partyRoles = deepFreeze(canonicalCopy(allowedPartyRoles));

  return async function verifyForKernel(binding, untrustedExpected) {
    try {
      const expected = exactExpected(untrustedExpected);
      if (!expected) return refusal('invalid_expected_binding_context');
      const evaluationTime = now();
      const options = {
        issuerKeys: pinnedIssuerKeys,
        now: evaluationTime,
        allowedMediaTypes: mediaTypes,
        allowedPartyRoles: partyRoles,
        allowedActionTypes: ['escrow.milestone.release'],
        requiredMaterialTermIds: /** @type {string[]} */ (contractorProjectSource
          ? ACTION_ESCROW_CONTRACTOR_REQUIRED_MATERIAL_TERM_IDS
          : ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS),
        expectedRequiredParties: expected.parties,
        expectedSupersedesDigest:
          expected.supersedes_document_action_binding_digest,
      };
      const authenticated = verifyDocumentActionBinding(binding, options);
      if (!authenticated.valid) return refusal(authenticated.reason);
      if (authenticated.binding_digest !== expected.document_action_binding_digest
        || authenticated.action_digest !== expected.release_action_digest
        || computeActionEscrowAgreementDigest(authenticated.agreement_id)
          !== expected.agreement_digest) {
        return refusal('kernel_binding_context_mismatch');
      }

      const actionTemplate = exactActionTemplate(
        binding,
        expected,
        contractorProjectSource,
      );
      if (!actionTemplate
        || !materialTermsMatchAction(
          binding,
          actionTemplate,
        )) {
        return refusal('material_action_mapping_mismatch');
      }
      const resolved = await resolveDocumentBytes(deepFreeze({
        agreement_id: authenticated.agreement_id,
        binding_id: authenticated.binding_id,
        binding_digest: authenticated.binding_digest,
        document_digest: authenticated.document_digest,
        document_media_type: binding.document.media_type,
        document_byte_length: binding.document.byte_length,
      }));
      const documentBytes = bytesCopy(resolved);
      if (!documentBytes) return refusal('document_bytes_unavailable');
      const verified = verifyDocumentActionBinding(binding, {
        ...options,
        documentBytes,
        documentMediaType: binding.document.media_type,
        releaseActionTemplate: actionTemplate,
      });
      if (!verified.valid) return refusal(verified.reason);

      return deepFreeze({
        valid: true,
        reason: 'valid',
        verification_digest: verified.binding_digest,
        document_digest: verified.document_digest,
        agreement_id: verified.agreement_id,
        binding_id: verified.binding_id,
        release_action_template: actionTemplate,
        agreement_digest: expected.agreement_digest,
        document_action_binding_digest: verified.binding_digest,
        milestone_id: expected.milestone_id,
        release_action_digest: verified.action_digest,
        parties_digest: expected.parties_digest,
        profile_digest: expected.profile_digest,
        ...(HASH.test(actionTemplate.project_record_snapshot_digest)
          ? {
            project_record_snapshot_digest:
              actionTemplate.project_record_snapshot_digest,
          }
          : {}),
        ...(verified.supersedes_digest === null
          ? {}
          : {
            supersedes_document_action_binding_digest:
              verified.supersedes_digest,
          }),
      });
    } catch {
      return refusal('document_action_binding_verifier_failed');
    }
  };
}

export function createActionEscrowDocumentBindingVerifier(options = {}) {
  return createDocumentBindingVerifier(options, {
    contractorProjectSource: false,
  });
}

export function createActionEscrowContractorDocumentBindingVerifier(options = {}) {
  return createDocumentBindingVerifier(options, {
    contractorProjectSource: true,
  });
}

export default Object.freeze({
  ACTION_ESCROW_AGREEMENT_DIGEST_VERSION,
  ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
  ACTION_ESCROW_CONTRACTOR_REQUIRED_MATERIAL_TERM_IDS,
  ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS,
  computeActionEscrowAgreementDigest,
  createActionEscrowContractorDocumentBindingVerifier,
  createActionEscrowDocumentBindingVerifier,
  validateActionEscrowReleaseTemplate,
});
