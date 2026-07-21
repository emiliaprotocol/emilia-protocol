// SPDX-License-Identifier: Apache-2.0

import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import { RELEASE_LOCK_DIGEST_PATTERN } from './constants.js';
import { bytesDigest, canonicalDigest } from './crypto.js';
import { releaseLockRefusal } from './errors.js';

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function text(value, max = 512) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function configuredAdapter(resolver, request, type) {
  if (typeof resolver !== 'function') {
    throw releaseLockRefusal(
      503,
      `${type}_adapter_unconfigured`,
      `No ${type.replace(/_/g, ' ')} adapter is configured for this Release Lock.`,
    );
  }
  const adapter = resolver(request);
  if (!adapter || typeof adapter !== 'object') {
    throw releaseLockRefusal(
      503,
      `${type}_adapter_unconfigured`,
      `No ${type.replace(/_/g, ' ')} adapter is configured for this Release Lock.`,
    );
  }
  return adapter;
}

function normalizedAcrobatEvidence(result, document) {
  if (result?.kind !== 'evidence_ready'
      || result.provider !== document.provider
      || !(result.document_bytes instanceof Uint8Array)
      || !isRecord(result.evidence)
      || result.evidence.provider !== document.provider
      || result.evidence.agreement_id !== document.reference
      || !isRecord(result.evidence.document)) {
    return null;
  }
  const digest = bytesDigest(result.document_bytes);
  if (result.evidence.document.sha256 !== digest
      || result.evidence.document.byte_length !== result.document_bytes.byteLength
      || !text(result.evidence.document.media_type, 128)
      || !text(result.evidence.observed_at, 64)) {
    return null;
  }
  const participantSets = result.evidence.participant_sets;
  if (!Array.isArray(participantSets) || participantSets.length === 0) return null;
  const participantSetDigest = canonicalDigest(participantSets);
  return {
    provider: document.provider,
    reference: document.reference,
    document_digest: digest,
    media_type: result.evidence.document.media_type,
    byte_length: result.document_bytes.byteLength,
    observed_at: result.evidence.observed_at,
    evidence: {
      '@version': result.evidence['@version'],
      provider: result.evidence.provider,
      retrieval_method: result.evidence.retrieval_method,
      api_origin: result.evidence.api_origin,
      agreement_id: result.evidence.agreement_id,
      agreement_status: result.evidence.agreement_status,
      agreement_version: result.evidence.agreement_version,
      agreement_events_digest: result.evidence.agreement_events_digest,
      participant_sets_digest: participantSetDigest,
      participant_set_count: participantSets.length,
      document: result.evidence.document,
      observed_at: result.evidence.observed_at,
    },
    verified_participants: participantSets,
  };
}

function contactPresent(participantSets, identifier) {
  return participantSets.some((set) => Array.isArray(set?.members)
    && set.members.some((member) => (
      member?.email === identifier
      || member?.phone === identifier
      || member?.identifier === identifier
    )));
}

function subjectPresent(participantSets, subject) {
  return participantSets.some((set) => Array.isArray(set?.members)
    && set.members.some((member) => {
      const partyId = member?.party_id ?? member?.partyId ?? member?.subject_id;
      if (partyId !== subject.party_id) return false;
      return !subject.role || !member.role || member.role === subject.role;
    }));
}

function money(value) {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]*)\.[0-9]{2}$/.test(value);
}

function evidenceDocument(value) {
  if (!isRecord(value)
      || !text(value.provider, 128)
      || !text(value.reference, 512)
      || !RELEASE_LOCK_DIGEST_PATTERN.test(value.digest || '')
      || !RELEASE_LOCK_DIGEST_PATTERN.test(value.evidence_digest || '')) {
    return null;
  }
  return JSON.parse(canonicalize(value));
}

function normalizedEffectContract(effect) {
  const action = effect?.action;
  const custodian = action?.custodian;
  if (!isRecord(effect)
      || !isRecord(action)
      || action.round !== 'DRAW_RELEASE'
      || canonicalDigest(action) !== effect.draw_action_hash
      || !RELEASE_LOCK_DIGEST_PATTERN.test(effect.draw_acceptance_digest || '')
      || !isRecord(custodian)
      || custodian.effect_reference !== effect.effect_reference
      || custodian.provider !== effect.provider
      || custodian.environment !== effect.environment
      || custodian.transaction_id !== effect.transaction_id
      || custodian.milestone_id !== effect.milestone_id
      || custodian.instruction !== 'release_milestone'
      || action.custodian_eligibility !== 'after_complete_draw_release_round'
      || !money(action.amount)
      || !text(action.currency, 3)
      || !Array.isArray(action.payees)
      || action.payees.length === 0
      || !Array.isArray(action.lien_waivers)
      || !Array.isArray(action.draw_documents)
      || !isRecord(action.evidence_hashes)) {
    throw releaseLockRefusal(
      409,
      'effect_binding_mismatch',
      'The reserved effect is not bound to a complete exact DRAW_RELEASE action.',
    );
  }

  const payeeIds = new Set();
  let total = BigInt(0);
  const payees = action.payees.map((payee) => {
    if (!isRecord(payee)
        || !text(payee.party_id, 256)
        || !text(payee.destination_id, 512)
        || !money(payee.amount)) {
      throw releaseLockRefusal(
        409,
        'effect_binding_mismatch',
        'The reserved effect contains a malformed payee schedule.',
      );
    }
    const key = `${payee.party_id}\0${payee.destination_id}`;
    if (payeeIds.has(key)) {
      throw releaseLockRefusal(
        409,
        'effect_binding_mismatch',
        'The reserved effect contains a duplicate payee schedule entry.',
      );
    }
    payeeIds.add(key);
    total += BigInt(payee.amount.replace('.', ''));
    return {
      party_id: payee.party_id,
      destination_id: payee.destination_id,
      amount: payee.amount,
    };
  }).sort((left, right) => (
    left.party_id.localeCompare(right.party_id)
      || left.destination_id.localeCompare(right.destination_id)
      || left.amount.localeCompare(right.amount)
  ));
  if (total !== BigInt(action.amount.replace('.', ''))) {
    throw releaseLockRefusal(
      409,
      'effect_binding_mismatch',
      'The reserved effect amount does not equal its exact payee schedule.',
    );
  }

  const completion = evidenceDocument(action.completion_evidence);
  const drawDocuments = action.draw_documents.map(evidenceDocument);
  const lienWaivers = action.lien_waivers.map((waiver) => {
    const document = evidenceDocument(waiver?.document);
    if (!text(waiver?.payee_party_id, 256) || !document) return null;
    return {
      payee_party_id: waiver.payee_party_id,
      document,
    };
  });
  const coveredPayees = new Set(lienWaivers.map((waiver) => waiver?.payee_party_id));
  const expectedPayees = new Set(payees.map((payee) => payee.party_id));
  const evidenceReferences = [
    completion,
    ...drawDocuments,
    ...lienWaivers.map((waiver) => waiver?.document),
  ];
  const referenceKeys = evidenceReferences.map(
    (document) => document && `${document.provider}\0${document.reference}`,
  );
  const hashBindings = action.evidence_hashes;
  const hashExact = completion
    && drawDocuments.every(Boolean)
    && lienWaivers.every(Boolean)
    && hashBindings.completion_evidence_hash === completion.digest
    && Array.isArray(hashBindings.draw_document_hashes)
    && hashBindings.draw_document_hashes.length === drawDocuments.length
    && hashBindings.draw_document_hashes.every(
      (digest, index) => digest === drawDocuments[index].digest,
    )
    && Array.isArray(hashBindings.lien_waiver_hashes)
    && hashBindings.lien_waiver_hashes.length === lienWaivers.length
    && hashBindings.lien_waiver_hashes.every((binding, index) => (
      binding?.payee_party_id === lienWaivers[index].payee_party_id
      && binding?.document_hash === lienWaivers[index].document.digest
    ));
  if (!hashExact
      || coveredPayees.size !== expectedPayees.size
      || [...expectedPayees].some((partyId) => !coveredPayees.has(partyId))
      || referenceKeys.some((key) => key === null)
      || new Set(referenceKeys).size !== referenceKeys.length) {
    throw releaseLockRefusal(
      409,
      'effect_binding_mismatch',
      'The reserved effect does not carry complete, disjoint, payee-bound evidence.',
    );
  }

  const contract = {
    '@version': 'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1',
    effect_reference: effect.effect_reference,
    transaction_id: effect.transaction_id,
    milestone_id: effect.milestone_id,
    draw_action_hash: effect.draw_action_hash,
    draw_acceptance_digest: effect.draw_acceptance_digest,
    amount: action.amount,
    currency: action.currency,
    payees,
    evidence: {
      completion,
      lien_waivers: lienWaivers,
      draw_documents: drawDocuments,
    },
  };
  return Object.freeze({
    contract,
    digest: canonicalDigest(contract),
  });
}

function exactProviderSchedule(transaction, milestoneId, contract) {
  if (!isRecord(transaction)
      || transaction.currency !== contract.currency
      || !Array.isArray(transaction.milestones)) {
    return false;
  }
  const milestone = transaction.milestones.find(
    (entry) => entry?.provider_item_id === milestoneId,
  );
  if (!milestone || !Array.isArray(milestone.schedules)) return false;
  const expected = contract.payees.map(
    (payee) => `${payee.destination_id}\0${payee.amount}`,
  ).sort();
  const observed = milestone.schedules.map((schedule) => {
    if (!text(schedule?.beneficiary_customer, 512) || !money(schedule?.amount)) {
      return null;
    }
    return `${schedule.beneficiary_customer}\0${schedule.amount}`;
  }).sort();
  return !observed.includes(null)
    && observed.length === expected.length
    && observed.every((entry, index) => entry === expected[index]);
}

export function createReleaseLockAdapterBoundary({
  resolveDocumentAdapter = null,
  resolveCustodianAdapter = null,
  resolveInvitationAdapter = null,
} = {}) {
  async function deliverInvitation(invitation) {
    const adapter = configuredAdapter(
      resolveInvitationAdapter,
      {
        channel: invitation.channel,
        role: invitation.role,
      },
      'invitation_delivery',
    );
    if (adapter.kind !== 'verified_contact_delivery'
        || adapter.channel !== invitation.channel
        || typeof adapter.deliver !== 'function') {
      throw releaseLockRefusal(
        503,
        'invitation_delivery_adapter_invalid',
        'The configured invitation delivery adapter does not satisfy the Release Lock contract.',
      );
    }

    let result;
    try {
      result = await adapter.deliver({
        lockId: invitation.lock_id,
        role: invitation.role,
        channel: invitation.channel,
        identifier: invitation.identifier,
        token: invitation.token,
        expiresAt: invitation.expires_at,
      });
    } catch (cause) {
      throw releaseLockRefusal(
        503,
        'invitation_delivery_unavailable',
        'A Release Lock invitation could not be delivered to its verified contact.',
        { cause },
      );
    }
    if (!isRecord(result)
        || result.kind !== 'delivered'
        || result.channel !== invitation.channel
        || result.role !== invitation.role
        || result.lock_id !== invitation.lock_id
        || !text(result.provider, 128)
        || !text(result.reference, 512)
        || !isCanonicalizable(result)) {
      throw releaseLockRefusal(
        503,
        'invitation_delivery_unavailable',
        'The invitation delivery provider returned an ambiguous or unbound result.',
      );
    }
    return Object.freeze({
      role: result.role,
      channel: result.channel,
      provider: result.provider,
      reference: result.reference,
      delivered: true,
    });
  }

  async function fetchDocument(document, context) {
    const adapter = configuredAdapter(
      resolveDocumentAdapter,
      {
        provider: document.provider,
        reference: document.reference,
      },
      'document_provider',
    );
    if (adapter.kind !== 'external_esign_adapter'
        || adapter.provider !== document.provider
        || typeof adapter.fetchFinalEvidence !== 'function') {
      throw releaseLockRefusal(
        503,
        'document_provider_adapter_invalid',
        'The configured document provider adapter does not satisfy the Release Lock contract.',
      );
    }

    let result;
    try {
      result = await adapter.fetchFinalEvidence({
        notification: {
          agreement: { id: document.reference },
        },
        expected: {
          agreementId: document.reference,
          status: document.verification.status,
          participantSets: document.verification.participant_sets,
        },
      });
    } catch (cause) {
      throw releaseLockRefusal(
        503,
        'document_provider_unavailable',
        'The authoritative document could not be fetched from the configured provider.',
        { cause },
      );
    }
    const normalized = normalizedAcrobatEvidence(result, document);
    if (!normalized) {
      const deterministic = ['refused', 'mismatch', 'not_final'].includes(result?.kind);
      throw releaseLockRefusal(
        deterministic ? 422 : 503,
        deterministic ? 'document_verification_refused' : 'document_provider_unavailable',
        deterministic
          ? 'The authoritative provider document did not match the requested final document.'
          : 'The authoritative document provider result was unavailable or ambiguous.',
      );
    }
    const contacts = Object.values<{ identifier: string }>(context?.contacts || {});
    if (context?.requireBoundParticipants === true
        && (contacts.length !== 2
          || contacts.some((contact) => !contactPresent(
          normalized.verified_participants,
          contact.identifier,
          )))) {
      throw releaseLockRefusal(
        422,
        'document_participant_mismatch',
        'The authoritative document participants do not match both verified Release Lock contacts.',
      );
    }
    const requiredSubjects = context?.requiredSubjects;
    if (requiredSubjects !== undefined
        && (!Array.isArray(requiredSubjects)
          || requiredSubjects.length === 0
          || requiredSubjects.some((subject) => (
            !isRecord(subject)
            || !text(subject.party_id, 256)
            || !subjectPresent(normalized.verified_participants, subject)
          )))) {
      throw releaseLockRefusal(
        422,
        'document_participant_mismatch',
        'The authoritative document does not identify every required Release Lock party.',
      );
    }
    const { verified_participants: _participants, ...safe } = normalized;
    return safe;
  }

  function custodianFor(effect, claimEffectBinding) {
    const adapter = configuredAdapter(
      resolveCustodianAdapter,
      {
        provider: effect.provider,
        environment: effect.environment,
        claimEffectBinding,
      },
      'custodian',
    );
    if (adapter.kind !== 'external_custodian'
        || adapter.provider !== effect.provider
        || adapter.environment !== effect.environment
        || typeof adapter.releaseMilestone !== 'function'
        || typeof adapter.reconcileTransaction !== 'function') {
      throw releaseLockRefusal(
        503,
        'custodian_adapter_invalid',
        'The configured custodian adapter does not satisfy the Action Escrow contract.',
      );
    }
    return adapter;
  }

  async function executeEffect(effect, claimEffectBinding) {
    const exact = normalizedEffectContract(effect);
    let effectClaimed = false;
    const adapter = custodianFor(effect, async (binding) => (
      effectClaimed
      && isRecord(binding)
      && binding.effect_reference === effect.effect_reference
      && binding.transaction_id === effect.transaction_id
      && binding.milestone_id === effect.milestone_id
    ));
    let preflight;
    try {
      preflight = await adapter.reconcileTransaction({
        transactionId: effect.transaction_id,
      });
    } catch (cause) {
      throw releaseLockRefusal(
        503,
        'custodian_preflight_unavailable',
        'The custodian could not prove the exact draw before release.',
        { cause },
      );
    }
    if (!isRecord(preflight)
        || preflight.kind !== 'reconciled'
        || preflight.provider !== effect.provider
        || preflight.environment !== effect.environment
        || preflight.transaction_id !== effect.transaction_id
        || !exactProviderSchedule(
          preflight.transaction,
          effect.milestone_id,
          exact.contract,
        )
        || !isCanonicalizable(preflight)) {
      throw releaseLockRefusal(
        409,
        'effect_binding_mismatch',
        'The custodian transaction does not match the exact signed draw.',
      );
    }
    const claimed = await claimEffectBinding({
      effect_reference: effect.effect_reference,
      transaction_id: effect.transaction_id,
      milestone_id: effect.milestone_id,
      effect_contract: exact.contract,
      effect_contract_digest: exact.digest,
    });
    if (claimed !== true) {
      throw releaseLockRefusal(
        409,
        'effect_claim_refused',
        'The exact custodian effect could not be durably claimed before execution.',
      );
    }
    effectClaimed = true;
    let result;
    try {
      result = await adapter.releaseMilestone({
        effectReference: effect.effect_reference,
        transactionId: effect.transaction_id,
        milestoneId: effect.milestone_id,
        amount: exact.contract.amount,
        currency: exact.contract.currency,
        payees: exact.contract.payees,
        evidence: exact.contract.evidence,
        effectContractDigest: exact.digest,
      });
    } catch (cause) {
      return {
        status: 'unknown_effect',
        retryable: false,
        result: {
          '@version': 'EP-RELEASE-LOCK-CUSTODIAN-RESULT-v1',
          provider: effect.provider,
          environment: effect.environment,
          operation: 'release_milestone',
          kind: 'provider_error',
          reason_code: 'PROVIDER_OUTCOME_UNKNOWN',
          effect_reference: effect.effect_reference,
          transaction_id: effect.transaction_id,
          milestone_id: effect.milestone_id,
          provider_phase: null,
          effect_contract_digest: exact.digest,
          preflight_result_digest: canonicalDigest(preflight),
        },
      };
    }
    if (!isRecord(result)
        || result.provider !== effect.provider
        || result.environment !== effect.environment
        || result.effect_reference !== effect.effect_reference
        || result.transaction_id !== effect.transaction_id
        || result.milestone_id !== effect.milestone_id
        || !isCanonicalizable(result)) {
      throw releaseLockRefusal(
        503,
        'custodian_provider_unavailable',
        'The custodian effect result is unavailable or not bound to the exact draw.',
      );
    }
    const status = result.kind === 'released'
      ? 'applied'
      : ['provider_action_required', 'refused'].includes(result.kind)
        ? 'no_effect'
        : 'unknown_effect';
    return {
      status,
      retryable: result.kind === 'provider_action_required',
      result: {
        '@version': 'EP-RELEASE-LOCK-CUSTODIAN-RESULT-v1',
        provider: result.provider,
        environment: result.environment,
        operation: result.operation,
        kind: result.kind,
        reason_code: result.reason_code ?? null,
        effect_reference: result.effect_reference,
        transaction_id: result.transaction_id,
        milestone_id: result.milestone_id,
        provider_phase: result.provider_phase ?? null,
        effect_contract_digest: exact.digest,
        preflight_result_digest: canonicalDigest(preflight),
        provider_result_digest: canonicalDigest(result),
      },
    };
  }

  async function reconcileEffect(effect) {
    const exact = normalizedEffectContract(effect);
    const adapter = custodianFor(effect, async () => false);
    let result;
    try {
      result = await adapter.reconcileTransaction({
        transactionId: effect.transaction_id,
      });
    } catch (cause) {
      throw releaseLockRefusal(
        503,
        'custodian_reconciliation_unavailable',
        'Authoritative custodian reconciliation is unavailable.',
        { cause },
      );
    }
    if (!isRecord(result)
        || result.kind !== 'reconciled'
        || result.provider !== effect.provider
        || result.environment !== effect.environment
        || result.transaction_id !== effect.transaction_id
        || !isRecord(result.transaction)
        || !isCanonicalizable(result)) {
      throw releaseLockRefusal(
        503,
        'custodian_reconciliation_unavailable',
        'Authoritative custodian reconciliation is unavailable or malformed.',
      );
    }
    const transaction = result.transaction;
    if (!exactProviderSchedule(transaction, effect.milestone_id, exact.contract)) {
      throw releaseLockRefusal(
        409,
        'effect_binding_mismatch',
        'Custodian reconciliation does not match the exact reserved draw action.',
      );
    }
    const milestone = Array.isArray(transaction.milestones)
      ? transaction.milestones.find((entry) => entry?.provider_item_id === effect.milestone_id)
      : null;
    const schedules = Array.isArray(milestone?.schedules) ? milestone.schedules : [];
    const disbursed = schedules.every(
      (schedule) => schedule.status?.disbursed_to_beneficiary === true,
    );
    const accepted = milestone.status?.accepted === true;
    const status = disbursed ? 'applied' : accepted ? 'unknown_effect' : 'no_effect';
    return {
      status,
      retryable: !accepted,
      result: {
        '@version': 'EP-RELEASE-LOCK-CUSTODIAN-RECONCILIATION-v1',
        provider: result.provider,
        environment: result.environment,
        operation: result.operation,
        effect_reference: effect.effect_reference,
        transaction_id: effect.transaction_id,
        milestone_id: effect.milestone_id,
        provider_phase: disbursed
          ? 'disbursed'
          : accepted
            ? 'accepted_pending_disbursement'
            : 'not_accepted',
        effect_contract_digest: exact.digest,
        provider_result_digest: canonicalDigest(result),
      },
    };
  }

  return Object.freeze({
    deliverInvitation,
    fetchDocument,
    executeEffect,
    reconcileEffect,
  });
}
