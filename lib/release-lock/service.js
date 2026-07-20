// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getRpConfig } from '../webauthn.js';
import {
  RELEASE_LOCK_EVIDENCE_VERSION,
  RELEASE_LOCK_LIMITATIONS,
  RELEASE_LOCK_MAX_LIFETIME_MS,
  RELEASE_LOCK_MIRROR_SESSION_TTL_MS,
  RELEASE_LOCK_PAIRING_TTL_MS,
  RELEASE_LOCK_ROLES,
  RELEASE_LOCK_ROUNDS,
} from './constants.js';
import {
  buildReleaseLockActionCheck,
  verifyReleaseLockActionCheck,
} from './action-check.js';
import {
  buildChangeOrderAction,
  buildDrawReleaseAction,
} from './action.js';
import { canonicalDigest, timingSafeTextEqual } from './crypto.js';
import {
  isReleaseLockError,
  mapReleaseLockRpcError,
  releaseLockRefusal,
} from './errors.js';
import {
  createReleaseLockRegistrationOptions,
  verifyReleaseLockRegistration,
} from './registration.js';
import {
  validateChangeOrderInput,
  validateDrawReleaseInput,
} from './validation.js';

function exactObject(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function requiredText(value, code = 'invalid_request') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
    throw releaseLockRefusal(400, code, 'Release Lock request is malformed.');
  }
  return value;
}

function currentMillis(now) {
  const value = typeof now === 'function' ? now() : now;
  if (!Number.isFinite(value)) throw new Error('Release Lock clock is invalid');
  return value;
}

const PARTICIPANT_EVIDENCE_LIMITATION = 'Participant evidence proves the holder\'s own approvals '
  + 'in full and records the counterparty\'s decision bindings by digest only. Verifying the '
  + 'counterparty\'s signature requires their credential key from the operator evidence export.';

function evidenceEnvelope(stored, now, extraLimitations = []) {
  const authenticityLimitation = 'The outer content digest detects transport corruption only. '
    + 'Authenticity comes only from re-verifying each signed evidence artifact under '
    + 'relying-party-pinned keys.';
  const body = {
    '@version': RELEASE_LOCK_EVIDENCE_VERSION,
    generated_at: new Date(currentMillis(now)).toISOString(),
    limitations: [...RELEASE_LOCK_LIMITATIONS, authenticityLimitation, ...extraLimitations],
    evidence: stored,
  };
  return Object.freeze({
    ...body,
    content_digest: {
      algorithm: 'sha-256',
      purpose: 'transport_corruption_check_only',
      canonical_json_digest: canonicalDigest(body),
    },
  });
}

function rpPolicy(provider) {
  const policy = provider();
  if (!policy?.rpID || !policy?.origin) {
    throw releaseLockRefusal(
      503,
      'webauthn_policy_unconfigured',
      'Release Lock WebAuthn RP policy is not configured.',
    );
  }
  return policy;
}

function assertCredentialPolicy(credential, policy) {
  if (credential?.rp_id !== policy.rpID || credential?.origin !== policy.origin) {
    throw releaseLockRefusal(
      409,
      'webauthn_policy_mismatch',
      'The enrolled credential does not match the active WebAuthn RP policy.',
    );
  }
}

function contactsForProvider(normalized) {
  return Object.fromEntries(RELEASE_LOCK_ROLES.map((role) => [
    role,
    {
      channel: normalized.contacts[role].channel,
      identifier: normalized.contacts[role].identifier,
    },
  ]));
}

/**
 * @param {Object} [options]
 * @param {Function} [options.rpc]
 * @param {Object} [options.cryptoSuite]
 * @param {Object} [options.adapters]
 * @param {number|Function} [options.now]
 * @param {Function} [options.randomUUID]
 * @param {Function} [options.rpConfigProvider]
 * @param {Function} [options.registrationOptions]
 * @param {Function} [options.registrationVerifier]
 * @param {Function} [options.actionCheckBuilder]
 * @param {Function} [options.actionCheckVerifier]
 * @param {Function} [options.authenticationOptions]
 * @returns {Object}
 */
export function createReleaseLockService({
  rpc,
  cryptoSuite,
  adapters,
  now = Date.now,
  randomUUID = crypto.randomUUID,
  rpConfigProvider = getRpConfig,
  registrationOptions = createReleaseLockRegistrationOptions,
  registrationVerifier = verifyReleaseLockRegistration,
  actionCheckBuilder = buildReleaseLockActionCheck,
  actionCheckVerifier = verifyReleaseLockActionCheck,
  authenticationOptions = generateAuthenticationOptions,
} = {}) {
  if (typeof rpc !== 'function') throw new TypeError('Release Lock rpc adapter is required');
  if (!cryptoSuite) throw new TypeError('Release Lock crypto suite is required');
  if (!adapters) throw new TypeError('Release Lock provider adapters are required');
  if (typeof randomUUID !== 'function') throw new TypeError('randomUUID is required');

  async function call(name, args) {
    try {
      const result = await (/** @type {Function} */ (rpc))(name, args);
      if (!result || typeof result !== 'object') {
        throw new Error('Release Lock RPC returned no result');
      }
      if (result.error) throw mapReleaseLockRpcError(result.error, name);
      if (result.data === null || result.data === undefined) {
        throw new Error('Release Lock RPC returned no data');
      }
      return result.data;
    } catch (error) {
      if (isReleaseLockError(error)) throw error;
      throw mapReleaseLockRpcError(error, name);
    }
  }

  async function createLock({ organizationId, contractorEntityId, input }) {
    requiredText(organizationId);
    requiredText(contractorEntityId);
    if (typeof adapters.deliverInvitation !== 'function') {
      throw releaseLockRefusal(
        503,
        'invitation_delivery_adapter_unconfigured',
        'Release Lock invitation delivery is not configured.',
      );
    }
    const nowMs = currentMillis(now);
    const normalized = validateChangeOrderInput(input, /** @type {any} */ ({
      now: nowMs,
      cryptoSuite,
      contractorEntityId,
    }));
    const lockId = `rlk_${crypto.randomBytes(16).toString('hex')}`;
    const createdAt = new Date(nowMs).toISOString();
    const documentEvidence = await adapters.fetchDocument(
      normalized.change_order.document,
      {
        contacts: contactsForProvider(normalized),
        requireBoundParticipants: true,
      },
    );
    const co = buildChangeOrderAction({
      lockId,
      version: 1,
      normalizedInput: normalized,
      documentEvidence,
      createdAt,
    });
    const contacts = RELEASE_LOCK_ROLES.map((role) => ({
      role,
      contact_binding_id: randomUUID(),
      channel: normalized.contacts[role].channel,
      identifier_digest: normalized.contacts[role].identifier_digest,
      verification_provider: normalized.contacts[role].verification_provider,
      verification_reference: normalized.contacts[role].verification_reference,
      verification_proof_digest: normalized.contacts[role].verification_proof_digest,
      verified_at: normalized.contacts[role].verified_at,
      verification_expires_at: normalized.contacts[role].verification_expires_at,
      authority_provider: normalized.contacts[role].authority.provider,
      authority_key_id: normalized.contacts[role].authority.key_id,
      authority_reference: normalized.contacts[role].authority.reference,
      authority_assertion: normalized.contacts[role].authority.assertion,
      authority_signature: normalized.contacts[role].authority.signature,
      authority_assertion_digest: normalized.contacts[role].authority.assertion_digest,
      authority_subject_digest: normalized.contacts[role].authority.subject_digest,
      authority_contact_binding_digest:
        normalized.contacts[role].authority.contact_binding_digest,
      authority_verified_at: normalized.contacts[role].authority.verified_at,
      authority_expires_at: normalized.contacts[role].authority.expires_at,
    }));
    const rawInvitations = RELEASE_LOCK_ROLES.map((role) => ({
      role,
      ...cryptoSuite.invitation(),
    }));
    const invitations = rawInvitations.map((invite) => ({
      invitation_id: randomUUID(),
      role: invite.role,
      contact_binding_id: /** @type {any} */ (
        contacts.find((entry) => entry.role === invite.role)
      ).contact_binding_id,
      token_digest: invite.digest,
      expires_at: normalized.invitation_expires_at,
    }));
    const pending = await call('release_lock_create_pending', {
      p_lock_id: lockId,
      p_organization_id: organizationId,
      p_contractor_entity_id: contractorEntityId,
      p_co_action: co.action,
      p_co_action_hash: co.actionHash,
      p_co_material_hash: co.materialHash,
      p_document_evidence: co.document,
      p_contacts: contacts,
      p_invitations: invitations,
      p_max_expires_at: normalized.lock_expires_at,
      p_created_by: contractorEntityId,
    });
    let deliveries;
    try {
      deliveries = await Promise.all(rawInvitations.map((invite) => (
        adapters.deliverInvitation({
          lock_id: lockId,
          role: invite.role,
          channel: normalized.contacts[invite.role].channel,
          identifier: normalized.contacts[invite.role].identifier,
          token: invite.token,
          expires_at: normalized.invitation_expires_at,
        })
      )));
    } catch (error) {
      try {
        await call('release_lock_cancel_pending', {
          p_lock_id: lockId,
          p_organization_id: organizationId,
          p_reason_code: 'INVITATION_DELIVERY_FAILED',
        });
      } catch {
        // Pending invitations are non-exchangeable even if compensation is unavailable.
      }
      throw error;
    }
    let stored;
    try {
      const activated = await call('release_lock_activate_invitations', {
        p_lock_id: lockId,
        p_organization_id: organizationId,
        p_invitation_ids: invitations.map((invitation) => invitation.invitation_id),
        p_delivery_receipts: deliveries,
      });
      stored = { ...pending, ...activated };
    } catch (error) {
      try {
        await call('release_lock_cancel_pending', {
          p_lock_id: lockId,
          p_organization_id: organizationId,
          p_reason_code: 'INVITATION_ACTIVATION_FAILED',
        });
      } catch {
        // Pending invitations are non-exchangeable even if compensation is unavailable.
      }
      throw error;
    }
    return Object.freeze({
      ...stored,
      action: co.action,
      invitation_deliveries: deliveries,
      limitations: RELEASE_LOCK_LIMITATIONS,
    });
  }

  async function exchangeInvitation(input) {
    const keys = new Set(['token', 'lock_id', 'role']);
    if (!exactObject(input, keys) || !RELEASE_LOCK_ROLES.includes(input.role)) {
      throw releaseLockRefusal(400, 'invalid_request', 'Invitation exchange is malformed.');
    }
    const session = cryptoSuite.session();
    const stored = await call('release_lock_exchange_invitation', {
      p_token_digest: cryptoSuite.invitationDigest(input.token),
      p_session_id: randomUUID(),
      p_session_digest: session.digest,
      p_expected_lock_id: requiredText(input.lock_id),
      p_expected_role: input.role,
      p_session_expires_at: new Date(
        currentMillis(now) + RELEASE_LOCK_MAX_LIFETIME_MS,
      ).toISOString(),
    });
    return Object.freeze({ ...stored, rawSessionToken: session.token });
  }

  async function createPairing({ rawSessionToken, lockId, round }) {
    if (!RELEASE_LOCK_ROUNDS.includes(round)) {
      throw releaseLockRefusal(400, 'invalid_release_lock_round', 'Release Lock round is invalid.');
    }
    const pairing = cryptoSuite.pairing();
    const expiresAt = new Date(
      currentMillis(now) + RELEASE_LOCK_PAIRING_TTL_MS,
    ).toISOString();
    const stored = await call('release_lock_create_pairing', {
      p_session_digest: cryptoSuite.sessionDigest(rawSessionToken),
      p_lock_id: requiredText(lockId),
      p_round: round,
      p_pairing_id: randomUUID(),
      p_token_digest: pairing.digest,
      p_expires_at: expiresAt,
    });
    return Object.freeze({ ...stored, rawPairingToken: pairing.token });
  }

  async function exchangePairing(input) {
    const keys = new Set(['token', 'lock_id', 'role', 'round']);
    if (!exactObject(input, keys)
        || !RELEASE_LOCK_ROLES.includes(input.role)
        || !RELEASE_LOCK_ROUNDS.includes(input.round)) {
      throw releaseLockRefusal(400, 'invalid_request', 'Action Mirror pairing exchange is malformed.');
    }
    const session = cryptoSuite.session();
    const stored = await call('release_lock_exchange_pairing', {
      p_token_digest: cryptoSuite.pairingDigest(input.token),
      p_expected_lock_id: requiredText(input.lock_id),
      p_expected_role: input.role,
      p_expected_round: input.round,
      p_session_id: randomUUID(),
      p_session_digest: session.digest,
      p_session_expires_at: new Date(
        currentMillis(now) + RELEASE_LOCK_MIRROR_SESSION_TTL_MS,
      ).toISOString(),
    });
    return Object.freeze({ ...stored, rawSessionToken: session.token });
  }

  async function resolveSession(rawSessionToken, lockId) {
    return call('release_lock_resolve_session', {
      p_session_digest: cryptoSuite.sessionDigest(rawSessionToken),
      p_lock_id: requiredText(lockId),
    });
  }

  async function participantView({ rawSessionToken, lockId }) {
    return call('release_lock_participant_view', {
      p_session_digest: cryptoSuite.sessionDigest(rawSessionToken),
      p_lock_id: requiredText(lockId),
    });
  }

  async function beginRegistration({ rawSessionToken, lockId }) {
    const session = await resolveSession(rawSessionToken, lockId);
    const policy = rpPolicy(rpConfigProvider);
    const generated = await registrationOptions(/** @type {any} */ ({
      session: {
        ...session,
        expires_at: session.session_expires_at,
      },
      existingCredentials: [],
      now,
      rpConfig: policy,
    }));
    const challengeId = randomUUID();
    await call('release_lock_begin_registration', {
      p_session_digest: cryptoSuite.sessionDigest(rawSessionToken),
      p_lock_id: lockId,
      p_challenge_id: challengeId,
      p_challenge: generated.challenge,
      p_rp_id: generated.rpId,
      p_origin: generated.origin,
      p_expires_at: generated.expiresAt,
    });
    return Object.freeze({
      challenge_id: challengeId,
      options: generated.options,
      expires_at: generated.expiresAt,
      claims: {
        identity_verified: false,
        biometric_verified: false,
        device_bound_claimed: false,
      },
    });
  }

  async function completeRegistration({
    rawSessionToken,
    lockId,
    input,
  }) {
    const keys = new Set(['challenge_id', 'attestation']);
    if (!exactObject(input, keys)) {
      throw releaseLockRefusal(400, 'registration_invalid', 'Registration response is malformed.');
    }
    const sessionDigest = cryptoSuite.sessionDigest(rawSessionToken);
    const challenge = await call('release_lock_load_registration', {
      p_session_digest: sessionDigest,
      p_lock_id: requiredText(lockId),
      p_challenge_id: requiredText(input.challenge_id),
    });
    const credential = await registrationVerifier({
      challenge,
      attestation: input.attestation,
      rpConfig: rpPolicy(rpConfigProvider),
    });
    return call('release_lock_complete_registration', {
      p_session_digest: sessionDigest,
      p_lock_id: lockId,
      p_challenge_id: input.challenge_id,
      p_credential_id: credential.credentialId,
      p_public_key_cose: credential.publicKeyCose,
      p_public_key_spki: credential.publicKeySpki,
      p_sign_count: credential.signCount,
      p_transports: credential.transports,
      p_device_type: credential.deviceType,
      p_backed_up: credential.backedUp,
      p_attestation_format: credential.attestationFormat,
      p_rp_id: credential.rpId,
      p_origin: credential.origin,
    });
  }

  async function stageDraw({
    organizationId,
    contractorEntityId,
    lockId,
    input,
  }) {
    const context = await call('release_lock_draw_context', {
      p_lock_id: requiredText(lockId),
      p_organization_id: requiredText(organizationId),
      p_expected_version: input?.expected_version,
      p_actor_id: requiredText(contractorEntityId),
    });
    const normalized = validateDrawReleaseInput(input, /** @type {any} */ ({
      now,
      maxExpiresAt: context.lock_expires_at,
    }));
    const requiredParties = context.co_action.parties.map((party) => ({
      party_id: party.party_id,
      role: party.role,
    }));
    const completion = await adapters.fetchDocument(
      normalized.draw.completion_evidence,
      {
        requireBoundParticipants: false,
        requiredSubjects: requiredParties,
      },
    );
    const lienWaivers = await Promise.all(normalized.draw.lien_waivers.map(
      async (waiver) => ({
        payee_party_id: waiver.payee_party_id,
        evidence: await adapters.fetchDocument(waiver.document, {
          requireBoundParticipants: false,
          requiredSubjects: [{
            party_id: waiver.payee_party_id,
          }],
        }),
      }),
    ));
    const drawDocuments = await Promise.all(normalized.draw.draw_documents.map(
      (document) => adapters.fetchDocument(document, {
        requireBoundParticipants: false,
        requiredSubjects: requiredParties,
      }),
    ));
    const built = buildDrawReleaseAction({
      lockId,
      version: normalized.expected_version,
      normalizedInput: normalized,
      acceptedChangeOrder: {
        version: context.version,
        action_hash: context.co_action_hash,
        acceptance_digest: context.co_acceptance_digest,
        parties: context.co_action.parties,
      },
      completionEvidence: completion,
      lienWaiverEvidence: lienWaivers,
      drawDocumentEvidence: drawDocuments,
      createdAt: new Date(currentMillis(now)).toISOString(),
    });
    const stored = await call('release_lock_stage_draw', {
      p_lock_id: lockId,
      p_organization_id: organizationId,
      p_expected_version: normalized.expected_version,
      p_actor_id: contractorEntityId,
      p_draw_action: built.action,
      p_draw_action_hash: built.actionHash,
      p_draw_material_hash: built.materialHash,
    });
    return Object.freeze({ ...stored, action: built.action });
  }

  async function amendLock({
    organizationId,
    contractorEntityId,
    lockId,
    expectedVersion,
    input,
  }) {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw releaseLockRefusal(400, 'invalid_request', 'expected_version is invalid.');
    }
    const context = await call('release_lock_amendment_context', {
      p_lock_id: requiredText(lockId),
      p_organization_id: requiredText(organizationId),
      p_expected_version: expectedVersion,
      p_actor_id: requiredText(contractorEntityId),
    });
    const normalized = validateChangeOrderInput(input, /** @type {any} */ ({
      now,
      cryptoSuite,
      contractorEntityId,
      maxExpiresAt: context.lock_expires_at,
      amendment: true,
    }));
    for (const role of RELEASE_LOCK_ROLES) {
      const stored = context.contact_bindings.find((entry) => entry.role === role);
      if (!stored || !timingSafeTextEqual(
        stored.identifier_digest,
        normalized.contacts[role].identifier_digest,
      )) {
        throw releaseLockRefusal(
          409,
          'contact_binding_changed',
          'An amendment cannot change either invitation contact binding.',
        );
      }
    }
    const documentEvidence = await adapters.fetchDocument(
      normalized.change_order.document,
      {
        contacts: contactsForProvider(normalized),
        requireBoundParticipants: true,
      },
    );
    const built = buildChangeOrderAction({
      lockId,
      version: context.next_version,
      normalizedInput: normalized,
      documentEvidence,
      createdAt: new Date(currentMillis(now)).toISOString(),
    });
    const stored = await call('release_lock_amend', {
      p_lock_id: lockId,
      p_organization_id: organizationId,
      p_expected_version: expectedVersion,
      p_actor_id: contractorEntityId,
      p_co_action: built.action,
      p_co_action_hash: built.actionHash,
      p_co_material_hash: built.materialHash,
      p_document_evidence: built.document,
    });
    return Object.freeze({ ...stored, action: built.action });
  }

  async function actionCheckOptions({
    rawSessionToken,
    lockId,
    round,
  }) {
    if (!RELEASE_LOCK_ROUNDS.includes(round)) {
      throw releaseLockRefusal(400, 'invalid_release_lock_round', 'Release Lock round is invalid.');
    }
    const sessionDigest = cryptoSuite.sessionDigest(rawSessionToken);
    const context = await call('release_lock_action_check_context', {
      p_session_digest: sessionDigest,
      p_lock_id: requiredText(lockId),
      p_round: round,
    });
    const policy = rpPolicy(rpConfigProvider);
    assertCredentialPolicy(context.credential, policy);
    const built = actionCheckBuilder(/** @type {any} */ ({
      lockId,
      version: context.version,
      round,
      role: context.role,
      contactBindingId: context.contact_binding_id,
      contractorEntityId: context.contractor_entity_id,
      credentialId: context.credential.credential_id,
      action: context.action,
      actionHash: context.action_hash,
      authorizationExpiresAt: context.session_expires_at,
      now,
    }));
    const options = await authenticationOptions({
      rpID: policy.rpID,
      challenge: Buffer.from(built.challenge, 'base64url'),
      userVerification: 'required',
      allowCredentials: [{
        id: context.credential.credential_id,
        transports: context.credential.transports || undefined,
      }],
    });
    const challengeId = randomUUID();
    await call('release_lock_store_action_challenge', {
      p_session_digest: sessionDigest,
      p_lock_id: lockId,
      p_challenge_id: challengeId,
      p_version: context.version,
      p_round: round,
      p_credential_id: context.credential.credential_id,
      p_action_hash: context.action_hash,
      p_prompt_set: built.promptSet,
      p_prompt_set_digest: built.promptSetDigest,
      p_answer_digest: built.answerDigest,
      p_binding_moment: built.bindingMoment,
      p_random_nonce: built.randomNonce,
      p_nonce: built.nonce,
      p_resolution_context: built.context,
      p_challenge: built.challenge,
      p_issued_at: built.issuedAt,
      p_expires_at: built.expiresAt,
    });
    return Object.freeze({
      challenge_id: challengeId,
      round,
      action_hash: context.action_hash,
      prompt_set: built.promptSet,
      prompt_set_digest: built.promptSetDigest,
      binding_moment: built.bindingMoment,
      options,
      expires_at: built.expiresAt,
    });
  }

  function effectFailureResult(effect, status, error) {
    return {
      '@version': 'EP-RELEASE-LOCK-CUSTODIAN-RESULT-v1',
      provider: effect.provider,
      environment: effect.environment,
      operation: 'release_milestone',
      kind: status === 'no_effect' ? 'refused_before_effect' : 'provider_outcome_unknown',
      reason_code: typeof error?.code === 'string'
        ? error.code.toUpperCase()
        : 'PROVIDER_OUTCOME_UNKNOWN',
      effect_reference: effect.effect_reference,
      transaction_id: effect.transaction_id,
      milestone_id: effect.milestone_id,
      provider_phase: null,
    };
  }

  async function recordEffectOutcome(effect, outcome) {
    if (!['no_effect', 'unknown_effect', 'applied'].includes(outcome?.status)
        || typeof outcome.retryable !== 'boolean'
        || (outcome.status !== 'no_effect' && outcome.retryable)
        || !outcome.result
        || typeof outcome.result !== 'object') {
      throw new Error('Release Lock adapter returned an unsupported effect outcome');
    }
    return call('release_lock_record_effect_outcome', {
      p_effect_reference: effect.effect_reference,
      p_outcome: outcome.status,
      p_retryable: outcome.retryable,
      p_provider_result: outcome.result,
    });
  }

  async function executeReservedEffect(effect) {
    let claimState = 'not_attempted';
    try {
      const outcome = await adapters.executeEffect(
        effect,
        async (binding) => {
          claimState = 'attempted';
          const claimed = await call('release_lock_claim_effect_binding', {
            p_effect_reference: binding?.effect_reference,
            p_transaction_id: binding?.transaction_id,
            p_milestone_id: binding?.milestone_id,
            p_effect_contract: binding?.effect_contract,
            p_effect_contract_digest: binding?.effect_contract_digest,
          });
          const accepted = claimed === true || claimed?.claimed === true;
          claimState = accepted ? 'claimed' : 'not_claimed';
          return accepted;
        },
      );
      return recordEffectOutcome(effect, outcome);
    } catch (error) {
      const status = ['attempted', 'claimed'].includes(claimState)
        ? 'unknown_effect'
        : 'no_effect';
      const retryable = status === 'no_effect'
        && !['effect_binding_mismatch', 'document_participant_mismatch'].includes(error?.code);
      try {
        await recordEffectOutcome(effect, {
          status,
          retryable,
          result: effectFailureResult(effect, status, error),
        });
      } catch {
        // The recovery RPC can re-establish the outcome from the durable effect state.
      }
      throw error;
    }
  }

  async function approve({
    rawSessionToken,
    lockId,
    round,
    input,
  }) {
    const keys = new Set(['challenge_id', 'answers', 'assertion']);
    if (!exactObject(input, keys) || !RELEASE_LOCK_ROUNDS.includes(round)) {
      throw releaseLockRefusal(400, 'invalid_request', 'Release Lock approval is malformed.');
    }
    const sessionDigest = cryptoSuite.sessionDigest(rawSessionToken);
    const challenge = await call('release_lock_load_action_challenge', {
      p_session_digest: sessionDigest,
      p_lock_id: requiredText(lockId),
      p_round: round,
      p_challenge_id: requiredText(input.challenge_id),
    });
    const policy = rpPolicy(rpConfigProvider);
    assertCredentialPolicy(challenge.credential, policy);
    const verified = await actionCheckVerifier(/** @type {any} */ ({
      challenge,
      submittedAnswers: input.answers,
      assertion: input.assertion,
      credential: challenge.credential,
      rpId: policy.rpID,
      allowedOrigins: [policy.origin],
      evaluationTime: new Date(currentMillis(now)),
    }));
    const approval = await call('release_lock_record_approval', {
      p_session_digest: sessionDigest,
      p_lock_id: lockId,
      p_round: round,
      p_challenge_id: input.challenge_id,
      p_credential_id: challenge.credential.credential_id,
      p_new_sign_count: verified.newCounter,
      p_submitted_answers: input.answers,
      p_submitted_answer_digest: verified.submittedAnswerDigest,
      p_resolution: verified.receipt,
      p_resolution_digest: canonicalDigest(verified.receipt),
    });
    if (approval.invoke_effect !== true) return approval;
    if (round !== 'DRAW_RELEASE' || !approval.effect) {
      throw new Error('CO_ACCEPTED attempted to invoke a custodian effect');
    }
    const recorded = await executeReservedEffect(approval.effect);
    return Object.freeze({ ...approval, effect: recorded });
  }

  async function evidence({ organizationId, lockId }) {
    const stored = await call('release_lock_evidence', {
      p_lock_id: requiredText(lockId),
      p_organization_id: requiredText(organizationId),
    });
    return evidenceEnvelope(stored, now);
  }

  async function participantEvidence({ rawSessionToken, lockId }) {
    const stored = await call('release_lock_participant_evidence', {
      p_session_digest: cryptoSuite.sessionDigest(rawSessionToken),
      p_lock_id: requiredText(lockId),
    });
    return evidenceEnvelope(stored, now, [PARTICIPANT_EVIDENCE_LIMITATION]);
  }

  async function reconcile({ effectReference }) {
    const recovery = await call('release_lock_recover_effect', {
      p_effect_reference: requiredText(effectReference),
    });
    if (recovery.mode === 'terminal') return recovery.result;
    const effect = recovery.effect;
    if (!effect || typeof effect !== 'object') {
      throw new Error('Release Lock recovery returned no exact effect');
    }
    if (recovery.mode === 'execute') return executeReservedEffect(effect);
    if (recovery.mode !== 'reconcile') {
      throw new Error('Release Lock recovery returned an unsupported mode');
    }
    try {
      const outcome = await adapters.reconcileEffect(effect);
      return recordEffectOutcome(effect, outcome);
    } catch (error) {
      try {
        await recordEffectOutcome(effect, {
          status: 'unknown_effect',
          retryable: false,
          result: effectFailureResult(effect, 'unknown_effect', error),
        });
      } catch {
        // A later recovery pass can retry authoritative reconciliation.
      }
      throw error;
    }
  }

  return Object.freeze({
    createLock,
    exchangeInvitation,
    createPairing,
    exchangePairing,
    resolveSession,
    participantView,
    beginRegistration,
    completeRegistration,
    stageDraw,
    amendLock,
    actionCheckOptions,
    approve,
    evidence,
    participantEvidence,
    reconcile,
  });
}

export const releaseLockServiceInternals = Object.freeze({
  exactObject,
  contactsForProvider,
  assertCredentialPolicy,
});
