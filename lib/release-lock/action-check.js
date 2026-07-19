// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { canonicalize } from '../../packages/verify/index.js';
import {
  computeBindingMomentHash,
  computeResolutionChallenge,
  verifyResolutionReceipt,
} from '../../packages/verify/resolution.js';
import {
  RELEASE_LOCK_ACTION_CHECK_VERSION,
  RELEASE_LOCK_CHALLENGE_TTL_MS,
  RELEASE_LOCK_CREDENTIAL_ID_PATTERN,
  RELEASE_LOCK_DIGEST_PATTERN,
  RELEASE_LOCK_ROLES,
  RELEASE_LOCK_ROUNDS,
} from './constants.js';
import {
  canonicalDigest,
  randomToken,
  timingSafeTextEqual,
} from './crypto.js';
import { releaseLockRefusal } from './errors.js';

function shuffled(values, randomInt) {
  const output = [...values];
  for (let index = output.length - 1; index > 0; index -= 1) {
    const selected = randomInt(index + 1);
    [output[index], output[selected]] = [output[selected], output[index]];
  }
  return output;
}

function moneyDecoys(value) {
  const cents = BigInt(value.replace('.', ''));
  const alternatives = new Set([
    cents + 1n,
    cents + 100n,
    cents > 100n ? cents - 100n : cents + 1000n,
  ]);
  return [...alternatives].map((amount) => {
    const digits = amount.toString().padStart(3, '0');
    return `${digits.slice(0, -2)}.${digits.slice(-2)}`;
  });
}

// Option ids are salted per challenge. Without the salt they are a pure
// function of (question_id, label), which makes them identical across roles and
// across challenges for the same action: one party's recorded answers would be
// a working answer key for the other party's comprehension check, and a label
// surviving an amendment would keep its id. Verification never re-derives an
// option id (it compares submitted answers against the stored prompt set and
// answer digest), so the salt only has to be consistent within one challenge.
function optionId(optionSalt, questionId, label) {
  return `opt_${canonicalDigest({ salt: optionSalt, question_id: questionId, label }).slice(-24)}`;
}

function question(questionId, stem, correct, decoys, ctx) {
  const labels = shuffled([...new Set([correct, ...decoys])].slice(0, 4), ctx.randomInt);
  if (labels.length < 2 || !labels.includes(correct)) {
    throw new Error(`Action Check question ${questionId} has an invalid answer set`);
  }
  const options = labels.map((label) => ({
    option_id: optionId(ctx.optionSalt, questionId, label),
    label,
  }));
  return {
    prompt: {
      question_id: questionId,
      stem,
      options,
    },
    answer: {
      question_id: questionId,
      option_id: optionId(ctx.optionSalt, questionId, correct),
    },
  };
}

function canonicalLabel(value) {
  return canonicalize(value);
}

function coQuestions(action, ctx) {
  const changeOrder = action.retained_change_order;
  const document = [
    changeOrder.document.provider,
    changeOrder.document.reference,
    changeOrder.document.digest,
  ].join(' | ');
  const delta = `${changeOrder.price_delta} ${changeOrder.currency}`;
  const scope = canonicalLabel(changeOrder.scope);
  const schedule = canonicalLabel(changeOrder.progress_schedule_effect);
  return [
    question(
      'co_document',
      'Which retained change-order document is being accepted?',
      document,
      [
        `${changeOrder.document.provider} | ${changeOrder.document.reference} | ${canonicalDigest(changeOrder.scope)}`,
        `${changeOrder.document.provider} | version-${action.version + 1} | ${changeOrder.document.digest}`,
        `unverified | ${changeOrder.document.reference} | ${changeOrder.document.digest}`,
      ],
      ctx,
    ),
    question(
      'co_price_delta',
      'What exact price delta does this change order record?',
      delta,
      moneyDecoys(changeOrder.price_delta.replace(/^-/, '')).map(
        (candidate) => `${changeOrder.price_delta.startsWith('-') ? '-' : ''}${candidate} ${changeOrder.currency}`,
      ),
      ctx,
    ),
    question(
      'co_scope',
      'Which exact scope belongs to this change-order version?',
      scope,
      [
        canonicalLabel(changeOrder.progress_schedule_effect),
        canonicalLabel({ scope_digest: canonicalDigest(changeOrder.scope) }),
        canonicalLabel({ unchanged: true }),
      ],
      ctx,
    ),
    question(
      'co_schedule_effect',
      'What exact effect on the progress schedule is being accepted?',
      schedule,
      [
        canonicalLabel(changeOrder.scope),
        canonicalLabel({ days: 0, unchanged: true }),
        canonicalLabel({ schedule_digest: canonicalDigest(changeOrder.progress_schedule_effect) }),
      ],
      ctx,
    ),
    question(
      'co_payment_boundary',
      'What payment authority does CO_ACCEPTED create?',
      'None. CO_ACCEPTED never authorizes payment.',
      [
        'It authorizes the full price delta immediately.',
        'It releases the next draw automatically.',
        'It authorizes any payment with the same currency.',
      ],
      ctx,
    ),
  ];
}

function payeeLabel(payees) {
  return payees
    .map((payee) => `${payee.party_id} -> ${payee.destination_id} (${payee.amount})`)
    .join(' ; ');
}

function lienWaiverHashLabels(hashes) {
  return hashes.map(
    (entry) => `${entry.payee_party_id}=${entry.document_hash}`,
  );
}

function drawQuestions(action, ctx) {
  const amount = `${action.amount} ${action.currency}`;
  const drawAndMilestone = [
    action.draw_id,
    action.milestone.id,
    action.milestone.label,
    amount,
  ].join(' | ');
  const payees = payeeLabel(action.payees);
  const accepted = [
    `v${action.accepted_change_order.version}`,
    action.accepted_change_order.action_hash,
    action.accepted_change_order.acceptance_digest,
  ].join(' | ');
  const evidence = [
    action.evidence_hashes.completion_evidence_hash,
    ...lienWaiverHashLabels(action.evidence_hashes.lien_waiver_hashes),
    ...action.evidence_hashes.draw_document_hashes,
  ].join(' | ');
  const custodian = [
    action.custodian.provider,
    action.custodian.environment,
    action.custodian.instruction,
    action.custodian.transaction_id,
    action.custodian.milestone_id,
  ].join(' | ');
  return [
    question(
      'draw_id_amount',
      'Which exact draw ID, milestone, amount, and currency are being authorized?',
      drawAndMilestone,
      [
        `${action.draw_id} | ${action.milestone.id} | ${action.milestone.label} | ${moneyDecoys(action.amount)[0]} ${action.currency}`,
        `${action.draw_id} | different-milestone | ${action.milestone.label} | ${amount}`,
        `${action.draw_id} | ${action.milestone.id} | ${action.milestone.label} | ${action.amount} XXX`,
      ],
      ctx,
    ),
    question(
      'draw_payees',
      'Which exact payees and destinations are bound to this draw?',
      payees,
      [
        payeeLabel([...action.payees].reverse()),
        `${action.payees[0].party_id} -> ${action.custodian.transaction_id} (${action.amount})`,
        `${action.parties?.[1]?.party_id || 'customer'} -> unbound (${action.amount})`,
      ],
      ctx,
    ),
    question(
      'draw_accepted_co',
      'Which accepted change-order version and digest does this draw depend on?',
      accepted,
      [
        `v${action.accepted_change_order.version + 1} | ${action.accepted_change_order.action_hash} | ${action.accepted_change_order.acceptance_digest}`,
        `v${action.accepted_change_order.version} | ${action.accepted_change_order.acceptance_digest} | ${action.accepted_change_order.action_hash}`,
        `v${action.accepted_change_order.version} | ${action.evidence_hashes.completion_evidence_hash} | ${action.accepted_change_order.acceptance_digest}`,
      ],
      ctx,
    ),
    question(
      'draw_evidence',
      'Which exact completion, lien-waiver, and draw-document hashes are bound?',
      evidence,
      [
        [
          ...lienWaiverHashLabels(action.evidence_hashes.lien_waiver_hashes),
          action.evidence_hashes.completion_evidence_hash,
          ...action.evidence_hashes.draw_document_hashes,
        ].join(' | '),
        action.evidence_hashes.completion_evidence_hash,
        action.accepted_change_order.action_hash,
      ],
      ctx,
    ),
    question(
      'draw_custodian_instruction',
      'Which exact custodian instruction can become eligible after both approvals?',
      custodian,
      [
        [
          action.custodian.provider,
          action.custodian.environment,
          'refund',
          action.custodian.transaction_id,
          action.custodian.milestone_id,
        ].join(' | '),
        [
          action.custodian.provider,
          action.custodian.environment,
          action.custodian.instruction,
          action.custodian.milestone_id,
          action.custodian.transaction_id,
        ].join(' | '),
        [
          action.completion_evidence.provider,
          action.custodian.environment,
          action.custodian.instruction,
          action.custodian.transaction_id,
          action.custodian.milestone_id,
        ].join(' | '),
      ],
      ctx,
    ),
  ];
}

function principalFor(lockId, version, round, role, contactBindingId) {
  return `release-lock:${lockId}:v${version}:${round}:${role}:${contactBindingId}`;
}

function nonceBinding({
  lockId,
  version,
  round,
  role,
  actionHash,
  promptSetDigest,
  answerDigest,
  randomNonce,
  expiresAt,
}) {
  return `rl_nonce_${canonicalDigest({
    '@version': 'EP-RELEASE-LOCK-NONCE-v1',
    lock_id: lockId,
    version,
    round,
    role,
    action_hash: actionHash,
    prompt_set_digest: promptSetDigest,
    answer_digest: answerDigest,
    random_nonce: randomNonce,
    expires_at: expiresAt,
  }).slice(7)}`;
}

function bindingMoment({
  lockId,
  version,
  round,
  role,
  action,
  actionHash,
  promptSetDigest,
  answerDigest,
}) {
  const coRound = round === 'CO_ACCEPTED';
  const findings = coRound
    ? [
        `Retained change-order digest: ${action.retained_change_order.document.digest}`,
        `Price delta: ${action.retained_change_order.price_delta} ${action.retained_change_order.currency}`,
        `Scope digest: ${canonicalDigest(action.retained_change_order.scope)}`,
        `Progress-schedule-effect digest: ${canonicalDigest(action.retained_change_order.progress_schedule_effect)}`,
        'Payment authorization: none',
      ]
    : [
        `Accepted change-order version: ${action.accepted_change_order.version}`,
        `Accepted change-order action hash: ${action.accepted_change_order.action_hash}`,
        `Accepted change-order acceptance digest: ${action.accepted_change_order.acceptance_digest}`,
        `Draw: ${action.draw_id}`,
        `Amount: ${action.amount} ${action.currency}`,
        `Payees digest: ${canonicalDigest(action.payees)}`,
        `Evidence hashes digest: ${canonicalDigest(action.evidence_hashes)}`,
        `Custodian instruction: ${action.custodian.instruction}`,
      ];
  return {
    synopsis: coRound
      ? 'Accept one exact retained change order without authorizing payment.'
      : 'Authorize one exact post-milestone draw release.',
    findings: [
      `Release Lock: ${lockId}`,
      `Version: ${version}`,
      `Round: ${round}`,
      `Role: ${role}`,
      `Action hash: ${actionHash}`,
      `Prompt-set digest: ${promptSetDigest}`,
      `Answer digest: ${answerDigest}`,
      ...findings,
    ],
    recommendations: [
      'Approve only if every Action Check answer matches the exact round-specific action.',
    ],
    offer: coRound
      ? 'CO_ACCEPTED records only this change-order acceptance. A later DRAW_RELEASE requires new evidence and a separate approval round.'
      : 'A different accepted change order, draw, amount, payee, evidence hash, or custodian instruction requires a new exact action.',
    question: {
      stem: `Approve only ${round} for Release Lock ${lockId} version ${version} in the ${role} role?`,
      options: [
        {
          label: `Approve exact ${round}`,
          reasoning: coRound
            ? 'Accept only the retained change-order document, scope, price delta, and schedule effect.'
            : 'Authorize only the exact draw action and bound custodian instruction.',
        },
        {
          label: 'Decline',
          reasoning: coRound
            ? 'Do not record change-order acceptance.'
            : 'Do not make any custodian instruction eligible.',
        },
      ],
      recommended_idx: 1,
      hatches: {
        free_text: false,
        dialogue: false,
      },
    },
    meta: {
      decision_class: coRound
        ? 'release_lock.change_order_acceptance'
        : 'release_lock.draw_release',
      calibration_note: 'No approval recommendation; verify every material field.',
    },
  };
}

export function buildReleaseLockActionCheck({
  lockId,
  version,
  round,
  role,
  contactBindingId,
  contractorEntityId,
  credentialId,
  action,
  actionHash,
  authorizationExpiresAt = null,
  now = Date.now,
  randomBytes = crypto.randomBytes,
  randomInt = crypto.randomInt,
} = {}) {
  if (!RELEASE_LOCK_ROUNDS.includes(round)
      || !RELEASE_LOCK_ROLES.includes(role)
      || !Number.isSafeInteger(version)
      || version < 1
      || !RELEASE_LOCK_CREDENTIAL_ID_PATTERN.test(credentialId || '')
      || !RELEASE_LOCK_DIGEST_PATTERN.test(actionHash || '')
      || action?.lock_id !== lockId
      || action?.version !== version
      || action?.round !== round
      || !contactBindingId
      || !contractorEntityId) {
    throw releaseLockRefusal(400, 'invalid_request', 'Action Check context is malformed.');
  }
  const nowMs = typeof now === 'function' ? now() : now;
  const issuedAt = new Date(nowMs).toISOString();
  const actionExpiresAt = Date.parse(action.expires_at);
  const authorizationExpiry = authorizationExpiresAt === null
    ? Number.POSITIVE_INFINITY
    : Date.parse(authorizationExpiresAt);
  const expiresAtMs = Math.min(
    actionExpiresAt,
    authorizationExpiry,
    nowMs + RELEASE_LOCK_CHALLENGE_TTL_MS,
  );
  if (!Number.isFinite(actionExpiresAt)
      || !Number.isFinite(expiresAtMs)
      || expiresAtMs <= nowMs) {
    throw releaseLockRefusal(410, 'release_lock_expired', 'The Release Lock round has expired.');
  }
  const expiresAt = new Date(expiresAtMs).toISOString();
  const optionSalt = randomToken(randomBytes);
  const ctx = { randomInt, optionSalt };
  const pairs = shuffled(
    round === 'CO_ACCEPTED' ? coQuestions(action, ctx) : drawQuestions(action, ctx),
    randomInt,
  );
  const promptSet = {
    '@version': RELEASE_LOCK_ACTION_CHECK_VERSION,
    lock_id: lockId,
    version,
    round,
    role,
    questions: pairs.map((entry) => entry.prompt),
  };
  const expectedAnswers = pairs.map((entry) => entry.answer);
  const answerBody = {
    '@version': `${RELEASE_LOCK_ACTION_CHECK_VERSION}-ANSWERS`,
    lock_id: lockId,
    version,
    round,
    role,
    answers: expectedAnswers,
  };
  const promptSetDigest = canonicalDigest(promptSet);
  const answerDigest = canonicalDigest(answerBody);
  const exactBindingMoment = bindingMoment({
    lockId,
    version,
    round,
    role,
    action,
    actionHash,
    promptSetDigest,
    answerDigest,
  });
  const envelopeHash = computeBindingMomentHash(exactBindingMoment);
  if (!envelopeHash) throw new Error('Action Check binding moment is not canonical');
  const randomNonce = randomToken(randomBytes);
  const nonce = nonceBinding({
    lockId,
    version,
    round,
    role,
    actionHash,
    promptSetDigest,
    answerDigest,
    randomNonce,
    expiresAt,
  });
  const context = {
    ep_version: '1.0',
    context_type: 'ep.resolution.v1',
    envelope_hash: envelopeHash,
    action_hash: actionHash,
    principal: principalFor(lockId, version, round, role, contactBindingId),
    principal_key_id: credentialId,
    initiator: contractorEntityId,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    resolution: {
      outcome: 'approved',
      selected_option: 0,
    },
  };
  const challenge = computeResolutionChallenge(context);
  if (!challenge) throw new Error('Action Check resolution context is not canonical');
  return Object.freeze({
    round,
    promptSet,
    promptSetDigest,
    expectedAnswers,
    answerDigest,
    bindingMoment: exactBindingMoment,
    randomNonce,
    nonce,
    context,
    challenge,
    issuedAt,
    expiresAt,
  });
}

function exactSubmittedAnswers(value, challenge) {
  if (!Array.isArray(value) || value.length !== challenge.prompt_set.questions.length) return false;
  return value.every((answer, index) => {
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)
        || Object.keys(answer).length !== 2
        || !Object.hasOwn(answer, 'question_id')
        || !Object.hasOwn(answer, 'option_id')) return false;
    const prompt = challenge.prompt_set.questions[index];
    return answer.question_id === prompt.question_id
      && prompt.options.some((option) => option.option_id === answer.option_id);
  });
}

function assertStoredChallenge(challenge) {
  const promptDigest = canonicalDigest(challenge.prompt_set);
  const envelopeHash = computeBindingMomentHash(challenge.binding_moment);
  const expectedNonce = nonceBinding({
    lockId: challenge.lock_id,
    version: challenge.version,
    round: challenge.round,
    role: challenge.role,
    actionHash: challenge.action_hash,
    promptSetDigest: challenge.prompt_set_digest,
    answerDigest: challenge.answer_digest,
    randomNonce: challenge.random_nonce,
    expiresAt: challenge.expires_at,
  });
  const expectedChallenge = computeResolutionChallenge(challenge.resolution_context);
  return RELEASE_LOCK_ROUNDS.includes(challenge.round)
    && timingSafeTextEqual(promptDigest, challenge.prompt_set_digest)
    && timingSafeTextEqual(envelopeHash, challenge.resolution_context.envelope_hash)
    && timingSafeTextEqual(expectedNonce, challenge.nonce)
    && timingSafeTextEqual(challenge.nonce, challenge.resolution_context.nonce)
    && timingSafeTextEqual(expectedChallenge, challenge.challenge)
    && challenge.resolution_context.action_hash === challenge.action_hash
    && challenge.resolution_context.principal_key_id === challenge.credential_id
    && challenge.resolution_context.principal === principalFor(
      challenge.lock_id,
      challenge.version,
      challenge.round,
      challenge.role,
      challenge.contact_binding_id,
    );
}

export async function verifyReleaseLockActionCheck({
  challenge,
  submittedAnswers,
  assertion,
  credential,
  rpId,
  allowedOrigins,
  evaluationTime = new Date(),
} = {}) {
  if (!assertStoredChallenge(challenge)) {
    throw releaseLockRefusal(409, 'stored_challenge_inconsistent', 'Stored Action Check binding is inconsistent.');
  }
  if (!exactSubmittedAnswers(submittedAnswers, challenge)) {
    throw releaseLockRefusal(400, 'action_check_invalid', 'Action Check answers are malformed.');
  }
  const submittedAnswerDigest = canonicalDigest({
    '@version': `${RELEASE_LOCK_ACTION_CHECK_VERSION}-ANSWERS`,
    lock_id: challenge.lock_id,
    version: challenge.version,
    round: challenge.round,
    role: challenge.role,
    answers: submittedAnswers,
  });
  if (!timingSafeTextEqual(submittedAnswerDigest, challenge.answer_digest)) {
    throw releaseLockRefusal(422, 'action_check_failed', 'One or more Action Check answers are incorrect.');
  }
  if (!assertion?.id
      || assertion.id !== credential.credential_id
      || !assertion.response
      || !Array.isArray(allowedOrigins)
      || allowedOrigins.length === 0
      || !rpId) {
    throw releaseLockRefusal(400, 'assertion_invalid', 'WebAuthn assertion is malformed.');
  }

  let authentication;
  try {
    authentication = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: challenge.challenge,
      expectedOrigin: allowedOrigins,
      expectedRPID: rpId,
      credential: {
        id: credential.credential_id,
        publicKey: Buffer.from(credential.public_key_cose, 'base64url'),
        counter: Number(credential.sign_count) || 0,
        transports: credential.transports || undefined,
      },
      requireUserVerification: true,
    });
  } catch {
    throw releaseLockRefusal(400, 'assertion_invalid', 'WebAuthn assertion did not verify.');
  }
  if (!authentication.verified) {
    throw releaseLockRefusal(400, 'assertion_invalid', 'WebAuthn assertion did not verify.');
  }

  const receipt = {
    profile: 'EP-RESOLUTION-v1',
    signoff: {
      '@type': 'ep.signoff',
      context: challenge.resolution_context,
      webauthn: {
        authenticator_data: assertion.response.authenticatorData,
        client_data_json: assertion.response.clientDataJSON,
        signature: assertion.response.signature,
      },
    },
  };
  const verified = verifyResolutionReceipt(receipt, {
    bindingMoment: challenge.binding_moment,
    expectedActionHash: challenge.action_hash,
    principalKeys: {
      [credential.credential_id]: {
        principal: challenge.resolution_context.principal,
        public_key: credential.public_key_spki,
      },
    },
    rpId,
    allowedOrigins,
    expectedSelectedOption: 0,
    expectedInitiator: challenge.resolution_context.initiator,
    expectedNonce: challenge.nonce,
    evaluationTime,
  });
  if (!verified.valid || !verified.authorizes_action || verified.outcome !== 'approved') {
    throw releaseLockRefusal(400, 'resolution_verification_refused', 'EP-RESOLUTION-v1 verification refused the approval.');
  }
  return Object.freeze({
    receipt,
    submittedAnswerDigest,
    newCounter: authentication.authenticationInfo.newCounter,
    verification: verified,
  });
}

export const releaseLockActionCheckInternals = Object.freeze({
  exactSubmittedAnswers,
  assertStoredChallenge,
  nonceBinding,
  principalFor,
});
