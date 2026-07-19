// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  buildReleaseLockActionCheck,
  releaseLockActionCheckInternals,
  verifyReleaseLockActionCheck,
} from './action-check.js';
import {
  buildChangeOrderAction,
  buildDrawReleaseAction,
} from './action.js';
import { createReleaseLockAdapterBoundary } from './adapters.js';
import {
  bytesDigest,
  canonicalDigest,
  createReleaseLockCrypto,
  authorityAssertionBytes,
} from './crypto.js';
import { mapReleaseLockRpcError } from './errors.js';
import { createReleaseLockService } from './service.js';
import {
  releaseLockValidationInternals,
  validateChangeOrderInput,
  validateDrawReleaseInput,
} from './validation.js';

const NOW = Date.parse('2030-01-01T00:00:00.000Z');
const LOCK_EXPIRES = '2030-01-20T00:00:00.000Z';
const INVITE_EXPIRES = '2030-01-03T00:00:00.000Z';
const CONTACT_EXPIRES = '2030-02-01T00:00:00.000Z';
const CO_EXPIRES = '2030-01-05T00:00:00.000Z';
const DRAW_EXPIRES = '2030-01-15T00:00:00.000Z';
const LOCK_ID = `rlk_${'1'.repeat(32)}`;
const ACTOR = 'contractor:acme';
const ORG = 'org_acme';
const DIGESTS = Object.freeze({
  co: `sha256:${'1'.repeat(64)}`,
  completion: `sha256:${'2'.repeat(64)}`,
  waiver: `sha256:${'3'.repeat(64)}`,
  draw: `sha256:${'4'.repeat(64)}`,
});
const AUTHORITY_KEYS = crypto.generateKeyPairSync('ed25519');
const AUTHORITY_KEY_ID = 'directory-key-2030';
const AUTHORITY_PUBLIC_KEY = AUTHORITY_KEYS.publicKey.export({
  format: 'der',
  type: 'spki',
}).toString('base64url');
const PINNED_AUTHORITY_KEYS = Object.freeze({
  pinned_project_directory: {
    [AUTHORITY_KEY_ID]: {
      algorithm: 'Ed25519',
      public_key: AUTHORITY_PUBLIC_KEY,
    },
  },
  different_directory: {
    [AUTHORITY_KEY_ID]: {
      algorithm: 'Ed25519',
      public_key: AUTHORITY_PUBLIC_KEY,
    },
  },
});

function cryptoSuite() {
  return createReleaseLockCrypto({
    tokenKey: Buffer.alloc(32, 7),
    contactKey: Buffer.alloc(32, 9),
    authorityKeys: PINNED_AUTHORITY_KEYS,
  });
}

function signAuthority(assertion) {
  return crypto.sign(
    null,
    authorityAssertionBytes(assertion),
    AUTHORITY_KEYS.privateKey,
  ).toString('base64url');
}

function party(suite, role, partyId, identifier) {
  const verification = {
    provider: 'verified_channel',
    reference: `verify_${role}`,
    verified_at: '2029-12-31T23:00:00.000Z',
    expires_at: CONTACT_EXPIRES,
  };
  const proofBody = {
    '@version': 'EP-RELEASE-LOCK-CONTACT-PROOF-v1',
    role,
    party_id: partyId,
    channel: 'email',
    identifier,
    ...verification,
  };
  const contactBindingDigest = suite.contactDigest('email', identifier);
  const assertion = {
    '@version': 'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1',
    algorithm: 'Ed25519',
    provider: 'pinned_project_directory',
    key_id: AUTHORITY_KEY_ID,
    reference: `authority_${role}`,
    role,
    party_id: partyId,
    subject_digest: canonicalDigest({
      provider: 'pinned_project_directory',
      subject: `subject_${role}`,
    }),
    contact_binding_digest: contactBindingDigest,
    verified_at: '2029-12-31T23:00:00.000Z',
    expires_at: CONTACT_EXPIRES,
  };
  return {
    party_id: partyId,
    display_name: role === 'contractor' ? 'ACME Contractor' : 'Project Customer',
    contact: {
      channel: 'email',
      identifier,
      verification: {
        ...verification,
        proof: suite.contactProofDigest(proofBody),
      },
    },
    authority: {
      assertion,
      signature: signAuthority(assertion),
    },
  };
}

function resignAuthority(value) {
  value.authority.signature = signAuthority(value.authority.assertion);
  return value;
}

function changeOrderInput(suite, {
  customerIdentifier = 'customer@example.com',
  scope = { add: ['north stair landing'] },
} = {}) {
  return {
    organization_id: ORG,
    change_order: {
      document: {
        provider: 'adobe_sign',
        reference: 'agreement_123',
        verification: {
          status: 'SIGNED',
          participant_sets: ['contractor', 'customer'],
        },
      },
      scope,
      price_delta: '1250.00',
      currency: 'USD',
      progress_schedule_effect: { calendar_days_added: 3 },
      expires_at: CO_EXPIRES,
    },
    lock_expires_at: LOCK_EXPIRES,
    invitation_expires_at: INVITE_EXPIRES,
    contractor_party: party(suite, 'contractor', ACTOR, 'builder@example.com'),
    customer_party: party(
      suite,
      'customer',
      'customer:project',
      customerIdentifier,
    ),
  };
}

function providerEvidence(document, digest) {
  return {
    provider: document.provider,
    reference: document.reference,
    document_digest: digest,
    media_type: 'application/pdf',
    byte_length: 4096,
    observed_at: '2030-01-01T00:00:00.000Z',
    evidence: {
      '@version': 'EP-EXTERNAL-DOCUMENT-EVIDENCE-v1',
      final: true,
      provider_reference: document.reference,
    },
  };
}

function drawInput() {
  return {
    organization_id: ORG,
    expected_version: 1,
    draw: {
      draw_id: 'draw_007',
      amount: '1250.00',
      currency: 'USD',
      payees: [{
        party_id: ACTOR,
        destination_id: 'custodian_destination_1',
        amount: '1250.00',
      }],
      milestone: {
        id: 'milestone_7',
        label: 'North stair landing complete',
      },
      completion_evidence: {
        provider: 'adobe_sign',
        reference: 'completion_123',
        verification: { status: 'SIGNED' },
      },
      lien_waivers: [{
        payee_party_id: ACTOR,
        document: {
          provider: 'adobe_sign',
          reference: 'waiver_123',
          verification: { status: 'SIGNED' },
        },
      }],
      draw_documents: [{
        provider: 'adobe_sign',
        reference: 'draw_packet_123',
        verification: { status: 'SIGNED' },
      }],
      custodian: {
        provider: 'escrow_com',
        environment: 'sandbox',
        transaction_id: 'txn_123',
        milestone_id: 'provider_milestone_7',
        instruction: 'release_milestone',
      },
      expires_at: DRAW_EXPIRES,
    },
  };
}

function builtActions() {
  const suite = cryptoSuite();
  const normalizedCo = validateChangeOrderInput(changeOrderInput(suite), {
    now: NOW,
    cryptoSuite: suite,
    contractorEntityId: ACTOR,
  });
  const co = buildChangeOrderAction({
    lockId: LOCK_ID,
    version: 1,
    normalizedInput: normalizedCo,
    documentEvidence: providerEvidence(normalizedCo.change_order.document, DIGESTS.co),
    createdAt: '2030-01-01T00:00:00.000Z',
  });
  const normalizedDraw = validateDrawReleaseInput(drawInput(), {
    now: NOW,
    maxExpiresAt: LOCK_EXPIRES,
  });
  const draw = buildDrawReleaseAction({
    lockId: LOCK_ID,
    version: 1,
    normalizedInput: normalizedDraw,
    acceptedChangeOrder: {
      version: 1,
      action_hash: co.actionHash,
      acceptance_digest: `sha256:${'a'.repeat(64)}`,
      parties: co.action.parties,
    },
    completionEvidence: providerEvidence(
      normalizedDraw.draw.completion_evidence,
      DIGESTS.completion,
    ),
    lienWaiverEvidence: [{
      payee_party_id: normalizedDraw.draw.lien_waivers[0].payee_party_id,
      evidence: providerEvidence(
        normalizedDraw.draw.lien_waivers[0].document,
        DIGESTS.waiver,
      ),
    }],
    drawDocumentEvidence: [providerEvidence(
      normalizedDraw.draw.draw_documents[0],
      DIGESTS.draw,
    )],
    createdAt: '2030-01-01T00:00:00.000Z',
  });
  return { co, draw, normalizedCo, normalizedDraw };
}

function effectFixture() {
  const { draw } = builtActions();
  return {
    effect_reference: draw.action.custodian.effect_reference,
    provider: draw.action.custodian.provider,
    environment: draw.action.custodian.environment,
    transaction_id: draw.action.custodian.transaction_id,
    milestone_id: draw.action.custodian.milestone_id,
    instruction: draw.action.custodian.instruction,
    draw_action_hash: draw.actionHash,
    draw_acceptance_digest: `sha256:${'b'.repeat(64)}`,
    action: draw.action,
  };
}

function serviceWith({
  rpc,
  adapters,
  actionCheckVerifier,
} = {}) {
  return createReleaseLockService({
    rpc,
    cryptoSuite: cryptoSuite(),
    adapters: adapters || {
      deliverInvitation: vi.fn(),
      fetchDocument: vi.fn(),
      executeEffect: vi.fn(),
      reconcileEffect: vi.fn(),
    },
    now: () => NOW,
    randomUUID: () => '11111111-1111-4111-8111-111111111111',
    rpConfigProvider: () => ({
      rpID: 'example.com',
      origin: 'https://example.com',
      rpName: 'Example',
    }),
    actionCheckVerifier,
  });
}

describe('Release Lock exact actions', () => {
  it('hardens primitive validation against hostile shapes and sensitive fields', () => {
    const {
      assertNoSensitiveKeys,
      canonicalCopy,
      exactKeys,
      instant,
      isRecord,
      text,
    } = releaseLockValidationInternals;

    expect(isRecord({})).toBe(true);
    expect(isRecord(Object.create(null))).toBe(true);
    for (const value of [null, [], new Date(), 'object']) {
      expect(isRecord(value)).toBe(false);
    }

    const allowed = new Set(['a', 'b']);
    expect(exactKeys({ a: 1, b: 2 }, allowed)).toBe(true);
    expect(exactKeys(null, allowed)).toBe(false);
    expect(exactKeys({ a: 1, b: 2, c: 3 }, allowed)).toBe(false);
    expect(exactKeys({ a: 1 }, allowed)).toBe(false);
    expect(exactKeys({ a: 1 }, allowed, new Set(['a']))).toBe(true);

    expect(text('abc', 'field')).toBe('abc');
    expect(text('abc', 'field', { pattern: /^[a-z]+$/ })).toBe('abc');
    for (const [value, options] of [
      [7, {}],
      ['', {}],
      ['abcd', { max: 3 }],
      ['a\u0000b', {}],
      ['ABC', { pattern: /^[a-z]+$/ }],
    ]) {
      expect(() => text(value, 'field', options)).toThrow(
        expect.objectContaining({ code: 'invalid_request' }),
      );
    }

    expect(instant('2030-01-01T00:00:00.000Z', 'instant')).toBe(NOW);
    for (const value of ['not-time', '2030-01-01T00:00:00+00:00']) {
      expect(() => instant(value, 'instant')).toThrow(
        expect.objectContaining({ code: 'invalid_request' }),
      );
    }

    expect(canonicalCopy({ b: 2, a: 1 }, 'value', 100))
      .toEqual({ a: 1, b: 2 });
    expect(() => canonicalCopy({ value: 1n }, 'value', 100)).toThrow(
      expect.objectContaining({ code: 'invalid_request' }),
    );
    expect(() => canonicalCopy({ value: 'too large' }, 'value', 2)).toThrow(
      expect.objectContaining({ code: 'payload_too_large' }),
    );

    expect(assertNoSensitiveKeys(null, 'value')).toBeUndefined();
    expect(assertNoSensitiveKeys(['safe', { nested: true }], 'value')).toBeUndefined();
    expect(() => assertNoSensitiveKeys({ api_key: 'secret' }, 'value')).toThrow(
      expect.objectContaining({ code: 'sensitive_material_field' }),
    );
    expect(() => assertNoSensitiveKeys({}, 'value', 17)).toThrow(
      expect.objectContaining({ code: 'invalid_request' }),
    );
  });

  it('keeps CO_ACCEPTED non-payment and DRAW_RELEASE separately bound', () => {
    const { co, draw } = builtActions();
    expect(co.action.round).toBe('CO_ACCEPTED');
    expect(co.action.payment_authorization).toBe(false);
    expect(co.action).not.toHaveProperty('custodian');
    expect(draw.action.round).toBe('DRAW_RELEASE');
    expect(draw.action.accepted_change_order.action_hash).toBe(co.actionHash);
    expect(draw.action.accepted_change_order.version).toBe(1);
    expect(draw.action.custodian.instruction).toBe('release_milestone');
    expect(draw.action.custodian_eligibility)
      .toBe('after_complete_draw_release_round');
    expect(draw.action.evidence_hashes).toEqual({
      completion_evidence_hash: DIGESTS.completion,
      lien_waiver_hashes: [{
        payee_party_id: ACTOR,
        document_hash: DIGESTS.waiver,
      }],
      draw_document_hashes: [DIGESTS.draw],
    });
  });

  it('refuses malformed, null, reused-contact, and mismatched-payee inputs as 4xx', () => {
    const suite = cryptoSuite();
    for (const invalid of [null, {}, []]) {
      expect(() => validateChangeOrderInput(invalid, {
        now: NOW,
        cryptoSuite: suite,
        contractorEntityId: ACTOR,
      })).toThrowError(expect.objectContaining({ status: 400 }));
    }
    const sameContact = changeOrderInput(suite, {
      customerIdentifier: 'builder@example.com',
    });
    expect(() => validateChangeOrderInput(sameContact, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrowError(expect.objectContaining({
      status: 400,
      code: 'contact_reused_across_roles',
    }));
    const invalidDraw = drawInput();
    invalidDraw.draw.payees[0].amount = '1249.99';
    expect(() => validateDrawReleaseInput(invalidDraw, {
      now: NOW,
      maxExpiresAt: LOCK_EXPIRES,
    })).toThrowError(expect.objectContaining({
      status: 400,
      code: 'payee_total_mismatch',
    }));
  });

  it('refuses evidence reuse across categories and requires waiver coverage per payee', () => {
    const collided = drawInput();
    collided.draw.draw_documents[0].reference =
      collided.draw.completion_evidence.reference;
    expect(() => validateDrawReleaseInput(collided, {
      now: NOW,
      maxExpiresAt: LOCK_EXPIRES,
    })).toThrow(expect.objectContaining({ code: 'evidence_category_collision' }));

    const twoPayees = drawInput();
    twoPayees.draw.amount = '1250.00';
    twoPayees.draw.payees = [
      {
        party_id: ACTOR,
        destination_id: 'custodian_destination_1',
        amount: '1000.00',
      },
      {
        party_id: 'supplier:millwork',
        destination_id: 'custodian_destination_2',
        amount: '250.00',
      },
    ];
    expect(() => validateDrawReleaseInput(twoPayees, {
      now: NOW,
      maxExpiresAt: LOCK_EXPIRES,
    })).toThrow(expect.objectContaining({
      code: 'invalid_lien_waivers',
    }));
  });

  it('refuses lien-waiver evidence rebound to a different payee', () => {
    const { co, normalizedDraw } = builtActions();
    expect(() => buildDrawReleaseAction({
      lockId: LOCK_ID,
      version: 1,
      normalizedInput: normalizedDraw,
      acceptedChangeOrder: {
        version: 1,
        action_hash: co.actionHash,
        acceptance_digest: `sha256:${'a'.repeat(64)}`,
        parties: co.action.parties,
      },
      completionEvidence: providerEvidence(
        normalizedDraw.draw.completion_evidence,
        DIGESTS.completion,
      ),
      lienWaiverEvidence: [{
        payee_party_id: 'attacker:substitute',
        evidence: providerEvidence(
          normalizedDraw.draw.lien_waivers[0].document,
          DIGESTS.waiver,
        ),
      }],
      drawDocumentEvidence: [providerEvidence(
        normalizedDraw.draw.draw_documents[0],
        DIGESTS.draw,
      )],
      createdAt: '2030-01-01T00:00:00.000Z',
    })).toThrow(expect.objectContaining({
      code: 'document_verification_refused',
    }));
  });

  it('refuses a contact proof that would expire before the second ceremony can occur', () => {
    const suite = cryptoSuite();
    const input = changeOrderInput(suite);
    input.customer_party = party(
      suite,
      'customer',
      'customer:project',
      'customer@example.com',
    );
    input.customer_party.contact.verification.expires_at = '2030-01-10T00:00:00.000Z';
    const proofBody = {
      '@version': 'EP-RELEASE-LOCK-CONTACT-PROOF-v1',
      role: 'customer',
      party_id: 'customer:project',
      channel: 'email',
      identifier: 'customer@example.com',
      provider: 'verified_channel',
      reference: 'verify_customer',
      verified_at: '2029-12-31T23:00:00.000Z',
      expires_at: '2030-01-10T00:00:00.000Z',
    };
    input.customer_party.contact.verification.proof = suite.contactProofDigest(proofBody);

    expect(() => validateChangeOrderInput(input, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrow(expect.objectContaining({ code: 'contact_verification_too_short' }));
  });

  it('requires one pinned external authority and two distinct authority subjects', () => {
    const suite = cryptoSuite();
    const reusedSubject = changeOrderInput(suite);
    reusedSubject.customer_party.authority.assertion.subject_digest =
      reusedSubject.contractor_party.authority.assertion.subject_digest;
    resignAuthority(reusedSubject.customer_party);
    expect(() => validateChangeOrderInput(reusedSubject, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrow(expect.objectContaining({ code: 'authority_subject_reused' }));

    const providerSwap = changeOrderInput(suite);
    providerSwap.customer_party.authority.assertion.provider = 'different_directory';
    resignAuthority(providerSwap.customer_party);
    expect(() => validateChangeOrderInput(providerSwap, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrow(expect.objectContaining({ code: 'authority_provider_mismatch' }));

    const forged = changeOrderInput(suite);
    forged.customer_party.authority.signature = Buffer.alloc(64).toString('base64url');
    expect(() => validateChangeOrderInput(forged, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrow(expect.objectContaining({ code: 'authority_verification_invalid' }));

    const contactSubstitution = changeOrderInput(suite);
    contactSubstitution.customer_party.contact.identifier = 'substitute@example.com';
    contactSubstitution.customer_party.contact.verification.proof =
      suite.contactProofDigest({
        '@version': 'EP-RELEASE-LOCK-CONTACT-PROOF-v1',
        role: 'customer',
        party_id: 'customer:project',
        channel: 'email',
        identifier: 'substitute@example.com',
        provider: 'verified_channel',
        reference: 'verify_customer',
        verified_at: '2029-12-31T23:00:00.000Z',
        expires_at: CONTACT_EXPIRES,
      });
    expect(() => validateChangeOrderInput(contactSubstitution, {
      now: NOW,
      cryptoSuite: suite,
      contractorEntityId: ACTOR,
    })).toThrow(expect.objectContaining({ code: 'authority_verification_invalid' }));
  });
});

describe('Release Lock Action Check hostility', () => {
  function challengeFixture() {
    const { co } = builtActions();
    const built = buildReleaseLockActionCheck({
      lockId: LOCK_ID,
      version: 1,
      round: 'CO_ACCEPTED',
      role: 'contractor',
      contactBindingId: '11111111-1111-4111-8111-111111111111',
      contractorEntityId: ACTOR,
      credentialId: 'credential_1234567890',
      action: co.action,
      actionHash: co.actionHash,
      now: () => NOW,
      randomBytes: () => Buffer.alloc(32, 5),
      randomInt: () => 0,
    });
    return {
      built,
      stored: {
        lock_id: LOCK_ID,
        version: 1,
        round: 'CO_ACCEPTED',
        role: 'contractor',
        contact_binding_id: '11111111-1111-4111-8111-111111111111',
        credential_id: 'credential_1234567890',
        action_hash: co.actionHash,
        prompt_set: built.promptSet,
        prompt_set_digest: built.promptSetDigest,
        answer_digest: built.answerDigest,
        binding_moment: built.bindingMoment,
        random_nonce: built.randomNonce,
        nonce: built.nonce,
        resolution_context: built.context,
        challenge: built.challenge,
        issued_at: built.issuedAt,
        expires_at: built.expiresAt,
      },
    };
  }

  it('detects prompt substitution before passkey verification', async () => {
    const { built, stored } = challengeFixture();
    const substituted = structuredClone(stored);
    substituted.prompt_set.questions[0].stem = 'Approve anything?';
    expect(releaseLockActionCheckInternals.assertStoredChallenge(substituted)).toBe(false);
    await expect(verifyReleaseLockActionCheck({
      challenge: substituted,
      submittedAnswers: built.expectedAnswers,
    })).rejects.toMatchObject({
      status: 409,
      code: 'stored_challenge_inconsistent',
    });
  });

  it('detects answer substitution before passkey verification', async () => {
    const { built, stored } = challengeFixture();
    const substituted = structuredClone(built.expectedAnswers);
    const firstPrompt = stored.prompt_set.questions[0];
    substituted[0].option_id = firstPrompt.options.find(
      (option) => option.option_id !== substituted[0].option_id,
    ).option_id;
    await expect(verifyReleaseLockActionCheck({
      challenge: stored,
      submittedAnswers: substituted,
    })).rejects.toMatchObject({
      status: 422,
      code: 'action_check_failed',
    });
    expect(canonicalDigest({
      '@version': 'EP-RELEASE-LOCK-ACTION-CHECK-v1-ANSWERS',
      lock_id: LOCK_ID,
      version: 1,
      round: 'CO_ACCEPTED',
      role: 'contractor',
      answers: substituted,
    })).not.toBe(stored.answer_digest);
  });

  it('refuses every malformed answer and WebAuthn assertion shape before crypto', async () => {
    const { built, stored } = challengeFixture();
    const first = built.expectedAnswers[0];
    const invalidAnswerSets = [
      undefined,
      [],
      [null, ...built.expectedAnswers.slice(1)],
      [[...Object.values(first)], ...built.expectedAnswers.slice(1)],
      [{ ...first, extra: true }, ...built.expectedAnswers.slice(1)],
      [{ option_id: first.option_id }, ...built.expectedAnswers.slice(1)],
      [{ question_id: first.question_id }, ...built.expectedAnswers.slice(1)],
      [{ ...first, question_id: 'wrong' }, ...built.expectedAnswers.slice(1)],
      [{ ...first, option_id: 'wrong' }, ...built.expectedAnswers.slice(1)],
    ];
    for (const submittedAnswers of invalidAnswerSets) {
      expect(releaseLockActionCheckInternals.exactSubmittedAnswers(
        submittedAnswers,
        stored,
      )).toBe(false);
    }

    const credential = {
      credential_id: 'credential_1234567890',
      public_key_cose: 'AQ',
      public_key_spki: 'AQ',
      sign_count: 0,
    };
    const validAssertion = {
      id: credential.credential_id,
      response: {},
    };
    const cases = [
      { assertion: null, allowedOrigins: ['https://example.com'], rpId: 'example.com' },
      { assertion: { ...validAssertion, id: '' }, allowedOrigins: ['https://example.com'], rpId: 'example.com' },
      { assertion: { ...validAssertion, id: 'other' }, allowedOrigins: ['https://example.com'], rpId: 'example.com' },
      { assertion: { id: credential.credential_id }, allowedOrigins: ['https://example.com'], rpId: 'example.com' },
      { assertion: validAssertion, allowedOrigins: null, rpId: 'example.com' },
      { assertion: validAssertion, allowedOrigins: [], rpId: 'example.com' },
      { assertion: validAssertion, allowedOrigins: ['https://example.com'], rpId: '' },
    ];
    for (const values of cases) {
      await expect(verifyReleaseLockActionCheck({
        challenge: stored,
        submittedAnswers: built.expectedAnswers,
        credential,
        ...values,
      })).rejects.toMatchObject({
        status: 400,
        code: 'assertion_invalid',
      });
    }
  });
});

describe('Release Lock provider boundary', () => {
  function reconciliationResult({
    beneficiary = 'custodian_destination_1',
    accepted = false,
    disbursed = false,
  } = {}) {
    return {
      kind: 'reconciled',
      provider: 'escrow_com',
      environment: 'sandbox',
      operation: 'reconcile_transaction',
      transaction_id: 'txn_123',
      transaction: {
        currency: 'USD',
        milestones: [{
          provider_item_id: 'provider_milestone_7',
          status: { accepted },
          schedules: [{
            beneficiary_customer: beneficiary,
            amount: '1250.00',
            status: {
              secured: true,
              payment_received: true,
              disbursed_to_beneficiary: disbursed,
            },
          }],
        }],
      },
    };
  }

  function releasedResult(kind = 'released', changes = {}) {
    const effect = effectFixture();
    return {
      kind,
      provider: 'escrow_com',
      environment: 'sandbox',
      operation: 'release_milestone',
      effect_reference: effect.effect_reference,
      transaction_id: effect.transaction_id,
      milestone_id: effect.milestone_id,
      provider_phase: kind === 'released' ? 'disbursed' : null,
      ...changes,
    };
  }

  function custodianBoundary({
    beneficiary = 'custodian_destination_1',
    ignoreClaim = false,
  } = {}) {
    const releaseMilestone = vi.fn();
    const reconcileTransaction = vi.fn(async () => reconciliationResult({ beneficiary }));
    const boundary = createReleaseLockAdapterBoundary({
      resolveCustodianAdapter: ({ claimEffectBinding }) => ({
        kind: 'external_custodian',
        provider: 'escrow_com',
        environment: 'sandbox',
        reconcileTransaction,
        releaseMilestone: releaseMilestone.mockImplementation(async (request) => {
          if (!ignoreClaim) {
            const claimed = await claimEffectBinding({
              effect_reference: request.effectReference,
              transaction_id: request.transactionId,
              milestone_id: request.milestoneId,
            });
            if (claimed !== true) {
              return {
                kind: 'refused',
                provider: 'escrow_com',
                environment: 'sandbox',
                operation: 'release_milestone',
                reason_code: 'EFFECT_REFERENCE_CONFLICT',
                effect_reference: request.effectReference,
                transaction_id: request.transactionId,
                milestone_id: request.milestoneId,
              };
            }
          }
          return releasedResult('released', {
            effect_reference: request.effectReference,
            transaction_id: request.transactionId,
            milestone_id: request.milestoneId,
          });
        }),
      }),
    });
    return { boundary, reconcileTransaction, releaseMilestone };
  }

  it('requires a bound, canonical invitation-delivery result', async () => {
    const invitation = {
      lock_id: LOCK_ID,
      role: 'customer',
      channel: 'email',
      identifier: 'customer@example.com',
      token: Buffer.alloc(32, 1).toString('base64url'),
      expires_at: INVITE_EXPIRES,
    };
    const valid = {
      kind: 'delivered',
      channel: 'email',
      role: 'customer',
      lock_id: LOCK_ID,
      provider: 'delivery_provider',
      reference: 'delivery_123',
    };
    const deliver = vi.fn(async () => valid);
    const boundary = createReleaseLockAdapterBoundary({
      resolveInvitationAdapter: () => ({
        kind: 'verified_contact_delivery',
        channel: 'email',
        deliver,
      }),
    });
    await expect(boundary.deliverInvitation(invitation)).resolves.toEqual({
      role: 'customer',
      channel: 'email',
      provider: 'delivery_provider',
      reference: 'delivery_123',
      delivered: true,
    });

    for (const result of [
      null,
      { ...valid, kind: 'queued' },
      { ...valid, channel: 'sms' },
      { ...valid, role: 'contractor' },
      { ...valid, lock_id: `rlk_${'2'.repeat(32)}` },
      { ...valid, provider: '' },
      { ...valid, reference: '' },
      { ...valid, extra: 1n },
    ]) {
      deliver.mockResolvedValueOnce(result);
      await expect(boundary.deliverInvitation(invitation)).rejects.toMatchObject({
        status: 503,
        code: 'invitation_delivery_unavailable',
      });
    }
    deliver.mockRejectedValueOnce(new Error('provider down'));
    await expect(boundary.deliverInvitation(invitation)).rejects.toMatchObject({
      status: 503,
      code: 'invitation_delivery_unavailable',
    });
  });

  it('refuses invitation adapters with the wrong kind, channel, or entry point', async () => {
    const invitation = {
      lock_id: LOCK_ID,
      role: 'customer',
      channel: 'email',
      identifier: 'customer@example.com',
      token: Buffer.alloc(32, 1).toString('base64url'),
      expires_at: INVITE_EXPIRES,
    };
    for (const adapter of [
      { kind: 'other', channel: 'email', deliver: vi.fn() },
      { kind: 'verified_contact_delivery', channel: 'sms', deliver: vi.fn() },
      { kind: 'verified_contact_delivery', channel: 'email' },
    ]) {
      const boundary = createReleaseLockAdapterBoundary({
        resolveInvitationAdapter: () => adapter,
      });
      await expect(boundary.deliverInvitation(invitation)).rejects.toMatchObject({
        status: 503,
        code: 'invitation_delivery_adapter_invalid',
      });
    }
  });

  it('preflights and durably claims the exact amount, payees, and evidence before release', async () => {
    const { boundary, reconcileTransaction, releaseMilestone } = custodianBoundary();
    const claim = vi.fn(async () => true);
    const effect = effectFixture();
    await expect(boundary.executeEffect(effect, claim)).resolves.toMatchObject({
      status: 'applied',
      result: {
        effect_reference: effect.effect_reference,
        effect_contract_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
    });
    expect(reconcileTransaction.mock.invocationCallOrder[0])
      .toBeLessThan(releaseMilestone.mock.invocationCallOrder[0]);
    expect(claim).toHaveBeenCalledTimes(1);
    expect(claim.mock.invocationCallOrder[0])
      .toBeLessThan(releaseMilestone.mock.invocationCallOrder[0]);
    expect(claim.mock.calls[0][0]).toMatchObject({
      effect_reference: effect.effect_reference,
      effect_contract: {
        amount: '1250.00',
        currency: 'USD',
        payees: [{
          party_id: ACTOR,
          destination_id: 'custodian_destination_1',
          amount: '1250.00',
        }],
        evidence: {
          lien_waivers: [{
            payee_party_id: ACTOR,
            document: {
              reference: 'waiver_123',
              digest: DIGESTS.waiver,
            },
          }],
        },
      },
      effect_contract_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
  });

  it('claims durably before a custodian adapter that ignores the claim callback', async () => {
    const { boundary, releaseMilestone } = custodianBoundary({ ignoreClaim: true });
    const claim = vi.fn(async () => true);

    await expect(boundary.executeEffect(effectFixture(), claim)).resolves.toMatchObject({
      status: 'applied',
    });
    expect(claim).toHaveBeenCalledTimes(1);
    expect(claim.mock.invocationCallOrder[0])
      .toBeLessThan(releaseMilestone.mock.invocationCallOrder[0]);
  });

  it('never calls the custodian when the durable effect claim is refused', async () => {
    const { boundary, releaseMilestone } = custodianBoundary();
    await expect(boundary.executeEffect(
      effectFixture(),
      async () => false,
    )).rejects.toMatchObject({
      status: 409,
      code: 'effect_claim_refused',
    });
    expect(releaseMilestone).not.toHaveBeenCalled();
  });

  it('turns a post-claim provider exception into an unknown, non-retryable effect', async () => {
    const { boundary, releaseMilestone } = custodianBoundary();
    releaseMilestone.mockRejectedValueOnce(new Error('connection reset'));
    await expect(boundary.executeEffect(
      effectFixture(),
      async () => true,
    )).resolves.toMatchObject({
      status: 'unknown_effect',
      retryable: false,
      result: {
        kind: 'provider_error',
        reason_code: 'PROVIDER_OUTCOME_UNKNOWN',
      },
    });
  });

  it.each([
    ['provider_action_required', 'no_effect', true],
    ['refused', 'no_effect', false],
    ['pending', 'unknown_effect', false],
  ])('maps custodian result %s to %s', async (kind, status, retryable) => {
    const { boundary, releaseMilestone } = custodianBoundary();
    releaseMilestone.mockResolvedValueOnce(releasedResult(kind));
    await expect(boundary.executeEffect(
      effectFixture(),
      async () => true,
    )).resolves.toMatchObject({ status, retryable });
  });

  it('refuses an unbound or non-canonical custodian mutation result', async () => {
    for (const result of [
      null,
      releasedResult('released', { provider: 'other' }),
      releasedResult('released', { environment: 'production' }),
      releasedResult('released', { effect_reference: 'effect_other' }),
      releasedResult('released', { transaction_id: 'txn_other' }),
      releasedResult('released', { milestone_id: 'milestone_other' }),
      releasedResult('released', { extra: 1n }),
    ]) {
      const { boundary, releaseMilestone } = custodianBoundary();
      releaseMilestone.mockResolvedValueOnce(result);
      await expect(boundary.executeEffect(
        effectFixture(),
        async () => true,
      )).rejects.toMatchObject({
        status: 503,
        code: 'custodian_provider_unavailable',
      });
    }
  });

  it.each([
    [false, false, 'no_effect', true, 'not_accepted'],
    [true, false, 'unknown_effect', false, 'accepted_pending_disbursement'],
    [true, true, 'applied', false, 'disbursed'],
  ])(
    'reconciles accepted=%s disbursed=%s to %s',
    async (accepted, disbursed, status, retryable, providerPhase) => {
      const { boundary, reconcileTransaction } = custodianBoundary();
      reconcileTransaction.mockResolvedValueOnce(reconciliationResult({
        accepted,
        disbursed,
      }));
      await expect(boundary.reconcileEffect(effectFixture())).resolves.toMatchObject({
        status,
        retryable,
        result: { provider_phase: providerPhase },
      });
    },
  );

  it('refuses malformed, unbound, or unavailable reconciliation results', async () => {
    const valid = reconciliationResult();
    for (const result of [
      null,
      { ...valid, kind: 'pending' },
      { ...valid, provider: 'other' },
      { ...valid, environment: 'production' },
      { ...valid, transaction_id: 'txn_other' },
      { ...valid, transaction: null },
      { ...valid, extra: 1n },
    ]) {
      const { boundary, reconcileTransaction } = custodianBoundary();
      reconcileTransaction.mockResolvedValueOnce(result);
      await expect(boundary.reconcileEffect(effectFixture())).rejects.toMatchObject({
        status: 503,
        code: 'custodian_reconciliation_unavailable',
      });
    }

    const { boundary, reconcileTransaction } = custodianBoundary();
    reconcileTransaction.mockRejectedValueOnce(new Error('provider down'));
    await expect(boundary.reconcileEffect(effectFixture())).rejects.toMatchObject({
      status: 503,
      code: 'custodian_reconciliation_unavailable',
    });
  });

  it('refuses a reconciliation schedule that diverges from the signed draw', async () => {
    const { boundary, reconcileTransaction } = custodianBoundary();
    reconcileTransaction.mockResolvedValueOnce(reconciliationResult({
      beneficiary: 'attacker_destination',
    }));
    await expect(boundary.reconcileEffect(effectFixture())).rejects.toMatchObject({
      status: 409,
      code: 'effect_binding_mismatch',
    });
  });

  it('refuses payee substitution before claim or provider mutation', async () => {
    const { boundary, releaseMilestone } = custodianBoundary({
      beneficiary: 'attacker_destination',
    });
    const claim = vi.fn(async () => true);
    await expect(boundary.executeEffect(effectFixture(), claim)).rejects.toMatchObject({
      status: 409,
      code: 'effect_binding_mismatch',
    });
    expect(claim).not.toHaveBeenCalled();
    expect(releaseMilestone).not.toHaveBeenCalled();
  });

  it('requires authoritative provider evidence for the exact named party', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const document = {
      provider: 'adobe_sign',
      reference: 'waiver_123',
      verification: {
        status: 'SIGNED',
        participant_sets: [{
          id: 'set_1',
          role: 'SIGNER',
          order: 1,
          members: [{ email: 'builder@example.com' }],
        }],
      },
    };
    const boundary = createReleaseLockAdapterBoundary({
      resolveDocumentAdapter: () => ({
        kind: 'external_esign_adapter',
        provider: 'adobe_sign',
        fetchFinalEvidence: async () => ({
          kind: 'evidence_ready',
          provider: 'adobe_sign',
          document_bytes: bytes,
          evidence: {
            '@version': 'EP-EXTERNAL-DOCUMENT-EVIDENCE-v1',
            provider: 'adobe_sign',
            retrieval_method: 'provider_api',
            api_origin: 'https://api.adobesign.com',
            agreement_id: 'waiver_123',
            agreement_status: 'SIGNED',
            agreement_version: 'v1',
            agreement_events_digest: DIGESTS.draw,
            participant_sets: [{
              set_id: 'set_1',
              role: 'SIGNER',
              order: 1,
              members: [{
                email: 'builder@example.com',
                party_id: ACTOR,
                role: 'contractor',
              }],
            }],
            document: {
              sha256: bytesDigest(bytes),
              byte_length: bytes.byteLength,
              media_type: 'application/pdf',
            },
            observed_at: '2030-01-01T00:00:00.000Z',
          },
        }),
      }),
    });
    await expect(boundary.fetchDocument(document, {
      requiredSubjects: [{ party_id: ACTOR, role: 'contractor' }],
    })).resolves.toMatchObject({
      provider: 'adobe_sign',
      reference: 'waiver_123',
    });
    await expect(boundary.fetchDocument(document, {
      requiredSubjects: [{ party_id: 'attacker:substitute' }],
    })).rejects.toMatchObject({
      status: 422,
      code: 'document_participant_mismatch',
    });
  });
});

describe('Release Lock service fail-closed behavior', () => {
  it('fails closed when live document or custodian adapters are unconfigured', async () => {
    const boundary = createReleaseLockAdapterBoundary();
    await expect(boundary.deliverInvitation({
      lock_id: LOCK_ID,
      role: 'customer',
      channel: 'email',
      identifier: 'customer@example.com',
      token: 'x'.repeat(43),
      expires_at: INVITE_EXPIRES,
    })).rejects.toMatchObject({
      status: 503,
      code: 'invitation_delivery_adapter_unconfigured',
    });
    await expect(boundary.fetchDocument({
      provider: 'adobe_sign',
      reference: 'agreement_123',
    }, {})).rejects.toMatchObject({
      status: 503,
      code: 'document_provider_adapter_unconfigured',
    });
    await expect(boundary.executeEffect(
      effectFixture(),
      async () => true,
    )).rejects.toMatchObject({
      status: 503,
      code: 'custodian_adapter_unconfigured',
    });
  });

  it('delivers each invitation to its verified contact and returns no raw secrets', async () => {
    const suite = cryptoSuite();
    let storedArgs;
    const delivered = [];
    const timeline = [];
    const adapters = {
      deliverInvitation: vi.fn(async (invitation) => {
        timeline.push(`deliver:${invitation.role}`);
        delivered.push(invitation);
        return {
          role: invitation.role,
          channel: invitation.channel,
          provider: 'test_delivery',
          reference: `delivery_${invitation.role}`,
          delivered: true,
        };
      }),
      fetchDocument: vi.fn(async (document) => providerEvidence(document, DIGESTS.co)),
      executeEffect: vi.fn(),
      reconcileEffect: vi.fn(),
    };
    const operations = [];
    const service = createReleaseLockService({
      rpc: async (name, args) => {
        operations.push(name);
        timeline.push(name);
        if (name === 'release_lock_create_pending') {
          storedArgs = args;
          return {
            data: {
              lock_id: args.p_lock_id,
              status: 'invitations_pending',
            },
            error: null,
          };
        }
        expect(name).toBe('release_lock_activate_invitations');
        return {
          data: {
            lock_id: args.p_lock_id,
            version: 1,
            round: 'CO_ACCEPTED',
            status: 'co_pending',
          },
          error: null,
        };
      },
      cryptoSuite: suite,
      adapters,
      now: () => NOW,
      randomUUID: (() => {
        let value = 0;
        return () => `11111111-1111-4111-8111-${String(value += 1).padStart(12, '0')}`;
      })(),
    });
    const result = await service.createLock({
      organizationId: ORG,
      contractorEntityId: ACTOR,
      input: changeOrderInput(suite),
    });
    expect(result).not.toHaveProperty('invitations');
    expect(result.invitation_deliveries).toEqual([
      {
        role: 'contractor',
        channel: 'email',
        provider: 'test_delivery',
        reference: 'delivery_contractor',
        delivered: true,
      },
      {
        role: 'customer',
        channel: 'email',
        provider: 'test_delivery',
        reference: 'delivery_customer',
        delivered: true,
      },
    ]);
    expect(delivered).toHaveLength(2);
    expect(delivered.every((invite) => invite.token.length === 43)).toBe(true);
    const persisted = JSON.stringify(storedArgs);
    const response = JSON.stringify(result);
    for (const invitation of delivered) {
      expect(persisted).not.toContain(invitation.token);
      expect(response).not.toContain(invitation.token);
    }
    expect(persisted).not.toContain('builder@example.com');
    expect(persisted).not.toContain('customer@example.com');
    expect(storedArgs.p_invitations.every(
      (invite) => /^hmac-sha256:[0-9a-f]{64}$/.test(invite.token_digest),
    )).toBe(true);
    expect(operations).toEqual([
      'release_lock_create_pending',
      'release_lock_activate_invitations',
    ]);
    expect(timeline[0]).toBe('release_lock_create_pending');
    expect(timeline.at(-1)).toBe('release_lock_activate_invitations');
  });

  it('cancels non-exchangeable pending invitations when either delivery fails', async () => {
    const suite = cryptoSuite();
    const storage = vi.fn(async (name) => {
      if (name === 'release_lock_create_pending') {
        return { data: { status: 'invitations_pending' }, error: null };
      }
      if (name === 'release_lock_cancel_pending') {
        return { data: { status: 'cancelled' }, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = createReleaseLockService({
      rpc: storage,
      cryptoSuite: suite,
      adapters: {
        deliverInvitation: vi.fn(async ({ role }) => {
          if (role === 'customer') {
            throw Object.assign(new Error('delivery unavailable'), {
              status: 503,
              code: 'invitation_delivery_unavailable',
            });
          }
          return {
            role,
            channel: 'email',
            provider: 'test_delivery',
            reference: `delivery_${role}`,
            delivered: true,
          };
        }),
        fetchDocument: vi.fn(async (document) => providerEvidence(document, DIGESTS.co)),
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
    });
    await expect(service.createLock({
      organizationId: ORG,
      contractorEntityId: ACTOR,
      input: changeOrderInput(suite),
    })).rejects.toMatchObject({
      status: 503,
      code: 'invitation_delivery_unavailable',
    });
    expect(storage.mock.calls.map(([name]) => name)).toEqual([
      'release_lock_create_pending',
      'release_lock_cancel_pending',
    ]);
  });

  it('never delivers an invitation when pending persistence fails', async () => {
    const suite = cryptoSuite();
    const deliverInvitation = vi.fn();
    const service = createReleaseLockService({
      rpc: async () => ({
        data: null,
        error: { message: 'connection reset', details: 'storage unavailable' },
      }),
      cryptoSuite: suite,
      adapters: {
        deliverInvitation,
        fetchDocument: vi.fn(async (document) => providerEvidence(document, DIGESTS.co)),
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
    });
    await expect(service.createLock({
      organizationId: ORG,
      contractorEntityId: ACTOR,
      input: changeOrderInput(suite),
    })).rejects.toMatchObject({
      status: 503,
      code: 'release_lock_storage_unavailable',
    });
    expect(deliverInvitation).not.toHaveBeenCalled();
  });

  it('binds every staged draw document to the authoritative required parties', async () => {
    const { co } = builtActions();
    const fetchDocument = vi.fn(async (document) => {
      const digest = {
        completion_123: DIGESTS.completion,
        waiver_123: DIGESTS.waiver,
        draw_packet_123: DIGESTS.draw,
      }[document.reference];
      return providerEvidence(document, digest);
    });
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_draw_context') {
        return {
          data: {
            version: 1,
            lock_expires_at: LOCK_EXPIRES,
            co_action_hash: co.actionHash,
            co_acceptance_digest: `sha256:${'a'.repeat(64)}`,
            co_action: co.action,
          },
          error: null,
        };
      }
      if (name === 'release_lock_stage_draw') {
        return {
          data: {
            lock_id: args.p_lock_id,
            version: 1,
            round: 'DRAW_RELEASE',
          },
          error: null,
        };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = serviceWith({
      rpc,
      adapters: {
        fetchDocument,
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
    });
    await expect(service.stageDraw({
      organizationId: ORG,
      contractorEntityId: ACTOR,
      lockId: LOCK_ID,
      input: drawInput(),
    })).resolves.toMatchObject({
      round: 'DRAW_RELEASE',
      action: {
        lien_waivers: [{
          payee_party_id: ACTOR,
        }],
      },
    });
    const requiredParties = co.action.parties.map(({ party_id, role }) => ({
      party_id,
      role,
    }));
    expect(fetchDocument.mock.calls[0][1].requiredSubjects).toEqual(requiredParties);
    expect(fetchDocument.mock.calls[1]).toEqual([
      drawInput().draw.lien_waivers[0].document,
      {
        requireBoundParticipants: false,
        requiredSubjects: [{ party_id: ACTOR }],
      },
    ]);
    expect(fetchDocument.mock.calls[2][1].requiredSubjects).toEqual(requiredParties);
  });

  it('labels the unsigned outer digest only as a transport corruption check', async () => {
    const service = serviceWith({
      rpc: async (name) => {
        expect(name).toBe('release_lock_evidence');
        return {
          data: {
            lock_id: LOCK_ID,
            signed_evidence: [{ profile: 'EP-RECEIPT-v1' }],
          },
          error: null,
        };
      },
    });
    const exported = await service.evidence({
      organizationId: ORG,
      lockId: LOCK_ID,
    });
    expect(exported).not.toHaveProperty('integrity');
    expect(exported.content_digest).toMatchObject({
      algorithm: 'sha-256',
      purpose: 'transport_corruption_check_only',
    });
    expect(JSON.stringify(exported.content_digest).toLowerCase())
      .not.toMatch(/authentic|integrity/);
    expect(exported.limitations.join(' ')).toContain(
      'Authenticity comes only from re-verifying each signed evidence artifact',
    );
    expect(exported.limitations.join(' ')).not.toContain(
      'records the counterparty\'s decision bindings by digest only',
    );
  });

  it('states on participant evidence that counterparty decisions are digest-only', async () => {
    const suite = cryptoSuite();
    const session = suite.session();
    const service = serviceWith({
      rpc: async (name) => {
        expect(name).toBe('release_lock_participant_evidence');
        return { data: { lock: { lock_id: LOCK_ID } }, error: null };
      },
    });
    const exported = await service.participantEvidence({
      rawSessionToken: session.token,
      lockId: LOCK_ID,
    });
    const limitations = exported.limitations.join(' ');
    expect(limitations).toContain(
      'Participant evidence proves the holder\'s own approvals in full',
    );
    expect(limitations).toContain(
      'requires their credential key from the operator evidence export',
    );
  });

  it.each([
    ['RL_INVITATION_SCOPE', 403, 'invitation_scope_mismatch'],
    ['RL_INVITATION_REPLAYED', 409, 'invitation_replayed'],
    ['RL_INVITATION_EXPIRED', 410, 'invitation_expired'],
  ])('maps hostile invitation refusal %s without a 500', async (marker, status, code) => {
    const suite = cryptoSuite();
    const invite = suite.invitation();
    const service = serviceWith({
      rpc: async () => ({ data: null, error: { message: marker } }),
    });
    await expect(service.exchangeInvitation({
      token: invite.token,
      lock_id: LOCK_ID,
      role: 'customer',
    })).rejects.toMatchObject({ status, code });
  });

  it('creates a short-lived round-scoped Action Mirror capability without persisting its secret', async () => {
    const suite = cryptoSuite();
    const session = suite.session();
    let storedArgs;
    const service = createReleaseLockService({
      rpc: async (name, args) => {
        expect(name).toBe('release_lock_create_pairing');
        storedArgs = args;
        return {
          data: {
            pairing_id: args.p_pairing_id,
            lock_id: args.p_lock_id,
            role: 'customer',
            round: args.p_round,
            expires_at: args.p_expires_at,
          },
          error: null,
        };
      },
      cryptoSuite: suite,
      adapters: {
        deliverInvitation: vi.fn(),
        fetchDocument: vi.fn(),
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      randomUUID: () => '11111111-1111-4111-8111-111111111111',
    });
    const result = await service.createPairing({
      rawSessionToken: session.token,
      lockId: LOCK_ID,
      round: 'DRAW_RELEASE',
    });

    expect(result).toMatchObject({
      lock_id: LOCK_ID,
      role: 'customer',
      round: 'DRAW_RELEASE',
    });
    expect(result.rawPairingToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(storedArgs.p_token_digest).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(storedArgs)).not.toContain(result.rawPairingToken);
    expect(Date.parse(storedArgs.p_expires_at) - NOW).toBe(5 * 60 * 1000);
  });

  it('exchanges an exact pairing into a short-lived session and types replay or scope refusal', async () => {
    const suite = cryptoSuite();
    const pairing = suite.pairing();
    const service = createReleaseLockService({
      rpc: async (name, args) => {
        expect(name).toBe('release_lock_exchange_pairing');
        expect(args.p_token_digest).toBe(suite.pairingDigest(pairing.token));
        return {
          data: {
            lock_id: LOCK_ID,
            role: 'customer',
            round: 'CO_ACCEPTED',
            session_expires_at: new Date(NOW + 30 * 60 * 1000).toISOString(),
          },
          error: null,
        };
      },
      cryptoSuite: suite,
      adapters: {
        deliverInvitation: vi.fn(),
        fetchDocument: vi.fn(),
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      randomUUID: () => '11111111-1111-4111-8111-111111111111',
    });
    const result = await service.exchangePairing({
      token: pairing.token,
      lock_id: LOCK_ID,
      role: 'customer',
      round: 'CO_ACCEPTED',
    });
    expect(result.rawSessionToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.round).toBe('CO_ACCEPTED');
  });

  it.each([
    ['RL_PAIRING_SCOPE', 403, 'pairing_scope_mismatch'],
    ['RL_PAIRING_REPLAYED', 409, 'pairing_replayed'],
    ['RL_PAIRING_EXPIRED', 410, 'pairing_expired'],
  ])('maps hostile pairing refusal %s without a 500', async (marker, status, code) => {
    const suite = cryptoSuite();
    const pairing = suite.pairing();
    const service = serviceWith({
      rpc: async () => ({ data: null, error: { message: marker } }),
    });
    await expect(service.exchangePairing({
      token: pairing.token,
      lock_id: LOCK_ID,
      role: 'customer',
      round: 'CO_ACCEPTED',
    })).rejects.toMatchObject({ status, code });
  });

  it.each([
    ['RL_SESSION_SCOPE', 403, 'session_scope_mismatch'],
    ['RL_CREDENTIAL_REUSED', 409, 'credential_reused_across_roles'],
    ['RL_CONTACT_REUSED', 409, 'contact_reused_across_roles'],
    ['RL_AUTHORITY_REUSED', 409, 'authority_subject_reused'],
    ['RL_INVITATION_INACTIVE', 409, 'invitation_inactive'],
    ['RL_VERSION_STALE', 409, 'stale_release_lock_version'],
    ['RL_CHALLENGE_REPLAYED', 409, 'challenge_replayed'],
    ['RL_APPROVAL_LIMIT', 409, 'approval_quorum_already_complete'],
    ['RL_EFFECT_RESERVATION_ACTIVE', 409, 'effect_recovery_too_early'],
    ['RL_EFFECT_NOT_RECOVERABLE', 409, 'effect_not_recoverable'],
  ])('types persistence refusal %s', (marker, status, code) => {
    expect(mapReleaseLockRpcError({ message: marker })).toMatchObject({ status, code });
  });

  it('never invokes a custodian for a complete CO_ACCEPTED round', async () => {
    const suite = cryptoSuite();
    const session = suite.session();
    const executeEffect = vi.fn();
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_load_action_challenge') {
        return {
          data: {
            credential: {
              credential_id: 'credential_1234567890',
              rp_id: 'example.com',
              origin: 'https://example.com',
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_record_approval') {
        return {
          data: {
            round: 'CO_ACCEPTED',
            quorum_complete: true,
            payment_authorized: false,
            invoke_effect: false,
          },
          error: null,
        };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = createReleaseLockService({
      rpc,
      cryptoSuite: suite,
      adapters: {
        fetchDocument: vi.fn(),
        executeEffect,
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      rpConfigProvider: () => ({
        rpID: 'example.com',
        origin: 'https://example.com',
      }),
      actionCheckVerifier: async () => ({
        receipt: { profile: 'EP-RESOLUTION-v1', signoff: { context: {} } },
        newCounter: 1,
      }),
    });
    const result = await service.approve({
      rawSessionToken: session.token,
      lockId: LOCK_ID,
      round: 'CO_ACCEPTED',
      input: {
        challenge_id: '11111111-1111-4111-8111-111111111111',
        answers: [],
        assertion: {},
      },
    });
    expect(result.payment_authorized).toBe(false);
    expect(executeEffect).not.toHaveBeenCalled();
  });

  it('claims and invokes one DRAW_RELEASE effect once', async () => {
    const suite = cryptoSuite();
    const session = suite.session();
    const effect = {
      effect_reference: 'rl:effect:1',
      provider: 'escrow_com',
      environment: 'sandbox',
      transaction_id: 'txn_123',
      milestone_id: 'provider_milestone_7',
      instruction: 'release_milestone',
      action: { payees: [], currency: 'USD' },
    };
    const executeEffect = vi.fn(async (boundEffect, claim) => {
      expect(boundEffect).toEqual(effect);
      const effectContract = {
        '@version': 'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1',
        effect_reference: effect.effect_reference,
      };
      const effectContractDigest = `sha256:${'c'.repeat(64)}`;
      await expect(claim({
        effect_reference: effect.effect_reference,
        transaction_id: effect.transaction_id,
        milestone_id: effect.milestone_id,
        effect_contract: effectContract,
        effect_contract_digest: effectContractDigest,
      })).resolves.toBe(true);
      return {
        status: 'applied',
        retryable: false,
        result: {
          provider: effect.provider,
          environment: effect.environment,
          effect_reference: effect.effect_reference,
          transaction_id: effect.transaction_id,
          milestone_id: effect.milestone_id,
        },
      };
    });
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_load_action_challenge') {
        return {
          data: {
            credential: {
              credential_id: 'credential_1234567890',
              rp_id: 'example.com',
              origin: 'https://example.com',
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_record_approval') {
        return {
          data: {
            round: 'DRAW_RELEASE',
            quorum_complete: true,
            invoke_effect: true,
            effect,
          },
          error: null,
        };
      }
      if (name === 'release_lock_claim_effect_binding') {
        expect(args).toMatchObject({
          p_effect_contract: {
            '@version': 'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1',
            effect_reference: effect.effect_reference,
          },
          p_effect_contract_digest: `sha256:${'c'.repeat(64)}`,
        });
        return { data: true, error: null };
      }
      if (name === 'release_lock_record_effect_outcome') {
        expect(args).toMatchObject({
          p_outcome: 'applied',
          p_retryable: false,
        });
        return {
          data: {
            effect_reference: effect.effect_reference,
            status: 'applied',
          },
          error: null,
        };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = createReleaseLockService({
      rpc,
      cryptoSuite: suite,
      adapters: {
        fetchDocument: vi.fn(),
        executeEffect,
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      rpConfigProvider: () => ({
        rpID: 'example.com',
        origin: 'https://example.com',
      }),
      actionCheckVerifier: async () => ({
        receipt: { profile: 'EP-RESOLUTION-v1', signoff: { context: {} } },
        newCounter: 1,
      }),
    });
    await expect(service.approve({
      rawSessionToken: session.token,
      lockId: LOCK_ID,
      round: 'DRAW_RELEASE',
      input: {
        challenge_id: '11111111-1111-4111-8111-111111111111',
        answers: [],
        assertion: {},
      },
    })).resolves.toMatchObject({
      quorum_complete: true,
      effect: { status: 'applied' },
    });
    expect(executeEffect).toHaveBeenCalledTimes(1);
    expect(rpc.mock.calls.filter(([name]) => name === 'release_lock_claim_effect_binding'))
      .toHaveLength(1);
  });

  it('refuses concurrent second approvals deterministically and invokes one effect', async () => {
    const suite = cryptoSuite();
    const contractorSession = suite.session();
    const customerSession = suite.session();
    const effect = {
      effect_reference: 'rl:effect:concurrent',
      provider: 'escrow_com',
      environment: 'sandbox',
      transaction_id: 'txn_concurrent',
      milestone_id: 'milestone_concurrent',
      instruction: 'release_milestone',
      action: { payees: [], currency: 'USD' },
    };
    let quorumConsumed = false;
    const executeEffect = vi.fn(async (boundEffect, claim) => {
      await claim({
        effect_reference: boundEffect.effect_reference,
        transaction_id: boundEffect.transaction_id,
        milestone_id: boundEffect.milestone_id,
      });
      return {
        status: 'applied',
        retryable: false,
        result: {
          provider: effect.provider,
          environment: effect.environment,
          effect_reference: effect.effect_reference,
          transaction_id: effect.transaction_id,
          milestone_id: effect.milestone_id,
        },
      };
    });
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_load_action_challenge') {
        return {
          data: {
            credential: {
              credential_id: args.p_challenge_id.endsWith('1')
                ? 'contractor_credential_1'
                : 'customer_credential_2',
              rp_id: 'example.com',
              origin: 'https://example.com',
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_record_approval') {
        if (quorumConsumed) {
          return { data: null, error: { message: 'RL_ROUND_COMPLETE' } };
        }
        quorumConsumed = true;
        return {
          data: {
            round: 'DRAW_RELEASE',
            quorum_complete: true,
            invoke_effect: true,
            effect,
          },
          error: null,
        };
      }
      if (name === 'release_lock_claim_effect_binding') {
        return { data: true, error: null };
      }
      if (name === 'release_lock_record_effect_outcome') {
        return { data: { status: 'applied' }, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = createReleaseLockService({
      rpc,
      cryptoSuite: suite,
      adapters: {
        fetchDocument: vi.fn(),
        executeEffect,
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      rpConfigProvider: () => ({
        rpID: 'example.com',
        origin: 'https://example.com',
      }),
      actionCheckVerifier: async ({ credential }) => ({
        receipt: {
          profile: 'EP-RESOLUTION-v1',
          signoff: { context: { principal_key_id: credential.credential_id } },
        },
        newCounter: 1,
      }),
    });
    const submission = (rawSessionToken, challengeId) => service.approve({
      rawSessionToken,
      lockId: LOCK_ID,
      round: 'DRAW_RELEASE',
      input: {
        challenge_id: challengeId,
        answers: [],
        assertion: {},
      },
    });
    const results = await Promise.allSettled([
      submission(
        contractorSession.token,
        '11111111-1111-4111-8111-111111111111',
      ),
      submission(
        customerSession.token,
        '22222222-2222-4222-8222-222222222222',
      ),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const refusal = results.find((result) => result.status === 'rejected');
    expect(refusal.reason).toMatchObject({
      status: 409,
      code: 'release_lock_round_complete',
    });
    expect(executeEffect).toHaveBeenCalledTimes(1);
  });

  it('does not record success after a claimed provider call becomes ambiguous', async () => {
    const suite = cryptoSuite();
    const session = suite.session();
    const providerError = new Error('provider connection closed after request');
    const rpc = vi.fn(async (name) => {
      if (name === 'release_lock_load_action_challenge') {
        return {
          data: {
            credential: {
              credential_id: 'credential_1234567890',
              rp_id: 'example.com',
              origin: 'https://example.com',
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_record_approval') {
        return {
          data: {
            round: 'DRAW_RELEASE',
            invoke_effect: true,
            effect: {
              effect_reference: 'rl:effect:ambiguous',
              provider: 'escrow_com',
              environment: 'sandbox',
              transaction_id: 'txn_ambiguous',
              milestone_id: 'milestone_ambiguous',
              instruction: 'release_milestone',
              action: { payees: [], currency: 'USD' },
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_claim_effect_binding') {
        return { data: true, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = createReleaseLockService({
      rpc,
      cryptoSuite: suite,
      adapters: {
        fetchDocument: vi.fn(),
        executeEffect: vi.fn(async (effect, claim) => {
          await claim({
            effect_reference: effect.effect_reference,
            transaction_id: effect.transaction_id,
            milestone_id: effect.milestone_id,
          });
          throw providerError;
        }),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
      rpConfigProvider: () => ({
        rpID: 'example.com',
        origin: 'https://example.com',
      }),
      actionCheckVerifier: async () => ({
        receipt: { profile: 'EP-RESOLUTION-v1', signoff: { context: {} } },
        newCounter: 1,
      }),
    });
    await expect(service.approve({
      rawSessionToken: session.token,
      lockId: LOCK_ID,
      round: 'DRAW_RELEASE',
      input: {
        challenge_id: '11111111-1111-4111-8111-111111111111',
        answers: [],
        assertion: {},
      },
    })).rejects.toBe(providerError);
    const recorded = rpc.mock.calls.find(
      ([name]) => name === 'release_lock_record_effect_outcome',
    );
    expect(recorded?.[1]).toMatchObject({
      p_outcome: 'unknown_effect',
      p_retryable: false,
    });
  });

  it('recovers a confirmed no-effect failure and retries the same effect idempotently', async () => {
    const effect = effectFixture();
    const transient = Object.assign(new Error('adapter unavailable'), {
      status: 503,
      code: 'custodian_adapter_unconfigured',
    });
    const recoveries = [];
    const executeEffect = vi.fn()
      .mockRejectedValueOnce(transient)
      .mockImplementationOnce(async (boundEffect, claim) => {
        await claim({
          effect_reference: boundEffect.effect_reference,
          transaction_id: boundEffect.transaction_id,
          milestone_id: boundEffect.milestone_id,
          effect_contract: { '@version': 'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1' },
          effect_contract_digest: `sha256:${'c'.repeat(64)}`,
        });
        return {
          status: 'applied',
          retryable: false,
          result: {
            provider: effect.provider,
            environment: effect.environment,
            effect_reference: effect.effect_reference,
            transaction_id: effect.transaction_id,
            milestone_id: effect.milestone_id,
          },
        };
      });
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_recover_effect') {
        recoveries.push(args);
        return {
          data: {
            mode: 'execute',
            effect,
          },
          error: null,
        };
      }
      if (name === 'release_lock_claim_effect_binding') {
        return { data: { claimed: true }, error: null };
      }
      if (name === 'release_lock_record_effect_outcome') {
        if (args.p_outcome === 'no_effect') {
          return { data: null, error: { message: 'RL_EFFECT_ALREADY_CLAIMED' } };
        }
        return {
          data: {
            effect_reference: effect.effect_reference,
            status: args.p_outcome,
          },
          error: null,
        };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const service = serviceWith({
      rpc,
      adapters: {
        executeEffect,
        reconcileEffect: vi.fn(),
      },
    });
    const recoveryInput = {
      effectReference: effect.effect_reference,
    };
    await expect(service.reconcile(recoveryInput)).rejects.toBe(transient);
    await expect(service.reconcile(recoveryInput)).resolves.toMatchObject({
      status: 'applied',
    });
    expect(recoveries).toHaveLength(2);
    expect(recoveries.every(
      (args) => args.p_effect_reference === effect.effect_reference,
    )).toBe(true);
    expect(executeEffect).toHaveBeenCalledTimes(2);
  });

  it('propagates provider and storage failures without continuing', async () => {
    const suite = cryptoSuite();
    const providerFailure = Object.assign(new Error('provider unavailable'), {
      status: 503,
      code: 'document_provider_unavailable',
    });
    const storage = vi.fn();
    const service = createReleaseLockService({
      rpc: storage,
      cryptoSuite: suite,
      adapters: {
        deliverInvitation: vi.fn(),
        fetchDocument: vi.fn(async () => {
          throw providerFailure;
        }),
        executeEffect: vi.fn(),
        reconcileEffect: vi.fn(),
      },
      now: () => NOW,
    });
    await expect(service.createLock({
      organizationId: ORG,
      contractorEntityId: ACTOR,
      input: changeOrderInput(suite),
    })).rejects.toBe(providerFailure);
    expect(storage).not.toHaveBeenCalled();

    const unavailable = serviceWith({
      rpc: async () => ({
        data: null,
        error: { message: 'connection reset', details: 'storage unavailable' },
      }),
    });
    await expect(unavailable.evidence({
      organizationId: ORG,
      lockId: LOCK_ID,
    })).rejects.toMatchObject({
      status: 503,
      code: 'release_lock_storage_unavailable',
    });
  });
});
