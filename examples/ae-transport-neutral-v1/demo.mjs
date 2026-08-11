#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * AE-CHALLENGE transport-neutral evidence negotiation demo.
 *
 * THE CLAIM THIS RUNS
 * -------------------
 * AE-CHALLENGE is evidence negotiation, not an OAuth replacement. One relying
 * party refuses one exact consequential action with one AE-CHALLENGE-v1
 * object, and the SAME challenge is then satisfied through TWO independent
 * evidence forms, evaluated by the SAME relying-party evaluator:
 *
 *   PATH 1 (OAuth):     a transaction-bound access token carrying RFC 9396
 *                       authorization_details for the exact action, verified
 *                       by the repo's draft-rosomakho-oauth-txn-challenge
 *                       AEB adapter. "OAuth as ONE evidence form."
 *   PATH 2 (non-OAuth): a human-key-signed EP authorization receipt
 *                       (Ed25519, packages/issue + packages/verify), with no
 *                       authorization server anywhere in the loop. "Evidence
 *                       OAuth cannot produce."
 *
 * One line: OAuth and others, not others instead of OAuth.
 *
 * WHAT IS REAL vs WHAT IS SIMULATED
 * ---------------------------------
 * REAL (repo code, not reimplemented here):
 *   - AE-CHALLENGE mint + RFC 9457 carrier: lib/negotiate/evidence-challenge.js
 *   - OAuth txn-challenge native verification (JWT signatures, txn binding,
 *     RAR details, audience, lifetimes): packages/verify
 *     aeb-oauth-transaction-challenge-adapter (source lock
 *     draft-rosomakho-oauth-txn-challenge-00)
 *   - CAID compute/verify: caid/impl/js/caid.mjs
 *   - Receipt issuance + verification: packages/issue, packages/verify
 *   - Reserve-before-effect consumption state machine:
 *     InMemoryAebConsumptionStore from packages/verify/aeb-adapter-contract
 * SIMULATED (STAND-INS, clearly labeled):
 *   - The OAuth protected-resource challenge JWT and the AS-issued access
 *     token are minted locally with throwaway ES256 keys. No live
 *     authorization server exists in this demo. The JWTs are constructed to
 *     the exact claim shape draft-rosomakho-oauth-txn-challenge-00 defines so
 *     the REAL adapter verifies them, but issuance itself is a stand-in.
 *   - The "human" approver key is a locally generated Ed25519 key pair.
 *
 * The evaluator keeps three outcomes distinct and never collapses them:
 *   ADMIT          evidence verified, denotes this exact action, authority
 *                  consumed exactly once, effect confirmed
 *   REFUSE         a check failed closed with a reason
 *   INDETERMINATE  the truth is unknown (effect response lost, or a prior
 *                  reservation is unresolved); authority is NOT released
 */
import crypto from 'node:crypto';

import {
  CHALLENGE_VERSION,
  createEvidenceChallenge,
  createEvidenceChallengeProblem,
  parseEvidenceChallengeProblem,
} from '../../lib/negotiate/evidence-challenge.js';
import { artifactDigest } from '../../lib/evidence/evidence-graph.js';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import {
  actionHash,
  generateEd25519KeyPair,
  issueTrustReceipt,
  publicKeyToSpkiB64u,
  softwareSignerFromPrivateKey,
} from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import {
  InMemoryAebConsumptionStore,
  digestAeb,
} from '../../packages/verify/aeb-adapter-contract.js';
import {
  OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
  OAUTH_TXN_CHALLENGE_MAPPER_ID,
  OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
  OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
  createOAuthTransactionChallengeActionDefinition,
  createOAuthTransactionChallengeAebAdapter,
} from '../../packages/verify/aeb-oauth-transaction-challenge-adapter.js';

export const DEMO_VERSION = 'EP-AE-TRANSPORT-NEUTRAL-DEMO-v1';

// Evidence-form identifiers. The challenge's present_as advertises which
// profile-specific presentation methods this relying party consumes; the
// AE-CHALLENGE core stays transport-neutral either way.
export const OAUTH_EVIDENCE_FORM = 'oauth-txn-challenge-v1';
export const RECEIPT_EVIDENCE_FORM = 'ep-receipt-v1';

const NOW = '2026-08-11T12:00:30Z';
const NOW_MS = Date.parse(NOW);
const NOW_SECONDS = Math.floor(NOW_MS / 1000);
const iso = (deltaMs) => new Date(NOW_MS + deltaMs).toISOString().replace(/\.\d{3}Z$/, 'Z');

const RS_AUDIENCE = 'https://rs.example/payments';
const OTHER_RS_AUDIENCE = 'https://other-rs.example/payments';
const AUTHORIZATION_SERVER = 'https://as.example';
const OAUTH_CLIENT_ID = 'agent-client-42';
const OAUTH_SUBJECT = 'principal:treasurer-9';
const ACTION_TYPE = 'payment.initiate.1';
const RAR_DETAIL_TYPE = 'ep-exact-action-v1';
const APPROVER_ID = 'ep:approver:treasurer-9';
const APPROVER_KEY_ID = 'ep:key:treasurer-9#2026-08';
const LOG_KEY_ID = 'ep:log:rs-example#1';

// The relying party's canonical Action Objects. CAID definitions pin which
// fields are material; the digest join across BOTH evidence forms is a
// recomputation over one of these objects, never a presented digest.
export const CAID_DEFINITIONS = Object.freeze([{
  action_type: ACTION_TYPE,
  required_fields: [
    { name: 'action_type', type: 'string' },
    { name: 'target', type: 'object' },
    { name: 'parameters', type: 'object' },
    { name: 'initiator', type: 'string' },
    { name: 'policy_id', type: 'string' },
  ],
  optional_fields: [{ name: 'requested_at', type: 'timestamp' }],
}]);

export const ACTION_A = Object.freeze({
  action_type: ACTION_TYPE,
  target: Object.freeze({ system: RS_AUDIENCE, resource: 'accounts/acct-981' }),
  parameters: Object.freeze({
    amount: '2500.00',
    currency: 'USD',
    beneficiary: 'vendor:acme-hvac',
  }),
  initiator: 'agent:procurement:7',
  policy_id: 'policy:rs-example:payments@1',
  requested_at: '2026-08-11T11:59:00Z',
});

export const ACTION_B = Object.freeze({
  ...ACTION_A,
  parameters: Object.freeze({ ...ACTION_A.parameters, amount: '250000.00' }),
});

// ---------------------------------------------------------------------------
// SIMULATED OAuth leg (STAND-IN). These JWTs stand in for what a real
// protected resource and authorization server would emit in the
// draft-rosomakho-oauth-txn-challenge flow. Verification below is the real
// repo adapter; only issuance is simulated.
// ---------------------------------------------------------------------------

function compactEs256(header, claims, privateKey) {
  const encodedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const encodedClaims = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const input = `${encodedHeader}.${encodedClaims}`;
  const signature = crypto.sign('sha256', Buffer.from(input, 'ascii'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${input}.${signature.toString('base64url')}`;
}

function rarDetailsFor(action) {
  // RFC 9396 authorization_details describing the exact action. The action
  // object rides inside the detail so both the AS-signed grant and the
  // relying party's expectation commit to the same canonical content.
  return [{ type: RAR_DETAIL_TYPE, action }];
}

/**
 * SIMULATED transaction-authorization outcome: the protected resource's
 * challenge JWT plus the AS-issued transaction-bound access token, both for
 * the SAME txn and the SAME authorization_details.
 */
function mintSimulatedOAuthEvidence({ keys, txn, action, audience = RS_AUDIENCE }) {
  const authorizationDetails = rarDetailsFor(action);
  const challengeClaims = {
    iss: RS_AUDIENCE,
    aud: AUTHORIZATION_SERVER,
    iat: NOW_SECONDS - 20,
    exp: NOW_SECONDS + 40,
    jti: `challenge-${crypto.randomUUID()}`,
    txn,
    authorization_details: authorizationDetails,
    reason: 'Approve this exact payment',
  };
  const accessClaims = {
    iss: AUTHORIZATION_SERVER,
    sub: OAUTH_SUBJECT,
    aud: audience,
    iat: NOW_SECONDS - 5,
    exp: NOW_SECONDS + 115,
    jti: `access-${crypto.randomUUID()}`,
    client_id: OAUTH_CLIENT_ID,
    txn,
    authorization_details: authorizationDetails,
  };
  return {
    challenge_jwt: compactEs256(
      { alg: 'ES256', typ: 'txn-authz-challenge+jwt', kid: 'resource-es256-1' },
      challengeClaims,
      keys.resource.privateKey,
    ),
    access_token_jwt: compactEs256(
      { alg: 'ES256', typ: 'at+jwt', kid: 'as-es256-1' },
      accessClaims,
      keys.authorizationServer.privateKey,
    ),
  };
}

// ---------------------------------------------------------------------------
// Non-OAuth leg: a human-key-signed EP authorization receipt over the SAME
// action object. Issuance and verification are the repo's real receipt path.
// No authorization server participates.
// ---------------------------------------------------------------------------

export async function issueHumanReceipt({ keys, action }) {
  return issueTrustReceipt({
    receiptId: `ep:receipt:${crypto.randomUUID()}`,
    action,
    policyHash: `sha256:${crypto.createHash('sha256').update('policy:payments:high-value@3').digest('hex')}`,
    approvers: [APPROVER_ID],
    requiredApprovals: 1,
    issuedAt: iso(-10_000),
    expiresAt: iso(300_000),
    committedAt: iso(-8_000),
    signers: [softwareSignerFromPrivateKey({
      privateKey: keys.approver.privateKey,
      approverKeyId: APPROVER_KEY_ID,
      signedAt: iso(-8_000),
      keyClass: 'B',
    })],
    log: { privateKey: keys.log.privateKey, logKeyId: LOG_KEY_ID },
  });
}

// ---------------------------------------------------------------------------
// The relying party. ONE evaluator for every evidence form. The relying
// party, never the presenter and never the authorization server, decides
// which evidence forms count.
// ---------------------------------------------------------------------------

/**
 * @param {object} opts
 * @param {ReturnType<typeof generateWorldKeys>} opts.keys
 * @param {string} opts.policyRequirement evidence requirement expression for
 *   the AE-CHALLENGE policy (e.g. 'transaction-authorization OR
 *   human-authorization-receipt').
 * @param {string[]} opts.acceptedForms which evidence forms THIS relying
 *   party admits. This is the evidence-neutrality control point: dropping
 *   OAUTH_EVIDENCE_FORM from the list refuses AS-issued tokens outright,
 *   with no change to the challenge format or the evaluator.
 */
export function createRelyingParty({ keys, acceptedForms, policyRequirement }) {
  const policy = {
    policy_id: 'policy:rs-example:payments@1',
    reliance_purpose: 'payment-initiation',
    requirement: policyRequirement,
  };

  // Pins for the REAL OAuth txn-challenge adapter (packages/verify).
  const detailsVerifierDescriptor = {
    id: 'rs.example:exact-action-details-v1',
    version: '1',
    implementation_digest: digestAeb({ implementation: 'rs.example:exact-action-details-v1', version: '1' }),
  };
  const detailsVerifier = {
    ...detailsVerifierDescriptor,
    verify({ requested, granted, expected }) {
      // The AS must not broaden what the resource challenged, and the grant
      // must denote the relying party's expected details exactly. The CAID is
      // recomputed from the granted detail's embedded action (content signed
      // by the AS), never read from a presented digest field.
      if (digestAeb(requested) !== digestAeb(granted)) {
        return { verified: false, reason: 'authorization_details_broadened' };
      }
      if (!Array.isArray(granted) || granted.length !== 1
          || granted[0]?.type !== RAR_DETAIL_TYPE
          || !Array.isArray(expected) || expected.length !== 1) {
        return { verified: false, reason: 'authorization_details_shape_invalid' };
      }
      const grantedCaid = computeCaid(granted[0].action, { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS });
      const expectedCaid = computeCaid(expected[0].action, { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS });
      if (!grantedCaid.caid || !expectedCaid.caid || grantedCaid.caid !== expectedCaid.caid) {
        return { verified: false, reason: 'granted_action_caid_mismatch' };
      }
      return { verified: true, reason: null };
    },
  };
  /** @type {import('../../packages/verify/aeb-oauth-transaction-challenge-adapter.js').OAuthTransactionChallengeAdapterConfig} */
  const oauthAdapterConfig = {
    '@version': OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
    evidence_role: 'transaction-authorization',
    subject: { id: 'organization:authorization-server', kind: 'organization', native_id: AUTHORIZATION_SERVER },
    action_type: ACTION_TYPE,
    protected_resource: RS_AUDIENCE,
    authorization_server: AUTHORIZATION_SERVER,
    oauth_client_id: OAUTH_CLIENT_ID,
    oauth_subject: OAUTH_SUBJECT,
    require_actor_context: false,
    clock_skew_seconds: 2,
    max_challenge_lifetime_seconds: 120,
    max_access_token_lifetime_seconds: 180,
    max_status_age_seconds: 120,
    details_verifier: detailsVerifierDescriptor,
  };
  /** @type {import('../../packages/verify/aeb-oauth-transaction-challenge-adapter.js').OAuthTransactionChallengeTrustRoot[]} */
  const oauthTrustRoots = [
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'protected-resource-challenge',
      issuer: RS_AUDIENCE,
      key_id: 'resource-es256-1',
      algorithm: 'ES256',
      public_key: publicKeyToSpkiB64u(keys.resource.publicKey),
    },
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'authorization-server-access-token',
      issuer: AUTHORIZATION_SERVER,
      key_id: 'as-es256-1',
      algorithm: 'ES256',
      public_key: publicKeyToSpkiB64u(keys.authorizationServer.publicKey),
    },
  ];
  const oauthAdapter = createOAuthTransactionChallengeAebAdapter({
    config: oauthAdapterConfig,
    trust_roots: oauthTrustRoots,
    details_verifier: detailsVerifier,
  });
  /** @type {import('../../packages/verify/aeb-adapter-contract.js').AebPinnedProfile} */
  const oauthMappingProfile = {
    version: OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
    definition: createOAuthTransactionChallengeActionDefinition(ACTION_TYPE, false),
    registry_entry_ref: 'mapping:oauth-transaction-payment',
    mapper_id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
    resolver: {
      id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: OAUTH_TXN_CHALLENGE_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'challenge.reason', 'challenge.jti', 'challenge.iat', 'challenge.exp',
        'access_token.jti', 'access_token.iat', 'access_token.exp',
      ],
    },
    profile_digest: digestAeb(null),
  };

  // Pins for the receipt leg: the approver-key directory entry and receipt
  // log key this relying party trusts. The presented receipt never supplies
  // its own trusted key.
  const approverKeys = {
    [APPROVER_KEY_ID]: {
      approver_id: APPROVER_ID,
      public_key: publicKeyToSpkiB64u(keys.approver.publicKey),
      key_class: 'B',
      valid_from: iso(-86_400_000),
      valid_to: iso(86_400_000),
      roles: ['high_value_payments'],
    },
  };
  const logPublicKey = publicKeyToSpkiB64u(keys.log.publicKey);

  // Reserve-before-effect consumption state (packages/verify reference
  // store; @emilia-protocol/gate ships the durable equivalents).
  const consumption = new InMemoryAebConsumptionStore();
  let effectCount = 0;

  function challengeFor(action, opts = {}) {
    const challenge = createEvidenceChallenge(action, policy, {
      expires_at: opts.expires_at ?? iso(120_000),
      audience: opts.audience ?? RS_AUDIENCE,
      present_as: acceptedForms,
      obtain_hints: [
        { form: OAUTH_EVIDENCE_FORM, hint: `POST ${AUTHORIZATION_SERVER}/token (txn challenge flow)` },
        { form: RECEIPT_EVIDENCE_FORM, hint: 'obtain an EP authorization receipt from an enrolled approver' },
      ].filter((entry) => acceptedForms.includes(entry.form)),
    });
    return { challenge, problem: createEvidenceChallengeProblem(challenge) };
  }

  function refuse(reason) {
    return { outcome: 'REFUSE', reason };
  }

  function verifyOAuthLeg(evidence, proposedAction, challenge, expectedCaid) {
    const expectedAction = {
      action_type: ACTION_TYPE,
      oauth_transaction: {
        // The AE-CHALLENGE id doubles as the OAuth transaction identifier in
        // this composition: the token must be bound to THIS negotiation.
        txn: challenge.challenge_id,
        authorization_details: rarDetailsFor(proposedAction),
      },
    };
    const adapterInput = {
      artifact: evidence,
      artifact_ref: `oauth-txn:${challenge.challenge_id}`,
      status: {
        checked_at: NOW,
        expires_at: iso(60_000),
        revocation_checked: true,
        revoked: false,
        consumed: false,
      },
      trust_roots: oauthTrustRoots,
      adapter_config: oauthAdapterConfig,
      expected_action: expectedAction,
      now: NOW,
    };
    const native = oauthAdapter.verifyNative(adapterInput);
    if (native.native_verification !== 'VERIFIED' || native.acceptance !== 'ACCEPTED') {
      if (native.acceptance === 'INDETERMINATE' && native.native_verification === 'VERIFIED') {
        return { outcome: 'INDETERMINATE', reason: native.reasons.join(',') || 'oauth_status_indeterminate' };
      }
      return refuse(native.reasons.join(',') || 'oauth_native_verification_failed');
    }
    const mapped = oauthAdapter.mapAction({ ...adapterInput, profile: oauthMappingProfile, native });
    if (mapped.mapping !== 'MATCH' || typeof mapped.caid !== 'string') {
      return refuse(mapped.reasons.join(',') || 'oauth_caid_mapping_failed');
    }
    // The adapter CAID covers the oauth_transaction wrapper. The exact-action
    // join to the relying party's own CAID happened inside the pinned details
    // verifier (granted[0].action recomputed and matched); assert the wrapper
    // commitment is over the SAME wrapper this evaluator constructed from the
    // current proposed action.
    const wrapperCaid = computeCaid(expectedAction, {
      suite: 'jcs-sha256',
      definitions: createOAuthTransactionChallengeActionDefinition(ACTION_TYPE, false).definitions,
    });
    if (wrapperCaid.caid !== mapped.caid) {
      return refuse('oauth_wrapper_caid_mismatch');
    }
    if (expectedCaid.digest !== computeCaid(proposedAction, { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS }).digest) {
      return refuse('proposed_action_caid_unstable');
    }
    return { outcome: 'VERIFIED', replayUnit: native.replay_unit };
  }

  function verifyReceiptLeg(evidence, proposedAction, expectedCaid) {
    const report = verifyTrustReceipt(evidence, {
      approverKeys,
      logPublicKey,
      now: NOW,
      verificationMode: 'current',
    });
    if (report.valid !== true) {
      return refuse(`receipt_refused:${report.errors?.[0] ?? 'invalid'}`);
    }
    // MATCH via CAID: recompute over the SIGNED action object carried by the
    // receipt and over the current proposed action. Never compare presented
    // digest fields alone.
    const receiptCaid = computeCaid(evidence?.action, { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS });
    if (!receiptCaid.caid || receiptCaid.caid !== expectedCaid.caid) {
      return refuse('receipt_action_caid_mismatch');
    }
    if (evidence.action_hash !== actionHash(proposedAction)) {
      return refuse('receipt_action_hash_mismatch');
    }
    return {
      outcome: 'VERIFIED',
      replayUnit: digestAeb({ form: RECEIPT_EVIDENCE_FORM, receipt: evidence }),
    };
  }

  /**
   * The single relying-party evaluator, fail-closed and form-neutral:
   * rederive the action commitment from the CURRENT proposed action, verify
   * the evidence natively, confirm it denotes the same action, check the
   * audience, then consume the authority exactly once before the effect.
   */
  function evaluate(challenge, presentation, proposedAction, opts = {}) {
    const effect = opts.effect ?? (() => ({ ok: true }));

    if (challenge?.['@version'] !== CHALLENGE_VERSION) return refuse('unknown_challenge_version');
    const expiresAt = Date.parse(challenge?.expires_at ?? '');
    if (!Number.isFinite(expiresAt) || NOW_MS >= expiresAt) return refuse('challenge_expired');
    if (challenge?.audience !== RS_AUDIENCE) return refuse('challenge_audience_mismatch');

    // Rederive the action commitment from the action about to execute. A
    // presented digest is never trusted; a challenge minted for a different
    // action dies here (time-of-check/time-of-use swap).
    const rederivedDigest = artifactDigest(proposedAction);
    if (challenge?.action_digest !== rederivedDigest) return refuse('challenge_action_digest_mismatch');
    const expectedCaid = computeCaid(proposedAction, { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS });
    if (!expectedCaid.caid) return refuse(`proposed_action_not_canonicalizable:${expectedCaid.refusals?.join(',')}`);

    // Evidence-form admission is the relying party's decision alone. An
    // AS-issued token presented where the policy demands human-key evidence
    // is refused HERE, without inspecting the token at all.
    const form = presentation?.form;
    if (!acceptedForms.includes(form) || !Array.isArray(challenge?.present_as)
        || !challenge.present_as.includes(form)) {
      return refuse('evidence_form_not_accepted_by_relying_party');
    }

    let leg;
    if (form === OAUTH_EVIDENCE_FORM) {
      leg = verifyOAuthLeg(presentation.evidence, proposedAction, challenge, expectedCaid);
    } else if (form === RECEIPT_EVIDENCE_FORM) {
      leg = verifyReceiptLeg(presentation.evidence, proposedAction, expectedCaid);
    } else {
      return refuse('evidence_form_not_accepted_by_relying_party');
    }
    if (leg.outcome !== 'VERIFIED') return leg;

    // Consume the authority exactly once: reserve BEFORE the effect. A key
    // already CONSUMED is a replay; a key still RESERVED is an unresolved
    // earlier attempt whose truth is unknown, so the only honest answer is
    // INDETERMINATE, not a retry.
    const authorityKey = `authority:${leg.replayUnit}`;
    if (!consumption.reserve(authorityKey, [leg.replayUnit])) {
      if (consumption.state(authorityKey) === 'CONSUMED') {
        return refuse('authority_already_consumed');
      }
      return { outcome: 'INDETERMINATE', reason: 'authority_reservation_unresolved_reconciliation_required' };
    }

    let effectResult;
    try {
      effectResult = effect();
    } catch {
      // The effect may or may not have happened; the response is lost. Do
      // NOT release the reservation: releasing would hand the authority back
      // for a blind retry and a possible double effect.
      return { outcome: 'INDETERMINATE', reason: 'effect_response_lost_authority_held' };
    }
    effectCount += 1;
    consumption.commit(authorityKey);
    return { outcome: 'ADMIT', reason: null, caid: expectedCaid.caid, effect: effectResult };
  }

  return {
    audience: RS_AUDIENCE,
    policy,
    challengeFor,
    evaluate,
    consumptionState: (replayUnit) => consumption.state(`authority:${replayUnit}`),
    effectCount: () => effectCount,
  };
}

export function generateWorldKeys() {
  return {
    // STAND-INS for the OAuth protected resource and authorization server.
    resource: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    authorizationServer: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    // Human approver + receipt log (real Ed25519 receipt path).
    approver: generateEd25519KeyPair(),
    log: generateEd25519KeyPair(),
  };
}

// ---------------------------------------------------------------------------
// Scenarios. Each case creates a fresh relying party unless the case is
// specifically about state carried across attempts (replay, lost effect).
// ---------------------------------------------------------------------------

export async function runAeTransportNeutralDemo() {
  const keys = generateWorldKeys();
  const bothForms = [OAUTH_EVIDENCE_FORM, RECEIPT_EVIDENCE_FORM];
  const eitherRequirement = 'transaction-authorization OR human-authorization-receipt';
  const cases = [];

  const record = (id, expected, result, note) => {
    cases.push({ id, expected, outcome: result.outcome, reason: result.reason ?? null, note });
    return result;
  };

  // HAPPY PATH 1: the SAME challenge shape, satisfied by simulated-OAuth
  // evidence, evaluated by the transport-neutral evaluator.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const { challenge, problem } = rs.challengeFor(ACTION_A);
    // The agent receives the RFC 9457 refusal and parses the SAME challenge
    // object back out of it: the negotiation loop is machine-readable.
    const parsed = parseEvidenceChallengeProblem(problem);
    const evidence = mintSimulatedOAuthEvidence({ keys, txn: parsed.challenge_id, action: ACTION_A });
    record(
      'admit-oauth-evidence-for-action-a',
      'ADMIT',
      rs.evaluate(parsed, { form: OAUTH_EVIDENCE_FORM, evidence }, ACTION_A),
      'OAuth transaction-bound token satisfies the challenge: OAuth is one evidence form.',
    );
  }

  // HAPPY PATH 2: the SAME evaluator, non-OAuth human-key evidence, no
  // authorization server in the loop.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const { challenge } = rs.challengeFor(ACTION_A);
    const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
    record(
      'admit-human-receipt-for-action-a',
      'ADMIT',
      rs.evaluate(challenge, { form: RECEIPT_EVIDENCE_FORM, evidence: receipt }, ACTION_A),
      'Human-key Ed25519 receipt satisfies the SAME challenge: evidence OAuth cannot produce.',
    );
  }

  // HOSTILE 1: OAuth token issued for action B, presented against action A.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const { challenge } = rs.challengeFor(ACTION_A);
    const evidence = mintSimulatedOAuthEvidence({ keys, txn: challenge.challenge_id, action: ACTION_B });
    record(
      'refuse-oauth-token-for-different-action',
      'REFUSE',
      rs.evaluate(challenge, { form: OAUTH_EVIDENCE_FORM, evidence }, ACTION_A),
      'The granted authorization_details recompute to action B, not the action about to execute.',
    );
  }

  // HOSTILE 2: human-key receipt replayed after its authority was consumed.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
    const first = rs.challengeFor(ACTION_A).challenge;
    const firstResult = rs.evaluate(first, { form: RECEIPT_EVIDENCE_FORM, evidence: receipt }, ACTION_A);
    const second = rs.challengeFor(ACTION_A).challenge; // fresh challenge, same receipt
    record(
      'refuse-receipt-replay-after-consume',
      'REFUSE',
      rs.evaluate(second, { form: RECEIPT_EVIDENCE_FORM, evidence: receipt }, ACTION_A),
      `First presentation was ${firstResult.outcome}; the replay hits consumed authority.`,
    );
  }

  // HOSTILE 3: evidence for the wrong audience.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const { challenge } = rs.challengeFor(ACTION_A);
    const evidence = mintSimulatedOAuthEvidence({
      keys, txn: challenge.challenge_id, action: ACTION_A, audience: OTHER_RS_AUDIENCE,
    });
    record(
      'refuse-evidence-for-wrong-audience',
      'REFUSE',
      rs.evaluate(challenge, { form: OAUTH_EVIDENCE_FORM, evidence }, ACTION_A),
      'Access token audience names a different relying party.',
    );
    // Challenge-level audience binding refuses independently of the token: a
    // challenge minted for another relying party is dead on arrival here.
    const foreign = rs.challengeFor(ACTION_A, { audience: OTHER_RS_AUDIENCE }).challenge;
    const goodEvidence = mintSimulatedOAuthEvidence({ keys, txn: foreign.challenge_id, action: ACTION_A });
    record(
      'refuse-challenge-bound-to-other-audience',
      'REFUSE',
      rs.evaluate(foreign, { form: OAUTH_EVIDENCE_FORM, evidence: goodEvidence }, ACTION_A),
      'The challenge itself is audience-bound; valid evidence cannot rescue it.',
    );
  }

  // HOSTILE 4 (load-bearing): the relying party's policy admits ONLY
  // human-key evidence. A perfectly valid AS-issued token is refused before
  // it is even parsed: the relying party, not the authorization server,
  // decides which evidence forms count.
  {
    const rs = createRelyingParty({
      keys,
      acceptedForms: [RECEIPT_EVIDENCE_FORM],
      policyRequirement: 'human-authorization-receipt',
    });
    const { challenge } = rs.challengeFor(ACTION_A);
    const evidence = mintSimulatedOAuthEvidence({ keys, txn: challenge.challenge_id, action: ACTION_A });
    record(
      'refuse-oauth-when-policy-requires-human-key',
      'REFUSE',
      rs.evaluate(challenge, { form: OAUTH_EVIDENCE_FORM, evidence }, ACTION_A),
      'Evidence-neutrality control point: the RS pins which forms count; the AS cannot override it.',
    );
  }

  // HOSTILE 5: the action is admitted for execution, the effect runs, and
  // the effect response is lost. The outcome is INDETERMINATE and the
  // authority stays held; a blind retry with the same evidence is NOT
  // re-executed.
  {
    const rs = createRelyingParty({ keys, acceptedForms: bothForms, policyRequirement: eitherRequirement });
    const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
    let effectsStarted = 0;
    const lossyEffect = () => {
      effectsStarted += 1;
      throw new Error('simulated: effect dispatched, response lost');
    };
    const first = rs.challengeFor(ACTION_A).challenge;
    const lost = record(
      'indeterminate-when-effect-response-lost',
      'INDETERMINATE',
      rs.evaluate(first, { form: RECEIPT_EVIDENCE_FORM, evidence: receipt }, ACTION_A, { effect: lossyEffect }),
      'Truth unknown: neither admitted nor refused, and the authority is not released.',
    );
    const retry = rs.evaluate(
      rs.challengeFor(ACTION_A).challenge,
      { form: RECEIPT_EVIDENCE_FORM, evidence: receipt },
      ACTION_A,
      { effect: lossyEffect },
    );
    cases.push({
      id: 'indeterminate-blind-retry-not-reexecuted',
      expected: 'INDETERMINATE',
      outcome: retry.outcome,
      reason: retry.reason ?? null,
      note: `effects started: ${effectsStarted} (must remain 1); first outcome ${lost.outcome}`,
      effects_started: effectsStarted,
    });
  }

  return {
    '@version': DEMO_VERSION,
    thesis: 'OAuth and others, not others instead of OAuth: AE-CHALLENGE is transport-neutral evidence negotiation; OAuth is one admissible evidence form among several.',
    composes_with: 'draft-rosomakho-oauth-txn-challenge-00 (consumed as an evidence form, not replaced)',
    cases,
  };
}

function printDemo(result) {
  const green = (value) => `\x1b[32m${value}\x1b[0m`;
  const red = (value) => `\x1b[31m${value}\x1b[0m`;
  console.log('='.repeat(78));
  console.log(' AE-CHALLENGE transport-neutral evidence negotiation');
  console.log(` ${result.thesis}`);
  console.log('='.repeat(78));
  for (const testCase of result.cases) {
    const ok = testCase.outcome === testCase.expected
      && (testCase.effects_started === undefined || testCase.effects_started === 1);
    console.log(` ${ok ? green('PASS') : red('FAIL')}  ${testCase.id}`);
    console.log(`       expected=${testCase.expected} actual=${testCase.outcome} reason=${testCase.reason ?? 'none'}`);
    if (testCase.note) console.log(`       ${testCase.note}`);
  }
  console.log('-'.repeat(78));
  console.log(' One relying party, one challenge format, one evaluator. The OAuth leg and');
  console.log(' the human-key leg each verify under their own native rules and join only');
  console.log(' through the recomputed action commitment. The RS decides what counts.');
  console.log('='.repeat(78));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runAeTransportNeutralDemo();
  printDemo(result);
  const ok = result.cases.every((item) => item.outcome === item.expected
    && (item.effects_started === undefined || item.effects_started === 1));
  process.exitCode = ok ? 0 : 1;
}
