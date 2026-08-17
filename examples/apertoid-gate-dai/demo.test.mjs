// SPDX-License-Identifier: Apache-2.0
// node --test examples/apertoid-gate-dai/demo.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DAI_DRAFT,
  evaluateDomainAuthorizedIssuer,
  validateIssuerAuthorizationPolicy,
  verifyIdJagAssertion,
} from './dai-profile.mjs';
import {
  ACTION,
  ADAPTER_KEYS,
  ADAPTER_STATUS_CHECKED_AT,
  ASSERTION,
  ISSUER_KEYS,
  LOOKUP_AFFIRMATIVE,
  MEMORY_PROJECTION_RECORD,
  MEMORY_VERIFICATION_LIMITS,
  POLICY_ENFORCE,
  SUBJECT_AUTHORITY,
  VERIFICATION_TIME,
} from './fixtures.mjs';
import { runDemo } from './demo.mjs';
import { createApertoIdGateDaiAdmission } from './gate.mjs';

function gate(overrides = {}) {
  return createApertoIdGateDaiAdmission({
    adapterKeys: ADAPTER_KEYS,
    adapterStatusCheckedAt: ADAPTER_STATUS_CHECKED_AT,
    memoryLimits: MEMORY_VERIFICATION_LIMITS,
    issuerKeys: ISSUER_KEYS,
    verificationTime: VERIFICATION_TIME,
    ...overrides,
  });
}

const REQUEST = Object.freeze({
  action: ACTION,
  memoryRecord: MEMORY_PROJECTION_RECORD,
  assertion: ASSERTION,
  lookup: LOOKUP_AFFIRMATIVE,
});

const mustNotExecute = async () => {
  throw new Error('effect ran on a non-admitted decision');
};

test('composition demo: all seven cases land on their expected outcome', async () => {
  const result = await runDemo();
  assert.equal(result.executions, 1);
  assert.equal(result.cases.happy_path, 'admitted_executed_once');
  assert.equal(result.cases.replay, 'replay_refused');
  assert.equal(
    result.cases.memory_leg_unavailable,
    'INDETERMINATE:memory_leg_indeterminate:adapter_status_unavailable',
  );
  assert.equal(result.cases.dai_lookup_servfail, 'dai_lookup_indeterminate:dns_servfail');
  assert.equal(result.cases.memory_context_substitution, 'memory_context_join_mismatch');
  assert.equal(result.cases.dai_assertion_substitution, 'dai_assertion_audience_mismatch');
  assert.equal(result.cases.monitor_mode_floor, 'dai_monitor_mode_below_admission_floor');
});

test('deterministic: two full runs produce byte-identical results', async () => {
  const first = await runDemo();
  const second = await runDemo();
  assert.equal(JSON.stringify(first), JSON.stringify(second));
});

test('the admitted decision joins the legs by digests over the exact action', async () => {
  const decision = await gate().admit(REQUEST, async () => {});
  assert.equal(decision.admitted, true);
  assert.match(decision.caid, /^sha256:[0-9a-f]{64}$/);
  // Leg A join: the verified record digest is the digest the action binds.
  assert.equal(
    decision.legs.memory.projection_record_digest,
    ACTION.context_binding.projection_record_digest,
  );
  // Leg B: the DAI outcome is carried with the assertion digest, so the
  // decision names exactly which delegation artifact covered the action.
  assert.equal(decision.legs.dai.satisfied, true);
  assert.equal(decision.legs.dai.mode, 'enforce');
  assert.equal(decision.legs.dai.subject_authority, SUBJECT_AUTHORITY);
  assert.match(decision.legs.dai.assertion_digest, /^sha256:[0-9a-f]{64}$/);
});

test('INDETERMINATE never authorizes and is not upgraded to a tamper claim', async () => {
  const decision = await gate({ adapterStatusCheckedAt: null }).admit(REQUEST, mustNotExecute);
  assert.equal(decision.admitted, false);
  assert.equal(decision.state, 'INDETERMINATE');
  assert.notEqual(decision.state, 'REFUSED');
});

test('a tampered projection record is refused, not INDETERMINATE', async () => {
  const tampered = structuredClone(MEMORY_PROJECTION_RECORD);
  tampered.projection_id = `${tampered.projection_id}-tampered`;
  const decision = await gate().admit(
    { ...REQUEST, memoryRecord: tampered },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.state, 'REFUSED');
  assert.match(decision.reason, /^memory_leg_not_verified:/);
});

test('an assertion signed by an unpinned issuer key is refused', async () => {
  const decision = await gate({ issuerKeys: {} }).admit(REQUEST, mustNotExecute);
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_assertion_issuer_key_not_pinned');
});

test('a tampered assertion signature is refused', async () => {
  const parts = ASSERTION.split('.');
  const flipped = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`;
  const decision = await gate().admit({ ...REQUEST, assertion: flipped }, mustNotExecute);
  assert.equal(decision.admitted, false);
  assert.match(decision.reason, /^dai_assertion_/);
});

test('DAI: an issuer absent from an enforce-mode policy is refused', async () => {
  const strippedPolicy = {
    ...POLICY_ENFORCE,
    authorized_issuers: [POLICY_ENFORCE.authorized_issuers[1]],
  };
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'affirmative', policy: strippedPolicy } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_no_authorized_issuer_entry_matches');
});

test('DAI: an empty authorized_issuers array is an explicit denial (enforce mode)', async () => {
  const denial = { subject_authority: SUBJECT_AUTHORITY, authorized_issuers: [] };
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'affirmative', policy: denial } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_no_authorized_issuer_entry_matches');
});

test('DAI: negative lookup rejects with no fallback', async () => {
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'negative', detail: 'nxdomain_then_404' } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_lookup_negative:nxdomain_then_404');
});

test('DAI: an unrecognized mode value makes the policy malformed (Indeterminate)', async () => {
  const futureMode = { ...POLICY_ENFORCE, mode: 'audit' };
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'affirmative', policy: futureMode } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_lookup_indeterminate:policy_malformed:mode_malformed');
});

test('DAI: a policy for a different subject authority never covers this subject', async () => {
  const foreign = { ...POLICY_ENFORCE, subject_authority: 'other.example' };
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'affirmative', policy: foreign } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_lookup_indeterminate:subject_authority_mismatch');
});

test('DAI: an expired delegation window does not match', async () => {
  const expired = {
    subject_authority: SUBJECT_AUTHORITY,
    authorized_issuers: [{
      issuer: 'https://idp.example.net',
      subject_identifier_formats: ['email'],
      valid_until: '2026-07-01T00:00:00Z',
    }],
  };
  const decision = await gate().admit(
    { ...REQUEST, lookup: { state: 'affirmative', policy: expired } },
    mustNotExecute,
  );
  assert.equal(decision.admitted, false);
  assert.equal(decision.reason, 'dai_no_authorized_issuer_entry_matches');
});

test('DAI: tenant-bound entry does not match an assertion without the tenant claim', () => {
  const claims = {
    iss: 'https://accounts.shared.example',
    aud: 'https://api.resource.example',
    email: 'alice@acme.example',
    email_verified: true,
  };
  const result = evaluateDomainAuthorizedIssuer({
    claims,
    subjectAuthority: SUBJECT_AUTHORITY,
    subjectIdentifierFormat: 'email',
    lookup: {
      state: 'affirmative',
      policy: {
        subject_authority: SUBJECT_AUTHORITY,
        authorized_issuers: [{ issuer: 'https://accounts.shared.example', tenant: 'acme-corp' }],
      },
    },
    evaluationTime: VERIFICATION_TIME,
  });
  assert.equal(result.satisfied, false);
  assert.equal(result.reason, 'no_authorized_issuer_entry_matches');
});

test('DAI: trailing-slash issuer is a distinct issuer (octet equality, no normalization)', () => {
  const claims = {
    iss: 'https://idp.example.net/',
    aud: 'https://api.resource.example',
    email: 'alice@acme.example',
    email_verified: true,
  };
  const result = evaluateDomainAuthorizedIssuer({
    claims,
    subjectAuthority: SUBJECT_AUTHORITY,
    subjectIdentifierFormat: 'email',
    lookup: LOOKUP_AFFIRMATIVE,
    evaluationTime: VERIFICATION_TIME,
  });
  assert.equal(result.satisfied, false);
});

test('policy validation: crit naming unimplemented processing is malformed', () => {
  const critical = { ...POLICY_ENFORCE, crit: ['signed_policy'], signed_policy: 'eyJhbGciOi' };
  const result = validateIssuerAuthorizationPolicy(critical);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'crit_member_not_implemented:signed_policy');
});

test('assertion verification is fail-closed on garbage input', () => {
  for (const hostile of [null, 42, '', 'a.b', 'a.b.c.d', '!!.!!.!!']) {
    const result = verifyIdJagAssertion(hostile, {
      issuerKeys: ISSUER_KEYS,
      evaluationTime: VERIFICATION_TIME,
    });
    assert.equal(result.valid, false);
    assert.equal(typeof result.reason, 'string');
  }
});

test('the pinned draft identity is carried by the profile module', () => {
  assert.equal(DAI_DRAFT.name, 'draft-mcguinness-oauth-domain-authorized-issuer');
  assert.equal(DAI_DRAFT.revision, '00');
  assert.equal(
    DAI_DRAFT.sha256,
    '2520dd24a6ed6c7936b32c0b2bba01af48ca95b486cad145a282f109d5b9606c',
  );
});
