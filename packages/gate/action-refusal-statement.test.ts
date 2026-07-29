// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  ACTION_REFUSAL_CLAIM_BOUNDARY,
  ACTION_REFUSAL_STATEMENT_VERSION,
  acceptActionRefusalStatement,
  actionRefusalStatementDigest,
  createMemoryActionRefusalReplayStore,
  signActionRefusalStatement,
  verifyActionRefusalExternalEvidence,
  verifyActionRefusalStatement,
} from './action-refusal-statement.js';

const NOW = Date.parse('2026-07-28T18:00:00.000Z');
const D = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = `caid:1:health.prior-authorization-determination.1:jcs-sha256:${'A'.repeat(43)}`;

function statementInput(): Record<string, any> {
  return {
    refusal_id: 'refusal:synthetic-pas:001',
    relying_party_id: 'payer:synthetic-example',
    caid: CAID,
    action_digest: D('1'),
    program: {
      program_id: 'rp.synthetic-payer.pas-adverse-determination.1',
      version: 1,
      source_digest: D('2'),
      program_digest: D('3'),
    },
    failed_requirement_ids: ['reviewer-authority', 'licensed-review'],
    evidence_digests: [D('5'), D('4')],
    challenge_digests: [D('7'), D('6')],
    nonce: Buffer.alloc(32, 8).toString('base64url'),
    refused_at: '2026-07-28T17:59:00.000Z',
    expires_at: '2026-07-28T18:04:00.000Z',
    refusal_class: 'evidence_unsatisfied',
    semantics: {
      verification: 'VERIFIED',
      match: 'MATCH',
      satisfaction: 'NOT_SATISFIED',
      authorization: 'NOT_EVALUATED',
    },
    delivery: null,
    custody: null,
    transparency_anchor: null,
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
  };
}

function fixture(overrides: Record<string, any> = {}) {
  const keys = crypto.generateKeyPairSync('ed25519');
  const statement = signActionRefusalStatement({
    ...statementInput(),
    ...overrides,
  }, {
    issuer_id: 'gate:synthetic-payer:prod',
    key_id: 'gate-refusal-key-1',
    private_key: keys.privateKey,
  });
  const trusted_keys = {
    'gate-refusal-key-1': {
      issuer_id: 'gate:synthetic-payer:prod',
      public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
  };
  const expected = {
    caid: CAID,
    action_digest: D('1'),
    relying_party_id: 'payer:synthetic-example',
    program_id: 'rp.synthetic-payer.pas-adverse-determination.1',
    program_version: 1,
    source_digest: D('2'),
    program_digest: D('3'),
    nonce: Buffer.alloc(32, 8).toString('base64url'),
  };
  return { keys, statement, trusted_keys, expected };
}

test('signs and verifies one exact-action technical refusal under a pinned issuer key', () => {
  const { statement, trusted_keys, expected } = fixture();
  const result = verifyActionRefusalStatement(statement, {
    trusted_keys,
    expected,
    now: NOW,
  });

  assert.equal(statement['@version'], ACTION_REFUSAL_STATEMENT_VERSION);
  assert.equal(result.verified, true);
  assert.equal(result.reason, null);
  assert.equal(result.refusal_digest, actionRefusalStatementDigest(statement));
  assert.deepEqual(statement.failed_requirement_ids, ['licensed-review', 'reviewer-authority']);
  assert.deepEqual(statement.evidence_digests, [D('4'), D('5')]);
  assert.deepEqual(statement.challenge_digests, [D('6'), D('7')]);
  assert.deepEqual(result.semantics, {
    verification: 'VERIFIED',
    match: 'MATCH',
    satisfaction: 'NOT_SATISFIED',
    authorization: 'NOT_EVALUATED',
  });
  assert.equal(result.claim_boundary, ACTION_REFUSAL_CLAIM_BOUNDARY);
  assert.equal(result.delivery_evidence, 'NOT_EVIDENCED');
  assert.equal(result.custody_evidence, 'NOT_EVIDENCED');
});

test('replay-checked acceptance consumes the relying-party nonce once and expiry fails closed', async () => {
  const { statement, trusted_keys, expected } = fixture();
  const replayStore = createMemoryActionRefusalReplayStore();
  const options = {
    trusted_keys,
    expected,
    now: NOW,
    replayStore,
    allowEphemeralReplayStore: true,
  };

  const first = await acceptActionRefusalStatement(statement, options);
  assert.equal(first.verified, true);
  assert.equal(first.accepted, true);
  assert.equal(first.replay_checked, true);
  assert.equal(first.replay_store_durable, false);

  const replay = await acceptActionRefusalStatement(statement, options);
  assert.equal(replay.verified, true);
  assert.equal(replay.accepted, false);
  assert.equal(replay.reason, 'statement_replay');

  const expired = verifyActionRefusalStatement(statement, {
    trusted_keys,
    expected,
    now: Date.parse('2026-07-28T18:04:00.000Z'),
  });
  assert.equal(expired.verified, false);
  assert.equal(expired.reason, 'refusal_expired');
});

test('external delivery, custody, and transparency references remain unverified until pinned adapters prove them', async () => {
  const delivery = {
    channel: 'https',
    recipient_id: 'provider:synthetic-example',
    delivered_at: '2026-07-28T18:00:00.000Z',
    custody_digest: D('8'),
  };
  const custody = {
    custodian_id: 'archive:synthetic-example',
    acknowledged_at: '2026-07-28T18:00:01.000Z',
    evidence_digest: D('9'),
  };
  const transparency_anchor = { method: 'scitt', evidence_digest: D('a') };
  const { statement, trusted_keys, expected } = fixture({ delivery, custody, transparency_anchor });

  const referenced = await verifyActionRefusalExternalEvidence(statement, {
    trusted_keys,
    required: ['delivery'],
  });
  assert.equal(referenced.accepted, false);
  assert.equal(referenced.reason, 'delivery_verifier_required');
  assert.equal(referenced.legs.delivery.status, 'REFERENCED_NOT_EXTERNALLY_VERIFIED');

  const verifiers = Object.fromEntries([
    ['delivery', D('8')],
    ['custody', D('9')],
    ['transparency_anchor', D('a')],
  ].map(([leg, digest]) => [leg, async ({ expected_evidence_digest }) => ({
    status: 'VERIFIED',
    evidence_digest: digest,
    reason: null,
    observed_expected_digest: expected_evidence_digest,
  })]));

  // Extra adapter fields are refused. An external verifier has a closed output
  // shape so it cannot smuggle an unreviewed trust decision into acceptance.
  const malformed = await verifyActionRefusalExternalEvidence(statement, {
    trusted_keys,
    required: ['delivery'],
    verifiers: { delivery: verifiers.delivery },
  });
  assert.equal(malformed.accepted, false);
  assert.equal(malformed.reason, 'delivery_verifier_result_invalid');

  const exactVerifiers = Object.fromEntries([
    ['delivery', D('8')],
    ['custody', D('9')],
    ['transparency_anchor', D('a')],
  ].map(([leg, digest]) => [leg, async () => ({
    status: 'VERIFIED', evidence_digest: digest, reason: null,
  })]));
  const replayStore = createMemoryActionRefusalReplayStore();
  const accepted = await acceptActionRefusalStatement(statement, {
    trusted_keys,
    expected,
    now: NOW,
    replayStore,
    allowEphemeralReplayStore: true,
    external_evidence: {
      required: ['delivery', 'custody', 'transparency_anchor'],
      verifiers: exactVerifiers,
    },
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.external_evidence.legs.delivery.status, 'VERIFIED');
  assert.equal(accepted.external_evidence.legs.custody.status, 'VERIFIED');
  assert.equal(accepted.external_evidence.legs.transparency_anchor.status, 'VERIFIED');
});

test('an external evidence digest mismatch fails before replay consumption', async () => {
  const delivery = {
    channel: 'https', recipient_id: 'provider:synthetic-example',
    delivered_at: '2026-07-28T18:00:00.000Z', custody_digest: D('8'),
  };
  const { statement, trusted_keys, expected } = fixture({ delivery });
  const replayStore = createMemoryActionRefusalReplayStore();
  const base = {
    trusted_keys, expected, now: NOW, replayStore, allowEphemeralReplayStore: true,
  };
  const mismatch = await acceptActionRefusalStatement(statement, {
    ...base,
    external_evidence: {
      required: ['delivery'],
      verifiers: { delivery: async () => ({ status: 'VERIFIED', evidence_digest: D('f'), reason: null }) },
    },
  });
  assert.equal(mismatch.accepted, false);
  assert.equal(mismatch.reason, 'delivery_evidence_digest_mismatch');
  assert.equal(mismatch.replay_checked, false);

  const accepted = await acceptActionRefusalStatement(statement, {
    ...base,
    external_evidence: {
      required: ['delivery'],
      verifiers: { delivery: async () => ({ status: 'VERIFIED', evidence_digest: D('8'), reason: null }) },
    },
  });
  assert.equal(accepted.accepted, true);
});

test('tampering any exact-action or pinned-program binding invalidates the statement', () => {
  const { statement, trusted_keys, expected } = fixture();
  for (const mutate of [
    (value: any) => { value.action_digest = D('9'); },
    (value: any) => { value.caid = value.caid.replace(/A$/, 'B'); },
    (value: any) => { value.program.source_digest = D('9'); },
    (value: any) => { value.failed_requirement_ids[0] = 'attacker-requirement'; },
    (value: any) => { value.challenge_digests[0] = D('9'); },
    (value: any) => { value.semantics.authorization = 'AUTHORIZED'; },
  ]) {
    const tampered = structuredClone(statement);
    mutate(tampered);
    const result = verifyActionRefusalStatement(tampered, { trusted_keys, expected, now: NOW });
    assert.equal(result.accepted, false);
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'digest_mismatch');
  }

  assert.equal(verifyActionRefusalStatement(statement, {
    trusted_keys,
    expected: { ...expected, program_version: 2 },
    now: NOW,
  }).reason, 'program_version_mismatch');
});

test('missing delivery and custody stay explicitly unevidenced; references are not external verification', () => {
  const missing = fixture();
  const missingResult = verifyActionRefusalStatement(missing.statement, {
    trusted_keys: missing.trusted_keys,
    expected: missing.expected,
    now: NOW,
  });
  assert.equal(missingResult.verified, true);
  assert.equal(missingResult.delivery_evidence, 'NOT_EVIDENCED');
  assert.equal(missingResult.custody_evidence, 'NOT_EVIDENCED');
  assert.equal(missingResult.transparency_anchor, 'NOT_REFERENCED');

  const referenced = fixture({
    delivery: {
      channel: 'https',
      recipient_id: 'agent:synthetic-reviewer',
      delivered_at: '2026-07-28T17:59:30.000Z',
      custody_digest: D('a'),
    },
    custody: {
      custodian_id: 'custodian:synthetic-reviewer',
      acknowledged_at: '2026-07-28T17:59:45.000Z',
      evidence_digest: D('b'),
    },
    transparency_anchor: { method: 'external-log', evidence_digest: D('c') },
  });
  const referencedResult = verifyActionRefusalStatement(referenced.statement, {
    trusted_keys: referenced.trusted_keys,
    expected: referenced.expected,
    now: NOW,
  });
  assert.equal(referencedResult.delivery_evidence, 'REFERENCED');
  assert.equal(referencedResult.custody_evidence, 'REFERENCED');
  assert.equal(referencedResult.transparency_anchor, 'REFERENCED_NOT_EXTERNALLY_VERIFIED');

  assert.throws(() => fixture({
    custody: {
      custodian_id: 'custodian:orphan',
      acknowledged_at: '2026-07-28T17:59:45.000Z',
      evidence_digest: D('d'),
    },
  }), /custody evidence is invalid/);
});

test('duplicate failed requirements and collapsed semantic axes are refused before signing', () => {
  assert.throws(() => fixture({
    failed_requirement_ids: ['licensed-review', 'licensed-review'],
  }), /requirements are duplicate/);
  assert.throws(() => fixture({
    semantics: {
      verification: 'VERIFIED',
      match: 'MATCH',
      satisfaction: 'SATISFIED',
      authorization: 'AUTHORIZED',
    },
  }), /statement shape is invalid/);
});

test('the deterministic conformance vector verifies and its mutations fail as declared', async () => {
  const vector = JSON.parse(readFileSync(new URL(
    '../../conformance/vectors/action-refusal-statement.v1.json',
    import.meta.url,
  ), 'utf8'));
  assert.equal(vector['@version'], 'EP-ACTION-REFUSAL-STATEMENT-CONFORMANCE-v1');
  assert.equal(vector.artifact_version, ACTION_REFUSAL_STATEMENT_VERSION);

  const positive = vector.positive;
  assert.equal(actionRefusalStatementDigest(positive.statement), positive.refusal_digest);
  assert.deepEqual(verifyActionRefusalStatement(positive.statement, {
    trusted_keys: vector.trusted_keys,
    expected: positive.expected,
    now: positive.now,
  }), positive.expect);

  for (const item of vector.mutations) {
    const mutated = structuredClone(positive.statement);
    const segments = item.path.split('/').slice(1);
    let target = mutated;
    for (const segment of segments.slice(0, -1)) target = target[segment];
    target[segments.at(-1)] = item.value;
    const result = verifyActionRefusalStatement(mutated, {
      trusted_keys: vector.trusted_keys,
      expected: positive.expected,
      now: positive.now,
    });
    assert.equal(result.accepted, false, item.id);
    assert.equal(result.reason, item.expect.reason, item.id);
  }

  const replayStore = createMemoryActionRefusalReplayStore();
  const replayOptions = {
    trusted_keys: vector.trusted_keys,
    expected: positive.expected,
    now: positive.now,
    replayStore,
    allowEphemeralReplayStore: true,
  };
  assert.equal((await acceptActionRefusalStatement(positive.statement, replayOptions)).accepted, true);
  assert.equal(
    (await acceptActionRefusalStatement(positive.statement, replayOptions)).reason,
    vector.replay_expect.reason,
  );
});
