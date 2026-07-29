// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { verifyActionRefusalStatement } from './action-refusal-statement.js';
import { createRelianceKernel } from './reliance-kernel.js';

const DIGEST = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = 'caid:1:payment.release.1:jcs-sha256:w5frm5Cl8eHeCZ4DMdsVvLGOdP7XByOjOrynopvQYTo';

function runtime(overrides: Record<string, unknown> = {}) {
  const keys = crypto.generateKeyPairSync('ed25519');
  return {
    trusted: {
      'refusal-key-1': {
        issuer_id: 'rp.example',
        public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    refusal: {
      signer: { issuer_id: 'rp.example', key_id: 'refusal-key-1', private_key: keys.privateKey },
      async context() {
        return {
          program: {
            program_id: 'payer.high-risk-actions',
            version: 2,
            source_digest: DIGEST('a'),
            program_digest: DIGEST('b'),
          },
          relying_party_id: 'rp.example',
          caid: CAID,
          action_digest: DIGEST('c'),
          refusal_id: 'refusal-runtime-0001',
          nonce: 'refusal-runtime-nonce-0001',
          refused_at: '2026-07-29T12:00:00.000Z',
          expires_at: '2026-07-30T12:00:00.000Z',
          evidence_digests: [],
          challenge_digest: DIGEST('d'),
          failed_requirement_ids: ['requirement.pinned-reliance-profile'],
          ...overrides,
        };
      },
    },
  };
}

test('runtime refusal is signed, recorded, and carried in the 428 challenge', async () => {
  const configured = runtime();
  const kernel = createRelianceKernel({ refusal: configured.refusal });
  const result = await kernel.check({}, {});

  assert.equal(result.allow, false);
  assert.equal(result.status, 428);
  assert.equal(result.verdict, 'do_not_rely_no_profile');
  assert.equal(result.refusal_statement_recorded, true);
  assert.equal(result.challenge.refusal_statement_digest, result.refusal_statement_digest);
  assert.deepEqual(result.challenge.refusal_statement, result.refusal_statement);

  const verification = verifyActionRefusalStatement(result.refusal_statement, {
    trusted_keys: configured.trusted,
    now: '2026-07-29T12:00:01.000Z',
  });
  assert.equal(verification.accepted, true);
  assert.equal(result.refusal_statement.refusal_class, 'indeterminate');

  const records = await kernel.evidence.all();
  assert.equal(records.length, 2);
  assert.equal(records[0].type, 'reliance.decision');
  assert.equal(records[1].type, 'reliance.refusal_statement');
  assert.equal(records[1].refusal_digest, result.refusal_statement_digest);
});

test('missing deployment-owned requirement ids refuses and never emits a false statement', async () => {
  const configured = runtime({ failed_requirement_ids: undefined });
  const kernel = createRelianceKernel({ refusal: configured.refusal });
  const result = await kernel.check({}, {});

  assert.equal(result.allow, false);
  assert.equal(result.status, 428);
  assert.equal(result.refusal_statement, null);
  assert.equal(result.refusal_statement_recorded, false);
  assert.match(result.challenge.refusal_statement_error, /requires explicit failed requirement ids/);
});

test('runtime configuration rejects a missing context function', () => {
  const configured = runtime();
  assert.throws(
    () => createRelianceKernel({ refusal: { ...configured.refusal, context: null as any } }),
    /requires signer and context/,
  );
});
