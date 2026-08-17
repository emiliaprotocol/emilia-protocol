// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'vitest';

import {
  EXECUTOR_PINS,
  PINNED_DRAFT,
  PINNED_DRAFT_SHA256,
  PROFILE,
  SCOPE_A,
  SCOPE_B,
  establishFundsAuthority,
  runProfile,
  scopeDigestOf,
} from './run.mjs';

const sourceLock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
const reference = JSON.parse(readFileSync(new URL('./report.reference.json', import.meta.url), 'utf8'));

function byId(report, id) {
  const entry = report.cases.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing case ${id}`);
  return entry;
}

test('the source lock pins the exact Hawkins draft bytes this profile instantiates', () => {
  assert.equal(sourceLock['@version'], 'HAWKINS-FUNDS-AUTHORITY-SOURCE-LOCK-v0.1');
  const pinned = sourceLock.ietf_archives.find((entry) => entry.name === PINNED_DRAFT);
  assert.ok(pinned, 'draft archive pin missing');
  assert.equal(pinned.sha256, PINNED_DRAFT_SHA256);
  assert.match(pinned.sha256, /^[0-9a-f]{64}$/);
});

test('the report is deterministic and matches the committed reference', () => {
  const { case_details, ...first } = runProfile();
  const { case_details: unusedDetails, ...second } = runProfile();
  assert.equal(first.report_digest, second.report_digest);
  assert.deepEqual(first, reference);
  assert.equal(first.profile, PROFILE);
  assert.equal(first.passed, true);
});

test('the two legs join only by the scope digest, and different scopes hash differently', () => {
  const a = scopeDigestOf(SCOPE_A);
  const b = scopeDigestOf(SCOPE_B);
  assert.match(a.digest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(a.digest, b.digest);
  // The digest is over exactly the deterministic encoding bytes.
  const recomputed = `sha256:${crypto.createHash('sha256').update(a.bytes).digest('hex')}`;
  assert.equal(a.digest, recomputed);
});

test('happy path: the funds-authority clause of Check 8 is established by the exact-scope receipt', () => {
  const report = runProfile();
  const entry = byId(report, 'funds-authority-established');
  assert.equal(entry.outcome.check8_funds_authority, 'established');
  assert.equal(entry.outcome.refusal, null);
  assert.equal(entry.passed, true);
  const detail = report.case_details.find((candidate) => candidate.id === 'funds-authority-established');
  assert.ok(detail);
  assert.equal(detail.outcome.evidence.receipt_checks.signature, true);
  assert.equal(detail.outcome.scope_digest, report.scope_model.scope_a.scope_digest);
});

test('a receipt for a different scope digest is refused by name', () => {
  const entry = byId(runProfile(), 'different-scope-digest-refused');
  assert.equal(entry.outcome.refusal, 'funds_authority_scope_mismatch');
});

test('absence of a receipt is failure of the check, never a pass', () => {
  const entry = byId(runProfile(), 'no-receipt-fails-closed');
  assert.equal(entry.outcome.check8_funds_authority, 'refused');
  assert.equal(entry.outcome.refusal, 'funds_authority_unavailable');
});

test('expired and revoked receipts are refused by name', () => {
  const report = runProfile();
  assert.equal(byId(report, 'expired-receipt-refused').outcome.refusal, 'funds_authority_receipt_expired');
  assert.equal(byId(report, 'revoked-receipt-refused').outcome.refusal, 'funds_authority_receipt_revoked');
});

test('a signer the executor did not pin for the account principal is refused by name', () => {
  const entry = byId(runProfile(), 'unpinned-signer-refused');
  assert.equal(entry.outcome.refusal, 'funds_authority_signer_not_pinned');
});

test('malformed and hostile presentations refuse with a reason instead of throwing', () => {
  const digest = scopeDigestOf(SCOPE_A).digest;
  const hostile = [
    {},
    { receipt: {} },
    { receipt: { '@version': 'EP-RECEIPT-v1' } },
    { receipt: { '@version': 'EP-RECEIPT-v1', payload: { action: null }, signature: { algorithm: 'Ed25519', value: 'AA' } } },
    { receipt: 'not-an-object' },
  ];
  for (const presentation of hostile) {
    const outcome = establishFundsAuthority({
      scopeDigest: digest,
      accountRef: 'acct:rail-fixture:treasury-operating-001',
      presentation,
      pins: EXECUTOR_PINS,
      now: '2026-08-16T12:00:00.000Z',
    });
    assert.equal(outcome.check8_funds_authority, 'refused');
    assert.equal(typeof outcome.refusal, 'string');
  }
  // An account with no pinned procedure fails the check, not permits it.
  const noProcedure = establishFundsAuthority({
    scopeDigest: digest,
    accountRef: 'acct:rail-fixture:unknown-account',
    presentation: null,
    pins: EXECUTOR_PINS,
    now: '2026-08-16T12:00:00.000Z',
  });
  assert.equal(noProcedure.refusal, 'funds_authority_unavailable');
});
