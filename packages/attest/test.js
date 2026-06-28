// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/attest — identity-verify + work-sign round-trip against the
 * published verifier. The receipt this package emits MUST verify under
 * @emilia-protocol/verify, and the identity/work hashes MUST be re-derivable
 * from the original bytes (the whole point: anyone can re-check offline).
 *
 * Runner: node --test (same as packages/verify and packages/issue).
 *
 * @license Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { verifyIdentity, signWorkReceipt, sha256Hex, ATTEST_VERSION } from './index.js';
import { generateEd25519KeyPair } from '../issue/index.js';
import { verifyReceipt } from '../verify/index.js';

const identityFile = Buffer.from('=== C-DAWG IDENTITY ===\nname: Continuum-Dawg\ntier: meta-orchestrator\n', 'utf8');
const knownGood = sha256Hex(identityFile); // the hash you stored in Keeper
const workFile = Buffer.from('the signed work product — a plan, a diff, a decision\n', 'utf8');

test('verifyIdentity: matches a known-good hash and rejects a tampered identity', () => {
  assert.equal(verifyIdentity({ identity: identityFile, knownGoodHash: knownGood }).verified, true);
  const tampered = Buffer.concat([identityFile, Buffer.from('  // sneaky', 'utf8')]);
  assert.equal(verifyIdentity({ identity: tampered, knownGoodHash: knownGood }).verified, false);
  assert.equal(verifyIdentity({ identity: identityFile, knownGoodHash: 'deadbeef' }).verified, false);
});

test('signWorkReceipt: produces an EP-RECEIPT-v1 that verifies under verifyReceipt, with a v2 anchor', () => {
  const { privateKey } = generateEd25519KeyPair();
  const { document, public_key } = signWorkReceipt({
    identity: identityFile,
    knownGoodHash: knownGood,
    work: workFile,
    signerPrivateKey: privateKey,
    subject: 'ep:approver:c-dawg',
    workName: 'sprint-plan.md',
    issuedAt: '2026-06-28T18:00:00Z',
    anchor: true,
    priorLeaves: ['ab'.repeat(32)],
  });

  assert.equal(document['@version'], 'EP-RECEIPT-v1');
  const res = verifyReceipt(document, public_key);
  assert.equal(res.checks.signature, true);
  assert.equal(res.checks.anchor, true);
  assert.equal(res.valid, true);

  // The bound hashes are re-derivable from the original bytes — anyone can re-check.
  assert.equal(document.payload.identity.hash, sha256Hex(identityFile));
  assert.equal(document.payload.work.hash, sha256Hex(workFile));
});

test('fail-closed: refuses to sign when the identity does not match known-good', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(() => signWorkReceipt({
    identity: identityFile,
    knownGoodHash: 'not-the-real-hash',
    work: workFile,
    signerPrivateKey: privateKey,
    subject: 'ep:approver:c-dawg',
    issuedAt: '2026-06-28T18:00:00Z',
  }), /fail-closed/);
});

test('tamper: swapping the work hash after signing breaks the signature', () => {
  const { privateKey } = generateEd25519KeyPair();
  const { document, public_key } = signWorkReceipt({
    identity: identityFile, knownGoodHash: knownGood, work: workFile,
    signerPrivateKey: privateKey, subject: 'ep:approver:c-dawg', issuedAt: '2026-06-28T18:00:00Z',
  });
  document.payload.work.hash = crypto.randomBytes(32).toString('hex'); // claim a different artifact ran
  assert.equal(verifyReceipt(document, public_key).checks.signature, false);
});

test('ATTEST_VERSION is exported', () => {
  assert.equal(ATTEST_VERSION, 'EP-ATTEST-v1');
});
