// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { actionDigest } from '../../packages/verify/dist/evidence-chain.js';
import { buildPoppyAction, createPoppyApprovalVerifier } from './evidence.mjs';
import { createSyntheticPoppyApprovalFixture, syntheticPoppyOperation as operation,
  syntheticPoppyOwner as owner, SYNTHETIC_POPPY_COMPANY as ISSUER } from './approval-fixture.mjs';

const fixture = ({ op, contextOwner, issuer, ...options }: any = {}): Promise<any> =>
  createSyntheticPoppyApprovalFixture({ operation: op, owner: contextOwner, actionIssuer: issuer, ...options });

test('accepts real P-256 Class-A ceremony and pinned Ed25519 log over the exact operation', async () => {
  const f = await fixture();
  const r = f.verifier.verify(f.request);
  assert.equal(r.satisfied, true, JSON.stringify(r));
  assert.equal(r.action_digest, `sha256:${actionDigest(buildPoppyAction(operation(), owner(), ISSUER))}`);
});

test('approved_by user is not proof; invented or missing evidence fails closed', async () => {
  const f = await fixture();
  for (const evidence of [null, {}, { approved_by: 'user' }, { ...f.evidence, components: [] }]) {
    assert.equal(f.verifier.verify({ ...f.request, evidence }).satisfied, false);
  }
});

for (const [label, mutate] of Object.entries({
  operation_id: (r: any) => { r.operation.operation_id = 'different'; },
  revision: (r: any) => { r.operation.revision = 2; },
  summary: (r: any) => { r.operation.summary = 'Refund $500.00 USD'; },
  terms: (r: any) => { r.operation.terms.amount = '500.00'; },
  expiry: (r: any) => { r.operation.expires_at = '2026-10-12T18:04:00Z'; },
  fresh_approval: (r: any) => { r.operation.user_approval_required = false; },
  account: (r: any) => { r.owner.accountId = 'other'; },
  client: (r: any) => { r.owner.clientId = 'https://other.example/client.json'; },
  user: (r: any) => { r.owner.userId = 'other'; },
})) {
  test(`refuses substitution of ${label}`, async () => {
    const f = await fixture(); const r = structuredClone(f.request); mutate(r);
    assert.equal(f.verifier.verify(r).satisfied, false);
  });
}

test('company issuer is bound, and cannot be substituted by chain or constructor trust injection', async () => {
  const f = await fixture({ issuer: 'https://other-company.example' });
  assert.equal(f.verifier.verify(f.request).satisfied, false);
});

test('HTTPS issuer path and separate approval-site origin are preserved exactly', async () => {
  const issuer = 'https://shop.example/oauth/tenant-123';
  const f = await createSyntheticPoppyApprovalFixture({ companyIssuer: issuer });
  assert.equal(f.verifier.verify(f.request).satisfied, true);
  assert.equal(f.evidence.action.company_issuer, issuer);
});

test('valid enrolled keys cannot supply fresh approval for an owner outside the pinned owner/profile association', async () => {
  const f = await fixture();
  for (const field of ['clientId', 'userId', 'accountId']) {
    const outsideScope = { ...owner(), [field]: 'outside' };
    const verifier = createPoppyApprovalVerifier({ ...f.config, ownerScope: outsideScope });
    const r = verifier.verify(f.request);
    assert.equal(r.satisfied, false);
    assert.deepEqual(r.reasons, ['approval_owner_outside_pinned_scope']);
  }
  const missingScope = createPoppyApprovalVerifier({ ...f.config, ownerScope: undefined });
  assert.equal(missingScope.verify(f.request).satisfied, false);
  f.config.ownerScope.accountId = 'later-mutated';
  assert.equal(f.verifier.verify(f.request).satisfied, true, 'constructor snapshots owner association');
});

test('signed-in authority survives same-client/user/account session replacement', async () => {
  const f = await fixture(); f.request.owner.sessionId = 'session-2';
  assert.equal(f.verifier.verify(f.request).satisfied, true);
});

test('signed-out evidence is bound to its original session', async () => {
  const o = owner(); o.accountId = null;
  const f = await fixture({ contextOwner: o });
  assert.equal(f.verifier.verify(f.request).satisfied, true);
  f.request.owner.sessionId = 'session-2';
  assert.equal(f.verifier.verify(f.request).satisfied, false);
});

test('terms absence differs from empty terms and all nested terms are covered', async () => {
  const op: any = operation(); delete op.terms;
  const f = await fixture({ op }); f.request.operation.terms = {};
  assert.equal(f.verifier.verify(f.request).satisfied, false);
  const g = await fixture({ op: { ...operation(), terms: { fees: [{ amount: '4', applies: true }] } } });
  g.request.operation.terms.fees[0].applies = false;
  assert.equal(g.verifier.verify(g.request).satisfied, false);
});

test('canonical object-key order does not change the approved terms', async () => {
  const f = await fixture();
  f.request.operation.terms = { destination: 'original-card', currency: 'USD', amount: '50.00', order_id: '100' };
  assert.equal(f.verifier.verify(f.request).satisfied, true);
});

test('fresh-user profile refuses standing_permission even when the receipt is valid', async () => {
  const f = await fixture();
  assert.equal(f.verifier.verify({ ...f.request, approved_by: 'standing_permission' }).satisfied, false);
});

for (const decision of ['denied', 'rejected', 'amended']) {
  test(`cryptographically signed ${decision} is not approval`, async () => {
    const f = await fixture({ decision });
    assert.equal(f.verifier.verify(f.request).satisfied, false);
  });
}

test('receipt signature or signed context tampering fails closed', async () => {
  for (const part of ['signature', 'context', 'checkpoint']) {
    const f = await fixture(); const receipt = f.evidence.components[0].evidence;
    if (part === 'signature') receipt.signoffs[0].webauthn.signature = Buffer.alloc(70).toString('base64url');
    if (part === 'context') receipt.contexts[0].approver = 'attacker';
    if (part === 'checkpoint') receipt.log_proof.checkpoint.root_hash = 'f'.repeat(64);
    assert.equal(f.verifier.verify(f.request).satisfied, false);
  }
});

test('UV, key class, keys, identity, policy, audience, revocation and directory freshness remain native pinned checks', async () => {
  for (const change of ['flags', 'class', 'key', 'log', 'identity', 'policy', 'origin', 'rp', 'revoked', 'directory']) {
    const f = await fixture(change === 'flags' ? { flags: 0x01 } : change === 'class' ? { keyClass: 'B' } : {});
    if (change === 'key') f.profile.approver_keys['key:123'].public_key =
      crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    if (change === 'policy') f.profile.expected_policy_hash = `sha256:${'b'.repeat(64)}`;
    if (change === 'log') f.profile.log_public_key =
      crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    if (change === 'identity') f.profile.approver_keys['key:123'].approver_id = 'wrong-human';
    if (change === 'origin') f.profile.allowed_origins = ['https://other.example'];
    if (change === 'rp') f.profile.rp_id = 'other.example';
    if (change === 'revoked') f.profile.approver_keys['key:123'].revoked_at = '2026-10-12T18:00:20Z';
    if (change === 'directory') f.profile.registry_checked_at = '2026-10-12T17:00:00Z';
    assert.equal(createPoppyApprovalVerifier(f.config).verify(f.request).satisfied, false);
  }
});

test('constructor snapshots pins and ignores evidence embedded trust, requirement and verification time', async () => {
  const f = await fixture();
  f.profile.expected_policy_hash = `sha256:${'b'.repeat(64)}`;
  f.evidence.policiesByType = { 'ep-receipt': f.profile };
  f.evidence.requirement = 'attacker'; f.evidence.verificationTime = '2099-01-01T00:00:00Z';
  assert.equal(f.verifier.verify(f.request).satisfied, true);
  const bad = await fixture(); bad.evidence.components[0].evidence.action.summary = 'forged';
  bad.evidence.keysByType = { 'ep-receipt': f.profile.approver_keys };
  assert.equal(bad.verifier.verify(bad.request).satisfied, false);
});

test('stale, future, expired receipt and expired operation refuse', async () => {
  for (const opts of [{ issuedAt: '2026-10-12T17:55:00Z' },
    { issuedAt: '2026-10-12T18:01:00Z', signedAt: '2026-10-12T18:01:15Z', committedAt: '2026-10-12T18:01:22Z' }]) {
    const f = await fixture(opts);
    assert.equal(f.verifier.verify(f.request).satisfied, false);
  }
  const f = await fixture();
  assert.equal(createPoppyApprovalVerifier({ ...f.config, now: () => Date.parse('2026-10-12T18:06:00Z') }).verify(f.request).satisfied, false);
  const expired = await fixture({ expiresAt: '2026-10-12T18:00:25Z' });
  assert.equal(expired.verifier.verify(expired.request).satisfied, false);
  // Context issuance alone is not enough: historical authenticity must not
  // admit a signoff or committed receipt from after the company's clock.
  const futureSignoff = await fixture({ signedAt: '2026-10-12T18:00:40Z', committedAt: '2026-10-12T18:00:45Z' });
  assert.equal(futureSignoff.verifier.verify(futureSignoff.request).satisfied, false);
  const futureCommit = await fixture({ committedAt: '2026-10-12T18:00:40Z' });
  assert.equal(futureCommit.verifier.verify(futureCommit.request).satisfied, false);
});

test('malformed configuration and a failed clock become refusals, not raw exceptions', async () => {
  const f = await fixture();
  for (const config of [{}, { ...f.config, companyIssuer: 'http://shop.example' },
    { ...f.config, epReceiptProfile: null }, { ...f.config, now: () => NaN },
    { ...f.config, now: () => { throw new Error('private clock detail'); } }]) {
    const r = createPoppyApprovalVerifier(config).verify(f.request);
    assert.equal(r.satisfied, false); assert.ok(!JSON.stringify(r).includes('private clock detail'));
  }
});

test('closed input types, unsafe revisions, deep/huge terms and getters refuse without leaking exceptions', async () => {
  const f = await fixture();
  for (const revision of [0, -1, '1', 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(f.verifier.verify({ ...f.request, operation: { ...operation(), revision } }).satisfied, false);
  }
  for (const terms of [[], null, 'terms', { big: 'x'.repeat(70000) }]) {
    assert.equal(f.verifier.verify({ ...f.request, operation: { ...operation(), terms } }).satisfied, false);
  }
  let nested: any = {}; for (let i = 0; i < 30; i++) nested = { nested };
  assert.equal(f.verifier.verify({ ...f.request, operation: { ...operation(), terms: nested } }).satisfied, false);
  const trap = { ...operation(), secret: 'never echo this' };
  Object.defineProperty(trap, 'summary', { get() { throw new Error('private secret'); }, enumerable: true });
  const r = f.verifier.verify({ ...f.request, operation: trap });
  assert.equal(r.satisfied, false); assert.ok(!JSON.stringify(r).includes('private secret'));
  assert.equal(f.verifier.verify({ ...f.request, owner: { ...owner(), untrustedOwnerClaim: true } }).satisfied, false);
});
