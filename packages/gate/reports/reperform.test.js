// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for the independent re-performance verifier — run with `node --test`.
 *
 * The positive-path fixtures come from a REAL gate run (real Ed25519 receipts,
 * real WebAuthn signoff / EP-QUORUM-v1 material minted by the EG-1 helpers),
 * so what is re-performed here is the actual production evidence shape, not a
 * hand-drawn imitation of it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGate, createEvidenceLog, mintDeviceSignoff, mintQuorumEvidence } from '../index.js';
import { meterUsage, buildUsageStatement } from '../metering.js';
import { buildUnderwriterAttestation } from './underwriter.js';
import { REPERFORMANCE_VERSION, reperformEvidence, compareToReported } from './reperform.js';

/* ------------------------------ helpers ------------------------------- */

function canon(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function makeKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function mint(privateKey, payload) {
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}
const HASH_FOR = (action) => crypto.createHash('sha256').update(canon({ action_type: action }), 'utf8').digest('hex');
let n = 0;
function receipt(privateKey, { action = 'payment.release', outcome = 'allow', quorum = false } = {}) {
  const payload = {
    receipt_id: `rcpt_${++n}`, subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(), claim: { action_type: action, outcome },
  };
  if (quorum) {
    payload.quorum = mintQuorumEvidence({ actionHash: HASH_FOR(action), threshold: 2 });
  } else if (outcome === 'allow_with_signoff') {
    const s = mintDeviceSignoff({ actionHash: HASH_FOR(action), approver: 'ep:approver:test' });
    payload.signoff = s.signoff;
    payload.approver_public_key = s.approver_public_key;
  }
  return mint(privateKey, payload);
}

const MANIFEST = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [
    { id: 'pay', action_type: 'payment.release', receipt_required: true, risk: 'critical', assurance_class: 'class_a', match: { protocol: 'mcp', tool: 'release_payment' } },
    { id: 'read', action_type: 'read.balance', receipt_required: false, match: { protocol: 'mcp', tool: 'read_balance' } },
  ],
};
const PAY = { protocol: 'mcp', tool: 'release_payment' };
const READ = { protocol: 'mcp', tool: 'read_balance' };
const T = Date.parse('2026-07-04T00:00:00.000Z');
const AUDIT_SCOPE = {
  rpId: 'emiliaprotocol.ai',
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
};

function auditorTrustFor(entries) {
  const approverKeys = {};
  const quorumPolicies = {};
  let next = 0;
  for (const entry of entries) {
    const payload = entry?.receipt?.payload;
    const signoff = entry?.signoff ?? payload?.signoff;
    const signoffKey = entry?.approver_public_key ?? payload?.approver_public_key;
    if (signoff?.context?.approver && signoffKey) {
      approverKeys[`audit_${next++}`] = {
        approver_id: signoff.context.approver,
        public_key: signoffKey,
        key_class: 'A',
      };
    }
    const quorum = entry?.quorum ?? payload?.quorum;
    if (quorum?.policy && typeof entry?.action === 'string') {
      quorumPolicies[entry.action] = structuredClone(quorum.policy);
      for (const member of quorum.members || []) {
        approverKeys[`audit_${next++}`] = {
          approver_id: member?.signoff?.context?.approver,
          public_key: member?.approver_public_key,
          key_class: 'A',
        };
      }
    }
  }
  return { approverKeys, quorumPolicies, ...AUDIT_SCOPE };
}

/**
 * A real gate run: 1 unguarded pass-through, 1 allow (genuine WebAuthn signoff
 * earns class_a), 1 replay refusal of the same receipt, 1 missing-receipt
 * refusal. Returns the log entries plus the issuer key.
 */
async function realGateEntries() {
  const { pub, privateKey } = makeKey();
  const log = createEvidenceLog();
  // Self-contained embedded-evidence mode: the receipt carries a genuine WebAuthn
  // signoff plus its approver key. That mode is now opt-in (allowEmbeddedApproverKeys)
  // so an unpinned embedded key does not launder trust by default.
  const g = createGate({
    manifest: MANIFEST,
    trustedKeys: [pub],
    log,
    allowEmbeddedApproverKeys: true,
    rpId: 'emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
  });
  const r = receipt(privateKey, { outcome: 'allow_with_signoff' });
  const passthrough = await g.check({ selector: READ });
  assert.equal(passthrough.reason, 'not_guarded');
  const allowed = await g.check({ selector: PAY, receipt: r });
  assert.equal(allowed.allow, true, allowed.reason);
  const replayed = await g.check({ selector: PAY, receipt: r });
  assert.equal(replayed.reason, 'replay_refused');
  const missing = await g.check({ selector: PAY });
  assert.equal(missing.reason, 'receipt_required');
  return { entries: log.all(), pub, privateKey };
}

/* -------------------------------- chain -------------------------------- */

test('empty entries: valid but boring — chain ok, zero counts, deterministic', async () => {
  const a = await reperformEvidence([], { now: T });
  const b = await reperformEvidence([], { now: T });
  assert.equal(a['@version'], REPERFORMANCE_VERSION);
  assert.deepEqual(a.chain, { ok: true, entries: 0, head: null });
  assert.deepEqual(a.counts, { allows: 0, denies: 0, replays_blocked: 0, by_action_type: {} });
  assert.deepEqual(a.receipts, { reverified: 0, failed: [], not_reverifiable: 0, no_receipt_presented: 0 });
  assert.equal(JSON.stringify(a), JSON.stringify(b)); // byte-identical: same inputs, pinned now
});

test('reperforms a real gate log: chain ok, head matches, counts recomputed from scratch', async () => {
  const { entries, pub } = await realGateEntries();
  assert.equal(entries.length, 4);
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T });

  assert.equal(rep.chain.ok, true);
  assert.equal(rep.chain.entries, 4);
  assert.equal(rep.chain.head, entries[3].hash);

  // Guarded decisions only: allow + replay deny + missing-receipt deny.
  assert.deepEqual(rep.counts, {
    allows: 1, denies: 2, replays_blocked: 1, by_action_type: { 'payment.release': 3 },
  });

  // The gate's own entries reference receipts but do not carry them — those
  // land in not_reverifiable, never in a silent pass.
  assert.equal(rep.receipts.reverified, 0);
  assert.deepEqual(rep.receipts.failed, []);
  assert.equal(rep.receipts.not_reverifiable, 2); // allow + replay deny carry receipt_id
  assert.equal(rep.receipts.no_receipt_presented, 2); // pass-through + missing-receipt deny
  assert.deepEqual(rep.integrity_warnings, []);
  // The honesty boundary travels inside the artifact.
  assert.ok(rep.honesty.status.includes('does not conclude'));
});

test('tampered middle entry breaks the chain from that point', async () => {
  const { entries, pub } = await realGateEntries();
  const tampered = entries.slice();
  tampered[1] = { ...tampered[1], action: 'evil.exfiltrate' }; // stale hash now
  const rep = await reperformEvidence(tampered, { issuerKeys: [pub], now: T });
  assert.equal(rep.chain.ok, false);
  assert.equal(rep.chain.broken_at, 1);
  assert.equal(rep.chain.reason, 'hash_mismatch');
  assert.equal(rep.chain.head, null); // a broken chain vouches for no head
});

test('removed entry and hash-consistent rewrite are caught by the real chain verifier', async () => {
  const { entries, pub } = await realGateEntries();

  // Remove a middle entry: each remaining body still matches its own hash, but
  // the prev_hash link is severed — evidence.js's verify() catches it.
  const removed = [entries[0], entries[2], entries[3]];
  const repRemoved = await reperformEvidence(removed, { issuerKeys: [pub], now: T });
  assert.equal(repRemoved.chain.ok, false);
  assert.equal(repRemoved.chain.reason, 'prev_hash_mismatch');

  // Rewrite a middle entry AND recompute its hash consistently: the per-entry
  // recompute passes, but the successor's prev_hash no longer matches.
  const rewritten = entries.slice();
  const { hash: _oldHash, ...body } = rewritten[1];
  const evilBody = { ...body, action: 'evil.exfiltrate' };
  rewritten[1] = { ...evilBody, hash: sha256hex(canon(evilBody)) };
  const repRewritten = await reperformEvidence(rewritten, { issuerKeys: [pub], now: T });
  assert.equal(repRewritten.chain.ok, false);
  assert.equal(repRewritten.chain.reason, 'prev_hash_mismatch');
});

test('a partial slice (not from genesis) fails closed', async () => {
  const { entries, pub } = await realGateEntries();
  const rep = await reperformEvidence(entries.slice(1), { issuerKeys: [pub], now: T });
  assert.equal(rep.chain.ok, false);
  assert.equal(rep.chain.reason, 'prev_hash_mismatch');
});

/* ---------------------- receipt re-verification ----------------------- */

/** A log whose decision entries CARRY their receipts (richer-logging deployer). */
async function carryingLog(privateKey, { rogueKey = null } = {}) {
  const log = createEvidenceLog();
  const at = new Date(T).toISOString();
  const base = { kind: 'decision', at, allow: true, status: 200, reason: 'allow', required_tier: 'class_a' };

  const rSignoff = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  await log.record({ ...base, action: 'payment.release', receipt_id: rSignoff.payload.receipt_id, receipt: rSignoff });

  const rQuorum = receipt(privateKey, { action: 'treasury.wire', outcome: 'allow', quorum: true });
  await log.record({ ...base, action: 'treasury.wire', required_tier: 'quorum', receipt_id: rQuorum.payload.receipt_id, receipt: rQuorum });

  // Stripped payloads: references a receipt but does not carry it.
  const rStripped = receipt(privateKey, { action: 'payment.release' });
  await log.record({ ...base, action: 'payment.release', receipt_id: rStripped.payload.receipt_id });

  if (rogueKey) {
    // A receipt minted by an issuer the auditor did NOT pin.
    const rRogue = receipt(rogueKey, { action: 'payment.release' });
    await log.record({ ...base, action: 'payment.release', receipt_id: rRogue.payload.receipt_id, receipt: rRogue });
  }
  return log;
}

test('carried receipt/signoff/quorum material re-verifies; stripped payloads land in not_reverifiable', async () => {
  const { pub, privateKey } = makeKey();
  const log = await carryingLog(privateKey);
  const entries = log.all();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T, ...auditorTrustFor(entries) });

  assert.equal(rep.chain.ok, true);
  // Entry 1: receipt + embedded WebAuthn signoff, entry 2: receipt + embedded
  // EP-QUORUM-v1 — every carried payload re-verified.
  assert.equal(rep.receipts.reverified, 2);
  assert.deepEqual(rep.receipts.failed, []);
  assert.equal(rep.receipts.not_reverifiable, 1);
});

test('failed re-verification is a NAMED failure, never absorbed', async () => {
  const { pub, privateKey } = makeKey();
  const rogue = makeKey();
  const log = await carryingLog(privateKey, { rogueKey: rogue.privateKey });
  const entries = log.all();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T, ...auditorTrustFor(entries) });

  assert.equal(rep.chain.ok, true); // the LOG honestly recorded a bad receipt — chain is intact
  assert.equal(rep.receipts.reverified, 2);
  assert.equal(rep.receipts.failed.length, 1);
  assert.equal(rep.receipts.failed[0].hash, entries[3].hash);
  assert.equal(rep.receipts.failed[0].reason, 'receipt:untrusted_or_invalid_signature');
});

test('no issuer keys pinned: carried receipts fail NAMED, never silently pass', async () => {
  const { privateKey } = makeKey();
  const log = await carryingLog(privateKey);
  const entries = log.all();
  const rep = await reperformEvidence(entries, { now: T, ...auditorTrustFor(entries) }); // issuerKeys omitted
  assert.equal(rep.receipts.reverified, 0);
  assert.ok(rep.receipts.failed.length >= 2);
  for (const f of rep.receipts.failed.filter((x) => x.reason.startsWith('receipt:'))) {
    assert.equal(f.reason, 'receipt:no_trusted_keys_configured');
  }
});

test('tampered embedded signoff and unpinned approver fail named', async () => {
  const log = createEvidenceLog();
  const at = new Date(T).toISOString();
  const good = mintDeviceSignoff({ actionHash: HASH_FOR('payment.release'), approver: 'ep:approver:test' });
  const unpinned = mintDeviceSignoff({ actionHash: HASH_FOR('payment.release'), approver: 'ep:approver:unknown' });
  // Tamper the signed context — challenge binding must fail.
  const evilSignoff = { ...good.signoff, context: { ...good.signoff.context, nonce: 'sig_forged' } };
  await log.record({
    kind: 'decision', at, action: 'payment.release', allow: true, status: 200, reason: 'allow',
    required_tier: 'class_a', receipt_id: 'rcpt_x1', signoff: evilSignoff, approver_public_key: good.approver_public_key,
  });
  await log.record({
    kind: 'decision', at, action: 'payment.release', allow: true, status: 200, reason: 'allow',
    required_tier: 'class_a', receipt_id: 'rcpt_x2', signoff: unpinned.signoff,
  });
  const entries = log.all();
  const rep = await reperformEvidence(entries, {
    now: T,
    approverKeys: {
      trusted: { approver_id: good.signoff.context.approver, public_key: good.approver_public_key, key_class: 'A' },
    },
    ...AUDIT_SCOPE,
  });
  assert.equal(rep.receipts.reverified, 0);
  assert.equal(rep.receipts.failed.length, 2);
  assert.equal(rep.receipts.failed[0].hash, entries[0].hash);
  assert.match(rep.receipts.failed[0].reason, /^signoff:checks_failed:.*challenge_binding/);
  assert.equal(rep.receipts.failed[1].reason, 'signoff:approver_key_unpinned_or_ambiguous');
});

test('presenter-carried approver key and quorum policy never become auditor trust roots', async () => {
  const log = createEvidenceLog();
  const at = new Date(T).toISOString();
  const q = mintQuorumEvidence({ actionHash: HASH_FOR('treasury.wire'), threshold: 2 });
  await log.record({
    kind: 'decision', at, action: 'treasury.wire', allow: true, status: 200, reason: 'allow',
    required_tier: 'quorum', receipt_id: 'rcpt_self_trusted', quorum: q,
  });
  const rep = await reperformEvidence(log.all(), { now: T, ...AUDIT_SCOPE });
  assert.equal(rep.receipts.reverified, 0);
  assert.equal(rep.receipts.failed[0].reason, 'quorum:quorum_policy_required');
});

/* --------------------------- compareToReported ------------------------- */

test('compareToReported: honest usage pack matches; altered counts are NAMED drift', async () => {
  const { entries, pub } = await realGateEntries();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  const period = { periodStart: Date.now() - 60_000, periodEnd: Date.now() + 60_000 };
  const usage = meterUsage(entries, period);

  const honest = compareToReported(rep, usage);
  assert.equal(honest.match, true);
  assert.deepEqual(honest.drift, []);

  // The signed-ready statement body carries the same @version + numbers.
  const statement = buildUsageStatement(usage, { org: 'acme' });
  assert.equal(compareToReported(rep, statement).match, true);

  const cooked = { ...usage, allows: usage.allows + 1, by_action_type: { ...usage.by_action_type, 'payment.release': 99 } };
  const out = compareToReported(rep, cooked);
  assert.equal(out.match, false);
  assert.deepEqual(out.drift, [
    { field: 'allows', reported: 2, recomputed: 1 },
    { field: 'by_action_type.payment.release', reported: 99, recomputed: 3 },
  ]);
});

test('compareToReported: underwriter pack overlap matches; altered volume is NAMED drift', async () => {
  const { entries, pub } = await realGateEntries();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  const pack = buildUnderwriterAttestation(entries, {
    insured: 'Acme Corp', periodStart: Date.now() - 60_000, periodEnd: Date.now() + 60_000, now: T,
  });

  const honest = compareToReported(rep, pack);
  assert.equal(honest.match, true);

  const cooked = { ...pack, volume: { ...pack.volume, allowed: pack.volume.allowed + 5 } };
  const out = compareToReported(rep, cooked);
  assert.equal(out.match, false);
  assert.deepEqual(out.drift, [{ field: 'volume.allowed', reported: 6, recomputed: 1 }]);
});

test('compareToReported: a stripped pack field can never silently match', async () => {
  const { entries, pub } = await realGateEntries();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  const usage = meterUsage(entries, { periodStart: Date.now() - 60_000, periodEnd: Date.now() + 60_000 });
  const stripped = { ...usage };
  delete stripped.replays_blocked;
  const out = compareToReported(rep, stripped);
  assert.equal(out.match, false);
  assert.deepEqual(out.drift, [{ field: 'replays_blocked', reported: null, recomputed: 1 }]);
});

test('compareToReported: unknown pack @version -> fail closed (throws)', async () => {
  const { entries, pub } = await realGateEntries();
  const rep = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  assert.throws(() => compareToReported(rep, { '@version': 'EP-GATE-MYSTERY-v7', allows: 1 }), /unknown pack @version/);
  assert.throws(() => compareToReported(rep, { allows: 1 }), /unknown pack @version/);
  assert.throws(() => compareToReported(rep, null), /reportedPack/);
  // Foreign / malformed "recomputed" is refused too — never compared fuzzily.
  assert.throws(() => compareToReported({}, { '@version': 'EP-GATE-USAGE-v1' }), /finite number/);
  assert.throws(() => compareToReported(null, { '@version': 'EP-GATE-USAGE-v1' }), /recomputed/);
});

/* ----------------------------- fail-closed misc ------------------------ */

test('malformed inputs are refused or surfaced, never guessed at', async () => {
  await assert.rejects(() => reperformEvidence('nope'), /entries must be an array/);
  await assert.rejects(() => reperformEvidence([], { issuerKeys: 'k1' }), /issuerKeys must be an array/);

  // A non-record object in the stream breaks the chain (named) AND is surfaced
  // in integrity_warnings for the count pass.
  const rep = await reperformEvidence(['garbage'], { now: T });
  assert.equal(rep.chain.ok, false);
  assert.equal(rep.chain.reason, 'not_an_object');
  assert.deepEqual(rep.integrity_warnings, [{ index: 0, reason: 'not_an_object' }]);
});

test('deterministic: same entries + pinned now -> byte-identical artifact', async () => {
  const { entries, pub } = await realGateEntries();
  const a = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  const b = await reperformEvidence(entries, { issuerKeys: [pub], now: T });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});
