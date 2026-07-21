// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — agentic audit-trail demo (EP-GATE-AUDIT-TRAIL-DEMO-v1).
 *
 * ONE COMMAND, <60s, fully offline: a scripted period of AI-agent activity runs
 * through a real Consequence Firewall (no mocks, no fabricated artifacts),
 * then the full auditor-facing stack is generated over the gate's tamper-evident
 * evidence log and RE-PERFORMED as the third-party auditor would:
 *
 *   PROLOGUE  an unguarded read passes through (the uncontrolled surface — reported, never hidden)
 *   ACT 1     a receipt-authorized payment (genuine WebAuthn device signoff -> class_a)  ALLOWED
 *   ACT 2     a quorum-authorized production delete (real EP-QUORUM-v1, 2 humans)        ALLOWED
 *   ACT 3     the same payment attempted with NO receipt                    REFUSED (428 challenge)
 *   ACT 4     a replay of Act 1's already-consumed receipt                  REFUSED (replay_refused)
 *   ACT 5     a tampered receipt (signed field mutated after signing)       REFUSED (receipt_rejected)
 *   ACT 6     underwriter attestation + Art. 14 pack + usage statement + auditor workpaper
 *   ACT 7     third-party RE-PERFORMANCE (reports/reperform.js): the hash chain is rebuilt
 *             and re-verified, the receipts carried in the evidence are cryptographically
 *             re-verified against the auditor-pinned issuer key, every count is recomputed
 *             from scratch and tied out against the issued reports — ZERO drift asserted.
 *
 * Evidence-custody pattern: the deployer runs the gate with an evidence log
 * that EMBEDS the presented receipt document in each decision record (the
 * `log` option of createGate). The hash chain then commits to the receipts
 * themselves, and the auditor can re-verify them from the log alone — including
 * the tampered receipt, whose re-verification independently FAILS exactly as
 * the gate refused it.
 *
 * Determinism: the clock is captured ONCE at start and injected everywhere
 * (gate `now`, receipt created_at, signoff windows, report generated_at); every
 * decision, count, hash-chain length and assertion is identical on every run.
 * Absolute timestamps are anchored to the run's start instant because receipt
 * freshness is wall-clock verified upstream — the demo never back- or
 * forward-dates a receipt to trick the verifier. No Math.random anywhere;
 * receipt/nonce identifiers are fixed strings, key material comes from
 * node:crypto keygen (as in production).
 *
 * HONESTY BOUNDARY: this demo EXERCISES the control and SUPPORTS an audit
 * walkthrough. It does not conclude, opine, or certify anything about any real
 * system — the reports it prints carry their own honesty notices, verbatim.
 *
 * Run:  node examples/audit/agentic-audit-trail-demo.mjs
 * Exits non-zero if ANY assertion fails.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGate, createEvidenceLog, mintDeviceSignoff, mintQuorumEvidence } from '../../packages/gate/index.js';
import { buildUnderwriterAttestation, UNDERWRITER_ATTESTATION_VERSION } from '../../packages/gate/reports/underwriter.js';
import { buildArt14EvidencePack, ART14_PACK_VERSION, ART14_HONESTY_NOTICE } from '../../packages/gate/reports/art14.js';
import { meterUsage, buildUsageStatement, USAGE_VERSION } from '../../packages/gate/metering.js';
import { buildAuditWorkpaper, AUDIT_WORKPAPER_VERSION, AUDIT_WORKPAPER_HONESTY_NOTICE } from '../../packages/gate/reports/auditor-workpaper.js';
import { reperformEvidence, compareToReported, REPERFORMANCE_VERSION } from '../../packages/gate/reports/reperform.js';

export const AUDIT_TRAIL_DEMO_VERSION = 'EP-GATE-AUDIT-TRAIL-DEMO-v1';

/* ----------------------------- deterministic clock ----------------------------- */
// Captured once; every subsequent timestamp is BASE + an explicit scripted offset.
const BASE = Date.now();
let tOffsetMs = 0;
const now = (): number => BASE + tOffsetMs;
const advance = (ms: number = 1000): void => { tOffsetMs += ms; };
const iso = (ms: number): string => new Date(ms).toISOString();

/* ------------------------- canonical JSON + receipt minting ------------------------- */
// Same sorted-key canonical JSON the receipt signature is computed over
// (idiom shared with @emilia-protocol/verify and the gate test suite).
const canon = (v: unknown): string => (v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v as Record<string, unknown>).sort().map((k) => JSON.stringify(k) + ':' + canon((v as Record<string, unknown>)[k])).join(',')}}`
      : JSON.stringify(v));
const HASH_FOR = (actionType: string): string => crypto.createHash('sha256').update(canon({ action_type: actionType }), 'utf8').digest('hex');

function makeIssuerKey(): { privateKey: crypto.KeyObject; pub: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}

/** Mint a REAL EP-RECEIPT-v1: Ed25519 over canonical JSON of the payload. */
function mintReceipt(privateKey: crypto.KeyObject, payload: any): any {
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

/* --------------------------------- the manifest --------------------------------- */
// What this deployment guards, and at what assurance tier. Reads are explicitly
// NOT guarded — the reports must show that surface as uncontrolled, not hide it.
const ORG = 'Meridian Clearing Co. (demo)';
const SYSTEM = 'meridian-payments-agent (demo)';
const MANIFEST = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [
    { id: 'pay', action_type: 'payment.release', receipt_required: true, risk: 'critical', assurance_class: 'class_a', match: { protocol: 'mcp', tool: 'release_payment' } },
    { id: 'wipe', action_type: 'infra.delete_production_db', receipt_required: true, risk: 'critical', assurance_class: 'quorum', match: { protocol: 'mcp', tool: 'delete_production_db' } },
    { id: 'read', action_type: 'read.balance', receipt_required: false, match: { protocol: 'mcp', tool: 'read_balance' } },
  ],
};
const SEL_PAY = { protocol: 'mcp', tool: 'release_payment' };
const SEL_WIPE = { protocol: 'mcp', tool: 'delete_production_db' };
const SEL_READ = { protocol: 'mcp', tool: 'read_balance' };

/* ------------------------------------- main ------------------------------------- */
async function main() {
  const t0 = process.hrtime.bigint();
  const lines: string[] = [];
  const say = (s: string) => lines.push(s);

  const issuer = makeIssuerKey();

  // Evidence-custody log: each decision record carries the receipt document that
  // was presented for it, so the hash chain commits to the receipts themselves
  // and the auditor can re-perform receipt verification from the log alone.
  const baseLog = createEvidenceLog({ strict: true });
  let presentedReceipt = null;
  const custodyLog = {
    async record(entry) {
      const enriched = entry.kind === 'decision' && presentedReceipt
        ? { ...entry, receipt: presentedReceipt }
        : entry;
      return baseLog.record(enriched);
    },
    all: () => baseLog.all(),
    verify: () => baseLog.verify(),
  };

  const gate = createGate({
    manifest: MANIFEST,
    trustedKeys: [issuer.pub],
    maxAgeSec: 900,
    now,
    log: custodyLog,
    allowEphemeralStore: true, // single-process demo; production requires a shared store
  });

  /** Present a receipt to the gate, keeping the custody log aware of the exhibit. */
  async function present(receipt, args) {
    presentedReceipt = receipt;
    try { return await gate.check({ ...args, receipt }); } finally { presentedReceipt = null; }
  }

  let receiptSeq = 0;
  /**
   * @param {object} opts
   * @param {string} opts.actionType
   * @param {string} opts.subject
   * @param {Record<string, any>} [opts.claimExtra]
   * @param {string} [opts.tier]
   * @param {string} [opts.approver]
   */
  function agentReceipt({ actionType, subject, claimExtra = {}, tier = 'class_a', approver }: any) {
    const claim: any = { action_type: actionType, ...claimExtra };
    const payload: any = {
      receipt_id: `rcpt_demo_${String(++receiptSeq).padStart(3, '0')}`,
      subject,
      issuer: 'ep:org:meridian-demo',
      created_at: iso(now()),
      claim,
    };
    if (tier === 'quorum') {
      claim.outcome = 'allow';
      payload.quorum = mintQuorumEvidence({ actionHash: HASH_FOR(actionType), threshold: 2, issuedAtMs: now() });
    } else {
      claim.outcome = 'allow_with_signoff';
      const s = mintDeviceSignoff({
        actionHash: HASH_FOR(actionType),
        approver,
        issuedAtMs: now(),
        nonce: `sig_demo_${String(receiptSeq).padStart(3, '0')}`,
      });
      payload.signoff = s.signoff;
      payload.approver_public_key = s.approver_public_key;
    }
    return mintReceipt(issuer.privateKey, payload);
  }

  /* PROLOGUE — routine read, not guarded by the manifest. Passes with no
   * ceremony; the reports must surface it as the uncontrolled surface. */
  const read = await gate.check({ selector: SEL_READ });
  assert.equal(read.allow, true);
  assert.equal(read.reason, 'not_guarded');
  say('PROLOGUE — read.balance (not guarded by manifest)                          → PASSED THROUGH (no receipt; reported as uncontrolled surface)');
  advance();

  /* ACT 1 — receipt-authorized payment. Genuine WebAuthn device signoff
   * embedded in the receipt cryptographically earns class_a. */
  const payReceipt = agentReceipt({
    actionType: 'payment.release',
    subject: 'agent:ap-clerk-7',
    approver: 'ep:approver:cfo',
    claimExtra: { amount_usd: 48500, currency: 'USD', payment_instruction_id: 'pi_demo_48500' },
  });
  const act1 = await present(payReceipt, { selector: SEL_PAY });
  assert.equal(act1.allow, true, `ACT 1 expected allow, got ${act1.reason}`);
  assert.equal(act1.reason, 'allow');
  assert.equal(act1.evidence.have_tier, 'class_a');
  const exec1 = await gate.recordExecution({ authorization: act1, outcome: 'executed', detail: 'wire released' });
  assert.equal(exec1.authorizes_decision, act1.evidence.hash);
  say(`ACT 1    — payment.release $48,500, receipt ${payReceipt.payload.receipt_id} (WebAuthn device signoff → class_a) → ALLOWED, executed`);
  advance();

  /* ACT 2 — quorum-authorized production delete. A REAL EP-QUORUM-v1 document:
   * 2 distinct humans, 2 distinct device keys, per-signer WebAuthn assertions. */
  const wipeReceipt = agentReceipt({
    actionType: 'infra.delete_production_db',
    subject: 'agent:infra-bot-2',
    tier: 'quorum',
    claimExtra: { database: 'prod-ledger-eu-1', change_ticket: 'CHG-88121' },
  });
  const act2 = await present(wipeReceipt, { selector: SEL_WIPE });
  assert.equal(act2.allow, true, `ACT 2 expected allow, got ${act2.reason}`);
  assert.equal(act2.evidence.have_tier, 'quorum');
  const exec2 = await gate.recordExecution({ authorization: act2, outcome: 'executed', detail: 'decommission completed' });
  assert.equal(exec2.authorizes_decision, act2.evidence.hash);
  say(`ACT 2    — infra.delete_production_db, receipt ${wipeReceipt.payload.receipt_id} (EP-QUORUM-v1, 2-of-2 humans)      → ALLOWED, executed`);
  advance();

  /* ACT 3 — the agent tries the payment again with NO receipt. Deny-by-default:
   * 428 + a machine-readable Receipt-Required challenge. */
  const act3 = await gate.check({ selector: SEL_PAY });
  assert.equal(act3.allow, false);
  assert.equal(act3.status, 428);
  assert.equal(act3.reason, 'receipt_required');
  assert.ok(act3.challenge?.required, 'ACT 3 must carry a Receipt-Required challenge');
  // header is only absent on non-challenge branches of check(); the 428 + challenge
  // asserted immediately above proves this is the Receipt-Required challenge branch.
  assert.match((act3 as any).header as string, /action=/);
  say('ACT 3    — payment.release attempted with NO receipt                       → REFUSED 428 (Receipt-Required challenge issued)');
  advance();

  /* ACT 4 — replay. Act 1's receipt was consumed on use; presenting the same
   * receipt again must be refused, not double-spent. */
  const act4 = await present(payReceipt, { selector: SEL_PAY });
  assert.equal(act4.allow, false);
  assert.equal(act4.reason, 'replay_refused');
  say(`ACT 4    — replay of already-consumed receipt ${payReceipt.payload.receipt_id}                        → REFUSED (replay_refused)`);
  advance();

  /* ACT 5 — tamper. A fresh, correctly signed receipt whose amount is mutated
   * AFTER signing. The Ed25519 signature no longer binds; refusal is mandatory. */
  const tamperedReceipt = agentReceipt({
    actionType: 'payment.release',
    subject: 'agent:ap-clerk-7',
    approver: 'ep:approver:cfo',
    claimExtra: { amount_usd: 950, currency: 'USD', payment_instruction_id: 'pi_demo_950' },
  });
  tamperedReceipt.payload.claim.amount_usd = 999999; // mutate a signed field
  const act5 = await present(tamperedReceipt, { selector: SEL_PAY });
  assert.equal(act5.allow, false);
  assert.match(act5.reason, /^receipt_rejected:/);
  say(`ACT 5    — tampered receipt ${tamperedReceipt.payload.receipt_id} (amount 950 → 999,999 after signing)     → REFUSED (${act5.reason})`);
  advance();

  /* The engagement period is closed; the evidence log is the record. */
  const entries = gate.evidence.all();
  const chain = gate.evidence.verify();
  assert.equal(chain.ok, true, 'evidence chain must verify before any report is built');
  assert.equal(entries.length, 8, 'expected 6 decisions + 2 executions');

  const periodStart = iso(BASE - 60_000);
  const periodEnd = iso(now() + 60_000); // inclusive for underwriter; exclusive for Art.14/usage/workpaper — both cover all entries

  /* ACT 6a — underwriter control attestation. */
  const attestation = buildUnderwriterAttestation(entries, {
    insured: ORG, periodStart, periodEnd, now,
  });
  assert.equal(attestation['@version'], UNDERWRITER_ATTESTATION_VERSION);
  assert.match(attestation.honesty.status, /Not an insurance document/);
  assert.equal(attestation.volume.guarded_decisions, 5);
  assert.equal(attestation.volume.allowed, 2);
  assert.equal(attestation.volume.denied, 3);
  assert.equal(attestation.denials.reasons.receipt_required, 1);
  assert.equal(attestation.denials.reasons.replay_refused, 1);
  assert.ok(Object.keys(attestation.denials.reasons).some((r) => r.startsWith('receipt_rejected:')), 'tamper refusal must appear in denial reasons');
  assert.equal(attestation.replay.attempts_blocked, 1);
  assert.equal(attestation.assurance.credited_tier_distribution_on_allow.class_a, 1);
  assert.equal(attestation.assurance.credited_tier_distribution_on_allow.quorum, 1);
  assert.deepEqual(attestation.quorum_usage, { hard_action_decisions: 1, allowed: 1, denied: 0 });
  assert.equal(attestation.exceptions.uncontrolled_passthroughs, 1);
  assert.equal(attestation.exceptions.replay_defense_bypassed, 0);
  assert.deepEqual(attestation.executions, { recorded: 2, executed: 2, failed: 0 });
  assert.equal(attestation.evidence.integrity_warnings.length, 0);
  assert.equal(attestation.narrative.near_misses, null, 'narrative is the broker\'s — never machine-generated');

  /* ACT 6b — EU AI Act Article 14 human-oversight evidence pack. */
  const art14 = buildArt14EvidencePack(entries, {
    organization: ORG, system: SYSTEM, periodStart, periodEnd, now,
  });
  assert.equal(art14['@version'], ART14_PACK_VERSION);
  assert.equal(art14.notice, ART14_HONESTY_NOTICE, 'honesty notice must be verbatim');
  assert.equal(art14.coverage.decisions_total, 6);
  assert.equal(art14.coverage.decisions_guarded, 5);
  assert.equal(art14.oversight_exercised.length, 2);
  assert.equal(art14.interventions.total, 3);
  assert.equal(art14.interventions.by_predicate.authorization_receipt_present, 1);
  assert.equal(art14.interventions.by_predicate.one_time_consumption, 1);
  assert.equal(art14.replay_tamper.replay_blocked, 1);
  assert.equal(art14.replay_tamper.tamper_blocked, 1);
  assert.equal(art14.uncontrolled_action_exceptions.total, 1);
  assert.equal(art14.integrity_warnings.length, 0);
  assert.equal(art14.evidence.entries_in_window, 8);

  /* ACT 6c — usage statement (billing-grade count over the same log). */
  const usage = meterUsage(entries, { periodStart, periodEnd });
  const statement = buildUsageStatement(usage, { org: ORG });
  assert.equal(statement['@version'], USAGE_VERSION);
  assert.equal(statement.protected_actions, 5);
  assert.equal(statement.allows, 2);
  assert.equal(statement.denies, 3);
  assert.equal(statement.replays_blocked, 1);
  assert.equal(statement.complete, true);
  assert.match(statement.content_hash, /^[0-9a-f]{64}$/);

  /* Cross-report tie-out: three independent builders, one log, one truth. */
  assert.equal(attestation.volume.guarded_decisions, statement.protected_actions);
  assert.equal(attestation.volume.allowed, statement.allows);
  assert.equal(attestation.volume.denied, statement.denies);
  assert.equal(art14.coverage.decisions_guarded, attestation.volume.guarded_decisions);
  assert.equal(art14.replay_tamper.replay_blocked, attestation.replay.attempts_blocked);

  /* ACT 6d — auditor control-testing workpaper (100% examination: sampleSize
   * covers the whole population; sampling is seed-pinned and RNG-free). */
  const workpaper = buildAuditWorkpaper(entries, {
    client: ORG,
    engagement: 'FY2026 ITGC — agentic authorization control (demo)',
    controlRef: 'ITGC-EP-GATE-01',
    periodStart,
    periodEnd,
    sampleSize: 5,
    sampleSeed: 'ep-demo-seed-001',
    now,
  });
  assert.equal(workpaper['@version'], AUDIT_WORKPAPER_VERSION);
  assert.equal(workpaper.notice, AUDIT_WORKPAPER_HONESTY_NOTICE, 'workpaper honesty notice must be verbatim');
  assert.equal(workpaper.population.size, 5);
  assert.equal(workpaper.population.excluded.not_guarded_passthroughs, 1);
  assert.equal(workpaper.population.excluded.executions, 2);
  assert.equal(workpaper.sampling.full_population, true);
  assert.equal(workpaper.sampling.basis, '100% examination');
  assert.equal(workpaper.exceptions.total, 0, `sampled items must show zero control exceptions, got ${JSON.stringify(workpaper.exceptions.items)}`);
  assert.equal(workpaper.integrity_warnings.length, 0);
  assert.deepEqual(workpaper.conclusion, { tested_by: null, reviewed_by: null, conclusion: null }, 'sign-off is the auditor\'s — must be emitted null');
  // Independent recomputation of the pinned population hash from the listed items.
  const recomputedPopHash = crypto.createHash('sha256')
    .update(workpaper.population.items.map((i) => i.hash).sort().join('\n'), 'utf8').digest('hex');
  assert.equal(workpaper.population.population_hash, recomputedPopHash, 'population hash must be recomputable from the listed items');
  say(`ACT 6    — reports issued: underwriter attestation ✓ · Art.14 pack ✓ · usage statement ✓ (hash ${statement.content_hash.slice(0, 12)}…) · auditor workpaper ✓ (population ${workpaper.population.size}, 0 exceptions)`);

  /* ACT 7 — third-party RE-PERFORMANCE. The auditor takes the raw entries and
   * the OUT-OF-BAND pinned issuer key, rebuilds the hash chain, re-verifies the
   * carried receipts/signoffs/quorums, recomputes every count from scratch, and
   * ties the recomputed numbers out against the issued reports. */
  const reperformance = await reperformEvidence(entries, { issuerKeys: [issuer.pub], now });
  assert.equal(reperformance['@version'], REPERFORMANCE_VERSION);
  assert.match(reperformance.honesty.status, /does not conclude/);

  // Chain: rebuilt link by link and re-verified — head must match the live log's.
  assert.equal(reperformance.chain.ok, true, 're-performance must re-verify the evidence chain');
  assert.equal(reperformance.chain.entries, 8);
  assert.equal(reperformance.chain.head, chain.head, 'recomputed chain head must equal the live chain head');

  // Receipts: the 3 genuine presentations (Act 1 payment, Act 2 quorum delete,
  // Act 4 replay of the genuine payment receipt) re-verify; the tampered
  // exhibit from Act 5 must FAIL re-verification — the auditor independently
  // reaches the same refusal the gate recorded.
  assert.equal(reperformance.receipts.reverified, 3, `expected 3 re-verified receipt presentations, got ${reperformance.receipts.reverified}`);
  assert.equal(reperformance.receipts.failed.length, 1, 'exactly the tampered exhibit must fail re-verification');
  assert.equal(reperformance.receipts.failed[0].hash, act5.evidence.hash, 'the failed exhibit must be Act 5\'s decision record');
  assert.match(reperformance.receipts.failed[0].reason, /^receipt:/);
  assert.equal(reperformance.receipts.not_reverifiable, 0, 'every referenced receipt must be carried in the log');
  assert.equal(reperformance.receipts.no_receipt_presented, 2); // prologue pass-through + Act 3 refusal
  assert.equal(reperformance.integrity_warnings.length, 0);

  // Counts recomputed from scratch, then tied out against BOTH issued packs.
  assert.deepEqual(reperformance.counts, {
    allows: 2,
    denies: 3,
    replays_blocked: 1,
    by_action_type: { 'infra.delete_production_db': 1, 'payment.release': 4 },
  });
  const tieOutUsage = compareToReported(reperformance, statement);
  assert.equal(tieOutUsage.match, true, `usage tie-out drift: ${JSON.stringify(tieOutUsage.drift)}`);
  assert.equal(tieOutUsage.drift.length, 0);
  const tieOutUnderwriter = compareToReported(reperformance, attestation);
  assert.equal(tieOutUnderwriter.match, true, `underwriter tie-out drift: ${JSON.stringify(tieOutUnderwriter.drift)}`);
  assert.equal(tieOutUnderwriter.drift.length, 0);
  const totalDrift = tieOutUsage.drift.length + tieOutUnderwriter.drift.length;

  say(`AUDITOR RE-PERFORMANCE: chain OK, ${reperformance.receipts.reverified} receipts re-verified, ${totalDrift} drift`);
  say(`         (tampered exhibit ${tamperedReceipt.payload.receipt_id} independently FAILED re-verification — ${reperformance.receipts.failed[0].reason} — matching the gate's refusal)`);

  /* ------------------------------- the narration ------------------------------- */
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`\n═══ EMILIA GATE — AGENTIC AUDIT-TRAIL DEMO (${AUDIT_TRAIL_DEMO_VERSION}) ═══`);
  console.log(`    ${ORG} · ${SYSTEM} · period ${periodStart} → ${periodEnd}\n`);
  for (const l of lines) console.log(l);
  console.log(`\nEvidence log: ${entries.length} hash-chained records (6 decisions, 2 executions) · chain head ${chain.head.slice(0, 12)}…`);
  console.log('Every report above SUPPORTS the auditor and carries its honesty boundary verbatim; none concludes, opines, or certifies.');
  console.log(`Done in ${(elapsedMs / 1000).toFixed(2)}s — deterministic, offline, ${elapsedMs < 60_000 ? 'under' : 'OVER'} the 60s budget.`);
}

main().catch((e) => {
  console.error(`\nAUDIT-TRAIL DEMO FAILED: ${e?.message ?? e}`);
  if (e?.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  process.exit(1);
});
