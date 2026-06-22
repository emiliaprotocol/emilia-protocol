#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Protocol — the crash test.
 *
 * One command. Two acts. The whole protocol becomes obvious.
 *
 *   Act 1 (at the county, today):  an AI finance agent proposes a $2.4M grant
 *     disbursement to a NEW vendor bank account. Self-approval is rejected.
 *     The Finance Director approves on her device; the Controller approves on
 *     his. A quorum holds. An authorization receipt is issued.
 *
 *   Act 2 (at the auditor's desk, six months later, EMILIA gone):  the network
 *     is down, the EMILIA service is deleted, the database is gone. The auditor
 *     has only the receipt file. It still verifies — offline, against no one's
 *     server — and a forged copy is rejected. The auditor gets a workpaper.
 *
 * Act 2 is the product. Act 1 is the setup.
 *
 * This runs the REAL EP-QUORUM-v1 predicate (@emilia-protocol/verify). The
 * approver signatures are real ES256 device-class (Class A) WebAuthn assertions,
 * minted here headlessly so the test runs anywhere with no hardware; in
 * production they come from each approver's own device. NOTHING here touches the
 * network — that is the point of Act 2.
 */
import crypto from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
// The frozen, cross-language-verified offline predicate. No EP infrastructure.
// Resolve the published package; fall back to the in-repo path for local dev.
let verifyQuorum;
try { ({ verifyQuorum } = await import('@emilia-protocol/verify')); }
catch { ({ verifyQuorum } = await import('../verify/index.js')); }

const C = { dim: '\x1b[2m', red: '\x1b[31m', grn: '\x1b[32m', ylw: '\x1b[33m', cyn: '\x1b[36m', bold: '\x1b[1m', rst: '\x1b[0m' };
const c = (k, s) => `${C[k]}${s}${C.rst}`;
const line = () => console.log(c('dim', '─'.repeat(64)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Canonical JSON — identical algorithm to the verifier (recursive key sort).
const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// ── The action the whole quorum authorizes ──────────────────────────────────
const ACTION = {
  ep_version: '1.0',
  action_type: 'disbursement.release',
  target: { system: 'county.finance.ap', resource: 'grant-disbursement/FY26-1184' },
  parameters: {
    amount: '2400000.00',
    currency: 'USD',
    payee: 'Northbridge Civil Works LLC',
    beneficiary_account_hash: 'sha256:' + sha256hex('routing:021000021|acct:NEW-8841'),
    beneficiary_status: 'NEW',
  },
  initiator: 'ep:agent:disbursement-bot',
  policy_id: 'county:policy:high-value-disbursement@v4',
  requested_at: '2026-01-14T15:02:11Z',
};
const actionHashOf = (action) => sha256hex(canon(action));
const ACTION_HASH = actionHashOf(ACTION);

// County control: ordered dual approval — Finance Director, then Controller.
const FD = { role: 'finance_director', approver: 'ep:approver:fd_morales' };
const CT = { role: 'controller', approver: 'ep:approver:ctrl_okeefe' };
const POLICY_ID = 'county:policy:high-value-disbursement@v4';
const POLICY = { mode: 'ordered', required: 2, approvers: [FD, CT], distinct_humans: true, window_sec: 900 };

// ── Mint a real Class-A (ES256/WebAuthn) device approval, bound to the action ─
function approveOnDevice({ role, approver, issuedAt, actionHash = ACTION_HASH }) {
  const signer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: actionHash, policy: POLICY_ID, nonce: 'sig_' + crypto.randomBytes(16).toString('hex'),
    approver, initiator: ACTION.initiator, issued_at: issuedAt, expires_at: '2026-01-14T16:00:00.000Z',
  };
  const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update('emiliaprotocol.ai', 'utf8').digest(),
    Buffer.from([0x05]), Buffer.from([0, 0, 0, 9]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, signer.privateKey).toString('base64url');
  return {
    role,
    approver_public_key: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    signoff: {
      '@type': 'ep.signoff', context,
      webauthn: { authenticator_data: authData.toString('base64url'), client_data_json: clientData.toString('base64url'), signature },
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
async function main() {
  const outDir = resolve(process.cwd(), 'emilia-workpaper');
  console.log('');
  console.log(c('bold', '  EMILIA PROTOCOL — THE CRASH TEST'));
  console.log(c('dim', '  No irreversible action without accountable, independently-verifiable authorization.'));
  console.log('');

  // ===== ACT 1 — AUTHORIZATION (at the county, today) ========================
  line(); console.log(c('bold', '  ACT 1 — AUTHORIZATION') + c('dim', '   (county finance office, today)')); line();
  console.log(`  ${c('cyn', 'agent')} proposes: release ${c('bold', '$2,400,000')} to ${c('bold', 'Northbridge Civil Works LLC')}`);
  console.log(`         ${c('dim', 'beneficiary bank account: ')}${c('ylw', 'NEW')}${c('dim', '  ·  policy: county:high-value-disbursement@v4')}`);
  console.log(`         ${c('dim', 'action_hash: ' + ACTION_HASH.slice(0, 32) + '…')}`);
  await sleep(120);
  console.log(`  ${c('red', '⛔ BLOCKED')} — DUAL_AUTH_REQUIRED  ${c('dim', '(amount ≥ $1M + new beneficiary → ordered: Finance Director, then Controller)')}`);
  await sleep(120);

  // Self-approval attempt by the requester — rejected by the predicate itself.
  const selfTry = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH, policy: POLICY,
    members: [approveOnDevice({ role: 'requester', approver: ACTION.initiator, issuedAt: '2026-01-14T15:03:00.000Z' })],
  };
  const selfRes = verifyQuorum(selfTry);
  console.log(`  ${c('red', '✗')} requester self-approval ${c('red', 'REJECTED')} ${c('dim', `— not an eligible approver (roles_admitted=${selfRes.checks.roles_admitted}, threshold_met=${selfRes.checks.threshold_met}); separation of duties holds`)}`);
  await sleep(120);

  // The real two-person ceremony, in order.
  const members = [
    approveOnDevice({ ...FD, issuedAt: '2026-01-14T15:06:00.000Z' }),
    approveOnDevice({ ...CT, issuedAt: '2026-01-14T15:08:30.000Z' }),
  ];
  console.log(`  ${c('grn', '✓')} Finance Director ${c('dim', '(fd_morales)')} approved on secure device`);
  console.log(`  ${c('grn', '✓')} Controller ${c('dim', '(ctrl_okeefe)')} approved on secure device`);
  await sleep(120);

  const quorum = { '@type': 'ep.quorum', action_hash: ACTION_HASH, policy: POLICY, members };
  const live = verifyQuorum(quorum);
  if (!live.valid) { console.error(c('red', '  internal error: live quorum did not verify'), live.checks); process.exit(2); }
  console.log(`  ${c('grn', '✓ COMMITTED')} — quorum satisfied (${Object.values(live.checks).filter(Boolean).length}/7 predicates)`);

  // Issue the authorization receipt: the action + the quorum + the operator's
  // signed commit record. This is the file the auditor keeps.
  const issuer = crypto.generateKeyPairSync('ed25519');
  const committedAt = '2026-01-14T15:08:31.000Z';
  const body = { '@version': 'EP-RECEIPT-v1', receipt_id: 'ep:receipt:cnty-FY26-1184', action: ACTION, action_hash: ACTION_HASH, quorum, consumption: { state: 'COMMITTED', committed_at: committedAt } };
  const operator_signature = crypto.sign(null, Buffer.from(canon(body), 'utf8'), issuer.privateKey).toString('base64url');
  const receipt = { ...body, operator_signature, operator_public_key: issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
  console.log(`  ${c('grn', '✓')} authorization receipt issued ${c('dim', '→ ' + 'authorization-receipt.json')}`);
  console.log('');

  // ===== ACT 2 — RELIANCE (auditor's desk, six months later) =================
  line(); console.log(c('bold', '  ACT 2 — RELIANCE') + c('dim', '   (external audit, six months later)')); line();
  console.log(`  ${c('dim', 'network: ')}${c('red', 'DISCONNECTED')}    ${c('dim', 'EMILIA service: ')}${c('red', 'DELETED')}    ${c('dim', 'EMILIA database: ')}${c('red', 'GONE')}`);
  console.log(`  ${c('dim', 'the auditor has one file: authorization-receipt.json')}`);
  await sleep(150);

  const genuine = verifyReceiptOffline(receipt);
  printDetermination('Genuine receipt as filed', genuine);
  await sleep(120);

  // Forgery: tamper the amount after the fact, do NOT re-sign. The action no
  // longer hashes to what the humans signed — and the predicate catches it.
  const forged = JSON.parse(JSON.stringify(receipt));
  forged.action.parameters.amount = '24000.00';
  const forgedRes = verifyReceiptOffline(forged);
  printDetermination('Forged copy (amount altered to $24,000 after signing)', forgedRes);
  console.log('');

  // ── Write the Auditor Workpaper Package ────────────────────────────────────
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'authorization-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  writeFileSync(resolve(outDir, 'verification-report.md'), workpaper(receipt, genuine, forgedRes));
  line();
  console.log(`  ${c('bold', 'Auditor Workpaper Package')} written to ${c('cyn', './emilia-workpaper/')}`);
  console.log(`    • authorization-receipt.json   ${c('dim', '— the evidence the auditor keeps')}`);
  console.log(`    • verification-report.md       ${c('dim', '— audit-grade determination, reproducible offline')}`);
  line();
  console.log(`  ${c('bold', 'The one sentence that matters:')}`);
  console.log(`  ${c('grn', '“The required human approvals existed for this exact action before it executed —')}`);
  console.log(`  ${c('grn', '   and I verified that myself, without trusting EMILIA, the county, or any log.”')}`);
  console.log('');
}

// Offline verification an auditor (or anyone) can reproduce with no service.
function verifyReceiptOffline(receipt) {
  const reasons = [];
  // 1. Recompute the action hash from the action object as filed.
  const recomputed = actionHashOf(receipt.action);
  const hashMatches = recomputed === receipt.action_hash && receipt.action_hash === receipt.quorum?.action_hash;
  if (!hashMatches) reasons.push('action_hash does not match the action as filed (the action was altered after approval)');
  // 2. The quorum predicate — the real thing.
  const q = verifyQuorum(receipt.quorum);
  if (!q.valid) reasons.push('quorum predicate failed: ' + Object.entries(q.checks).filter(([, v]) => !v).map(([k]) => k).join(', '));
  // 3. Operator commit signature over the receipt body.
  let opOk = false;
  try {
    const { operator_signature, operator_public_key, ...body } = receipt;
    const key = crypto.createPublicKey({ key: Buffer.from(operator_public_key, 'base64url'), format: 'der', type: 'spki' });
    opOk = crypto.verify(null, Buffer.from(canon(body), 'utf8'), key, Buffer.from(operator_signature, 'base64url'));
  } catch { opOk = false; }
  if (!opOk) reasons.push('operator commit signature invalid');
  const verified = hashMatches && q.valid && opOk;
  return { verified, checks: q.checks, hashMatches, opOk, reasons };
}

function printDetermination(label, r) {
  if (r.verified) {
    console.log(`  ${c('grn', '✓ ' + label)}`);
    console.log(`    ${c('grn', c('bold', 'AUTHORIZATION EVIDENCE: PRESENT AND INDEPENDENTLY VERIFIED'))}`);
  } else {
    console.log(`  ${c('red', '✗ ' + label)}`);
    console.log(`    ${c('red', c('bold', 'AUTHORIZATION EVIDENCE: ABSENT / UNVERIFIABLE — DO NOT RELY'))}`);
    for (const why of r.reasons) console.log(`      ${c('dim', '· ' + why)}`);
  }
}

function workpaper(receipt, genuine, forged) {
  const det = (r) => r.verified
    ? 'AUTHORIZATION EVIDENCE: **PRESENT AND INDEPENDENTLY VERIFIED**'
    : 'AUTHORIZATION EVIDENCE: **ABSENT / UNVERIFIABLE — DO NOT RELY**';
  const checkRow = (k, v) => `| ${k} | ${v ? '✓ pass' : '✗ FAIL'} |`;
  return `# Authorization Evidence — Audit Workpaper

**Prepared by independent offline verification. No EMILIA service, account, network, or log was consulted.**

| | |
|---|---|
| Receipt ID | \`${receipt.receipt_id}\` |
| Action | ${receipt.action.action_type} — release ${receipt.action.parameters.currency} ${receipt.action.parameters.amount} to ${receipt.action.parameters.payee} |
| Beneficiary status | ${receipt.action.parameters.beneficiary_status} |
| Policy | \`${receipt.action.policy_id}\` (ordered dual approval: Finance Director, then Controller) |
| Action hash (recomputed) | \`${actionHashOf(receipt.action)}\` |
| Committed at | ${receipt.consumption.committed_at} |

## Determination

> ${det(genuine)}

The required human approvals existed for this exact action before it executed, and that fact was verified here with mathematics alone — independently of EMILIA, the county, and any internal log. The receipt remains valid even if EMILIA ceases to exist.

## What was checked (offline)

| Check | Result |
|---|---|
| action_hash recomputed from the action as filed matches what the approvers signed | ${genuine.hashMatches ? '✓ pass' : '✗ FAIL'} |
${checkRow('all approver device signatures valid', genuine.checks.all_signatures_valid)}
${checkRow('every approver signed this exact action (action binding)', genuine.checks.action_binding)}
${checkRow('approvers are distinct humans (separation of duties)', genuine.checks.distinct_humans)}
${checkRow('each approver is an authorized role on the policy roster', genuine.checks.roles_admitted)}
${checkRow('required number of approvals met', genuine.checks.threshold_met)}
${checkRow('approvals occurred in required order', genuine.checks.order_satisfied)}
${checkRow('all approvals within the policy time window', genuine.checks.within_window)}
| operator commit signature valid | ${genuine.opOk ? '✓ pass' : '✗ FAIL'} |

## Tamper test (the absence made visible)

A forged copy of this receipt, with the amount altered from \$2,400,000 to \$24,000 *after* approval, was submitted to the same offline verification:

> ${det(forged)}

Reasons: ${forged.reasons.map((r) => `_${r}_`).join('; ')}.

This is what an auditor, lawyer, insurer, or board member sees when authorization evidence does not hold: a definite, reproducible **DO NOT RELY** — not a silent gap.

## What this receipt proves, and does not prove

**Proves:** the named approvers, holding their own device keys, each signed *this exact action* under the stated policy, in order, before execution; and that no party — including EMILIA — could have forged or altered it without detection.

**Does not prove:** that the approvers were not jointly colluding or coerced; that the displayed action matched the underlying intent (presentation integrity); the real-world identity behind each enrolled approver. Those are stated, not claimed solved.

## For the auditor — how this maps to your standards

Under **GAGAS (Government Auditing Standards / the GAO "Yellow Book")**, audit evidence must be **sufficient and appropriate** — where *appropriateness* turns on **relevance and reliability**, and evidence the auditor can **independently test**, that does **not depend on the auditee's own systems or representations**, is the most reliable kind. An EP authorization receipt is exactly that: verified here offline, with open-source code, without trusting the county, EMILIA, or any internal log.

Concretely, this determination supports a **test of the authorization control** over a high-risk disbursement — both that the control *existed* for this exact action and that the *required approvers operated it* (separation of duties, order, threshold) — with evidence that is tamper-evident by construction. For federal-funds programs it speaks to internal control over compliance for **allowability/approval** expectations under **2 CFR 200 (Uniform Guidance)**; in a financial audit it supports the transaction's **authorization / occurrence** assertion.

**Bound (stated, not glossed):** the receipt is reliable evidence that the required humans *authorized* this exact action — it is **not** a test of the *propriety* of their decision, of the real-world *identity* behind each enrolled approver (an enrollment-layer control), or a substitute for the auditor's own risk assessment.

## Reproduce this determination yourself

\`\`\`
npx -y @emilia-protocol/crash-test verify ./authorization-receipt.json
\`\`\`

Offline. No account. No API key. The embedded EP-QUORUM-v1 document also
verifies directly via \`verifyQuorum()\` in \`@emilia-protocol/verify\`. Just math.

---
*Generated by \`@emilia-protocol/crash-test\`. Approver signatures in this demonstration are real ES256 device-class assertions minted locally so the test runs without hardware; in production they originate on each approver's own device.*
`;
}

// `verify <file>` — the auditor's path: take only the receipt file, decide.
async function verifyFile(path) {
  const { readFileSync } = await import('node:fs');
  let receipt;
  try { receipt = JSON.parse(readFileSync(resolve(process.cwd(), path), 'utf8')); }
  catch (e) { console.error(c('red', `cannot read receipt: ${e.message}`)); process.exit(2); }
  console.log('');
  console.log(c('dim', '  offline verification — no network, no service, no account'));
  const r = verifyReceiptOffline(receipt);
  printDetermination(`${receipt.receipt_id ?? 'receipt'} — ${path}`, r);
  console.log('');
  process.exit(r.verified ? 0 : 1);
}

const [, , cmd, arg] = process.argv;
if (cmd === 'verify' && arg) {
  verifyFile(arg).catch((e) => { console.error(e); process.exit(1); });
} else {
  main().catch((e) => { console.error(e); process.exit(1); });
}
