#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Protocol — the crash test.
 *
 * One command. Two acts. The whole protocol becomes obvious.
 *
 *   Act 1 (today):  an AI agent proposes an irreversible, high-risk action.
 *     Self-approval is rejected. Two distinct, accountable humans approve the
 *     exact action on their own devices. A quorum holds. A receipt is issued.
 *
 *   Act 2 (later, EMILIA gone):  the network is down, the EMILIA service is
 *     deleted, the database is gone. Only the receipt file remains. It still
 *     verifies — offline, against no one's server — and a forged copy is
 *     rejected. The relying party gets an audit-grade workpaper.
 *
 * Act 2 is the product. Act 1 is the setup.
 *
 * Scenarios (same engine, different high-risk action):
 *   (default)            a $2.4M county grant disbursement to a new vendor
 *   --scenario clinical    a high-alert IV medication, independent double-check
 *   --scenario procurement a hospital capital purchase (3T MRI), dual control
 *   --scenario release-authorization  an autonomous effector release, ordered
 *                          two-person authorization (DoD 3000.09 human-control)
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
const actionHashOf = (action) => sha256hex(canon(action));

// ── Mint a real Class-A (ES256/WebAuthn) device approval, bound to the action ─
function approveOnDevice({ role, approver, issuedAt, actionHash, policyId, initiator, expiresAt }) {
  const signer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: actionHash, policy: policyId, nonce: 'sig_' + crypto.randomBytes(16).toString('hex'),
    approver, initiator, issued_at: issuedAt, expires_at: expiresAt,
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

// ── Scenarios — same predicate, different high-risk action ───────────────────
const SCENARIOS = {
  finance: {
    key: 'finance',
    act1Where: 'county finance office, today',
    act2Where: 'external audit, six months later',
    receiptId: 'ep:receipt:cnty-FY26-1184',
    action: {
      ep_version: '1.0',
      action_type: 'disbursement.release',
      target: { system: 'county.finance.ap', resource: 'grant-disbursement/FY26-1184' },
      parameters: {
        amount: '2400000.00', currency: 'USD',
        payee: 'Northbridge Civil Works LLC',
        beneficiary_account_hash: 'sha256:' + sha256hex('routing:021000021|acct:NEW-8841'),
        beneficiary_status: 'NEW',
      },
      initiator: 'ep:agent:disbursement-bot',
      policy_id: 'county:policy:high-value-disbursement@v4',
      requested_at: '2026-01-14T15:02:11Z',
    },
    approvers: [
      { role: 'finance_director', approver: 'ep:approver:fd_morales', label: 'Finance Director', short: 'fd_morales', issuedAt: '2026-01-14T15:06:00.000Z' },
      { role: 'controller', approver: 'ep:approver:ctrl_okeefe', label: 'Controller', short: 'ctrl_okeefe', issuedAt: '2026-01-14T15:08:30.000Z' },
    ],
    windowSec: 900, expiresAt: '2026-01-14T16:00:00.000Z',
    selfApprovalAt: '2026-01-14T15:03:00.000Z', committedAt: '2026-01-14T15:08:31.000Z',
    proposalLines: (a) => [
      `  ${c('cyn', 'agent')} proposes: release ${c('bold', '$2,400,000')} to ${c('bold', 'Northbridge Civil Works LLC')}`,
      `         ${c('dim', 'beneficiary bank account: ')}${c('ylw', 'NEW')}${c('dim', '  ·  policy: county:high-value-disbursement@v4')}`,
    ],
    blockedLine: () => `  ${c('red', '⛔ BLOCKED')} — DUAL_AUTH_REQUIRED  ${c('dim', '(amount ≥ $1M + new beneficiary → ordered: Finance Director, then Controller)')}`,
    forge: (r) => { r.action.parameters.amount = '24000.00'; return 'Forged copy (amount altered to $24,000 after signing)'; },
    actionSummary: (a) => `${a.action_type} — release ${a.parameters.currency} ${a.parameters.amount} to ${a.parameters.payee}`,
    extraRow: (a) => ['Beneficiary status', a.parameters.beneficiary_status],
    policyDesc: 'ordered dual approval: Finance Director, then Controller',
    forgeNarrative: 'A forged copy of this receipt, with the amount altered from $2,400,000 to $24,000 *after* approval, was submitted to the same offline verification:',
    boundNote: 'a test of the *propriety* of their decision, of the real-world *identity* behind each enrolled approver (an enrollment-layer control), or a substitute for the auditor\'s own risk assessment',
    standards: `## For the auditor — how this maps to your standards

Under **GAGAS (Government Auditing Standards / the GAO "Yellow Book")**, audit evidence must be **sufficient and appropriate** — where *appropriateness* turns on **relevance and reliability**, and evidence the auditor can **independently test**, that does **not depend on the auditee's own systems or representations**, is the most reliable kind. An EP authorization receipt is exactly that: verified here offline, with open-source code, without trusting the county, EMILIA, or any internal log.

Concretely, this supports a **test of the authorization control** over a high-risk disbursement — both that the control *existed* for this exact action and that the *required approvers operated it* (separation of duties, order, threshold). For federal-funds programs it speaks to internal control over compliance for **allowability/approval** under **2 CFR 200 (Uniform Guidance)**; in a financial audit it supports the transaction's **authorization / occurrence** assertion.`,
  },

  'release-authorization': {
    key: 'release-authorization',
    act1Where: 'forward area, contested — intermittent comms',
    act2Where: 'post-mission review / accountability inquiry, weeks later',
    receiptId: 'ep:receipt:eng-A7Q-2291',
    action: {
      ep_version: '1.0',
      action_type: 'effector.release.authorize',
      target: { system: 'c2.effector-control', resource: 'engagement/ENG-A7Q-2291' },
      parameters: {
        designated_track: 'TRK-7731',
        track_class: 'ground-mobile',
        effector: 'loitering-munition:LM-4',
        roe_profile: 'ROE:defensive-counterfire@v3',
        engagement_window: 'T+00:14',
        track_hash: 'sha256:' + sha256hex('track:TRK-7731|class:ground-mobile|grid:38SMB4481'),
      },
      initiator: 'ep:agent:autonomy-core',
      policy_id: 'dod:policy:human-authorized-engagement@3000.09',
      requested_at: '2026-03-02T09:41:07Z',
    },
    approvers: [
      { role: 'mission_commander', approver: 'ep:approver:mc_hale', label: 'Mission Commander', short: 'mc_hale', issuedAt: '2026-03-02T09:41:40.000Z' },
      { role: 'weapons_safety_officer', approver: 'ep:approver:wso_reyes', label: 'Weapons Safety Officer', short: 'wso_reyes', issuedAt: '2026-03-02T09:41:52.000Z' },
    ],
    windowSec: 120, expiresAt: '2026-03-02T09:43:07.000Z',
    selfApprovalAt: '2026-03-02T09:41:20.000Z', committedAt: '2026-03-02T09:41:53.000Z',
    proposalLines: (a) => [
      `  ${c('cyn', 'autonomy core')} proposes: authorize ${c('bold', a.parameters.effector)} against designated track ${c('bold', a.parameters.designated_track)}`,
      `         ${c('dim', 'ROE: ')}${c('ylw', a.parameters.roe_profile)}${c('dim', '  ·  policy: dod:human-authorized-engagement@3000.09')}`,
    ],
    blockedLine: () => `  ${c('red', '⛔ BLOCKED')} — TWO_PERSON_AUTH_REQUIRED  ${c('dim', '(autonomous effector release → ordered: Mission Commander, then Weapons Safety Officer)')}`,
    forge: (r) => { r.action.parameters.designated_track = 'TRK-9002'; return 'Forged copy (designated track re-pointed from TRK-7731 to TRK-9002 after authorization)'; },
    actionSummary: (a) => `${a.action_type} — authorize ${a.parameters.effector} against ${a.parameters.designated_track} under ${a.parameters.roe_profile}`,
    extraRow: (a) => ['ROE profile', a.parameters.roe_profile],
    policyDesc: 'ordered two-person authorization: Mission Commander, then Weapons Safety Officer',
    forgeNarrative: 'A forged copy of this receipt, with the designated track re-pointed to a different target *after* authorization, was submitted to the same offline verification:',
    boundNote: 'a judgment about whether the engagement was lawful or appropriate under the rules of engagement (that remains the commander\'s responsibility) — only that the required humans authorized *this exact action against this exact designated track*, unaltered, before release',
    standards: `## For the review board — how this maps to human-control policy

**DoD Directive 3000.09** requires that autonomous and semi-autonomous weapon systems allow commanders and operators to exercise **appropriate levels of human judgment over the use of force**. An EP authorization receipt is verifiable evidence that the required human judgment was exercised for **this exact action**: a named, ordered two-person authorization, bound to the specific designated track, that a reviewer can confirm **offline** — in a contested or disconnected environment — without trusting the platform, the operator, or any log.

This supports a **test of the human-authorization control** over an autonomous effector release: both that the control *existed* for this exact engagement and that the *required humans operated it* (identity, order, separation of duties, and binding to the designated track). It is the kind of artifact "meaningful human control" (as discussed at the **UN CCW GGE on LAWS**) requires. It is **necessary, not sufficient**: it does not judge the lawfulness or ROE-appropriateness of the engagement — only that the required humans authorized it, unaltered, before it executed.`,
  },

  clinical: {
    key: 'clinical',
    act1Where: 'hospital, night shift, today',
    act2Where: 'patient-safety / regulatory review, months later',
    receiptId: 'ep:receipt:hosp-ORD-44817',
    action: {
      ep_version: '1.0',
      action_type: 'medication.high_alert.administer',
      target: { system: 'ehr.cpoe', resource: 'medication-order/heparin-iv/ORD-44817' },
      parameters: {
        medication: 'heparin sodium',
        route: 'IV infusion',
        concentration: '25,000 units / 250 mL',
        rate: '1,200 units/hr',
        high_alert_class: 'anticoagulant',
        // No PHI in the receipt — only one-way hashes of the identifiers.
        patient_ref: 'sha256:' + sha256hex('MRN:HB-220714|enc:E-99231'),
        encounter_ref: 'sha256:' + sha256hex('enc:E-99231'),
      },
      initiator: 'ep:agent:medadmin-assist',
      policy_id: 'hospital:policy:high-alert-independent-double-check@v3',
      requested_at: '2026-03-09T02:14:40Z',
    },
    approvers: [
      { role: 'administering_nurse', approver: 'ep:approver:rn_okafor', label: 'Administering RN', short: 'rn_okafor', issuedAt: '2026-03-09T02:16:00.000Z' },
      { role: 'independent_verifier_nurse', approver: 'ep:approver:rn_delacruz', label: 'Independent verifier RN', short: 'rn_delacruz', issuedAt: '2026-03-09T02:18:10.000Z' },
    ],
    windowSec: 600, expiresAt: '2026-03-09T02:40:00.000Z',
    selfApprovalAt: '2026-03-09T02:15:00.000Z', committedAt: '2026-03-09T02:18:11.000Z',
    proposalLines: (a) => [
      `  ${c('cyn', 'agent')} proposes: administer ${c('bold', 'heparin IV infusion')} at ${c('bold', '1,200 units/hr')}`,
      `         ${c('dim', 'class: ')}${c('ylw', 'HIGH-ALERT anticoagulant')}${c('dim', '  ·  patient: <hashed ref, no PHI>  ·  policy: high-alert-independent-double-check@v3')}`,
    ],
    blockedLine: () => `  ${c('red', '⛔ BLOCKED')} — HIGH_ALERT_DOUBLE_CHECK_REQUIRED  ${c('dim', '(ISMP high-alert med → independent double-check by a second qualified clinician before administration)')}`,
    forge: (r) => { r.action.parameters.rate = '12,000 units/hr'; return 'Forged copy (infusion rate altered to 12,000 units/hr — a 10× error — after the double-check)'; },
    actionSummary: (a) => `${a.action_type} — ${a.parameters.medication} ${a.parameters.route} @ ${a.parameters.rate}`,
    extraRow: (a) => ['High-alert class', a.parameters.high_alert_class + ' (patient ref is a hash — no PHI in this receipt)'],
    policyDesc: 'independent double-check: administering nurse, then a second qualified clinician',
    forgeNarrative: 'A forged copy of this receipt, with the infusion rate altered from 1,200 units/hr to 12,000 units/hr *after* the double-check, was submitted to the same offline verification:',
    boundNote: 'a test of the *clinical appropriateness* of the order (that remains the prescriber\'s and pharmacist\'s judgment), or of the real-world *identity* behind each enrolled clinician (an enrollment-layer control)',
    standards: `## For the safety officer / surveyor — how this maps to your standards

The two-person ceremony here is the **independent double-check** that **ISMP** recommends and that **Joint Commission Medication Management (MM) standards and National Patient Safety Goals** expect for **high-alert medications** (anticoagulants, insulin, opioids, chemotherapy). EP turns that double-check from an attestation in a log the hospital controls into **tamper-evident, offline-verifiable evidence**: that two distinct, qualified clinicians authorized *this exact order* — this drug, this concentration, this rate — before administration.

**HIPAA posture (by design):** the receipt carries **only one-way hashes** of the patient and encounter identifiers — no name, no MRN, no clinical content. The authorization evidence can therefore be verified and shared with auditors, surveyors, or a court **without a PHI disclosure**.

**Break-glass, not blocked:** EP is fail-closed, but an emergency override is itself a high-risk action that emits its own receipt — *who* overrode, *when*, under *what* stated justification — so the time-critical path is never hard-blocked, and the override is the most auditable event in the chart rather than the least.`,
  },

  procurement: {
    key: 'procurement',
    act1Where: 'health-system supply chain, today',
    act2Where: 'internal audit / payment-fraud review, later',
    receiptId: 'ep:receipt:hs-CAP-2026-0042',
    action: {
      ep_version: '1.0',
      action_type: 'procurement.capital.release',
      target: { system: 'erp.supplychain', resource: 'purchase-order/CAP-2026-0042' },
      parameters: {
        amount: '1850000.00', currency: 'USD',
        item: '3T MRI system + 5-yr service contract',
        vendor: 'Meridian Imaging Systems',
        vendor_status: 'NEW',
        vendor_account_hash: 'sha256:' + sha256hex('routing:124003116|acct:NEW-7720'),
        budget_line: 'capital/radiology/FY26',
        sourcing: 'off-contract sole-source (no GPO contract)',
      },
      initiator: 'ep:agent:procurement-bot',
      policy_id: 'healthsystem:policy:capital-purchase-dual-control@v2',
      requested_at: '2026-02-03T17:41:09Z',
    },
    approvers: [
      { role: 'department_director', approver: 'ep:approver:dir_alvarez', label: 'Radiology Dept Director', short: 'dir_alvarez', issuedAt: '2026-02-03T17:55:00.000Z' },
      { role: 'cfo', approver: 'ep:approver:cfo_whitfield', label: 'Chief Financial Officer', short: 'cfo_whitfield', issuedAt: '2026-02-04T10:12:00.000Z' },
    ],
    windowSec: 172800, expiresAt: '2026-02-06T18:00:00.000Z',
    selfApprovalAt: '2026-02-03T17:42:00.000Z', committedAt: '2026-02-04T10:12:01.000Z',
    proposalLines: (a) => [
      `  ${c('cyn', 'agent')} proposes: release PO for ${c('bold', '$1,850,000')} to ${c('bold', 'Meridian Imaging Systems')} ${c('dim', '(3T MRI)')}`,
      `         ${c('dim', 'vendor: ')}${c('ylw', 'NEW')}${c('dim', '  ·  off-contract sole-source  ·  budget: capital/radiology/FY26')}`,
    ],
    blockedLine: () => `  ${c('red', '⛔ BLOCKED')} — CAPITAL_DUAL_AUTH_REQUIRED  ${c('dim', '(amount ≥ $250k + new off-contract vendor → ordered: Dept Director, then CFO)')}`,
    forge: (r) => { r.action.parameters.vendor_account_hash = 'sha256:' + sha256hex('routing:124003116|acct:FRAUD-9001'); return 'Forged copy (vendor bank account swapped after approval — a classic payment-redirect / BEC fraud)'; },
    actionSummary: (a) => `${a.action_type} — ${a.parameters.currency} ${a.parameters.amount} to ${a.parameters.vendor} for ${a.parameters.item}`,
    extraRow: (a) => ['Vendor status', a.parameters.vendor_status + ' · ' + a.parameters.sourcing],
    policyDesc: 'ordered dual control: Department Director, then CFO',
    forgeNarrative: 'A forged copy of this receipt, with the vendor\'s bank account swapped *after* approval (the textbook payment-redirect fraud), was submitted to the same offline verification:',
    boundNote: 'a test of whether the purchase was the best *value* or clinically justified — only that the required officers authorized *this exact purchase order*, to this payee account, before release',
    standards: `## For internal audit / the controller — how this maps to your standards

This is **segregation of duties** over capital spend made into evidence: an agent may *initiate* a purchase order, but release requires two distinct, accountable officers (here Department Director, then CFO), and the receipt proves they authorized *this exact PO — this amount, this vendor, this payee account*, in order, before release. That is direct support for **internal control over financial reporting (ICFR)** and the **authorization / occurrence** assertions, and — for tax-exempt health systems — for the governance and controls represented on **IRS Form 990**.

It is also a specific control against **payment-redirect / business-email-compromise (BEC) fraud**, the single most common way capital dollars are stolen: because the payee account is inside the signed action, swapping it after approval breaks verification (as the tamper test below shows), rather than sailing through because a downstream system trusted an edited record.`,
  },
};

// ─────────────────────────────────────────────────────────────────────────────
async function main(S) {
  const A = S.action;
  const ACTION_HASH = actionHashOf(A);
  const POLICY_ID = A.policy_id;
  const POLICY = {
    mode: 'ordered', required: 2,
    approvers: S.approvers.map(({ role, approver }) => ({ role, approver })),
    distinct_humans: true, window_sec: S.windowSec,
  };
  const mint = (over) => approveOnDevice({
    actionHash: ACTION_HASH, policyId: POLICY_ID, initiator: A.initiator, expiresAt: S.expiresAt, ...over,
  });

  const outDir = resolve(process.cwd(), 'emilia-workpaper');
  console.log('');
  console.log(c('bold', '  EMILIA PROTOCOL — THE CRASH TEST') + (S.key === 'finance' ? '' : c('dim', `   [scenario: ${S.key}]`)));
  console.log(c('dim', '  No irreversible action without accountable, independently-verifiable authorization.'));
  console.log('');

  // ===== ACT 1 — AUTHORIZATION ===============================================
  line(); console.log(c('bold', '  ACT 1 — AUTHORIZATION') + c('dim', `   (${S.act1Where})`)); line();
  for (const ln of S.proposalLines(A)) console.log(ln);
  console.log(`         ${c('dim', 'action_hash: ' + ACTION_HASH.slice(0, 32) + '…')}`);
  await sleep(120);
  console.log(S.blockedLine());
  await sleep(120);

  // Self-approval attempt by the requester — rejected by the predicate itself.
  const selfTry = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH, policy: POLICY,
    members: [mint({ role: 'requester', approver: A.initiator, issuedAt: S.selfApprovalAt })],
  };
  const selfRes = verifyQuorum(selfTry);
  console.log(`  ${c('red', '✗')} requester self-approval ${c('red', 'REJECTED')} ${c('dim', `— not an eligible approver (roles_admitted=${selfRes.checks.roles_admitted}, threshold_met=${selfRes.checks.threshold_met}); separation of duties holds`)}`);
  await sleep(120);

  // The real two-person ceremony, in order.
  const members = S.approvers.map((ap) => mint({ role: ap.role, approver: ap.approver, issuedAt: ap.issuedAt }));
  for (const ap of S.approvers) console.log(`  ${c('grn', '✓')} ${ap.label} ${c('dim', '(' + ap.short + ')')} approved on secure device`);
  await sleep(120);

  const quorum = { '@type': 'ep.quorum', action_hash: ACTION_HASH, policy: POLICY, members };
  const live = verifyQuorum(quorum);
  if (!live.valid) { console.error(c('red', '  internal error: live quorum did not verify'), live.checks); process.exit(2); }
  console.log(`  ${c('grn', '✓ COMMITTED')} — quorum satisfied (${Object.values(live.checks).filter(Boolean).length}/7 predicates)`);

  // Issue the authorization receipt: the action + the quorum + the operator's
  // signed commit record. This is the file the relying party keeps.
  const issuer = crypto.generateKeyPairSync('ed25519');
  const body = { '@version': 'EP-RECEIPT-v1', receipt_id: S.receiptId, action: A, action_hash: ACTION_HASH, quorum, consumption: { state: 'COMMITTED', committed_at: S.committedAt } };
  const operator_signature = crypto.sign(null, Buffer.from(canon(body), 'utf8'), issuer.privateKey).toString('base64url');
  const receipt = { ...body, operator_signature, operator_public_key: issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
  console.log(`  ${c('grn', '✓')} authorization receipt issued ${c('dim', '→ authorization-receipt.json')}`);
  console.log('');

  // ===== ACT 2 — RELIANCE ====================================================
  line(); console.log(c('bold', '  ACT 2 — RELIANCE') + c('dim', `   (${S.act2Where})`)); line();
  console.log(`  ${c('dim', 'network: ')}${c('red', 'DISCONNECTED')}    ${c('dim', 'EMILIA service: ')}${c('red', 'DELETED')}    ${c('dim', 'EMILIA database: ')}${c('red', 'GONE')}`);
  console.log(`  ${c('dim', 'the relying party has one file: authorization-receipt.json')}`);
  await sleep(150);

  const genuine = verifyReceiptOffline(receipt);
  printDetermination('Genuine receipt as filed', genuine);
  await sleep(120);

  // Forgery: tamper the action after the fact, do NOT re-sign. The action no
  // longer hashes to what the humans signed — and the predicate catches it.
  const forged = JSON.parse(JSON.stringify(receipt));
  const forgeLabel = S.forge(forged);
  const forgedRes = verifyReceiptOffline(forged);
  printDetermination(forgeLabel, forgedRes);
  console.log('');

  // ── Write the Workpaper Package ────────────────────────────────────────────
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'authorization-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  writeFileSync(resolve(outDir, 'verification-report.md'), workpaper(receipt, genuine, forgedRes, S));
  line();
  console.log(`  ${c('bold', 'Workpaper Package')} written to ${c('cyn', './emilia-workpaper/')}`);
  console.log(`    • authorization-receipt.json   ${c('dim', '— the evidence the relying party keeps')}`);
  console.log(`    • verification-report.md       ${c('dim', '— audit-grade determination, reproducible offline')}`);
  line();
  console.log(`  ${c('bold', 'The one sentence that matters:')}`);
  console.log(`  ${c('grn', '“The required human approvals existed for this exact action before it executed —')}`);
  console.log(`  ${c('grn', '   and I verified that myself, without trusting EMILIA, the operator, or any log.”')}`);
  console.log('');
}

// Offline verification a relying party (or anyone) can reproduce with no service.
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

function workpaper(receipt, genuine, forged, S) {
  const a = receipt.action;
  const det = (r) => r.verified
    ? 'AUTHORIZATION EVIDENCE: **PRESENT AND INDEPENDENTLY VERIFIED**'
    : 'AUTHORIZATION EVIDENCE: **ABSENT / UNVERIFIABLE — DO NOT RELY**';
  const checkRow = (k, v) => `| ${k} | ${v ? '✓ pass' : '✗ FAIL'} |`;
  const [exLabel, exVal] = S.extraRow(a);
  return `# Authorization Evidence — Workpaper

**Prepared by independent offline verification. No EMILIA service, account, network, or log was consulted.**

| | |
|---|---|
| Receipt ID | \`${receipt.receipt_id}\` |
| Action | ${S.actionSummary(a)} |
| ${exLabel} | ${exVal} |
| Policy | \`${a.policy_id}\` (${S.policyDesc}) |
| Action hash (recomputed) | \`${actionHashOf(a)}\` |
| Committed at | ${receipt.consumption.committed_at} |

## Determination

> ${det(genuine)}

The required human approvals existed for this exact action before it executed, and that fact was verified here with mathematics alone — independently of EMILIA, the operator, and any internal log. The receipt remains valid even if EMILIA ceases to exist.

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

${S.forgeNarrative}

> ${det(forged)}

Reasons: ${forged.reasons.map((r) => `_${r}_`).join('; ')}.

This is what an auditor, surveyor, lawyer, insurer, or board member sees when authorization evidence does not hold: a definite, reproducible **DO NOT RELY** — not a silent gap.

## What this receipt proves, and does not prove

**Proves:** the named approvers, holding their own device keys, each signed *this exact action* under the stated policy, in order, before execution; and that no party — including EMILIA — could have forged or altered it without detection.

**Does not prove:** that the approvers were not jointly colluding or coerced; that the displayed action matched the underlying intent (presentation integrity); the real-world identity behind each enrolled approver. Those are stated, not claimed solved.

**Bound (stated, not glossed):** the receipt is reliable evidence that the required humans *authorized* this exact action — it is **not** ${S.boundNote}.

${S.standards}

## Reproduce this determination yourself

\`\`\`
npx -y @emilia-protocol/crash-test verify ./authorization-receipt.json
\`\`\`

Offline. No account. No API key. The embedded EP-QUORUM-v1 document also
verifies directly via \`verifyQuorum()\` in \`@emilia-protocol/verify\`. Just math.

---
*Generated by \`@emilia-protocol/crash-test\` (scenario: ${S.key}). Approver signatures in this demonstration are real ES256 device-class assertions minted locally so the test runs without hardware; in production they originate on each approver's own device.*
`;
}

// `verify <file>` — the relying party's path: take only the receipt file, decide.
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

// ── Argument parsing: --scenario <key> | --scenario=<key>, then `verify <file>` ─
const argv = process.argv.slice(2);
let scenarioKey = 'finance';
const si = argv.findIndex((x) => x === '--scenario' || x.startsWith('--scenario='));
if (si >= 0) {
  const tok = argv[si];
  if (tok.includes('=')) { scenarioKey = tok.split('=')[1]; argv.splice(si, 1); }
  else { scenarioKey = argv[si + 1]; argv.splice(si, 2); }
}
if (!SCENARIOS[scenarioKey]) {
  console.error(`unknown scenario "${scenarioKey}". valid: ${Object.keys(SCENARIOS).join(', ')}`);
  process.exit(2);
}
const [cmd, arg] = argv;
if (cmd === 'verify' && arg) {
  verifyFile(arg).catch((e) => { console.error(e); process.exit(1); });
} else {
  main(SCENARIOS[scenarioKey]).catch((e) => { console.error(e); process.exit(1); });
}
