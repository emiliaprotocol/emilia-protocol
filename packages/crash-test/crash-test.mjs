#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Protocol — the crash test.
 *
 * One command. Two acts. The whole protocol becomes obvious.
 *
 *   Act 1 (today):  an AI agent proposes an irreversible, high-risk action.
 *     Self-approval is rejected. Two separately enrolled demo keys sign the
 *     exact action under a pinned quorum policy. A receipt is issued.
 *
 *   Act 2 (later, EMILIA gone):  the network is down, the EMILIA service is
 *     deleted, the database is gone. The receipt and relying-party-owned trust
 *     profile still verify offline, while a forged copy is rejected.
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
 * approver signatures use the real ES256 WebAuthn verification shape, but are
 * minted headlessly with synthetic identities and software keys. This demo does
 * not claim hardware backing, attestation, real-world identity, or execution.
 */
import crypto from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
// The frozen, cross-language-verified offline predicate. No EP infrastructure.
// Resolve the published package; fall back to the in-repo path for local dev.
let verifyQuorum;
let strictJsonGate;
try {
  ({ verifyQuorum } = await import('@emilia-protocol/verify'));
  ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json'));
} catch {
  ({ verifyQuorum } = await import('../verify/index.js'));
  ({ strictJsonGate } = await import('../verify/strict-json.js'));
}

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
const trustProfileHashOf = (profile) => `sha256:${sha256hex(canon(profile))}`;
const RP_ID = 'emiliaprotocol.ai';
const ALLOWED_ORIGINS = ['https://www.emiliaprotocol.ai'];
const MAX_INPUT_BYTES = 8 * 1024 * 1024;

function readStrictJson(path, label) {
  const raw = readFileSync(path);
  if (raw.length > MAX_INPUT_BYTES) throw new Error(`${label} exceeds ${MAX_INPUT_BYTES} bytes`);
  const text = raw.toString('utf8');
  const gate = strictJsonGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  return JSON.parse(text);
}

// ── Mint a synthetic ES256/WebAuthn-shaped approval, bound to the action ─────
function signSyntheticWebAuthn({ role, approver, issuedAt, actionHash, policyId, initiator, expiresAt }) {
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

Under **GAGAS (Government Auditing Standards / the GAO "Yellow Book")**, audit evidence must be **sufficient and appropriate**. This demonstration shows one potentially useful property: an auditor can reproduce the cryptographic checks offline under trust inputs the auditor controls, rather than accepting keys embedded by the presenter.

Concretely, it can support a **test of an authorization-control artifact** over a high-risk disbursement: whether the keys enrolled for the required approver identifiers signed the exact action under the pinned separation-of-duties, order, and threshold rules. The auditor must separately evaluate enrollment, key custody, control operation, and the sufficiency of this evidence for the engagement.`,
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
    boundNote: 'a judgment about whether the engagement was lawful or appropriate under the rules of engagement, evidence of human perception or intent, or proof that execution followed authorization — only that the enrolled keys produced the required exact-action signatures and the pinned operator signed the commit record',
    standards: `## For the review board — how this maps to human-control policy

**DoD Directive 3000.09** requires that autonomous and semi-autonomous weapon systems allow commanders and operators to exercise **appropriate levels of human judgment over the use of force**. This demonstration does not prove that judgment. It shows how a reviewer could check, offline and under independently pinned trust inputs, whether two enrolled keys signed an exact designated-track action in the required order.

This can support a **test of a cryptographic authorization artifact**. It is **necessary, not sufficient** for a real control assessment: identity enrollment, device custody, trusted time, revocation, human understanding, ROE compliance, platform enforcement, and execution/effect evidence remain separate requirements.`,
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
        // Synthetic demo identifiers only. Hashing real identifiers does not by
        // itself establish HIPAA de-identification.
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
      `         ${c('dim', 'class: ')}${c('ylw', 'HIGH-ALERT anticoagulant')}${c('dim', '  ·  patient: <synthetic hashed ref>  ·  policy: high-alert-independent-double-check@v3')}`,
    ],
    blockedLine: () => `  ${c('red', '⛔ BLOCKED')} — HIGH_ALERT_DOUBLE_CHECK_REQUIRED  ${c('dim', '(ISMP high-alert med → independent double-check by a second qualified clinician before administration)')}`,
    forge: (r) => { r.action.parameters.rate = '12,000 units/hr'; return 'Forged copy (infusion rate altered to 12,000 units/hr — a 10× error — after the double-check)'; },
    actionSummary: (a) => `${a.action_type} — ${a.parameters.medication} ${a.parameters.route} @ ${a.parameters.rate}`,
    extraRow: (a) => ['High-alert class', a.parameters.high_alert_class + ' (synthetic patient reference for this demo)'],
    policyDesc: 'independent double-check: administering nurse, then a second qualified clinician',
    forgeNarrative: 'A forged copy of this receipt, with the infusion rate altered from 1,200 units/hr to 12,000 units/hr *after* the double-check, was submitted to the same offline verification:',
    boundNote: 'a test of the *clinical appropriateness* of the order (that remains the prescriber\'s and pharmacist\'s judgment), or of the real-world *identity* behind each enrolled clinician (an enrollment-layer control)',
    standards: `## For the safety officer / surveyor — how this maps to your standards

The two-person ceremony models an **independent double-check** for a high-alert medication. EP makes the exact signed order and policy checks reproducible offline under hospital-pinned keys. It does not establish that the key holders were qualified clinicians, that either person perceived the displayed fields, or that administration followed the authorization.

**HIPAA boundary:** this demonstration contains only synthetic identifiers. Hashing a real MRN or encounter identifier does **not** automatically de-identify it or make disclosure permissible. A production profile needs data-minimization, linkage-risk, access-control, retention, and disclosure analysis by the covered entity.

**Break-glass is not demonstrated here:** a production deployment needs a separately authorized emergency-override path with its own evidence, monitoring, and retrospective review.`,
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
    boundNote: 'a test of whether the purchase was the best *value* or clinically justified, proof of the key holders\' real-world roles, or evidence that payment followed authorization — only the exact-action signatures and operator commit described above',
    standards: `## For internal audit / the controller — how this maps to your standards

This models **segregation of duties** over capital spend: an agent may initiate a purchase order, while the pinned policy requires signatures from keys enrolled for Department Director and CFO identifiers. The receipt makes the exact PO fields, order, and signature checks reproducible; control ownership and real-world identity remain outside the receipt.

It also demonstrates a useful property for **payment-redirect / business-email-compromise (BEC) controls**: because the payee account digest is inside the signed action, swapping it after approval breaks verification. Preventing payment fraud still requires trusted beneficiary enrollment, change controls, and enforcement at the payment rail.`,
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
  const mint = (over) => signSyntheticWebAuthn({
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
  const selfRes = verifyQuorum(selfTry, { rpId: RP_ID, allowedOrigins: ALLOWED_ORIGINS });
  console.log(`  ${c('red', '✗')} requester self-approval ${c('red', 'REJECTED')} ${c('dim', `— not an eligible approver (roles_admitted=${selfRes.checks.roles_admitted}, threshold_met=${selfRes.checks.threshold_met}); separation of duties holds`)}`);
  await sleep(120);

  // The real two-person ceremony, in order.
  const members = S.approvers.map((ap) => mint({ role: ap.role, approver: ap.approver, issuedAt: ap.issuedAt }));
  for (const ap of S.approvers) console.log(`  ${c('grn', '✓')} ${ap.label} ${c('dim', '(' + ap.short + ')')} signed with a separate demo WebAuthn key`);
  await sleep(120);

  const quorum = { '@type': 'ep.quorum', action_hash: ACTION_HASH, policy: POLICY, members };
  const live = verifyQuorum(quorum, { rpId: RP_ID, allowedOrigins: ALLOWED_ORIGINS });
  if (!live.valid) { console.error(c('red', '  internal error: live quorum did not verify'), live.checks); process.exit(2); }
  console.log(`  ${c('grn', '✓ COMMITTED')} — every quorum predicate satisfied`);

  // Issue the authorization receipt. The relying party separately pins the
  // policy, enrolled approver keys, WebAuthn scope, and operator key.
  const issuer = crypto.generateKeyPairSync('ed25519');
  const trustProfile = {
    '@type': 'ep.crash-test.trust-profile.v1',
    profile_id: `ep:trust-profile:${S.key}:v1`,
    rp_id: RP_ID,
    allowed_origins: ALLOWED_ORIGINS,
    quorum_policy: POLICY,
    approvers: members.map((member) => ({
      role: member.role,
      approver: member.signoff.context.approver,
      public_key: member.approver_public_key,
    })),
    operator_public_key: issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const body = {
    '@version': 'EP-RECEIPT-v1',
    receipt_id: S.receiptId,
    action: A,
    action_hash: ACTION_HASH,
    trust_profile_hash: trustProfileHashOf(trustProfile),
    quorum,
    consumption: { state: 'COMMITTED', committed_at: S.committedAt },
  };
  const operator_signature = crypto.sign(null, Buffer.from(canon(body), 'utf8'), issuer.privateKey).toString('base64url');
  const receipt = { ...body, operator_signature };
  console.log(`  ${c('grn', '✓')} authorization receipt issued ${c('dim', '→ authorization-receipt.json')}`);
  console.log('');

  // ===== ACT 2 — RELIANCE ====================================================
  line(); console.log(c('bold', '  ACT 2 — RELIANCE') + c('dim', `   (${S.act2Where})`)); line();
  console.log(`  ${c('dim', 'network: ')}${c('red', 'DISCONNECTED')}    ${c('dim', 'EMILIA service: ')}${c('red', 'DELETED')}    ${c('dim', 'EMILIA database: ')}${c('red', 'GONE')}`);
  console.log(`  ${c('dim', 'the relying party has the receipt plus its previously pinned trust profile')}`);
  await sleep(150);

  const genuine = verifyReceiptOffline(receipt, trustProfile);
  printDetermination('Genuine receipt as filed', genuine);
  await sleep(120);

  // Forgery: tamper the action after the fact, do NOT re-sign. The action no
  // longer hashes to what the humans signed — and the predicate catches it.
  const forged = JSON.parse(JSON.stringify(receipt));
  const forgeLabel = S.forge(forged);
  const forgedRes = verifyReceiptOffline(forged, trustProfile);
  printDetermination(forgeLabel, forgedRes);
  console.log('');

  // ── Write the Workpaper Package ────────────────────────────────────────────
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'authorization-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  writeFileSync(resolve(outDir, 'relying-party-trust-profile.json'), JSON.stringify(trustProfile, null, 2) + '\n');
  writeFileSync(resolve(outDir, 'verification-report.md'), workpaper(receipt, genuine, forgedRes, S));
  line();
  console.log(`  ${c('bold', 'Workpaper Package')} written to ${c('cyn', './emilia-workpaper/')}`);
  console.log(`    • authorization-receipt.json   ${c('dim', '— the evidence the relying party keeps')}`);
  console.log(`    • relying-party-trust-profile.json ${c('dim', '— policy and keys pinned out of band')}`);
  console.log(`    • verification-report.md       ${c('dim', '— audit-grade determination, reproducible offline')}`);
  line();
  console.log(`  ${c('bold', 'The one sentence that matters:')}`);
  console.log(`  ${c('grn', '“The enrolled approver keys signed this exact action under my pinned policy —')}`);
  console.log(`  ${c('grn', '   and I reproduced that result offline without trusting the presenter.”')}`);
  console.log('');
}

// Offline verification under relying-party-owned trust inputs. Keys and policy
// inside the presented receipt are never accepted as their own authority.
function verifyReceiptOffline(receipt, trustProfile) {
  const reasons = [];
  const falseChecks = {
    all_signatures_valid: false,
    action_binding: false,
    distinct_humans: false,
    distinct_keys: false,
    initiator_excluded: false,
    roles_admitted: false,
    threshold_met: false,
    order_satisfied: false,
    chain_linked: false,
    within_window: false,
  };
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { verified: false, checks: falseChecks, hashMatches: false, trustProfileMatches: false, policyMatches: false, committed: false, chronology: false, opOk: false, reasons: ['receipt must be an object'] };
  }
  if (!trustProfile || typeof trustProfile !== 'object' || Array.isArray(trustProfile)) {
    return { verified: false, checks: falseChecks, hashMatches: false, trustProfileMatches: false, policyMatches: false, committed: false, chronology: false, opOk: false, reasons: ['a relying-party trust profile is required'] };
  }

  const rpId = typeof trustProfile.rp_id === 'string' && trustProfile.rp_id ? trustProfile.rp_id : null;
  const allowedOrigins = Array.isArray(trustProfile.allowed_origins)
    && trustProfile.allowed_origins.length > 0
    && trustProfile.allowed_origins.every((origin) => {
      try {
        const url = new URL(origin);
        return url.protocol === 'https:' && url.origin === origin;
      } catch { return false; }
    }) ? trustProfile.allowed_origins : null;
  if (trustProfile['@type'] !== 'ep.crash-test.trust-profile.v1' || !rpId || !allowedOrigins) {
    reasons.push('relying-party trust profile is malformed or lacks HTTPS WebAuthn scope');
  }

  let trustProfileMatches = false;
  try { trustProfileMatches = receipt.trust_profile_hash === trustProfileHashOf(trustProfile); }
  catch { trustProfileMatches = false; }
  if (!trustProfileMatches) reasons.push('receipt is not bound to the supplied relying-party trust profile');

  let hashMatches = false;
  try {
    const recomputed = actionHashOf(receipt.action);
    hashMatches = recomputed === receipt.action_hash && receipt.action_hash === receipt.quorum?.action_hash;
  } catch { hashMatches = false; }
  if (!hashMatches) reasons.push('action_hash does not match the action as filed (the action was altered after approval)');

  const policyMatches = Boolean(receipt.quorum?.policy && trustProfile.quorum_policy
    && canon(receipt.quorum.policy) === canon(trustProfile.quorum_policy));
  if (!policyMatches) reasons.push('receipt quorum policy differs from the relying party pinned policy');

  const pins = new Map();
  let pinsValid = Array.isArray(trustProfile.approvers) && trustProfile.approvers.length > 0;
  if (pinsValid) {
    for (const pin of trustProfile.approvers) {
      const id = `${pin?.role ?? ''}\0${pin?.approver ?? ''}`;
      if (!pin?.role || !pin?.approver || !pin?.public_key || pins.has(id)) { pinsValid = false; break; }
      try {
        crypto.createPublicKey({ key: Buffer.from(pin.public_key, 'base64url'), format: 'der', type: 'spki' });
      } catch { pinsValid = false; break; }
      pins.set(id, pin.public_key);
    }
  }
  if (!pinsValid) reasons.push('relying-party approver enrollment pins are missing or malformed');

  let q = { valid: false, checks: falseChecks };
  if (pinsValid && rpId && allowedOrigins && Array.isArray(receipt.quorum?.members)) {
    const members = receipt.quorum.members.map((member) => ({
      ...member,
      approver_public_key: pins.get(`${member?.role ?? ''}\0${member?.signoff?.context?.approver ?? ''}`) ?? '',
    }));
    q = verifyQuorum({
      ...receipt.quorum,
      policy: trustProfile.quorum_policy,
      members,
    }, { rpId, allowedOrigins });
  }
  if (!q.valid) reasons.push('quorum predicate failed under relying-party policy and enrolled keys: '
    + Object.entries(q.checks).filter(([, value]) => !value).map(([key]) => key).join(', '));

  const committedAt = receipt.consumption?.committed_at;
  const committedMs = typeof committedAt === 'string' ? Date.parse(committedAt) : NaN;
  const committed = receipt.consumption?.state === 'COMMITTED'
    && Number.isFinite(committedMs)
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(committedAt);
  if (!committed) reasons.push('operator commit state or timestamp is invalid');
  const receiptMembers = Array.isArray(receipt.quorum?.members) ? receipt.quorum.members : null;
  const approvalTimes = receiptMembers
    ? receiptMembers.map((member) => Date.parse(member?.signoff?.context?.issued_at)).filter(Number.isFinite)
    : [];
  const chronology = committed && receiptMembers && approvalTimes.length === receiptMembers.length
    && approvalTimes.every((time) => time <= committedMs);
  if (!chronology) reasons.push('signed approval timestamps do not precede the operator commit timestamp');

  let opOk = false;
  try {
    const { operator_signature, ...body } = receipt;
    const key = crypto.createPublicKey({
      key: Buffer.from(trustProfile.operator_public_key, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    opOk = key.asymmetricKeyType === 'ed25519'
      && crypto.verify(null, Buffer.from(canon(body), 'utf8'), key, Buffer.from(operator_signature, 'base64url'));
  } catch { opOk = false; }
  if (!opOk) reasons.push('operator commit signature is invalid under the relying party pinned operator key');

  const verified = reasons.length === 0 && trustProfileMatches && hashMatches && policyMatches
    && pinsValid && q.valid && committed && chronology && opOk;
  return { verified, checks: q.checks, hashMatches, trustProfileMatches, policyMatches, committed, chronology, opOk, reasons };
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

**Prepared by offline verification under the relying party's pinned trust profile. No EMILIA service, account, network, or operator-supplied key was consulted.**

| | |
|---|---|
| Receipt ID | \`${receipt.receipt_id}\` |
| Action | ${S.actionSummary(a)} |
| ${exLabel} | ${exVal} |
| Policy | \`${a.policy_id}\` (${S.policyDesc}) |
| Relying-party trust profile | \`${receipt.trust_profile_hash}\` |
| Action hash (recomputed) | \`${actionHashOf(a)}\` |
| Committed at | ${receipt.consumption.committed_at} |

## Determination

> ${det(genuine)}

The keys enrolled by the relying party for the required approver identifiers signed this exact action under the relying party's pinned policy. The operator commit also verifies under the separately pinned operator key. This determination is reproducible offline even if EMILIA ceases to exist.

## What was checked (offline)

| Check | Result |
|---|---|
| action_hash recomputed from the action as filed matches what the approvers signed | ${genuine.hashMatches ? '✓ pass' : '✗ FAIL'} |
| receipt bound to the supplied relying-party trust profile | ${genuine.trustProfileMatches ? '✓ pass' : '✗ FAIL'} |
| presented policy exactly matches the relying party pinned policy | ${genuine.policyMatches ? '✓ pass' : '✗ FAIL'} |
${checkRow('all approver device signatures valid', genuine.checks.all_signatures_valid)}
${checkRow('every approver signed this exact action (action binding)', genuine.checks.action_binding)}
${checkRow('approvers are distinct humans (separation of duties)', genuine.checks.distinct_humans)}
${checkRow('each approver is an authorized role on the policy roster', genuine.checks.roles_admitted)}
${checkRow('required number of approvals met', genuine.checks.threshold_met)}
${checkRow('approvals occurred in required order', genuine.checks.order_satisfied)}
${checkRow('all approvals within the policy time window', genuine.checks.within_window)}
| operator asserted COMMITTED state with a valid timestamp | ${genuine.committed ? '✓ pass' : '✗ FAIL'} |
| signed approval timestamps are no later than the operator commit timestamp | ${genuine.chronology ? '✓ pass' : '✗ FAIL'} |
| operator commit signature valid under the relying party pinned key | ${genuine.opOk ? '✓ pass' : '✗ FAIL'} |

## Tamper test (the absence made visible)

${S.forgeNarrative}

> ${det(forged)}

Reasons: ${forged.reasons.map((r) => `_${r}_`).join('; ')}.

This is what an auditor, surveyor, lawyer, insurer, or board member sees when authorization evidence does not hold: a definite, reproducible **DO NOT RELY** — not a silent gap.

## What this receipt proves, and does not prove

**Proves under the supplied trust profile:** the keys enrolled for the listed approver identifiers each signed *this exact action* under the pinned policy and WebAuthn scope; the signed approval timestamps satisfy the pinned order/window rules; and the pinned operator key signed the resulting commit record. Altering those signed fields is detectable.

**Does not prove:** who correctly enrolled or protected the pinned keys; what a person perceived or intended; that approvers were not colluding or coerced; trusted time; revocation freshness unless separately supplied; action legality, safety, or wisdom; that execution occurred; or that execution matched or followed the authorization. The operator's \`COMMITTED\` value is a signed assertion, not effect evidence.

**Bound (stated, not glossed):** the receipt is reliable evidence that the required humans *authorized* this exact action — it is **not** ${S.boundNote}.

${S.standards}

## Reproduce this determination yourself

\`\`\`
npx -y @emilia-protocol/crash-test verify ./authorization-receipt.json \\
  --trust ./relying-party-trust-profile.json
\`\`\`

Offline. No account. No API key. The receipt is judged under trust material the
relying party supplies; the presented artifact cannot establish its own authority.

---
*Generated by \`@emilia-protocol/crash-test\` (scenario: ${S.key}). The demonstration uses real ES256 WebAuthn-shaped signatures minted locally, not hardware-backed passkeys. A production deployment must enroll authenticators, validate attestation as policy requires, protect trust-profile distribution, and supply separate execution/effect evidence for execution claims.*
`;
}

// `verify <file>` — the relying party's path: take only the receipt file, decide.
async function verifyFile(path, trustPath) {
  let receipt;
  let trustProfile;
  try {
    if (!trustPath) throw new Error('missing --trust <relying-party-trust-profile.json>');
    receipt = readStrictJson(resolve(process.cwd(), path), 'receipt');
    trustProfile = readStrictJson(resolve(process.cwd(), trustPath), 'trust profile');
  } catch (e) { console.error(c('red', `cannot verify receipt: ${e.message}`)); process.exit(2); }
  console.log('');
  console.log(c('dim', '  offline verification — receipt judged under relying-party-pinned policy and keys'));
  const r = verifyReceiptOffline(receipt, trustProfile);
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
  const trustIndex = argv.indexOf('--trust');
  const trustPath = trustIndex >= 0 ? argv[trustIndex + 1] : null;
  verifyFile(arg, trustPath).catch((e) => { console.error(e); process.exit(1); });
} else {
  main(SCENARIOS[scenarioKey]).catch((e) => { console.error(e); process.exit(1); });
}
