// SPDX-License-Identifier: Apache-2.0
//
// EP-RECOURSE-REFERENCE vector — WHO stands behind an authorized agent action.
//
//   node examples/recourse/recourse-reference-vector.mjs           # verify + print
//   node examples/recourse/recourse-reference-vector.mjs --emit    # (re)write .json
//
// EMILIA proves the RECOURSE REFERENCE: a named responsible party signed a
// commitment to stand behind THIS exact authorized action, bound by digest to a
// GENUINE authorization receipt. EMILIA does NOT bear the loss, adjudicate the
// exclusions, verify solvency, or move funds — claim-not-guarantee,
// evidence-not-adjudication. It is the socket an insurer / surety / employer /
// facilitator plugs into: they bring the balance sheet; EMILIA makes the loss
// event provable and the commitment verifiable offline.
//
// Verified-vs-accepted (same discipline as federation): a reference VERIFIES if
// its signature and bindings hold; it is ACCEPTED only when the relying party
// (gateway/claimant) has PINNED the responsible-party issuer key out-of-band. A
// self-asserted recourse reference is never accepted unpinned.
//
// Deterministic: fixed Ed25519 seeds + fixed fields → byte-reproducible across
// implementations. Demo keys, NOT production issuers.

import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { canonicalize } from '../scitt/ep-receipt-scitt-conformance.mjs';

const sha256hex = (b: any) => crypto.createHash('sha256').update(b).digest('hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const keyFromSeed = (label: string) => {
  const seed = crypto.createHash('sha256').update(label).digest();
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' });
  return { priv, pub: crypto.createPublicKey(priv as any) };
};
const spkiB64u = (pub: any) => pub.export({ type: 'spki', format: 'der' }).toString('base64url');
const signB64u = (priv: any, bytes: any) => crypto.sign(null, Buffer.from(bytes), priv).toString('base64url');

// ── The action both the receipt and the recourse are ABOUT ───────────────────
const ACTION = { action_type: 'finance.wire_transfer', target: 'wire:vendor-acme-250000', amount: '250000.00', currency: 'USD' };
const SUBJECT_DIGEST = sha256hex(Buffer.from(canonicalize(ACTION), 'utf8'));

// ── An authorization receipt (the WHO-authorized leg the recourse rides) ─────
const issuer = keyFromSeed('ep:recourse-vector:v1:auth-issuer');
const receiptPayload = {
  receipt_id: 'ep:receipt:recourse-vector-0001',
  subject: 'agent:autonomous:treasury-bot',
  created_at: '2026-07-02T00:00:00Z',
  claim: { action_type: ACTION.action_type, target: ACTION.target, subject_digest: SUBJECT_DIGEST, outcome: 'allow_with_signoff', approver: 'jane.doe@yourco.example', assurance: 'class_a' },
};
const receiptPayloadBytes = Buffer.from(canonicalize(receiptPayload), 'utf8');
const RECEIPT_PAYLOAD_DIGEST = `sha256:${sha256hex(receiptPayloadBytes)}`;

// ── The recourse issuer (a third-party guarantor / insurer / surety) ─────────
const recourseIssuer = keyFromSeed('ep:recourse-vector:v1:responsible-party');

function buildRecourse(overrides: any = {}) {
  const body = {
    '@type': 'ep.recourse-reference',
    '@version': 'EP-RECOURSE-REFERENCE-v1',
    subject_digest: SUBJECT_DIGEST,
    authorization: { receipt_id: receiptPayload.receipt_id, receipt_payload_digest: RECEIPT_PAYLOAD_DIGEST },
    responsible_party: { entity: 'did:web:acme-recourse.example', legal_name: 'Acme Recourse LLC', role: 'third_party' },
    coverage: {
      action_class: 'urn:ep:action:finance.wire_transfer',
      limit: { amount: '1000000.00', currency: 'USD' },
      exclusions_digest: `sha256:${sha256hex('EXCLUSIONS-DOC-v1')}`,
      window: { not_before: '2026-07-01T00:00:00Z', not_after: '2026-12-31T23:59:59Z' },
    },
    dispute_endpoint: 'https://acme-recourse.example/dispute',
    settlement_instruction: 'ref:settlement-schedule-A',
    evidence_requirements: ['EP-RECEIPT-v1', 'EP-EXECUTION-ATTESTATION-v1'],
    retention: '7y',
    status_url: 'https://acme-recourse.example/recourse/status/recourse-vector-0001',
    issued_at: '2026-07-02T00:00:00Z',
    expires_at: '2026-12-31T23:59:59Z',
    ...overrides,
  };
  const signable = { ...body };
  const bytes = Buffer.from(canonicalize(signable), 'utf8');
  const value = signB64u(recourseIssuer.priv, bytes);
  return { ...body, signature: { algorithm: 'Ed25519', value }, issuer_key: spkiB64u(recourseIssuer.pub) };
}

// ── Verifier ─────────────────────────────────────────────────────────────────
// Returns { verified, accepted, checks } — verified = signature+bindings hold;
// accepted = verified AND the issuer key is pinned by the relying party AND the
// action time is within the coverage window.
/**
 * @param {object} ref  the signed recourse reference document
 * @param {object} [opts]
 * @param {string} [opts.presentedSubjectDigest]
 * @param {string} [opts.presentedReceiptPayloadDigest]
 * @param {string[]} [opts.pinnedIssuerKeys]
 * @param {string} [opts.atTime]
 * @returns {{verified:boolean, accepted:boolean, checks:object}}
 */
export function verifyRecourse(ref: any, { presentedSubjectDigest, presentedReceiptPayloadDigest, pinnedIssuerKeys, atTime }: any = {}) {
  const checks = { signature: false, subject_binding: false, authorization_binding: false, within_window: false, issuer_pinned: false };
  try {
    const { signature, issuer_key, ...body } = ref;
    // 1. signature over the canonical body, by the reference's own issuer key
    const bytes = Buffer.from(canonicalize(body), 'utf8');
    const pub = crypto.createPublicKey({ key: Buffer.from(issuer_key, 'base64url'), format: 'der', type: 'spki' });
    checks.signature = crypto.verify(null, bytes, pub, Buffer.from(signature.value, 'base64url'));
    // 2. bound to THIS exact action
    checks.subject_binding = ref.subject_digest === presentedSubjectDigest;
    // 3. bound to a GENUINE authorization (the presented receipt's payload digest)
    checks.authorization_binding = ref.authorization.receipt_payload_digest === presentedReceiptPayloadDigest;
    // 4. action time within the coverage window
    // atTime is optional (@param {string} [opts.atTime]); Date.parse tolerates
    // undefined at runtime (coerces to "undefined" -> NaN), which the
    // !Number.isNaN(t) check below already handles as fail-closed.
    const t = Date.parse(/** @type {string} */ (atTime));
    checks.within_window = !Number.isNaN(t)
      && t >= Date.parse(ref.coverage.window.not_before)
      && t <= Date.parse(ref.coverage.window.not_after);
    // 5. ACCEPTANCE: issuer pinned out-of-band (verified != accepted)
    checks.issuer_pinned = Array.isArray(pinnedIssuerKeys) && pinnedIssuerKeys.includes(issuer_key);
  } catch { /* fail closed */ }
  const verified = checks.signature && checks.subject_binding && checks.authorization_binding;
  const accepted = verified && checks.within_window && checks.issuer_pinned;
  return { verified, accepted, checks };
}

const PINNED = [spkiB64u(recourseIssuer.pub)];
const ATTIME = '2026-07-02T12:00:00Z';
const opts = { presentedSubjectDigest: SUBJECT_DIGEST, presentedReceiptPayloadDigest: RECEIPT_PAYLOAD_DIGEST, pinnedIssuerKeys: PINNED, atTime: ATTIME };

const positive = buildRecourse();

// ── Negatives (MUST-reject / fail-closed) ────────────────────────────────────
const negatives = [
  {
    id: 'tampered_terms', reason: 'coverage_limit_altered_after_signing',
    detail: 'The coverage limit is raised after signing; the signature no longer verifies.',
    run: () => { const r = buildRecourse(); r.coverage = { ...r.coverage, limit: { amount: '999999999.00', currency: 'USD' } }; return verifyRecourse(r, opts); },
    expect: (v) => v.checks.signature === false && v.accepted === false,
  },
  {
    id: 'wrong_action', reason: 'subject_mismatch',
    detail: 'A recourse for action A is presented against a Capsule/gateway for action B.',
    run: () => verifyRecourse(positive, { ...opts, presentedSubjectDigest: sha256hex('different-action') }),
    expect: (v) => v.checks.subject_binding === false && v.accepted === false,
  },
  {
    id: 'authorization_mismatch', reason: 'recourse_not_bound_to_this_authorization',
    detail: 'The recourse references a different receipt than the one presented — recourse cannot ride a forged/other authorization.',
    run: () => verifyRecourse(positive, { ...opts, presentedReceiptPayloadDigest: `sha256:${sha256hex('other-receipt')}` }),
    expect: (v) => v.checks.authorization_binding === false && v.accepted === false,
  },
  {
    id: 'expired_window', reason: 'action_outside_coverage_window',
    detail: 'The action occurs after the coverage window closes; verified terms, but not accepted.',
    run: () => verifyRecourse(positive, { ...opts, atTime: '2027-06-01T00:00:00Z' }),
    expect: (v) => v.verified === true && v.checks.within_window === false && v.accepted === false,
  },
  {
    id: 'untrusted_issuer', reason: 'responsible_party_not_pinned',
    detail: 'A self-asserted recourse from a non-pinned issuer verifies but is NEVER accepted (no self-asserted recourse).',
    run: () => verifyRecourse(positive, { ...opts, pinnedIssuerKeys: [] }),
    expect: (v) => v.verified === true && v.checks.issuer_pinned === false && v.accepted === false,
  },
];

function vectorJson() {
  const { signature, issuer_key, ...body } = positive;
  return {
    vector: 'EP-RECOURSE-REFERENCE v1',
    spec: 'docs/EP-RECOURSE-REFERENCE-SPEC.md',
    schema: 'public/schemas/ep-recourse-reference.schema.json',
    canonicalization: 'RFC 8785 (JCS); SHA-256; Ed25519',
    note: 'EMILIA proves the reference + its binding to a genuine authorization. It does NOT bear the loss, adjudicate coverage, or move funds.',
    action: ACTION,
    subject_digest: SUBJECT_DIGEST,
    authorization: { receipt_id: receiptPayload.receipt_id, receipt_payload_digest: RECEIPT_PAYLOAD_DIGEST },
    recourse_reference: positive,
    accepted_when: { pinned_issuer_key: issuer_key, at_time_within_window: ATTIME },
    must_reject: negatives.map(({ run, expect, ...rest }) => rest),
  };
}

function main() {
  const pos = verifyRecourse(positive, opts);
  console.log('EP-RECOURSE-REFERENCE vector');
  console.log(`  action           = ${JSON.stringify(ACTION)}`);
  console.log(`  subject_digest   = ${SUBJECT_DIGEST}`);
  console.log(`  responsible      = ${positive.responsible_party.legal_name} (${positive.responsible_party.role})`);
  console.log(`  coverage         = ${positive.coverage.limit.amount} ${positive.coverage.limit.currency}, ${positive.coverage.window.not_before} .. ${positive.coverage.window.not_after}`);
  console.log(`  POSITIVE: verified=${pos.verified} accepted=${pos.accepted} (sig=${pos.checks.signature} subj=${pos.checks.subject_binding} auth=${pos.checks.authorization_binding} window=${pos.checks.within_window} pinned=${pos.checks.issuer_pinned})`);
  console.log('  MUST-REJECT:');
  let allNeg = true;
  for (const n of negatives) { const v = n.run(); const ok = n.expect(v); allNeg = allNeg && ok; console.log(`    ${ok ? 'ENFORCED' : 'MISSING '} ${n.id} → ${n.reason}`); }

  if (process.argv.includes('--emit')) {
    const p = fileURLToPath(new URL('./recourse-reference-vector.json', import.meta.url));
    writeFileSync(p, JSON.stringify(vectorJson(), null, 2) + '\n');
    console.log(`  wrote ${p}`);
  }
  const ok = pos.verified && pos.accepted && allNeg;
  console.log(`\n${ok ? 'RECOURSE VECTOR OK' : 'RECOURSE VECTOR FAIL'} — the recourse commitment is verifiable offline and bound to a genuine authorization; EMILIA proves it, does not bear it.`);
  if (!ok) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { ACTION, SUBJECT_DIGEST, RECEIPT_PAYLOAD_DIGEST, buildRecourse, positive, vectorJson };
