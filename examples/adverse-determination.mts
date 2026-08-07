// SPDX-License-Identifier: Apache-2.0
//
// EMILIA — adverse determination. A utilization-management AI recommends
// DENYING a prior-auth request. Watch the gate refuse to emit it, watch a
// NAMED LICENSED reviewer sign the exact determination, watch the replay and
// the tamper fail, and watch a third party re-perform the whole thing offline
// with no access to the payer's database.
//
//   node examples/adverse-determination.mjs          (paced, screen-recordable)
//   FAST=1 node examples/adverse-determination.mjs   (no pauses)
//
// Fully offline: real digests, real Ed25519 and WebAuthn P-256 ceremonies,
// real verifiers, real capability store. No network, no API key, deterministic.
//
// PHI-FREE AND FULLY SYNTHETIC. Pairwise pseudonymous member reference, a
// synthetic Luhn-valid NPI, a synthetic license number, a synthetic criteria
// document, a synthetic payer. Nothing here is a real person or record.
//
// California SB 1120 makes licensed-professional review of adverse
// medical-necessity decisions an auditable operational event; it does not
// mandate EMILIA, CAIDs, signatures, or cryptographic receipts. This file is a
// reference composition of existing EMILIA primitives. It is not legal advice,
// not a compliance determination, and not a DHCS, CMS, California, HL7, or
// Da Vinci standard or endorsement. Running it makes no one compliant.
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  buildDavinciPasReviewBinding,
  digestPasValue,
  verifyDavinciPasReviewBinding,
} from '../lib/health/davinci-pas-binding.js';
import { verifyTrustReceipt } from '../packages/verify/index.js';
import { evaluateReliance, validateRelianceProfile } from '../packages/verify/reliance.js';
import { signAuthorityProof } from '../lib/authority/proof.js';
import {
  canonicalize as gateCanonicalize,
  capabilityActionDigest,
  createGate,
  createMemoryCapabilityStore,
  executeWithCapability,
  hashCanonical,
  mintCapabilityReceipt,
  mintDeviceSignoff,
  reconcileCapabilityOperation,
  CAPABILITY_SCOPE_PROFILE,
} from '../packages/gate/index.js';
import {
  buildAssurancePackage,
  renderAssuranceWorkpaper,
  reperformAssurancePackage,
} from '../packages/gate/reports/assurance-package.js';

const pause = (ms: number) => (process.env.FAST ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));
const line = (s = '') => console.log(s);
const rule = () => line('─'.repeat(72));

const canon = (v: any): string => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p: string) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l: string, r: string) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const short = (s: string, n = 46) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** Wrap for the terminal without altering a character of the quoted text. */
function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  let current = '';
  for (const word of text.split(' ')) {
    if (current.length === 0) current = word;
    else if (`${current} ${word}`.length <= width) current = `${current} ${word}`;
    else { out.push(current); current = word; }
  }
  if (current.length > 0) out.push(current);
  return out;
}

// ── Synthetic world ────────────────────────────────────────────────────────
const NOW_ISO = '2026-07-21T18:35:00.000Z';
const NOW = Date.parse(NOW_ISO);
const OPERATION_ID = 'adverse-determination-2026-07-21-0001';
const PAIRWISE_MEMBER = 'pairwise:synthetic-member-7H3k9Q2p';
const ORG_ID = 'synthetic-health-plan';
const RP_ID = 'www.emiliaprotocol.ai';
const ALLOWED_ORIGINS = ['https://www.emiliaprotocol.ai'];

const CLAIM_PROFILE = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const RESPONSE_PROFILE = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const REVIEWER_URL = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-claimResponseReviewer';
const REVIEW_ACTION_URL = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewAction';
const REVIEW_ACTION_CODE_URL = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewActionCode';
const X12_REVIEW_ACTION_SYSTEM = 'https://codesystem.x12.org/005010/306';
const ADJUDICATION_SYSTEM = 'http://terminology.hl7.org/CodeSystem/adjudication';
const CRITERIA_SYSTEM = 'https://payer.example.test/CodeSystem/synthetic-um-criteria';

// The payer's medical-necessity criteria, as a document. Its digest IS the
// policy digest carried in the determination, so a third party can recompute
// the pin from the criteria text itself.
const CRITERIA_DOCUMENT = Object.freeze({
  '@type': 'EP-DEMO-UM-CRITERIA-v1',
  criteria_id: 'SYN-UM-4.2',
  title: 'Synthetic UM criteria: elective major joint replacement',
  requirement: 'At least 12 weeks of documented conservative therapy before elective joint replacement is considered medically necessary.',
  policy_id: 'policy:um-medical-necessity:2026-07',
  policy_version: '2026-07',
  effective: '2026-07-01',
});
const POLICY = Object.freeze({
  policy_id: 'policy:um-medical-necessity:2026-07',
  policy_version: '2026-07',
  policy_digest: digestPasValue(CRITERIA_DOCUMENT),
});

const DENIAL_RATIONALE = 'Record documents 4 weeks of conservative therapy; SYN-UM-4.2 requires 12. Not medically necessary at this time.';

// The licensed reviewer's credential. There is no license-state field on the
// CAID action (unknown action fields are refused), so the credential travels
// in the discovery packet and is bound into the determination through
// reviewer_identity_evidence_digest = digestPasValue(REVIEWER_CREDENTIAL).
const REVIEWER_REF = 'reviewer:um-medical-director-017';
const REVIEWER_CREDENTIAL = Object.freeze({
  '@type': 'EP-DEMO-REVIEWER-CREDENTIAL-v1',
  reviewer_ref: REVIEWER_REF,
  display_name: 'A. Romero, MD (synthetic)',
  npi: '1234567893',
  license_state: 'CA',
  license_number: 'SYNTHETIC-A-118842',
  specialty_taxonomy: '207X00000X',
  credential_source: 'payer credentialing system of record (synthetic)',
  credential_verified_at: '2026-07-20T16:00:00Z',
});
const REVIEWER_AUTHORITY_GRANT = Object.freeze({
  '@type': 'EP-DEMO-REVIEWER-AUTHORITY-GRANT-v1',
  reviewer_ref: REVIEWER_REF,
  granted_by: 'Organization/synthetic-health-plan',
  scope: 'medical_prior_authorization.adverse_decision',
  policy_id: POLICY.policy_id,
  policy_version: POLICY.policy_version,
  valid_from: '2026-01-01T00:00:00Z',
  valid_to: '2027-01-01T00:00:00Z',
});

// ── Synthetic Da Vinci PAS 2.2.1 resources (server-owned, never portable) ───
function pasClaim() {
  return {
    resourceType: 'Claim',
    id: 'synthetic-pa-claim-0001',
    meta: { profile: [CLAIM_PROFILE] },
    identifier: [{ system: 'https://payer.example.test/prior-auth', value: 'SYN-PA-0001' }],
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/synthetic-member-0001' },
    created: '2026-07-21T18:30:00Z',
    insurer: { reference: 'Organization/synthetic-health-plan' },
    provider: { reference: 'Organization/synthetic-requesting-provider' },
    priority: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/processpriority', code: 'normal' }] },
    diagnosis: [{ sequence: 1, diagnosisCodeableConcept: { coding: [{ system: 'http://hl7.org/fhir/sid/icd-10-cm', code: 'M17.11' }] } }],
    supportingInfo: [{ sequence: 1, category: { text: 'clinical note' }, valueString: 'synthetic clinical narrative, 4 weeks PT documented' }],
    item: [{
      sequence: 1,
      productOrService: { coding: [{ system: 'http://www.ama-assn.org/go/cpt', code: '27447' }] },
      servicedDate: '2026-08-15',
      locationCodeableConcept: { coding: [{ system: 'https://www.cms.gov/Medicare/Coding/place-of-service-codes', code: '22' }] },
      quantity: { value: 1 },
    }],
  };
}

function reviewerExtension() {
  return {
    url: REVIEWER_URL,
    extension: [
      { url: 'wasHumanReviewedFlag', valueBoolean: true },
      { url: 'reviewerNPI', valueIdentifier: { system: 'http://hl7.org/fhir/sid/us-npi', value: REVIEWER_CREDENTIAL.npi } },
      { url: 'reviewerSpecialty', valueCodeableConcept: { coding: [{ system: 'http://nucc.org/provider-taxonomy', code: REVIEWER_CREDENTIAL.specialty_taxonomy }] } },
    ],
  };
}

// reviewActionCode A3 = denied, A1 = approved. The denial rationale and the
// cited criteria live INSIDE item.adjudication, which is what decision_digest
// covers, so editing the rationale changes the determination's CAID.
function pasClaimResponse(reviewActionCode: string, rationale: string) {
  return {
    resourceType: 'ClaimResponse',
    id: 'synthetic-pa-response-0001',
    meta: { profile: [RESPONSE_PROFILE] },
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/synthetic-member-0001' },
    created: '2026-07-21T18:34:00Z',
    insurer: { reference: 'Organization/synthetic-health-plan' },
    request: { reference: 'Claim/synthetic-pa-claim-0001' },
    outcome: 'complete',
    extension: reviewActionCode === 'A1' ? [] : [reviewerExtension()],
    item: [{
      itemSequence: 1,
      adjudication: [{
        category: { coding: [{ system: ADJUDICATION_SYSTEM, code: 'submitted' }] },
        reason: {
          coding: [{ system: CRITERIA_SYSTEM, code: CRITERIA_DOCUMENT.criteria_id }],
          text: rationale,
        },
        extension: [{
          url: REVIEW_ACTION_URL,
          extension: [{
            url: REVIEW_ACTION_CODE_URL,
            valueCodeableConcept: { coding: [{ system: X12_REVIEW_ACTION_SYSTEM, code: reviewActionCode }] },
          }],
        }],
      }],
    }],
  };
}

/** The exact server-observed input the binding projects from. */
function determinationInput({ withReviewer = true, reviewActionCode = 'A3', rationale = DENIAL_RATIONALE } = {}) {
  const claim = pasClaim();
  const claim_response = pasClaimResponse(reviewActionCode, rationale);
  const claim_response_digest = digestPasValue(claim_response);
  const input: any = {
    operation_id: OPERATION_ID,
    pairwise_patient_ref: PAIRWISE_MEMBER,
    claim,
    claim_response,
    policy: { ...POLICY },
  };
  if (withReviewer && reviewActionCode !== 'A1') {
    input.reviewer = {
      reviewer_ref: REVIEWER_REF,
      identity_evidence: {
        status: 'accepted',
        subject_ref: REVIEWER_REF,
        evidence_digest: digestPasValue(REVIEWER_CREDENTIAL),
        fhir_reviewer_digest: digestPasValue(claim_response.extension[0]),
      },
      authority_evidence: {
        status: 'accepted',
        subject_ref: REVIEWER_REF,
        evidence_digest: digestPasValue(REVIEWER_AUTHORITY_GRANT),
        scope: 'medical_prior_authorization.adverse_decision',
        policy_digest: POLICY.policy_digest,
        claim_response_digest,
      },
    };
  }
  return input;
}

// ── Keys ───────────────────────────────────────────────────────────────────
const logKey = ed();        // the payer's transparency log
const intake = ed();        // Class-B: the UM triage agent that filed the case
const reviewer = p256();    // Class-A: the licensed reviewer's bound device
const registryKey = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('b4'.repeat(32), 'hex')]),
  format: 'der',
  type: 'pkcs8',
});
// Node's crypto.createPublicKey accepts a private KeyObject at runtime (it
// derives the public key); @types/node's overloads omit KeyObject, cast only.
const registryPub = crypto.createPublicKey(registryKey as any).export({ type: 'spki', format: 'der' }).toString('base64url');
const REGISTRY_HEAD = `sha256:${'22'.repeat(32)}`;

/** A real WebAuthn P-256 assertion over the signoff-context digest. */
function classA(digestHex: string) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ALLOWED_ORIGINS[0] }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update(RP_ID).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return {
    authenticator_data: authData.toString('base64url'),
    client_data_json: clientDataJSON.toString('base64url'),
    signature: crypto.sign('sha256', signedData, reviewer.privateKey).toString('base64url'),
  };
}

/**
 * The Section-6.2 Trust Receipt the reviewer's device signs. Its action carries
 * the determination's CAID and action digest, so the reviewer's signature runs
 * down a digest chain that terminates at the exact member reference, service
 * line, cited criteria and denial rationale. What they saw is what they signed.
 *
 * NOTE on `contexts[].decision`: the reviewer is APPROVING the issuance of an
 * adverse determination. The reliance kernel only admits approval contexts into
 * the authorization set (isApprovalContext in packages/verify/src/reliance.ts),
 * so `decision` is left undefined here. A signed `decision:'denied'` context is
 * decision evidence, not authorization evidence; the clinical outcome ("denied")
 * lives in the determination's own decision_outcome field, not in the signoff
 * context. This is a real semantic seam, not a workaround.
 */
function buildDeterminationReceipt(binding: any, nonce: string) {
  const action = {
    ep_version: '1.0',
    action_type: 'health.adverse_determination.issue',
    organization_id: ORG_ID,
    policy_hash: POLICY.policy_digest,
    target: { system: 'um.prior-auth', resource: `determination/${OPERATION_ID}` },
    parameters: {
      determination_caid: binding.caid,
      determination_action_digest: binding.action_digest,
      decision_outcome: binding.action.decision_outcome,
      pairwise_patient_ref: binding.action.pairwise_patient_ref,
      reviewer_ref: binding.action.reviewer_ref,
      reviewer_credential_digest: binding.action.reviewer_identity_evidence_digest,
      criteria_cited: CRITERIA_DOCUMENT.criteria_id,
    },
    initiator: 'ep:entity:um-triage-agent',
    policy_id: POLICY.policy_id,
    requested_at: '2026-07-21T18:30:10Z',
  };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash,
    policy_id: POLICY.policy_id,
    policy_hash: POLICY.policy_digest,
    initiator: action.initiator,
    required_approvals: 2,
    issued_at: '2026-07-21T18:30:20Z',
    expires_at: '2026-07-21T18:45:20Z',
  };
  const ctxAgent = { ...base, approver: 'ep:approver:um-triage-agent', approver_index: 1, nonce: `${nonce}-1` };
  const ctxReviewer = { ...base, approver: 'ep:approver:licensed-reviewer', approver_index: 2, nonce: `${nonce}-2` };
  const dAgent = sha(canon(ctxAgent));
  const dReviewer = sha(canon(ctxReviewer));
  const receipt: any = {
    receipt_id: `ep:receipt:${nonce}`,
    action,
    action_hash,
    contexts: [ctxAgent, ctxReviewer],
    signoffs: [
      { context_hash: `sha256:${dAgent}`, signature: crypto.sign(null, Buffer.from(dAgent, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:um-agent#1', signed_at: '2026-07-21T18:31:00Z' },
      { context_hash: `sha256:${dReviewer}`, signature: 'webauthn', key_class: 'A', approver_key_id: 'ep:key:reviewer#1', signed_at: '2026-07-21T18:34:10Z', webauthn: classA(dReviewer) },
    ],
    consumption: { nonce: `${nonce}-consume`, state: 'COMMITTED', committed_at: '2026-07-21T18:34:20Z' },
  };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:synthetic-health-plan#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = {
    alg: 'EP-MERKLE-v2',
    leaf_hash: `sha256:${leaf}`,
    leaf_index: 0,
    inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }],
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

const APPROVER_KEYS = {
  'ep:key:um-agent#1': { approver_id: 'ep:approver:um-triage-agent', public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:reviewer#1': { approver_id: 'ep:approver:licensed-reviewer', public_key: reviewer.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};

const reviewerAuthority = (over: any = {}) => signAuthorityProof({
  authority_id: 'auth_um_medical_director',
  subject: 'ep:approver:licensed-reviewer',
  organization_id: ORG_ID,
  role: 'licensed_medical_reviewer',
  scope: ['health.adverse_determination.issue'],
  limits: {},
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-21T18:30:00.000Z' },
  registry_head: REGISTRY_HEAD,
  registry_epoch: 9,
  policy_hash: POLICY.policy_digest,
  issued_at: '2026-07-21T18:30:00.000Z',
  ...over,
} as any, registryKey);

// ── The relying party's own pinned rule ────────────────────────────────────
// The published profile is loaded from disk exactly as shipped. Its trust
// anchors are EMPTY by design: a payer, a regulator, or a plaintiff's expert
// overlays its OWN roots. Verified is not accepted.
const PUBLISHED_PROFILE = JSON.parse(readFileSync(
  new URL('../public/schemas/reliance-profiles/cms-prior-auth.v1.json', import.meta.url),
  'utf8',
));
const OVERLAID_PROFILE = {
  ...PUBLISHED_PROFILE,
  accepted_registry_keys: [{ issuer_id: 'auth_um_medical_director', organization_id: ORG_ID, public_key: registryPub, min_epoch: 9, registry_head: REGISTRY_HEAD }],
  accepted_issuer_keys: [logKey.pub],
  accepted_policy_hashes: [POLICY.policy_digest],
};

// ── The provider portal that loses the response mid-issue ──────────────────
const PROVIDER_EVIDENCE_VERSION = 'EP-DEMO-DETERMINATION-DELIVERY-v1';
function createProviderPortal() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pinnedPublicKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const written = new Map<string, any>();
  let calls = 0;
  return {
    providerId: 'provider-portal.example.test',
    pinnedPublicKey,
    get calls() { return calls; },
    get writtenCount() { return written.size; },
    async execute(action: any, ctx: any) {
      calls += 1;
      const operationId = ctx?.operation_id;
      if (!operationId) throw new TypeError('provider operation_id is required');
      // The determination IS written to the patient record here, before the
      // connection drops. That is exactly why a blind retry is unsafe.
      if (!written.has(operationId)) {
        written.set(operationId, { action: structuredClone(action), at: '2026-07-21T18:35:04.000Z' });
      }
      const error: any = new Error('provider portal response lost after the determination was written');
      error.code = 'PROVIDER_RESPONSE_LOST';
      throw error;
    },
    signedEvidence(operationId: string) {
      const record = written.get(operationId);
      if (!record) throw new Error('provider portal has no written determination for that operation');
      const body = {
        '@version': PROVIDER_EVIDENCE_VERSION,
        provider_id: 'provider-portal.example.test',
        operation_id: operationId,
        status: 'committed',
        action_digest: capabilityActionDigest(record.action),
        written_at: record.at,
      };
      return {
        body,
        signature: {
          algorithm: 'Ed25519',
          public_key: pinnedPublicKey,
          value: crypto.sign(null, Buffer.from(gateCanonicalize(body), 'utf8'), privateKey).toString('base64url'),
        },
      };
    },
  };
}

/** Authenticate the portal's evidence against a PINNED key before believing it. */
function verifyDeliveryEvidence(portal: any) {
  return (evidence: any, ctx: any) => {
    if (!evidence?.body || !evidence?.signature) return { valid: false };
    if (evidence.body['@version'] !== PROVIDER_EVIDENCE_VERSION
      || evidence.signature.algorithm !== 'Ed25519'
      || evidence.signature.public_key !== portal.pinnedPublicKey
      || evidence.body.provider_id !== portal.providerId
      || evidence.body.operation_id !== ctx.operation_id
      || evidence.body.status !== 'committed'
      || evidence.body.action_digest !== ctx.action_digest) return { valid: false };
    const authentic = crypto.verify(
      null,
      Buffer.from(gateCanonicalize(evidence.body), 'utf8'),
      crypto.createPublicKey({ key: Buffer.from(portal.pinnedPublicKey, 'base64url'), format: 'der', type: 'spki' }),
      Buffer.from(evidence.signature.value, 'base64url'),
    );
    if (!authentic) return { valid: false };
    return {
      valid: true,
      outcome: 'executed',
      action_digest: ctx.action_digest,
      evidence_digest: `sha256:${hashCanonical(evidence)}`,
    };
  };
}

// ═══════════════════════════════════════════════════════════════════════════
async function main() {
  line();
  line('  EMILIA — adverse determination: who signed the denial?');
  rule();
  line('  Synthetic, PHI-free, fully offline. California SB 1120 requires that');
  line('  an adverse medical-necessity determination not rest on AI alone: a');
  line('  licensed human must review. This shows what that looks like as');
  line('  portable evidence. Not legal advice, not an endorsement, not a');
  line('  compliance determination.');
  await pause(2600);

  // ── 1. The UM AI recommends denial ───────────────────────────────────────
  line('\n  [1/8] utilization-management AI');
  line('        "4 weeks conservative therapy documented, criteria require 12."');
  line(`        → recommend_denial(${PAIRWISE_MEMBER})`);
  line('          service   CPT 27447 · requested 2026-08-15 · POS 22');
  line(`          criteria  ${CRITERIA_DOCUMENT.criteria_id}, ${CRITERIA_DOCUMENT.title}`);
  line('          model     synthetic-um-triage@2026.07   confidence 0.91');
  await pause(2400);

  // ── 2. The gate refuses ──────────────────────────────────────────────────
  const noReviewer = buildDavinciPasReviewBinding(determinationInput({ withReviewer: false }));
  const approvalPath = buildDavinciPasReviewBinding(determinationInput({ reviewActionCode: 'A1' }));
  line('\n  [2/8] the gate REFUSES to emit the adverse determination');
  line('        buildDavinciPasReviewBinding(denial, no reviewer evidence)');
  line(`        → ok: ${(noReviewer as any).ok}   reasons: ${(noReviewer as any).reasons.join(', ')}`);
  line('        ⛔  no valid licensed-review evidence, no adverse determination.');
  await pause(1800);
  line('        the same call on an APPROVAL (X12 A1) builds with no reviewer:');
  line(`        → ok: ${(approvalPath as any).ok}   decision_outcome: ${(approvalPath as any).binding?.action.decision_outcome}`);
  line('        the rule is scoped to adverse outcomes. It is not a tax on yes,');
  line('        and missing evidence is never authority to withhold medically');
  line('        necessary care: it routes to lawful human review.');
  await pause(2800);

  // ── 3. A named licensed reviewer signs THIS determination ────────────────
  const input = determinationInput();
  const built = buildDavinciPasReviewBinding(input);
  if (!(built as any).ok) throw new Error(`binding failed: ${(built as any).reasons.join(',')}`);
  const binding = (built as any).binding;

  line('\n  [3/8] a NAMED LICENSED reviewer signs the EXACT determination');
  line(`        ${REVIEWER_CREDENTIAL.display_name} · NPI ${REVIEWER_CREDENTIAL.npi} (synthetic, Luhn-valid)`);
  line(`        license ${REVIEWER_CREDENTIAL.license_state} ${REVIEWER_CREDENTIAL.license_number} · taxonomy ${REVIEWER_CREDENTIAL.specialty_taxonomy}`);
  await pause(1200);
  line('        signs over the member reference, the service line, the cited');
  line('        criteria, and this rationale:');
  const rationaleLines = wrap(DENIAL_RATIONALE, 62);
  rationaleLines.forEach((l, i) => line(`          ${i === 0 ? '"' : ' '}${l}${i === rationaleLines.length - 1 ? '"' : ''}`));
  await pause(2000);
  const [caidHead, caidTail] = binding.caid.split(':jcs-sha256:');
  line(`        caid          ${caidHead}`);
  line(`                      :jcs-sha256:${caidTail}`);
  line(`        decision      ${binding.action.decision_outcome}  (X12 review action A3)`);
  line(`        reviewer_ref  ${binding.action.reviewer_ref}`);
  line(`        credential    ${short(binding.action.reviewer_identity_evidence_digest, 30)}`);
  line(`        criteria      ${short(binding.action.policy_digest, 30)}`);

  // A real PHI search over the real portable bytes.
  const portable = JSON.stringify(binding);
  const probes: Array<[string, string]> = [
    ['patient ref', 'Patient/synthetic-member-0001'],
    ['claim id', 'SYN-PA-0001'],
    ['CPT', '27447'],
    ['ICD-10', 'M17.11'],
    ['note', 'synthetic clinical narrative'],
    ['rationale text', DENIAL_RATIONALE],
  ];
  const leaks = probes.filter(([, needle]) => portable.includes(needle));
  line(`        the portable object is ${portable.length} bytes and carries digests only.`);
  line(`        searched it for ${probes.map(([label]) => label).join(', ')}:`);
  line(`        ${leaks.length === 0 ? 'none present ✓' : `LEAKED ${leaks.map(([label]) => label).join(', ')}`}`);
  await pause(2800);

  // ── 4. Minted, and consumed ONCE at the determination boundary ────────────
  const receipt = buildDeterminationReceipt(binding, OPERATION_ID);
  const trust = verifyTrustReceipt(receipt, { approverKeys: APPROVER_KEYS, logPublicKey: logKey.pub, rpId: RP_ID, allowedOrigins: ALLOWED_ORIGINS, now: NOW } as any);

  const consumedActions = new Set<string>();      // the RP's own atomic state
  const consumedCaids = new Set<string>();        // the determination fence
  const relianceOpts = {
    approverKeys: APPROVER_KEYS,
    logPublicKey: logKey.pub,
    rpId: RP_ID,
    allowedOrigins: ALLOWED_ORIGINS,
    isConsumed: ({ action_hash }: any) => consumedActions.has(action_hash),
  };
  const presented = { action_type: 'health.adverse_determination.issue', organization_id: ORG_ID, policy_hash: POLICY.policy_digest, action_hash: receipt.action_hash };
  const relianceInput = {
    action: presented,
    receipt,
    authority_proof: reviewerAuthority(),
    revocation_state: { checked_at: '2026-07-21T18:30:00.000Z' },
    relying_party_profile: OVERLAID_PROFILE,
    now: NOW,
  };
  const firstReliance = evaluateReliance(relianceInput, relianceOpts);
  const detVerify = verifyDavinciPasReviewBinding(binding, {
    ...input,
    expected_operation_id: OPERATION_ID,
    expected_caid: binding.caid,
    consumed_caids: consumedCaids,
  });

  line('\n  [4/8] minted, then CONSUMED ONCE at the determination boundary');
  line(`        verifyTrustReceipt(...)            → ${trust.valid ? 'valid' : 'INVALID'}  (Class-A WebAuthn)`);
  line('        rule: public/schemas/reliance-profiles/cms-prior-auth.v1.json');
  line(`        validateRelianceProfile(published) → ok: ${validateRelianceProfile(PUBLISHED_PROFILE).ok}`);
  line(`        its trust anchors ship EMPTY (${PUBLISHED_PROFILE.accepted_issuer_keys.length} issuer, ${PUBLISHED_PROFILE.accepted_policy_hashes.length} policy, ${PUBLISHED_PROFILE.accepted_registry_keys.length} registry keys).`);
  line('        the relying party overlays its OWN roots before anything can');
  line('        be relied on. Verified is not accepted.');
  await pause(2200);
  line(`        evaluateReliance(...)              → ${firstReliance.verdict}`);
  line(`        verifyDavinciPasReviewBinding(...) → valid: ${detVerify.valid}`);
  consumedActions.add(receipt.action_hash.replace(/^sha256:/, ''));
  consumedCaids.add(binding.caid);
  line('        consumed: this CAID is now spent at this boundary.');
  await pause(2200);

  // ── 5. Replay ────────────────────────────────────────────────────────────
  const replayDet = verifyDavinciPasReviewBinding(binding, { ...input, consumed_caids: consumedCaids });
  const replayReliance = evaluateReliance(relianceInput, relianceOpts);
  line('\n  [5/8] the same determination is submitted again');
  line(`        verifyDavinciPasReviewBinding(...) → valid: ${replayDet.valid}  ${replayDet.reasons.join(', ')}`);
  line(`        evaluateReliance(...)              → ${replayReliance.verdict}`);
  line('        the same adverse determination cannot be issued twice.');
  await pause(2400);

  // ── 6. Tamper ────────────────────────────────────────────────────────────
  const softened = 'Record documents 4 weeks of conservative therapy; criteria met. Denied on administrative grounds.';
  const rationaleTamper = verifyDavinciPasReviewBinding(binding, determinationInput({ rationale: softened }));

  const swapped = JSON.parse(JSON.stringify(binding));
  swapped.action.reviewer_ref = 'reviewer:um-medical-director-099';
  const reviewerTamper = verifyDavinciPasReviewBinding(swapped, input);

  line('\n  [6/8] tamper');
  line('        (a) the ClaimResponse produced in discovery has a softened');
  line('            rationale: "…criteria met. Denied on administrative');
  line('            grounds." The verifier reprojects it and refuses.');
  line(`            valid: ${rationaleTamper.valid}`);
  for (const l of wrap(rationaleTamper.reasons.join(', '), 56)) line(`            ${l}`);
  await pause(2000);
  line('        (b) the reviewer of record is swapped after signing:');
  line('            reviewer:um-medical-director-017 → …-099');
  line(`            valid: ${reviewerTamper.valid}`);
  for (const l of wrap(reviewerTamper.reasons.join(', '), 56)) line(`            ${l}`);
  line('        the rationale and the reviewer are both inside the CAID.');
  await pause(2600);

  // ── 7. The provider system drops the connection mid-issue ────────────────
  const ISSUE_ACTION = Object.freeze({
    action_type: 'health.adverse_determination.issue',
    amount: 1,                        // one determination
    currency: 'DETERMINATION',
    determination_caid: binding.caid,
    determination_action_digest: binding.action_digest,
    determination_operation_id: OPERATION_ID,
  });
  const SELECTOR = { protocol: 'demo', tool: 'issue_adverse_determination' };
  const MANIFEST = {
    '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
    actions: [{
      id: 'adverse-determination-issue',
      action_type: ISSUE_ACTION.action_type,
      receipt_required: true,
      risk: 'critical',
      assurance_class: 'class_a',
      match: SELECTOR,
      execution_binding: {
        required_fields: ['action_type', 'amount', 'currency', 'determination_caid', 'determination_action_digest', 'determination_operation_id'],
      },
    }],
  };
  const issuer = ed();
  const baseActionHash = crypto.createHash('sha256').update(gateCanonicalize({ action_type: ISSUE_ACTION.action_type }), 'utf8').digest('hex');
  const deviceApproval = mintDeviceSignoff({ actionHash: baseActionHash, approver: 'ep:approver:licensed-reviewer', issuedAtMs: NOW });
  const basePayload = {
    receipt_id: 'ep:receipt:adverse-determination-issue',
    created_at: new Date(NOW - 1000).toISOString(),
    subject: 'agent:um-issuance',
    issuer: `ep:org:${ORG_ID}`,
    claim: { ...ISSUE_ACTION, outcome: 'allow_with_signoff', capability_only: true },
    signoff: deviceApproval.signoff,
    approver_public_key: deviceApproval.approver_public_key,
  };
  const baseReceipt = {
    '@version': 'EP-RECEIPT-v1',
    payload: basePayload,
    signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(gateCanonicalize(basePayload), 'utf8'), issuer.privateKey).toString('base64url') },
    public_key: issuer.pub,
  };
  const gate = createGate({
    manifest: MANIFEST,
    trustedKeys: [issuer.pub],
    approverKeys: { 'ep:key:reviewer-device': { approver_id: deviceApproval.signoff.context.approver, public_key: deviceApproval.approver_public_key, key_class: 'A' } },
    rpId: 'emiliaprotocol.ai',
    allowedOrigins: ALLOWED_ORIGINS,
    allowEphemeralStore: true,
    now: () => NOW,
  } as any);
  const minted = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: issuer.privateKey,
    budget: { amount: 1, currency: 'DETERMINATION' },   // exactly ONE issuance
    expiry: new Date(NOW + 60_000).toISOString(),
    revocationMode: 'direct',
    capabilityId: 'ep:capability:adverse-determination-0001',
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'determination_operation_id',
      action_digests: [capabilityActionDigest(ISSUE_ACTION)],
    },
  } as any);
  const store = createMemoryCapabilityStore();
  if (!store.registerCapability(minted.capabilityReceipt)) throw new Error('capability registration failed');
  const portal = createProviderPortal();
  const issue = () => executeWithCapability({
    capabilityReceipt: minted.capabilityReceipt,
    // mintCapabilityReceipt is called without `threshold`, so it defaults to
    // {m:1,n:1} and `secret` always takes the Buffer branch. Cast only.
    secret: minted.secret as Buffer,
    action: ISSUE_ACTION,
    store,
    gate,
    selector: SELECTOR,
    observedAction: ISSUE_ACTION,
    trustedIssuerKeys: [issuer.pub],
    operationId: OPERATION_ID,
    now: () => NOW,
    executeAction: (a: any, ctx: any) => portal.execute(a, ctx),
  });

  const attempt = await issue();
  const operation = store.getOperation(OPERATION_ID);
  const blindRetry = await issue();

  line('\n  [7/8] the provider portal drops the connection mid-issue');
  line(`        executeWithCapability(...)  → ok: ${attempt.ok}  reason: ${attempt.reason}`);
  line(`        capability operation        → status: ${operation.status}  outcome: ${operation.outcome}`);
  await pause(1800);
  line(`        blind retry                 → ok: ${blindRetry.ok}  reason: ${blindRetry.reason}`);
  line(`        portal write attempts: ${portal.calls}   determinations written: ${portal.writtenCount}`);
  line('        INDETERMINATE is not proof the effect succeeded or failed. It');
  line('        is a safety state that holds replay authority until authentic,');
  line('        action-bound provider evidence reconciles it. A duplicate');
  line('        adverse determination on a patient record is its own harm.');
  await pause(2800);
  const reconciled = await reconcileCapabilityOperation({
    store,
    capabilityId: minted.capabilityReceipt.capability.id,
    operationId: OPERATION_ID,
    action: ISSUE_ACTION,
    evidence: portal.signedEvidence(OPERATION_ID),
    verifyEvidence: verifyDeliveryEvidence(portal),
    now: () => NOW,
  });
  const settled = store.getOperation(OPERATION_ID);
  line('        the portal later returns SIGNED delivery evidence, checked');
  line('        against a PINNED provider key and this exact action digest:');
  line(`        reconcileCapabilityOperation(...) → ok: ${reconciled.ok}  outcome: ${(reconciled as any).outcome}`);
  line(`        operation → outcome: ${settled.outcome}  reconciliation_outcome: ${settled.reconciliation_outcome}`);
  line('        the recorded runtime outcome STAYS indeterminate. Reconciliation');
  line('        records authenticated evidence beside it and never restores');
  line('        budget. History is not rewritten.');
  await pause(2600);

  // ── 8. The discovery packet ──────────────────────────────────────────────
  const decisions = [
    { decision_id: 'AD-0001', action: { ...presented }, receipt, authority_proof: reviewerAuthority(), revocation_state: { checked_at: '2026-07-21T18:30:00.000Z' }, consumption: { consumed: false }, stated_verdict: 'rely' },
    { decision_id: 'AD-0001-resubmission', action: { ...presented }, receipt, authority_proof: reviewerAuthority(), revocation_state: { checked_at: '2026-07-21T18:30:00.000Z' }, consumption: { consumed: true }, stated_verdict: 'do_not_rely_already_consumed' },
  ];
  const pkg = buildAssurancePackage(decisions, { profile: OVERLAID_PROFILE, organization: { id: ORG_ID, name: 'Synthetic Health Plan' }, now: NOW });
  const reperformed = reperformAssurancePackage(pkg, {
    approverKeys: APPROVER_KEYS,
    logPublicKey: logKey.pub,
    rpId: RP_ID,
    allowedOrigins: ALLOWED_ORIGINS,
    isConsumed: () => false,
    now: NOW,
  });

  line('\n  [8/8] the discovery packet');
  line('        what the payer hands its own counsel, or a regulator, or the');
  line('        plaintiff. One file. No database access.');
  line(`        EP-ASSURANCE-PACKAGE-v1  digest ${short(pkg.package_digest, 28)}`);
  await pause(1600);
  line();
  for (const l of renderAssuranceWorkpaper(reperformed).split('\n')) line(l.length > 0 ? `      ${l}` : '');
  await pause(2400);

  // The reviewer→determination leg, recomputed by a third party from the
  // credential and the criteria document alone.
  const independentPolicyDigest = digestPasValue(CRITERIA_DOCUMENT);
  const independentCredentialDigest = digestPasValue(REVIEWER_CREDENTIAL);
  const independent = verifyDavinciPasReviewBinding(binding, { ...determinationInput(), expected_caid: binding.caid });
  line('\n      recomputed from the packet alone, no payer database:');
  line(`        criteria document → policy_digest matches    ${independentPolicyDigest === binding.action.policy_digest}`);
  line(`        credential (name/NPI/CA license) → matches   ${independentCredentialDigest === binding.action.reviewer_identity_evidence_digest}`);
  line(`        verifyDavinciPasReviewBinding → valid        ${independent.valid}`);
  line(`        conclusion.supportable                       ${String(reperformed.conclusion.supportable)}`);
  line('      the packet establishes WHO authorized WHAT, WHEN, under WHICH');
  line('      criteria. It does not conclude. A person concludes.');
  await pause(2400);

  line();
  rule();
  line('  A mutable "reviewed_by: dr_smith" row proves nothing under discovery.');
  line('  This binds a named licensed reviewer to one exact determination, and');
  line('  a third party who was never in the room can check it offline.');
  line('  Reference composition. Not a deployed system, not certified, not');
  line('  independently attested, not legal advice.');
  line('  docs/health/ADVERSE-DETERMINATION-GATE.md   ·   emiliaprotocol.ai');
  line();

  // Fail the run loudly if any printed claim stopped being true.
  const invariants: Array<[string, boolean]> = [
    ['gate refuses an adverse determination with no reviewer evidence', (noReviewer as any).ok === false && (noReviewer as any).reasons.includes('adverse_reviewer_required')],
    ['an approval builds without reviewer evidence', (approvalPath as any).ok === true && (approvalPath as any).binding.action.decision_outcome === 'approved'],
    ['no PHI in the portable determination', leaks.length === 0],
    ['the trust receipt verifies', trust.valid === true],
    ['first presentation relies', firstReliance.verdict === 'rely'],
    ['first determination verification is valid', detVerify.valid === true],
    ['replay is refused at the determination fence', replayDet.valid === false && replayDet.reasons.includes('replay_refused')],
    ['replay is refused at the reliance boundary', replayReliance.verdict === 'do_not_rely_already_consumed'],
    ['a softened rationale fails verification', rationaleTamper.valid === false && rationaleTamper.reasons.includes('claim_response_digest_mismatch')],
    ['a swapped reviewer fails verification', reviewerTamper.valid === false && reviewerTamper.reasons.includes('caid_mismatch')],
    ['the lost response is indeterminate', attempt.ok === false && attempt.reason === 'effect_indeterminate' && operation.outcome === 'indeterminate'],
    ['the blind retry is refused', blindRetry.ok === false && blindRetry.reason === 'operation_already_committed'],
    ['the portal wrote exactly one determination', portal.calls === 1 && portal.writtenCount === 1],
    ['authenticated evidence reconciles the operation', reconciled.ok === true && (reconciled as any).outcome === 'executed'],
    ['the recorded outcome is not rewritten', settled.outcome === 'indeterminate' && settled.reconciliation_outcome === 'executed'],
    ['re-performance confirms the determination', reperformed.results[0].recomputed_verdict === 'rely'],
    ['re-performance confirms the resubmission refusal', reperformed.results[1].recomputed_verdict === 'do_not_rely_already_consumed'],
    ['no drift between stated and recomputed verdicts', reperformed.population.relied_on_inadmissible_evidence === 0],
    ['the tool refuses to conclude', reperformed.conclusion.supportable === null],
    ['the independent leg recomputes', independent.valid === true && independentPolicyDigest === binding.action.policy_digest && independentCredentialDigest === binding.action.reviewer_identity_evidence_digest],
  ];
  const failed = invariants.filter(([, ok]) => !ok);
  if (failed.length > 0) {
    line('  DEMO INVARIANTS FAILED. A printed claim is no longer true:');
    for (const [label] of failed) line(`    ✗ ${label}`);
    line();
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
