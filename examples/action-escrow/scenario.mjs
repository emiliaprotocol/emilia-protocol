// SPDX-License-Identifier: Apache-2.0
/**
 * Action Escrow kitchen-renovation reference scenario.
 *
 * The document/action binding, party signatures, durable state transitions,
 * one-time release, and portable package verification are real. The e-sign
 * provider, custodian, identities, project facts, evidence files, and balances
 * are deterministic local simulations. EMILIA never holds or moves funds.
 */
import crypto from 'node:crypto';

import { canonicalize, verifyReceipt } from '../../packages/verify/index.js';
import {
  computeReleaseActionDigest,
  signDocumentActionBinding,
  verifyDocumentActionBinding,
} from '../../packages/verify/document-action-binding.js';
import {
  RESOLUTION_CONTEXT_TYPE,
  RESOLUTION_VERSION,
  computeResolutionChallenge,
  computeResolutionResponseHash,
  verifyResolutionReceipt,
} from '../../packages/verify/resolution.js';
import {
  ACTION_ESCROW_PROFILE_VERSION,
  createActionEscrowReleaseBindingMoment,
  computeActionEscrowReleaseBindingMomentDigest,
  computeActionEscrowResolutionNonce,
  createActionEscrowKernel,
} from '../../packages/gate/action-escrow.js';
import {
  computeActionEscrowAgreementDigest,
  createActionEscrowDocumentBindingVerifier,
} from '../../packages/gate/action-escrow-verifiers.js';
import {
  ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION,
  verifyActionEscrowEvidencePackage,
} from '../../packages/gate/action-escrow-evidence.js';
import {
  assembleActionEscrowEvidencePackage,
} from '../../packages/gate/action-escrow-package.js';
import {
  createActionEscrowCustodianBridge,
  createActionEscrowCustodianStatementVerifier,
} from '../../packages/gate/action-escrow-custodian.js';
import {
  createActionEscrowStatePackageVerifier,
  signActionEscrowStateStatement,
} from '../../packages/gate/action-escrow-state.js';
import { createAcrobatSignAdapter } from '../../lib/integrations/action-escrow/acrobat-sign.js';
import { defineExternalCustodianAdapter } from '../../lib/integrations/action-escrow/licensed-custodian.js';

export const ACTION_ESCROW_VERSION = 'EP-ACTION-ESCROW-DEMO-v2';
export const ACTION_ESCROW_ACTION = 'escrow.milestone.release';

const AGREEMENT_ID = 'AGR-KITCHEN-2048';
const BINDING_ID = 'DAB-KITCHEN-2048-V2';
const MILESTONE_ID = 'MS-03-CABINETRY';
const CREATED_AT = '2026-07-17T16:00:00.000Z';
const FIXED_NOW_MS = Date.parse(CREATED_AT);
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const RESOLUTION_RP_ID = 'emiliaprotocol.ai';
const RESOLUTION_ORIGIN = 'https://www.emiliaprotocol.ai';
const MAPPING_ISSUER_ID = 'demo:emilia-mapping-issuer';
const OPERATOR_ID = 'demo:action-escrow-operator';
const CUSTODIAN_PROVIDER_ID = 'harborline_demo';
const REQUIRED_TERM_IDS = Object.freeze([
  'amendment_version',
  'completion_requirements_digest',
  'document_authorizes_payment',
  'milestone_name',
  'payee_id',
  'release.amount',
  'release.destination_id',
  'release.milestone_id',
  'release_requires_mutual_approval',
  'retainage_amount',
]);

const DEMO_BOUNDARIES = Object.freeze([
  'The Acrobat Sign adapter and custodian adapter run against deterministic local responses. No external provider API is called.',
  'All identities, provider and license references, project facts, evidence files, and balances are fictional.',
  'The DAB signature, party signatures, Action Escrow kernel, state signature, and evidence-package verification are real.',
  'A signed document establishes neither payment authorization nor a release approval.',
  'EMILIA does not hold or move money. Only the simulated external custodian reports funding and release state.',
  'The scenario does not judge workmanship, physical completion, legal enforceability, identity, comprehension, voluntariness, or licensing.',
]);

function invariant(condition, message) {
  if (!condition) throw new Error(`Action Escrow invariant failed: ${message}`);
}

function clone(value) {
  return structuredClone(value);
}

function sha256Bytes(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

export function sha256Canonical(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), 'utf8'));
}

function publicKeyBase64url(keyObject) {
  return keyObject.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function deterministicDemoKey(label) {
  const seed = crypto
    .createHash('sha256')
    .update(`EMILIA_ACTION_ESCROW_DEMO_ONLY:${label}`, 'utf8')
    .digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKeyObject = crypto.createPublicKey(privateKey);
  const publicKey = publicKeyBase64url(publicKeyObject);
  return {
    privateKey,
    publicKey,
    publicKeyObject,
    keyId: `demo:${label}:${sha256Bytes(Buffer.from(publicKey, 'utf8')).slice(7, 19)}`,
  };
}

function deterministicP256Key(label) {
  let privateBytes = crypto
    .createHash('sha256')
    .update(`EMILIA_ACTION_ESCROW_WEBAUTHN_DEMO_ONLY:${label}`, 'utf8')
    .digest();
  const ecdh = crypto.createECDH('prime256v1');
  let accepted = false;
  for (let counter = 0; counter < 256; counter += 1) {
    try {
      ecdh.setPrivateKey(privateBytes);
      accepted = true;
      break;
    } catch {
      privateBytes = crypto
        .createHash('sha256')
        .update(privateBytes)
        .update(Buffer.from([counter]))
        .digest();
    }
  }
  invariant(accepted, `deterministic P-256 key derivation failed for ${label}`);
  const point = ecdh.getPublicKey(null, 'uncompressed');
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: privateBytes.toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33, 65).toString('base64url'),
  };
  const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const publicKeyObject = crypto.createPublicKey(privateKey);
  const publicKey = publicKeyBase64url(publicKeyObject);
  return {
    privateKey,
    publicKey,
    publicKeyObject,
    keyId: `demo:resolution:${label}:${sha256Bytes(Buffer.from(publicKey, 'utf8')).slice(7, 19)}`,
  };
}

function signReceipt(privateKey, payload) {
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto
        .sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey)
        .toString('base64url'),
    },
  };
}

function receiptDigest(receipt) {
  return sha256Canonical(receipt);
}

function dollars(amountMinor) {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
  }).format(amountMinor / 100);
}

function pdfEscape(value) {
  return String(value).replaceAll('\\', '\\\\').replaceAll('(', '\\(').replaceAll(')', '\\)');
}

function createPdf(textLines) {
  const commands = [
    'BT',
    '/F1 18 Tf',
    '54 742 Td',
    `(${pdfEscape(textLines[0])}) Tj`,
    '/F1 10 Tf',
    ...textLines.slice(1).flatMap((line) => ['0 -24 Td', `(${pdfEscape(line)}) Tj`]),
    'ET',
  ].join('\n');
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(commands, 'utf8')} >>\nstream\n${commands}\nendstream`,
  ];

  let body = '%PDF-1.4\n%EMILIA-ACTION-ESCROW\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(Buffer.byteLength(body, 'utf8'));
    body += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = Buffer.byteLength(body, 'utf8');
  body += `xref\n0 ${objects.length + 1}\n`;
  body += '0000000000 65535 f \n';
  offsets.slice(1).forEach((offset) => {
    body += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n`;
  body += `startxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(body, 'utf8');
}

function finalMaterialTerms() {
  const completionRequirements = [
    'Upper and lower cabinetry installed to the approved layout',
    'Island cabinetry anchored',
    'Countertop template completed',
    'Contractor completion statement and three evidence files submitted',
  ];
  return {
    agreement_id: AGREEMENT_ID,
    amendment_version: 2,
    project: {
      name: 'Lakeview kitchen renovation',
      property: '1432 Lakeview Avenue, Portland, OR (fictional)',
      contractor: 'Oak & Line Builders LLC (fictional)',
      homeowner: 'Maya Chen (fictional)',
    },
    milestone: {
      id: MILESTONE_ID,
      name: 'Cabinet installation and countertop template',
      release_amount: '18400.00',
      release_amount_minor: 1840000,
      currency: 'USD',
      retainage_amount: '4600.00',
      retainage_minor: 460000,
      completion_requirements: completionRequirements,
    },
    payee: {
      contractor_id: 'contractor:oak-line-builders',
      destination_id: 'custody-destination:oak-line:ending-4821',
    },
    release_rule: {
      document_signatures_authorize_payment: false,
      exact_release_approvals_required: ['homeowner', 'contractor'],
      custodian_role: 'external_funds_holder_and_release_executor',
      one_time_release: true,
    },
  };
}

function dabMaterialTerms(terms) {
  return [
    { term_id: 'amendment_version', type: 'integer', value: terms.amendment_version },
    {
      term_id: 'completion_requirements_digest',
      type: 'digest',
      value: sha256Canonical(terms.milestone.completion_requirements),
    },
    {
      term_id: 'release.destination_id',
      type: 'identifier',
      value: terms.payee.destination_id,
    },
    {
      term_id: 'document_authorizes_payment',
      type: 'boolean',
      value: terms.release_rule.document_signatures_authorize_payment,
    },
    { term_id: 'release.milestone_id', type: 'identifier', value: terms.milestone.id },
    { term_id: 'milestone_name', type: 'string', value: terms.milestone.name },
    { term_id: 'payee_id', type: 'identifier', value: terms.payee.contractor_id },
    {
      term_id: 'release.amount',
      type: 'amount',
      value: terms.milestone.release_amount,
      currency: terms.milestone.currency,
    },
    {
      term_id: 'release_requires_mutual_approval',
      type: 'boolean',
      value: true,
    },
    {
      term_id: 'retainage_amount',
      type: 'amount',
      value: terms.milestone.retainage_amount,
      currency: terms.milestone.currency,
    },
  ];
}

function materialTermMapping(terms) {
  return [
    { id: 'agreement_id', pdf_text: `Agreement: ${terms.agreement_id}` },
    { id: 'amendment_version', pdf_text: `Amendment version: ${terms.amendment_version}` },
    { id: 'project', pdf_text: `Project: ${terms.project.name}` },
    { id: 'property', pdf_text: `Property: ${terms.project.property}` },
    {
      id: 'milestone_id',
      pdf_text: `Milestone: ${terms.milestone.id} - ${terms.milestone.name}`,
    },
    {
      id: 'release_amount',
      pdf_text: `Release amount: ${dollars(terms.milestone.release_amount_minor)} ${terms.milestone.currency}`,
    },
    {
      id: 'retainage_amount',
      pdf_text: `Retainage after release: ${dollars(terms.milestone.retainage_minor)}`,
    },
    { id: 'payee_id', pdf_text: `Payee: ${terms.project.contractor}` },
    { id: 'destination_id', pdf_text: `Custodian destination: ${terms.payee.destination_id}` },
    {
      id: 'release_requires_mutual_approval',
      pdf_text: 'Release requires separate exact-action approval from homeowner and contractor.',
    },
  ];
}

function buildFinalDocument(terms, mapping) {
  const bytes = createPdf([
    'FINAL KITCHEN RENOVATION MILESTONE AGREEMENT',
    ...mapping.map((entry) => entry.pdf_text),
    'Document signatures confirm agreement to these final bytes.',
    'Document signatures do not authorize payment or judge workmanship.',
  ]);
  return {
    filename: 'lakeview-kitchen-milestone-3-final.pdf',
    media_type: 'application/pdf',
    bytes,
    size_bytes: bytes.length,
    sha256: sha256Bytes(bytes),
  };
}

async function fetchSimulatedAcrobatEvidence(document) {
  const agreement = {
    id: 'ADOBE-SIM-AGR-KITCHEN-2048-V2',
    name: 'Lakeview kitchen milestone 3',
    status: 'SIGNED',
    participantSetsInfo: [
      {
        id: 'ADOBE-SIM-PARTICIPANT-HOMEOWNER',
        role: 'SIGNER',
        order: 1,
        memberInfos: [
          { email: 'homeowner@example.invalid', status: 'COMPLETED' },
        ],
      },
      {
        id: 'ADOBE-SIM-PARTICIPANT-CONTRACTOR',
        role: 'SIGNER',
        order: 2,
        memberInfos: [
          { email: 'contractor@example.invalid', status: 'COMPLETED' },
        ],
      },
    ],
  };
  const agreementEvents = {
    events: [{
      id: 'ADOBE-SIM-EVENT-FINAL',
      type: 'SIGNED',
      date: '2026-07-17T15:04:59Z',
      versionId: 'ADOBE-SIM-VERSION-FINAL-2',
    }],
  };
  const fakeFetch = async (url) => {
    const requestUrl = new URL(url);
    if (requestUrl.pathname.endsWith('/combinedDocument')) {
      invariant(
        requestUrl.searchParams.get('versionId')
          === agreementEvents.events[0].versionId,
        'Acrobat simulation must fetch the authoritative document version',
      );
      return new Response(document.bytes, {
        status: 200,
        headers: { 'Content-Type': 'application/pdf' },
      });
    }
    if (requestUrl.pathname.endsWith('/events')) {
      return new Response(JSON.stringify(agreementEvents), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
    return new Response(JSON.stringify(agreement), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  };
  const adapter = createAcrobatSignAdapter({
    apiOrigin: 'https://api.na1.adobesign.com',
    oauthAccessToken: 'deterministic-local-demo-token',
    fetch: fakeFetch,
    clock: () => '2026-07-17T15:05:00.000Z',
  });
  const evidence = await adapter.fetchFinalEvidence({
    notification: {
      event: 'AGREEMENT_SIGNED',
      agreement: { id: agreement.id },
    },
    expected: {
      agreementId: agreement.id,
      status: 'SIGNED',
      participantSets: [
        {
          id: 'ADOBE-SIM-PARTICIPANT-HOMEOWNER',
          role: 'SIGNER',
          order: 1,
          members: [{
            email: 'homeowner@example.invalid',
            status: 'COMPLETED',
          }],
        },
        {
          id: 'ADOBE-SIM-PARTICIPANT-CONTRACTOR',
          role: 'SIGNER',
          order: 2,
          members: [{
            email: 'contractor@example.invalid',
            status: 'COMPLETED',
          }],
        },
      ],
    },
  });
  invariant(evidence.kind === 'evidence_ready', 'simulated Acrobat adapter must return final evidence');
  invariant(
    Buffer.from(evidence.document_bytes).equals(document.bytes),
    'DAB must receive the exact provider-refetched PDF bytes',
  );
  return evidence;
}

function completionEvidenceManifest(terms) {
  return {
    '@version': 'ACTION-ESCROW-COMPLETION-EVIDENCE-v1',
    evidence_id: 'EVD-MS-03-20260717',
    agreement_id: terms.agreement_id,
    milestone_id: terms.milestone.id,
    submitted_by: terms.payee.contractor_id,
    submitted_at: '2026-07-17T15:30:00.000Z',
    statement: 'Contractor reports the milestone complete and submits the listed evidence.',
    artifacts: [
      {
        filename: 'cabinet-wall-a.jpg',
        media_type: 'image/jpeg',
        sha256: sha256Bytes(Buffer.from('DEMO-EVIDENCE:CABINET-WALL-A', 'utf8')),
      },
      {
        filename: 'island-anchor.jpg',
        media_type: 'image/jpeg',
        sha256: sha256Bytes(Buffer.from('DEMO-EVIDENCE:ISLAND-ANCHOR', 'utf8')),
      },
      {
        filename: 'countertop-template.pdf',
        media_type: 'application/pdf',
        sha256: sha256Bytes(Buffer.from('DEMO-EVIDENCE:COUNTERTOP-TEMPLATE', 'utf8')),
      },
    ],
    claim_boundary: 'Integrity and submitter signature only; not proof of workmanship or physical completion.',
  };
}

function makeCompletionEvidence({ manifest, contractorKey, bindings }) {
  const receipt = signReceipt(contractorKey.privateKey, {
    receipt_id: 'ae_completion_ms03',
    subject: manifest.submitted_by,
    issuer: manifest.submitted_by,
    created_at: '2026-07-17T15:31:00.000Z',
    signer: {
      party_id: manifest.submitted_by,
      role: 'contractor',
      key_id: contractorKey.keyId,
    },
    claim: {
      action_type: 'escrow.milestone.evidence.submit',
      outcome: 'submitted',
      ...bindings,
      evidence_manifest: manifest,
      evidence_manifest_digest: sha256Canonical(manifest),
    },
  });
  return {
    manifest,
    receipt,
    sha256: sha256Canonical(manifest),
  };
}

function releaseAction({
  terms,
  document,
  materialTermsDigest,
  completionDigest,
  profileDigest,
}) {
  return {
    action_type: ACTION_ESCROW_ACTION,
    action_escrow_profile_digest: profileDigest,
    agreement_id: terms.agreement_id,
    agreement_digest: computeActionEscrowAgreementDigest(terms.agreement_id),
    milestone_id: terms.milestone.id,
    amount: terms.milestone.release_amount,
    currency: terms.milestone.currency,
    destination_id: terms.payee.destination_id,
    payee_id: terms.payee.contractor_id,
    custodian_provider: CUSTODIAN_PROVIDER_ID,
    custodian_environment: 'sandbox',
    custodian_transaction_id: 'SIM-TXN-AGR-KITCHEN-2048',
    custodian_milestone_id: 'SIM-MS-03-CABINETRY',
    document_sha256: document.sha256,
    material_terms_sha256: materialTermsDigest,
    completion_evidence_sha256: completionDigest,
    amendment_version: terms.amendment_version,
  };
}

function makeAgreementAcceptance({
  party,
  key,
  bindings,
  documentDigest,
}) {
  return signReceipt(key.privateKey, {
    receipt_id: `ae_document_acceptance_${party.role}`,
    subject: party.party_id,
    issuer: party.party_id,
    created_at: '2026-07-17T15:10:00.000Z',
    signer: {
      party_id: party.party_id,
      role: party.role,
      key_id: key.keyId,
    },
    claim: {
      action_type: 'escrow.agreement.accept',
      outcome: 'accepted',
      ...bindings,
      document_digest: documentDigest,
      authorizes_payment: false,
    },
  });
}

function actionEscrowResolutionBindingInput(bindings, action) {
  return {
    agreement_digest: bindings.agreement_digest,
    document_action_binding_digest: bindings.document_action_binding_digest,
    milestone_id: bindings.milestone_id,
    release_action_digest: bindings.release_action_digest,
    profile_digest: bindings.profile_digest,
    evidence_digest: bindings.evidence_digest,
    release_action_template: action,
  };
}

function resolutionOutcome(outcome, detail) {
  if (outcome === 'approved') return { outcome, selected_option: 0 };
  if (outcome === 'declined') return { outcome };
  if (outcome === 'rejected') {
    return {
      outcome,
      objection_hash: computeResolutionResponseHash(detail),
    };
  }
  if (outcome === 'amended') {
    return {
      outcome,
      response_hash: computeResolutionResponseHash(detail),
      successor_envelope_hash: sha256Canonical({
        '@version': 'EP-ACTION-ESCROW-SUCCESSOR-REFERENCE-v1',
        ...detail,
      }),
    };
  }
  throw new Error(`unsupported resolution outcome: ${outcome}`);
}

function makeResolution({
  party,
  key,
  outcome,
  bindings,
  action,
  detail,
}) {
  const bindingInput = actionEscrowResolutionBindingInput(bindings, action);
  const bindingMoment = createActionEscrowReleaseBindingMoment(bindingInput);
  invariant(bindingMoment !== null, 'resolution binding moment must be constructible');
  const context = {
    ep_version: '1.0',
    context_type: RESOLUTION_CONTEXT_TYPE,
    envelope_hash: computeActionEscrowReleaseBindingMomentDigest(bindingInput),
    action_hash: bindings.release_action_digest,
    principal: party.party_id,
    principal_key_id: key.keyId,
    initiator: 'contractor:oak-line-builders',
    nonce: computeActionEscrowResolutionNonce(bindingInput, party.party_id),
    issued_at: '2026-07-17T15:40:00.000Z',
    expires_at: '2026-07-17T16:40:00.000Z',
    resolution: resolutionOutcome(outcome, detail),
  };
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: computeResolutionChallenge(context),
    origin: RESOLUTION_ORIGIN,
  }), 'utf8');
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RESOLUTION_RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signedBytes = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  return {
    profile: RESOLUTION_VERSION,
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: crypto
          .sign('sha256', signedBytes, key.privateKey)
          .toString('base64url'),
      },
    },
  };
}

function verifyResolutionArtifact(artifact, {
  party,
  key,
  bindings,
  action,
}) {
  const bindingInput = actionEscrowResolutionBindingInput(bindings, action);
  return verifyResolutionReceipt(artifact, {
    bindingMoment: createActionEscrowReleaseBindingMoment(bindingInput),
    expectedActionHash: bindings.release_action_digest,
    expectedSelectedOption: 0,
    expectedNonce: computeActionEscrowResolutionNonce(bindingInput, party.party_id),
    expectedInitiator: 'contractor:oak-line-builders',
    evaluationTime: CREATED_AT,
    rpId: RESOLUTION_RP_ID,
    allowedOrigins: [RESOLUTION_ORIGIN],
    principalKeys: {
      [key.keyId]: {
        principal: party.party_id,
        public_key: key.publicKey,
      },
    },
  });
}

function durableCasStore() {
  const values = new Map();
  return {
    durable: true,
    atomicExpectedRevisionCas: true,
    linearizableReads: true,
    monotonicRevisions: true,
    nonExpiring: true,
    async read(key) {
      const current = values.get(key);
      return current ? { ...current } : null;
    },
    async compareAndSwap(key, expectedRevision, value) {
      const current = values.get(key);
      const currentRevision = current?.revision ?? null;
      if (currentRevision !== expectedRevision) {
        return { applied: false, revision: currentRevision };
      }
      const revision = expectedRevision === null ? 0 : expectedRevision + 1;
      values.set(key, { revision, value });
      return { applied: true, revision };
    },
  };
}

function expectedBindings(recordOrExpected) {
  return {
    agreement_digest: recordOrExpected.agreement_digest,
    document_action_binding_digest: recordOrExpected.document_action_binding_digest,
    milestone_id: recordOrExpected.milestone_id,
    release_action_digest: recordOrExpected.release_action_digest,
    parties_digest: recordOrExpected.parties_digest,
    profile_digest: recordOrExpected.profile_digest,
  };
}

function bindingVerifierOptions({ mappingKey, document, releaseActionTemplate, parties }) {
  return {
    issuerKeys: {
      [mappingKey.keyId]: {
        issuer_id: MAPPING_ISSUER_ID,
        public_key: mappingKey.publicKey,
      },
    },
    now: CREATED_AT,
    allowedMediaTypes: ['application/pdf'],
    allowedPartyRoles: ['contractor', 'homeowner'],
    allowedActionTypes: [ACTION_ESCROW_ACTION],
    requiredMaterialTermIds: REQUIRED_TERM_IDS,
    expectedBindingId: BINDING_ID,
    expectedAgreementId: AGREEMENT_ID,
    documentBytes: document.bytes,
    documentMediaType: document.media_type,
    releaseActionTemplate,
    expectedRequiredParties: parties,
    expectedSupersedesDigest: null,
  };
}

function makeFundingStatement({
  key,
  bindings,
  terms,
}) {
  return signReceipt(key.privateKey, {
    receipt_id: 'ae_custody_funding_ms03',
    subject: CUSTODIAN_PROVIDER_ID,
    issuer: CUSTODIAN_PROVIDER_ID,
    created_at: '2026-07-17T15:20:00.000Z',
    signer: {
      provider_id: CUSTODIAN_PROVIDER_ID,
      key_id: key.keyId,
      mode: 'deterministic_demo_ed25519',
    },
    claim: {
      provider_id: CUSTODIAN_PROVIDER_ID,
      statement_type: 'funding',
      status: 'funded',
      agreement_id: AGREEMENT_ID,
      ...bindings,
      amount: terms.milestone.release_amount,
      currency: terms.milestone.currency,
      destination_id: terms.payee.destination_id,
      custodian_transaction_id: 'SIM-TXN-AGR-KITCHEN-2048',
      custodian_milestone_id: 'SIM-MS-03-CABINETRY',
      custody_mode: 'SIMULATED_LOCAL_PROVIDER',
      emilia_holds_funds: false,
    },
  });
}

function createSimulatedCustodian({ terms }) {
  const state = {
    status: 'unfunded',
    releaseCalls: 0,
    reconciliationCalls: 0,
    releaseStatement: null,
  };
  const transaction = () => ({
    transaction_id: 'SIM-TXN-AGR-KITCHEN-2048',
    state: state.status,
    currency: terms.milestone.currency,
    milestones: [{
      provider_item_id: 'SIM-MS-03-CABINETRY',
      schedules: [{
        amount: terms.milestone.release_amount,
        beneficiary_customer: terms.payee.destination_id,
      }],
    }],
    simulated: true,
  });
  const adapter = defineExternalCustodianAdapter({
    provider: CUSTODIAN_PROVIDER_ID,
    environment: 'sandbox',
    customerDiligence: {
      provider_model: 'licensed_external_custodian',
      simulation: true,
      license_status: 'not_verified_demo_reference_only',
      emilia_holds_funds: false,
    },
    capabilities: {
      create_transaction: true,
      reconcile_transaction: true,
      milestone_release: 'provider_api',
      direct_disbursement: 'provider_action_required',
    },
    async createTransaction() {
      if (state.status !== 'unfunded') {
        return {
          kind: 'existing',
          provider: CUSTODIAN_PROVIDER_ID,
          environment: 'sandbox',
          operation: 'create_transaction',
          transaction: transaction(),
        };
      }
      state.status = 'funded';
      return {
        kind: 'created',
        provider: CUSTODIAN_PROVIDER_ID,
        environment: 'sandbox',
        operation: 'create_transaction',
        transaction: transaction(),
      };
    },
    async reconcileTransaction(request) {
      state.reconciliationCalls += 1;
      if (request.transactionId !== 'SIM-TXN-AGR-KITCHEN-2048') {
        return {
          kind: 'not_found',
          provider: CUSTODIAN_PROVIDER_ID,
          environment: 'sandbox',
          operation: 'reconcile_transaction',
        };
      }
      return {
        kind: 'reconciled',
        provider: CUSTODIAN_PROVIDER_ID,
        environment: 'sandbox',
        operation: 'reconcile_transaction',
        transaction_id: request.transactionId,
        transaction: transaction(),
      };
    },
    async releaseMilestone(request) {
      if (request.transactionId !== 'SIM-TXN-AGR-KITCHEN-2048'
        || request.milestoneId !== 'SIM-MS-03-CABINETRY'
        || typeof request.effectReference !== 'string') {
        return {
          kind: 'refused',
          provider: CUSTODIAN_PROVIDER_ID,
          environment: 'sandbox',
          operation: 'release_milestone',
          reason_code: 'ACTION_DIGEST_MISMATCH',
        };
      }
      if (state.status !== 'funded' || state.releaseCalls > 0) {
        return {
          kind: 'refused',
          provider: CUSTODIAN_PROVIDER_ID,
          environment: 'sandbox',
          operation: 'release_milestone',
          reason_code: 'NOT_RELEASABLE',
        };
      }
      state.status = 'released';
      state.releaseCalls += 1;
      return {
        kind: 'released',
        provider: CUSTODIAN_PROVIDER_ID,
        environment: 'sandbox',
        operation: 'release_milestone',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
        transaction: transaction(),
      };
    },
    async requestMilestoneDisbursement(request) {
      if (request.transactionId === 'SIM-TXN-AGR-KITCHEN-2048'
        && request.milestoneId === 'SIM-MS-03-CABINETRY'
        && state.status === 'released') {
        return {
          kind: 'released',
          provider: CUSTODIAN_PROVIDER_ID,
          environment: 'sandbox',
          operation: 'request_milestone_disbursement',
          effect_reference: request.effectReference,
          transaction_id: request.transactionId,
          milestone_id: request.milestoneId,
          transaction: transaction(),
        };
      }
      return {
        kind: 'provider_action_required',
        provider: CUSTODIAN_PROVIDER_ID,
        environment: 'sandbox',
        operation: 'request_milestone_disbursement',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
        reason_code: 'SIMULATED_PROVIDER_ACTION_REQUIRED',
        provider_phase: 'not_accepted',
      };
    },
  });
  return {
    adapter,
    state,
    provider: {
      provider_id: CUSTODIAN_PROVIDER_ID,
      display_name: 'Harborline Custody Sandbox',
      provider_class: 'licensed_external_custodian',
      provider_mode: 'SIMULATED_LOCAL_PROVIDER',
      license_reference: 'SIMULATED-NOT-A-LICENSE',
      emilia_holds_funds: false,
      notice: 'Models a customer-selected licensed external custodian. No custodian is connected, no license is asserted, and no real funds move.',
    },
  };
}

function attackResult({
  id,
  title,
  layer,
  mutation,
  result,
  expectedReason,
  detail,
}) {
  const reason = result?.reason || result?.code || 'unknown_refusal';
  return {
    id,
    title,
    layer,
    mutation,
    refused: result?.valid === false || result?.ok === false,
    reason,
    expected_reason: expectedReason,
    detail,
  };
}

function buildView({
  terms,
  mapping,
  document,
  binding,
  documentVerification,
  completion,
  action,
  acceptances,
  approvals,
  approvalVerification,
  outcomes,
  custodian,
  fundingStatement,
  fundingVerification,
  releaseVerification,
  releaseResult,
  replayResult,
  attacks,
  evidencePackage,
  packageVerification,
}) {
  return {
    version: ACTION_ESCROW_VERSION,
    scenario_mode: 'DETERMINISTIC_LOCAL_REFERENCE',
    project: {
      name: terms.project.name,
      milestone: `${terms.milestone.id} · ${terms.milestone.name}`,
      release_amount: dollars(terms.milestone.release_amount_minor),
      release_amount_minor: terms.milestone.release_amount_minor,
      currency: terms.milestone.currency,
      contractor: terms.project.contractor,
      homeowner: terms.project.homeowner,
      destination_id: terms.payee.destination_id,
      amendment_version: terms.amendment_version,
    },
    integration_rows: [
      {
        id: 'document',
        number: '01',
        label: 'Final document + material-term mapping',
        status: documentVerification.dab.valid ? 'VERIFIED + MATCHED' : 'REFUSED',
        pass: documentVerification.dab.valid,
        detail: `${binding.material_terms.length} typed material terms and the final PDF digest verify under the shipped DAB profile.`,
        boundary: 'A mapping proves what the document and action denote. It proves neither acceptance nor payment approval.',
        source: 'Pinned mapping issuer + shipped DAB verifier',
      },
      {
        id: 'execution',
        number: '02',
        label: 'E-sign document execution',
        status: documentVerification.checks.simulated_provider_refetch_completed
          ? 'PROVIDER VERIFIED'
          : 'REFUSED',
        pass: documentVerification.checks.simulated_provider_refetch_completed,
        detail: 'The provider record, two independent participant sets, version event, and exact final PDF were authoritatively refetched.',
        boundary: 'Provider execution evidence is not party acceptance and authorizes no release.',
        source: 'Simulated Acrobat adapter',
      },
      {
        id: 'agreement',
        number: '03',
        label: 'Mutual agreement acceptance',
        status: documentVerification.checks.both_agreement_acceptances_verified
          ? '2 OF 2 ACCEPTED'
          : 'REFUSED',
        pass: documentVerification.checks.both_agreement_acceptances_verified,
        detail: 'Each party separately accepted the exact final PDF bytes and current document-action binding.',
        boundary: 'Agreement acceptance authorizes no release.',
        source: 'Two pinned demo party keys',
      },
      {
        id: 'approvals',
        number: '04',
        label: 'Homeowner + contractor exact release approvals',
        status: approvalVerification.homeowner.valid && approvalVerification.contractor.valid
          ? '2 OF 2 APPROVED'
          : 'REFUSED',
        pass: approvalVerification.homeowner.valid && approvalVerification.contractor.valid,
        detail: 'Each party separately signed the exact action digest, evidence digest, amount, destination, and amendment version.',
        boundary: 'E-sign acceptance alone was refused as release authority.',
        source: 'Two pinned P-256 WebAuthn demo keys + Action Escrow kernel',
      },
      {
        id: 'custodian',
        number: '05',
        label: 'External custodian funding + release state',
        status: releaseVerification.valid ? 'FUNDED → RELEASED' : 'REFUSED',
        pass: fundingVerification.valid && releaseVerification.valid,
        detail: `${dollars(terms.milestone.release_amount_minor)} was reported funded, then released once to the bound destination.`,
        boundary: 'SIMULATED CUSTODY. No real money moved. EMILIA never held funds.',
        source: custodian.provider.display_name,
      },
    ],
    document: {
      filename: document.filename,
      size_bytes: document.size_bytes,
      sha256: document.sha256,
      material_terms_sha256: sha256Canonical(binding.material_terms),
      mapping_sha256: binding.binding_digest,
      signing_provider: {
        name: 'Adobe Acrobat Sign',
        mode: 'simulated_local_adapter',
        envelope_id: 'ADOBE-SIM-AGR-KITCHEN-2048-V2',
        reported_state: 'SIGNED',
        notice: 'Simulated adapter only. No Adobe partnership, endorsement, credential, or live API call is implied.',
      },
      material_terms: terms,
      binding_material_terms: binding.material_terms,
      mapping,
      verification: documentVerification,
      acceptance_receipt_ids: {
        homeowner: acceptances.homeowner.payload.receipt_id,
        contractor: acceptances.contractor.payload.receipt_id,
      },
    },
    completion: {
      evidence_id: completion.manifest.evidence_id,
      submitted_at: completion.manifest.submitted_at,
      artifacts: completion.manifest.artifacts,
      sha256: completion.sha256,
      verification: {
        valid: true,
        shipped_verifier: '@emilia-protocol/verify.verifyReceipt',
        claim_boundary: completion.manifest.claim_boundary,
      },
    },
    release: {
      action,
      action_sha256: computeReleaseActionDigest(action),
      approvals: {
        homeowner: {
          receipt_id: approvals.homeowner.signoff.context.nonce,
          outcome: approvals.homeowner.signoff.context.resolution.outcome,
          verification: approvalVerification.homeowner,
        },
        contractor: {
          receipt_id: approvals.contractor.signoff.context.nonce,
          outcome: approvals.contractor.signoff.context.resolution.outcome,
          verification: approvalVerification.contractor,
        },
      },
      gate: {
        allowed: releaseResult.ok,
        reason: releaseResult.code,
        decision_hash: sha256Canonical(approvals.homeowner),
        execution_hash: releaseResult.record.release.provider_verification.statement_digest,
        evidence_chain_verified: packageVerification.valid,
        replay_refused: replayResult.code === 'release_already_applied',
        release_calls: custodian.state.releaseCalls,
      },
    },
    custodian: {
      provider: custodian.provider,
      funding: fundingStatement.payload.claim,
      release: custodian.state.releaseStatement.payload,
      funding_verification: fundingVerification,
      release_verification: releaseVerification,
    },
    outcomes,
    attacks,
    bundle: {
      version: evidencePackage.version,
      digest: evidencePackage.package_digest,
      verification_passed: packageVerification.valid,
      portable_for: ['homeowner', 'contractor'],
      checks: packageVerification.checks,
    },
    boundaries: DEMO_BOUNDARIES,
  };
}

export async function runActionEscrowScenario() {
  const keys = {
    mapping: deterministicDemoKey('mapping-issuer'),
    homeowner: deterministicDemoKey('homeowner'),
    contractor: deterministicDemoKey('contractor'),
    homeownerResolution: deterministicP256Key('homeowner'),
    contractorResolution: deterministicP256Key('contractor'),
    custodian: deterministicDemoKey('external-custodian'),
    operator: deterministicDemoKey('state-operator'),
  };
  const parties = [
    { party_id: 'contractor:oak-line-builders', role: 'contractor' },
    { party_id: 'party:homeowner:maya-chen-demo', role: 'homeowner' },
  ];
  const partyByRole = Object.fromEntries(parties.map((party) => [party.role, party]));
  const profile = {
    '@version': ACTION_ESCROW_PROFILE_VERSION,
    profile_id: 'kitchen-milestone-mutual-release',
    provider_id: CUSTODIAN_PROVIDER_ID,
    required_acceptance_party_ids: parties.map((party) => party.party_id),
    required_release_approver_party_ids: parties.map((party) => party.party_id),
    prohibit_self_approval: false,
  };

  const terms = finalMaterialTerms();
  const mapping = materialTermMapping(terms);
  const document = buildFinalDocument(terms, mapping);
  const esignEvidence = await fetchSimulatedAcrobatEvidence(document);
  const completionManifest = completionEvidenceManifest(terms);
  const action = releaseAction({
    terms,
    document,
    materialTermsDigest: sha256Canonical(
      dabMaterialTerms(terms).sort((left, right) => (
        left.term_id < right.term_id ? -1 : left.term_id > right.term_id ? 1 : 0
      )),
    ),
    completionDigest: sha256Canonical(completionManifest),
    profileDigest: sha256Canonical(profile),
  });
  const binding = signDocumentActionBinding({
    binding_id: BINDING_ID,
    agreement_id: AGREEMENT_ID,
    document: {
      bytes: esignEvidence.document_bytes,
      media_type: 'application/pdf',
    },
    material_terms: dabMaterialTerms(terms),
    release_action_template: action,
    parties,
    required_parties: parties,
    validity: {
      not_before: '2026-07-01T00:00:00.000Z',
      not_after: '2027-07-01T00:00:00.000Z',
    },
  }, {
    issuer_id: MAPPING_ISSUER_ID,
    key_id: keys.mapping.keyId,
    privateKey: keys.mapping.privateKey,
  });
  const dabOptions = bindingVerifierOptions({
    mappingKey: keys.mapping,
    document,
    releaseActionTemplate: action,
    parties,
  });
  const dabVerification = verifyDocumentActionBinding(binding, dabOptions);
  invariant(dabVerification.valid, `DAB must verify (${dabVerification.reason})`);

  const kernelBindings = {
    agreement_digest: computeActionEscrowAgreementDigest(AGREEMENT_ID),
    document_action_binding_digest: dabVerification.binding_digest,
    milestone_id: MILESTONE_ID,
    release_action_digest: dabVerification.action_digest,
    parties_digest: sha256Canonical(parties),
    profile_digest: sha256Canonical(profile),
  };
  const boundCompletion = makeCompletionEvidence({
    manifest: completionManifest,
    contractorKey: keys.contractor,
    bindings: kernelBindings,
  });

  const acceptances = {
    homeowner: makeAgreementAcceptance({
      party: partyByRole.homeowner,
      key: keys.homeowner,
      bindings: kernelBindings,
      documentDigest: document.sha256,
    }),
    contractor: makeAgreementAcceptance({
      party: partyByRole.contractor,
      key: keys.contractor,
      bindings: kernelBindings,
      documentDigest: document.sha256,
    }),
  };
  const keyByPartyId = new Map([
    [partyByRole.homeowner.party_id, keys.homeowner],
    [partyByRole.contractor.party_id, keys.contractor],
  ]);
  const resolutionKeyByPartyId = new Map([
    [partyByRole.homeowner.party_id, keys.homeownerResolution],
    [partyByRole.contractor.party_id, keys.contractorResolution],
  ]);

  function verifyAcceptanceArtifact(artifact, expected) {
    const party = parties.find((entry) => entry.party_id === expected.party_id);
    const key = keyByPartyId.get(expected.party_id);
    const cryptoResult = key ? verifyReceipt(artifact, key.publicKey) : { valid: false };
    const claim = artifact?.payload?.claim;
    const signer = artifact?.payload?.signer;
    const valid = Boolean(
      party
      && key
      && cryptoResult.valid
      && signer?.party_id === party.party_id
      && signer?.role === party.role
      && signer?.key_id === key.keyId
      && claim?.action_type === 'escrow.agreement.accept'
      && claim?.outcome === 'accepted'
      && claim?.authorizes_payment === false
      && Object.entries(expectedBindings(expected))
        .every(([field, value]) => claim?.[field] === value),
    );
    return {
      valid,
      acceptance_digest: receiptDigest(artifact),
      party_id: signer?.party_id ?? null,
      principal_key_id: signer?.key_id ?? null,
      ...expectedBindings(expected),
    };
  }

  function verifyCompletionArtifact(artifact, expected) {
    const cryptoResult = verifyReceipt(artifact, keys.contractor.publicKey);
    const claim = artifact?.payload?.claim;
    const signer = artifact?.payload?.signer;
    const valid = Boolean(
      cryptoResult.valid
      && signer?.party_id === partyByRole.contractor.party_id
      && signer?.key_id === keys.contractor.keyId
      && claim?.action_type === 'escrow.milestone.evidence.submit'
      && claim?.outcome === 'submitted'
      && claim?.evidence_manifest_digest === sha256Canonical(claim?.evidence_manifest)
      && Object.entries(expectedBindings(expected))
        .every(([field, value]) => claim?.[field] === value),
    );
    return {
      valid,
      evidence_digest: claim?.evidence_manifest_digest ?? null,
      submitter_party_id: signer?.party_id ?? null,
      observed_at: claim?.evidence_manifest?.submitted_at ?? null,
      ...expectedBindings(expected),
    };
  }

  function verifyFundingArtifact(artifact, expected) {
    const cryptoResult = verifyReceipt(artifact, keys.custodian.publicKey);
    const claim = artifact?.payload?.claim;
    const bindingsMatch = Object.entries(expectedBindings(expected))
      .every(([field, value]) => claim?.[field] === value);
    const valid = Boolean(
      cryptoResult.valid
      && bindingsMatch
      && claim?.provider_id === expected.provider_id
      && claim?.statement_type === 'funding'
      && claim?.status === 'funded'
      && claim?.agreement_id === AGREEMENT_ID
      && claim?.amount === terms.milestone.release_amount
      && claim?.currency === terms.milestone.currency
      && claim?.destination_id === terms.payee.destination_id
      && claim?.custodian_transaction_id === action.custodian_transaction_id
      && claim?.custodian_milestone_id === action.custodian_milestone_id
      && claim?.custody_mode === 'SIMULATED_LOCAL_PROVIDER'
      && claim?.emilia_holds_funds === false,
    );
    return {
      valid,
      authenticated: valid,
      statement_type: claim?.statement_type ?? null,
      status: claim?.status ?? null,
      statement_digest: receiptDigest(artifact),
      provider_id: claim?.provider_id ?? null,
      provider_transaction_id: claim?.custodian_transaction_id ?? null,
      provider_milestone_id: claim?.custodian_milestone_id ?? null,
      amount: claim?.amount ?? null,
      currency: claim?.currency ?? null,
      destination_id: claim?.destination_id ?? null,
      ...expectedBindings(expected),
    };
  }

  const custodian = createSimulatedCustodian({ terms });
  const custodianBridge = createActionEscrowCustodianBridge({
    adapter: custodian.adapter,
    observationSigner: {
      key_id: keys.custodian.keyId,
      privateKey: keys.custodian.privateKey,
    },
    now: () => '2026-07-17T15:46:00.000Z',
  });
  const verifyCustodianObservation = createActionEscrowCustodianStatementVerifier({
    operatorKeys: {
      [keys.custodian.keyId]: {
        public_key: keys.custodian.publicKey,
      },
    },
    providerId: CUSTODIAN_PROVIDER_ID,
    environment: 'sandbox',
  });
  const kernelDocumentBindingVerifier = createActionEscrowDocumentBindingVerifier({
    issuerKeys: {
      [keys.mapping.keyId]: {
        issuer_id: MAPPING_ISSUER_ID,
        public_key: keys.mapping.publicKey,
      },
    },
    resolveDocumentBytes: async (expected) => (
      expected.agreement_id === AGREEMENT_ID
      && expected.binding_id === BINDING_ID
      && expected.binding_digest === dabVerification.binding_digest
      && expected.document_digest === document.sha256
      && expected.document_media_type === document.media_type
      && expected.document_byte_length === document.size_bytes
        ? Uint8Array.from(document.bytes)
        : null
    ),
    allowedMediaTypes: ['application/pdf'],
    allowedPartyRoles: ['contractor', 'homeowner'],
    now: () => CREATED_AT,
  });

  const kernel = createActionEscrowKernel({
    store: durableCasStore(),
    provider: custodianBridge,
    profilesById: { [profile.profile_id]: profile },
    now: () => CREATED_AT,
    verifyDocumentActionBinding: kernelDocumentBindingVerifier,
    verifyAgreementAcceptance: async (artifact, expected) => (
      verifyAcceptanceArtifact(artifact, expected)
    ),
    verifyMilestoneEvidence: async (artifact, expected) => (
      verifyCompletionArtifact(artifact, expected)
    ),
    verifyResolutionReceipt: async (artifact, expected) => {
      const party = parties.find((entry) => entry.party_id === expected.party_id);
      const key = resolutionKeyByPartyId.get(expected.party_id);
      const verification = party && key
        ? verifyResolutionArtifact(artifact, {
          party,
          key,
          bindings: { ...expectedBindings(expected), evidence_digest: expected.evidence_digest },
          action,
        })
        : { valid: false, outcome: null, authorizes_action: false };
      return {
        valid: verification.valid,
        authorizes_action: verification.authorizes_action,
        outcome: verification.outcome,
        party_id: expected.party_id,
        party_role: party?.role ?? null,
        principal_key_id: artifact?.signoff?.context?.principal_key_id ?? null,
        nonce: artifact?.signoff?.context?.nonce ?? null,
        issued_at: artifact?.signoff?.context?.issued_at ?? null,
        expires_at: artifact?.signoff?.context?.expires_at ?? null,
        evidence_digest: expected.evidence_digest,
        binding_moment_digest: expected.binding_moment_digest,
        expected_selected_option: expected.expected_selected_option,
        expected_initiator: expected.expected_initiator,
        expected_nonce: expected.expected_nonce,
        ...expectedBindings(expected),
      };
    },
    verifyProviderStatement: async (artifact, expected) => (
      artifact?.payload?.statement_type === 'release'
        ? verifyCustodianObservation(artifact, { ...expected, statement_type: 'release' })
        : verifyFundingArtifact(artifact, expected)
    ),
    verifyStateCommand: async () => ({
      valid: false,
      authorizes_command: false,
      reason: 'no_state_command_in_reference_run',
    }),
  });

  function common(idempotencyKey, extra = {}) {
    return {
      agreement_digest: kernelBindings.agreement_digest,
      document_action_binding_digest: kernelBindings.document_action_binding_digest,
      milestone_id: kernelBindings.milestone_id,
      release_action_digest: kernelBindings.release_action_digest,
      parties,
      profile,
      idempotency_key: idempotencyKey,
      ...extra,
    };
  }

  let lifecycle = await kernel.create(common('create', {
    document_action_binding: binding,
  }));
  invariant(lifecycle.ok && lifecycle.state === 'draft', `kernel create: ${lifecycle.code}`);
  lifecycle = await kernel.beginAcceptance(common('begin-acceptance'));
  invariant(lifecycle.ok && lifecycle.state === 'awaiting_acceptance', `begin acceptance: ${lifecycle.code}`);
  lifecycle = await kernel.acceptAgreement(common('accept-homeowner', {
    party_id: partyByRole.homeowner.party_id,
    agreement_acceptance: acceptances.homeowner,
  }));
  invariant(lifecycle.ok && lifecycle.state === 'awaiting_acceptance', `homeowner acceptance: ${lifecycle.code}`);
  lifecycle = await kernel.acceptAgreement(common('accept-contractor', {
    party_id: partyByRole.contractor.party_id,
    agreement_acceptance: acceptances.contractor,
  }));
  invariant(lifecycle.ok && lifecycle.state === 'effective', `contractor acceptance: ${lifecycle.code}`);

  lifecycle = await kernel.requestFunding(common('request-funding'));
  invariant(lifecycle.ok && lifecycle.state === 'awaiting_funding', `request funding: ${lifecycle.code}`);
  const custodianCreated = await custodian.adapter.createTransaction({
    agreement_id: AGREEMENT_ID,
    release_action_digest: kernelBindings.release_action_digest,
  });
  invariant(custodianCreated.kind === 'created', 'simulated custodian must report a funded transaction');
  const fundingStatement = makeFundingStatement({
    key: keys.custodian,
    bindings: kernelBindings,
    terms,
  });
  const fundingVerification = verifyFundingArtifact(fundingStatement, {
    ...kernelBindings,
    provider_id: CUSTODIAN_PROVIDER_ID,
  });
  invariant(fundingVerification.valid, 'funding statement signature must verify');
  lifecycle = await kernel.recordFunding(common('record-funding', {
    provider_statement: fundingStatement,
  }));
  invariant(lifecycle.ok && lifecycle.state === 'funded', `record funding: ${lifecycle.code}`);

  const tamperedEvidence = clone(boundCompletion.receipt);
  tamperedEvidence.payload.claim.evidence_manifest.artifacts[0].sha256 = `sha256:${'00'.repeat(32)}`;
  const milestoneAttackResult = await kernel.submitMilestone(common('attack-evidence', {
    milestone_evidence: tamperedEvidence,
  }));
  invariant(
    milestoneAttackResult.code === 'milestone_evidence_invalid',
    `tampered milestone evidence refusal: ${milestoneAttackResult.code}`,
  );
  lifecycle = await kernel.submitMilestone(common('submit-evidence', {
    milestone_evidence: boundCompletion.receipt,
  }));
  invariant(lifecycle.ok && lifecycle.state === 'milestone_submitted', `submit evidence: ${lifecycle.code}`);

  const resolutionBindings = {
    ...kernelBindings,
    evidence_digest: boundCompletion.sha256,
  };
  const homeownerDecisions = {
    approve: makeResolution({
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      outcome: 'approved',
      bindings: resolutionBindings,
      action,
      detail: { reason_code: 'milestone_accepted' },
    }),
    decline: makeResolution({
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      outcome: 'declined',
      bindings: resolutionBindings,
      action,
      detail: { reason_code: 'not_ready_to_release' },
    }),
    reject: makeResolution({
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      outcome: 'rejected',
      bindings: resolutionBindings,
      action,
      detail: { reason_code: 'evidence_not_accepted' },
    }),
    amend: makeResolution({
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      outcome: 'amended',
      bindings: resolutionBindings,
      action,
      detail: {
        proposed_amendment_version: 3,
        proposed_release_amount: '17200.00',
      },
    }),
  };
  const contractorApproval = makeResolution({
    party: partyByRole.contractor,
    key: keys.contractorResolution,
    outcome: 'approved',
    bindings: resolutionBindings,
    action,
    detail: { reason_code: 'exact_release_confirmed' },
  });

  const documentAsPaymentResult = await kernel.approveRelease(common('document-is-not-payment', {
    party_id: partyByRole.homeowner.party_id,
    resolution: acceptances.homeowner,
  }));
  invariant(
    documentAsPaymentResult.code === 'resolution_profile_invalid',
    'document acceptance must not become payment authorization',
  );

  const outcomeResults = {};
  for (const outcome of ['decline', 'reject', 'amend']) {
    outcomeResults[outcome] = await kernel.approveRelease(common(`outcome-${outcome}`, {
      party_id: partyByRole.homeowner.party_id,
      resolution: homeownerDecisions[outcome],
    }));
    invariant(
      outcomeResults[outcome].code === 'resolution_not_approved',
      `${outcome} must not authorize the original release`,
    );
  }

  const wrongSignerApproval = makeResolution({
    party: partyByRole.homeowner,
    key: keys.contractorResolution,
    outcome: 'approved',
    bindings: resolutionBindings,
    action,
    detail: { mutation: 'contractor key claims homeowner approval seat' },
  });
  const signerAttackResult = await kernel.approveRelease(common('attack-signer', {
    party_id: partyByRole.homeowner.party_id,
    resolution: wrongSignerApproval,
  }));
  invariant(
    signerAttackResult.code === 'resolution_verification_refused',
    `wrong signer refusal: ${signerAttackResult.code}`,
  );

  const homeownerApprovalResult = await kernel.approveRelease(common('approve-homeowner', {
    party_id: partyByRole.homeowner.party_id,
    resolution: homeownerDecisions.approve,
  }));
  invariant(homeownerApprovalResult.ok, `homeowner approval: ${homeownerApprovalResult.code}`);
  const contractorApprovalResult = await kernel.approveRelease(common('approve-contractor', {
    party_id: partyByRole.contractor.party_id,
    resolution: contractorApproval,
  }));
  invariant(contractorApprovalResult.ok, `contractor approval: ${contractorApprovalResult.code}`);

  const releaseResult = await kernel.release(common('release-operation'));
  invariant(
    releaseResult.ok && releaseResult.code === 'release_committed',
    `release: ${releaseResult.code} (calls=${custodian.state.releaseCalls}, reconciliations=${custodian.state.reconciliationCalls})`,
  );
  custodian.state.releaseStatement = releaseResult.record.release.provider_statement;
  invariant(custodian.state.releaseCalls === 1, 'custodian must receive exactly one release call');
  const replayResult = await kernel.release(common('release-operation-replay'));
  invariant(
    !replayResult.ok && replayResult.code === 'release_already_applied',
    `replay refusal: ${replayResult.code}`,
  );
  invariant(custodian.state.releaseCalls === 1, 'replay must not reach the custodian');

  const releaseVerification = await verifyCustodianObservation(
    custodian.state.releaseStatement,
    {
      ...kernelBindings,
      provider_id: CUSTODIAN_PROVIDER_ID,
      statement_type: 'release',
      provider_idempotency_key: releaseResult.record.release.provider_idempotency_key,
      provider_request_digest: releaseResult.record.release.provider_request.request_digest,
      provider_transaction_id: action.custodian_transaction_id,
      provider_milestone_id: action.custodian_milestone_id,
      amount: action.amount,
      currency: action.currency,
      destination_id: action.destination_id,
    },
  );
  invariant(releaseVerification.valid, 'release statement signature must verify');

  const mutatedPdf = Buffer.from(document.bytes);
  mutatedPdf[mutatedPdf.length - 8] ^= 1;
  const pdfAttack = verifyDocumentActionBinding(binding, {
    ...dabOptions,
    documentBytes: mutatedPdf,
  });
  const mutatedBinding = clone(binding);
  mutatedBinding.material_terms
    .find((term) => term.term_id === 'release.amount').value = '28400.00';
  const materialTermsAttack = verifyDocumentActionBinding(mutatedBinding, dabOptions);
  const destinationAttack = verifyDocumentActionBinding(binding, {
    ...dabOptions,
    releaseActionTemplate: {
      ...action,
      destination_id: 'custody-destination:attacker:ending-0000',
    },
  });
  const amountAttack = verifyDocumentActionBinding(binding, {
    ...dabOptions,
    releaseActionTemplate: { ...action, amount: '28400.00' },
  });
  const amendmentAttack = verifyDocumentActionBinding(binding, {
    ...dabOptions,
    releaseActionTemplate: { ...action, amendment_version: 3 },
  });

  const attacks = [
    attackResult({
      id: 'pdf-bytes',
      title: 'PDF bytes',
      layer: 'document_action_binding',
      mutation: 'One byte in the final PDF changes after acceptance.',
      result: pdfAttack,
      expectedReason: 'document_digest_mismatch',
      detail: 'The shipped DAB verifier recomputes the final-document digest.',
    }),
    attackResult({
      id: 'material-terms',
      title: 'Material terms',
      layer: 'document_action_binding',
      mutation: 'The structured release amount changes without a new issuer signature.',
      result: materialTermsAttack,
      expectedReason: 'binding_digest_mismatch',
      detail: 'The material-term list is inside the signed DAB digest.',
    }),
    attackResult({
      id: 'destination',
      title: 'Destination / payee',
      layer: 'document_action_binding',
      mutation: 'The custodian destination is replaced before release.',
      result: destinationAttack,
      expectedReason: 'action_digest_mismatch',
      detail: 'The replacement destination produces a different exact action digest.',
    }),
    attackResult({
      id: 'amount',
      title: 'Amount',
      layer: 'document_action_binding',
      mutation: 'The release amount is increased by $10,000.',
      result: amountAttack,
      expectedReason: 'action_digest_mismatch',
      detail: 'Decimal amount and currency are bound into the release template.',
    }),
    attackResult({
      id: 'signer',
      title: 'Signer',
      layer: 'action_escrow_kernel',
      mutation: 'The contractor key claims the homeowner approval seat.',
      result: signerAttackResult,
      expectedReason: 'resolution_verification_refused',
      detail: 'The kernel invokes the relying party verifier with the required homeowner identity.',
    }),
    attackResult({
      id: 'milestone-evidence',
      title: 'Milestone evidence',
      layer: 'action_escrow_kernel',
      mutation: 'A completion artifact digest changes after the contractor signature.',
      result: milestoneAttackResult,
      expectedReason: 'milestone_evidence_invalid',
      detail: 'The evidence receipt fails its real Ed25519 signature and manifest join.',
    }),
    attackResult({
      id: 'amendment-version',
      title: 'Amendment version',
      layer: 'document_action_binding',
      mutation: 'Version 3 is presented with a version 2 action signature.',
      result: amendmentAttack,
      expectedReason: 'action_digest_mismatch',
      detail: 'A new amendment needs a new DAB and fresh party approvals.',
    }),
    attackResult({
      id: 'replay',
      title: 'Replay',
      layer: 'action_escrow_kernel',
      mutation: 'The exact release operation is presented a second time.',
      result: replayResult,
      expectedReason: 'release_already_applied',
      detail: 'The durable released state closes the second call before the custodian.',
    }),
  ];
  invariant(attacks.length === 8, 'attack bench must contain eight mutations');
  invariant(
    attacks.every((attack) => attack.refused && attack.reason === attack.expected_reason),
    `every attack must refuse as expected: ${JSON.stringify(attacks)}`,
  );

  const approvalVerification = {
    homeowner: verifyResolutionArtifact(homeownerDecisions.approve, {
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      bindings: resolutionBindings,
      action,
    }),
    contractor: verifyResolutionArtifact(contractorApproval, {
      party: partyByRole.contractor,
      key: keys.contractorResolution,
      bindings: resolutionBindings,
      action,
    }),
  };
  invariant(
    approvalVerification.homeowner.authorizes_action
      && approvalVerification.contractor.authorizes_action,
    'both exact release approvals must verify',
  );

  const outcomeDefinitions = [
    {
      outcome: 'approve',
      title: 'Approve',
      detail: 'Homeowner approves the exact release action.',
      effect: 'eligible_for_gate',
      resolution: homeownerDecisions.approve,
      coreResult: homeownerApprovalResult,
    },
    {
      outcome: 'decline',
      title: 'Decline',
      detail: 'Homeowner declines this release without replacement terms.',
      effect: 'no_release',
      resolution: homeownerDecisions.decline,
      coreResult: outcomeResults.decline,
    },
    {
      outcome: 'reject',
      title: 'Reject',
      detail: 'Homeowner rejects the submitted milestone evidence for this release.',
      effect: 'no_release',
      resolution: homeownerDecisions.reject,
      coreResult: outcomeResults.reject,
    },
    {
      outcome: 'amend',
      title: 'Amend',
      detail: 'Homeowner proposes version 3; the original release remains closed.',
      effect: 'new_mutual_acceptance_required',
      resolution: homeownerDecisions.amend,
      coreResult: outcomeResults.amend,
    },
  ];
  const outcomes = outcomeDefinitions.map((entry) => {
    const verification = verifyResolutionArtifact(entry.resolution, {
      party: partyByRole.homeowner,
      key: keys.homeownerResolution,
      bindings: resolutionBindings,
      action,
    });
    return {
      outcome: entry.outcome,
      title: entry.title,
      detail: entry.detail,
      effect: entry.effect,
      signed: verification.valid,
      release_authorized: entry.outcome === 'approve'
        && entry.coreResult.ok
        && contractorApprovalResult.ok,
      receipt_id: entry.resolution.signoff.context.nonce,
      signature_verified: verification.valid,
      reason: entry.coreResult.code,
      proposed_amendment: entry.outcome === 'amend' ? 3 : null,
    };
  });

  const stateStatement = signActionEscrowStateStatement({
    statementId: 'state:AGR-KITCHEN-2048:released',
    agreementId: AGREEMENT_ID,
    bindingDigest: kernelBindings.document_action_binding_digest,
    actionDigest: kernelBindings.release_action_digest,
    profileDigest: releaseResult.record.profile_digest,
    state: 'released',
    revision: releaseResult.record.revision,
    amendmentDigests: [],
    stateRecord: releaseResult.record,
    previousStatementDigest: null,
    occurredAt: CREATED_AT,
  }, {
    operatorId: OPERATOR_ID,
    keyId: keys.operator.keyId,
    privateKey: keys.operator.privateKey,
  });

  const evidencePackage = assembleActionEscrowEvidencePackage({
    kernelRecord: releaseResult.record,
    finalPdfBytes: document.bytes,
    documentFileName: document.filename,
    documentExecution: {
      provider: 'acrobat_sign',
      mode: 'simulated_local_adapter',
      agreement_id: AGREEMENT_ID,
      binding_digest: kernelBindings.document_action_binding_digest,
      document_digest: document.sha256,
      authorizes_action: false,
      evidence: esignEvidence.evidence,
    },
    operatorStateStatement: stateStatement,
    verificationProfile: {
      id: profile.profile_id,
      digest: releaseResult.record.profile_digest,
    },
  }, {
    now: FIXED_NOW_MS,
  });
  invariant(
    evidencePackage.version === ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION,
    'download must use the shipped Action Escrow evidence-package profile',
  );

  const verifyPackagedState = createActionEscrowStatePackageVerifier({
    trustedKeys: {
      [keys.operator.keyId]: {
        operator_id: OPERATOR_ID,
        public_key: keys.operator.publicKey,
      },
    },
    now: CREATED_AT,
    minimumRevision: releaseResult.record.revision,
  });
  const packageVerification = await verifyActionEscrowEvidencePackage(evidencePackage, {
    documentBytes: document.bytes,
    expectedAgreementId: AGREEMENT_ID,
    now: CREATED_AT,
    verifyBinding: async (artifact, expected) => {
      const result = verifyDocumentActionBinding(artifact, {
        ...dabOptions,
        expectedAgreementId: expected.expectedAgreementId,
        documentBytes: document.bytes,
      });
      return result.document_digest === expected.expectedDocumentDigest
        ? result
        : { ...result, valid: false, reason: 'document_digest_mismatch' };
    },
    verifyProfile: async (packagedProfile, expected) => ({
      valid: packagedProfile?.id === profile.profile_id
        && packagedProfile?.digest === releaseResult.record.profile_digest,
      agreement_id: expected.agreementId,
      binding_digest: expected.bindingDigest,
      action_digest: expected.actionDigest,
      profile_digest: releaseResult.record.profile_digest,
      required_release_parties: parties,
    }),
    verifyDocumentExecution: async (execution, expected) => ({
      valid: execution?.provider === 'acrobat_sign'
        && execution?.mode === 'simulated_local_adapter'
        && execution?.agreement_id === expected.agreementId
        && execution?.binding_digest === expected.bindingDigest
        && execution?.document_digest === expected.documentDigest
        && execution?.authorizes_action === false
        && execution?.evidence?.provider === 'acrobat_sign'
        && execution?.evidence?.agreement_status === 'SIGNED'
        && execution?.evidence?.document?.sha256 === expected.documentDigest,
      authorizes_action: false,
      agreement_id: expected.agreementId,
      binding_digest: expected.bindingDigest,
      document_digest: expected.documentDigest,
      state: 'executed',
    }),
    verifyAgreementAcceptance: async (acceptance, expected) => {
      const party = parties.find((entry) => entry.party_id === expected.partyId);
      const key = keyByPartyId.get(expected.partyId);
      const cryptoResult = key ? verifyReceipt(acceptance, key.publicKey) : { valid: false };
      const claim = acceptance?.payload?.claim;
      const signer = acceptance?.payload?.signer;
      const valid = Boolean(
        party
        && key
        && cryptoResult.valid
        && signer?.party_id === expected.partyId
        && signer?.role === expected.role
        && signer?.key_id === key.keyId
        && claim?.outcome === 'accepted'
        && claim?.authorizes_payment === false
        && claim?.document_action_binding_digest === expected.bindingDigest
        && claim?.document_digest === expected.documentDigest,
      );
      return {
        valid,
        accepts_agreement: valid,
        authorizes_action: false,
        agreement_id: expected.agreementId,
        party_id: expected.partyId,
        role: expected.role,
        binding_digest: expected.bindingDigest,
        document_digest: expected.documentDigest,
        principal_key_id: signer?.key_id ?? null,
      };
    },
    verifyState: verifyPackagedState,
    verifyReleaseApproval: async (resolution, expected) => {
      const party = parties.find((entry) => entry.party_id === expected.partyId);
      const key = resolutionKeyByPartyId.get(expected.partyId);
      const verification = party && key
        ? verifyResolutionArtifact(resolution, {
          party,
          key,
          bindings: resolutionBindings,
          action,
        })
        : { valid: false, outcome: null, authorizes_action: false };
      const admission = expected.stateRecord?.snapshot?.operations
        ?.filter((entry) => entry.operation === 'approve_release')
        ?.[expected.approvalIndex];
      return {
        valid: verification.valid,
        authorizes_action: verification.authorizes_action,
        outcome: verification.outcome,
        agreement_id: expected.agreementId,
        party_id: expected.partyId,
        role: expected.role,
        binding_digest: kernelBindings.document_action_binding_digest,
        action_digest: kernelBindings.release_action_digest,
        milestone_evidence_digests: expected.milestoneEvidenceDigests,
        principal_key_id: resolution?.signoff?.context?.principal_key_id ?? null,
        issued_at: resolution?.signoff?.context?.issued_at ?? null,
        expires_at: resolution?.signoff?.context?.expires_at ?? null,
        admitted_at: admission?.at ?? null,
      };
    },
    verifyFunding: async (statement, expected) => {
      const verification = verifyFundingArtifact(statement, {
        ...kernelBindings,
        provider_id: CUSTODIAN_PROVIDER_ID,
      });
      return {
        valid: verification.valid,
        agreement_id: expected.agreementId,
        binding_digest: expected.bindingDigest,
        action_digest: expected.actionDigest,
        state: verification.status,
      };
    },
    verifyMilestone: async (milestone, expected) => {
      const verification = verifyCompletionArtifact(milestone?.evidence, kernelBindings);
      return {
        valid: verification.valid
          && verification.evidence_digest === boundCompletion.sha256,
        agreement_id: expected.agreementId,
        milestone_id: milestone?.milestone_id,
        binding_digest: expected.bindingDigest,
        action_digest: expected.actionDigest,
        evidence_digest: verification.evidence_digest,
      };
    },
    verifyAmendment: async () => ({
      valid: false,
      reason: 'no_amendment_expected',
    }),
    verifyRelease: async (release, expected) => {
      const verification = await verifyCustodianObservation(release?.provider_statement, {
        ...kernelBindings,
        provider_id: CUSTODIAN_PROVIDER_ID,
        statement_type: 'release',
        provider_idempotency_key: releaseResult.record.release.provider_idempotency_key,
        provider_request_digest: releaseResult.record.release.provider_request.request_digest,
        provider_transaction_id: action.custodian_transaction_id,
        provider_milestone_id: action.custodian_milestone_id,
        amount: action.amount,
        currency: action.currency,
        destination_id: action.destination_id,
      });
      const valid = verification.valid
        && release?.reservation?.release_key === releaseResult.record.release.release_key
        && release?.provider_request?.idempotency_key
          === releaseResult.record.release.provider_idempotency_key
        && release?.execution_record?.operation === 'release'
        && release?.execution_record?.code === 'release_committed'
        && release?.execution_record?.outcome === 'applied'
        && release?.execution_record?.ok === true;
      return {
        valid,
        agreement_id: expected.agreementId,
        binding_digest: expected.bindingDigest,
        action_digest: expected.actionDigest,
        state: 'released',
      };
    },
  });
  invariant(
    packageVerification.valid,
    `portable evidence package must verify (${packageVerification.reason})`,
  );

  const documentAcceptanceVerification = {
    homeowner: verifyAcceptanceArtifact(acceptances.homeowner, {
      ...kernelBindings,
      party_id: partyByRole.homeowner.party_id,
    }),
    contractor: verifyAcceptanceArtifact(acceptances.contractor, {
      ...kernelBindings,
      party_id: partyByRole.contractor.party_id,
    }),
  };
  const documentVerification = {
    verified: dabVerification.valid
      && esignEvidence.kind === 'evidence_ready'
      && documentAcceptanceVerification.homeowner.valid
      && documentAcceptanceVerification.contractor.valid,
    status: 'issuer_mapping_verified',
    authorizes_payment: false,
    dab: dabVerification,
    esign_evidence: esignEvidence.evidence,
    acceptance_verification: documentAcceptanceVerification,
    document_as_payment_refusal: documentAsPaymentResult.code,
    checks: {
      simulated_provider_refetch_completed: esignEvidence.kind === 'evidence_ready',
      final_pdf_digest_verified: dabVerification.document_digest === document.sha256,
      structured_terms_bound: dabVerification.binding_digest === binding.binding_digest,
      mapping_issuer_signature_verified: dabVerification.valid,
      both_agreement_acceptances_verified:
        documentAcceptanceVerification.homeowner.valid
        && documentAcceptanceVerification.contractor.valid,
      signed_document_is_not_payment_authority:
        documentAsPaymentResult.code === 'resolution_profile_invalid',
    },
  };

  const view = buildView({
    terms,
    mapping,
    document,
    binding,
    documentVerification,
    completion: boundCompletion,
    action,
    acceptances,
    approvals: {
      homeowner: homeownerDecisions.approve,
      contractor: contractorApproval,
    },
    approvalVerification,
    outcomes,
    custodian,
    fundingStatement,
    fundingVerification,
    releaseVerification,
    releaseResult,
    replayResult,
    attacks,
    evidencePackage,
    packageVerification,
  });

  return {
    version: ACTION_ESCROW_VERSION,
    view,
    bundle: evidencePackage,
    bundleVerification: packageVerification,
    pdf: {
      filename: document.filename,
      media_type: document.media_type,
      bytes: document.bytes,
    },
  };
}
