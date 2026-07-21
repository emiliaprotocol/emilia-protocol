// SPDX-License-Identifier: Apache-2.0
// Deterministic executable fixtures for EP-AUTHORITY-DOC-PROOF-JOIN-v1.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createAuthorityDoc, docCoreDigest } from '../../lib/authority/authority-doc.js';
import { verifyAuthorityProofViaDocument } from '../../lib/authority/document-proof-join.js';
import { signAuthorityProof } from '../../lib/authority/proof.js';
import { canonicalize } from '../../packages/verify/index.js';

function keyFromByte(byte) {
  const seed = Buffer.alloc(32, byte);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const pub = (privateKey) => crypto.createPublicKey(privateKey)
  .export({ type: 'spki', format: 'der' }).toString('base64url');
const digest = (value) => `sha256:${crypto.createHash('sha256')
  .update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')}`;

const root0 = keyFromByte(0x41);
const root1 = keyFromByte(0x42);
const issuer = keyFromByte(0x43);
const alternateIssuer = keyFromByte(0x44);
const mallory = keyFromByte(0x45);
const REGISTRY_HEAD = `sha256:${'11'.repeat(32)}`;
const REGISTRY_ISSUER_ID = 'ep:authority-registry:acme-payments';
const PROOF_TIME = '2026-07-10T00:00:00.000Z';

/**
 * @param {{
 *   usages?: string[],
 *   initialUsages?: string[],
 *   validFrom?: string,
 *   validTo?: string,
 *   revokedAt?: string,
 *   continuityKey?: import('node:crypto').KeyObject,
 *   doc1IssuedAt?: string,
 *   addRevocationDoc?: boolean,
 *   registryIssuerId?: string,
 * }} [options]
 */
function buildDocs({
  usages = ['evidence_issuer', 'authority_proof_issuer'],
  initialUsages = usages,
  validFrom = '2026-01-01T00:00:00.000Z',
  validTo = '2027-01-01T00:00:00.000Z',
  revokedAt = undefined,
  continuityKey = root0,
  doc1IssuedAt = '2026-06-01T00:00:00.000Z',
  addRevocationDoc = false,
  registryIssuerId = REGISTRY_ISSUER_ID,
}: {
  usages?: string[];
  initialUsages?: string[];
  validFrom?: string;
  validTo?: string;
  revokedAt?: string;
  continuityKey?: crypto.KeyObject;
  doc1IssuedAt?: string;
  addRevocationDoc?: boolean;
  registryIssuerId?: string;
} = {}) {
  const issuerEntry = {
    key: pub(issuer),
    registry_issuer_id: registryIssuerId,
    usages,
    custody_class: 'A',
    valid_from: validFrom,
    valid_to: validTo,
    ...(revokedAt ? { revoked_at: revokedAt } : {}),
  };
  const org = { id: 'org1', name: 'Acme Payments', domain: 'acme.example' };
  const doc0 = createAuthorityDoc({
    org,
    issuer_keys: [{ ...issuerEntry, usages: initialUsages }],
    issued_at: '2026-01-01T00:00:00.000Z',
  }, root0);
  const doc1 = createAuthorityDoc({
    org,
    issuer_keys: [issuerEntry],
    issued_at: doc1IssuedAt,
  }, root1, { doc: doc0, continuityPrivateKey: continuityKey });
  if (!addRevocationDoc) return [doc0, doc1];
  const doc2 = createAuthorityDoc({
    org,
    issuer_keys: [{ ...issuerEntry, revoked_at: revokedAt }],
    issued_at: revokedAt,
  }, root1, { doc: doc1, continuityPrivateKey: root1 });
  return [doc0, doc1, doc2];
}

function buildProof(docs, privateKey = issuer, overrides = {}) {
  const introducedBy = docs[Math.min(1, docs.length - 1)];
  return signAuthorityProof({
    authority_id: 'auth_cfo',
    subject: 'ep:approver:ada',
    organization_id: 'org1',
    registry_issuer_id: REGISTRY_ISSUER_ID,
    authority_document: {
      head_digest: docCoreDigest(introducedBy),
      head_seq: introducedBy.seq,
      issuer_kid: introducedBy.issuer_keys[0].kid,
    },
    role: 'cfo',
    scope: ['payment.release'],
    limits: { max_amount_usd: 50000, currency: 'USD' },
    validity: {
      from: '2026-01-01T00:00:00.000Z',
      to: '2027-01-01T00:00:00.000Z',
    },
    revocation: { status: 'not_revoked', checked_at: PROOF_TIME },
    registry_head: REGISTRY_HEAD,
    registry_epoch: 17,
    policy_hash: `sha256:${'22'.repeat(32)}`,
    issued_at: PROOF_TIME,
    ...overrides,
  }, privateKey);
}

function fixture(mutation: string) {
  let docs = buildDocs();
  let proof = buildProof(docs);
  const opts: any = {
    expectedDocumentHead: docCoreDigest(docs.at(-1)),
    expectedBootstrapDigest: docCoreDigest(docs[0]),
    expectedOrganizationId: 'org1',
    expectedOrganizationDomain: 'acme.example',
    expectedRegistryIssuerId: REGISTRY_ISSUER_ID,
    expectedProofIssuedAt: PROOF_TIME,
    expectRegistryHead: REGISTRY_HEAD,
    expectMinEpoch: 17,
  };
  switch (mutation) {
    case 'none': break;
    case 'remove_document_anchors':
      delete opts.expectedDocumentHead;
      delete opts.expectedBootstrapDigest;
      break;
    case 'wrong_document_head':
      opts.expectedDocumentHead = `sha256:${'ff'.repeat(32)}`;
      break;
    case 'break_continuity':
      docs = buildDocs({ continuityKey: mallory });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'non_rotation_issuer_signs_successor':
      docs = buildDocs({ continuityKey: issuer });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'explicit_rotation_issuer_signs_successor':
      docs = buildDocs({
        usages: ['evidence_issuer', 'authority_proof_issuer', 'authority_doc_rotation'],
        continuityKey: issuer,
      });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'expired_rotation_issuer_signs_successor':
      docs = buildDocs({
        usages: ['evidence_issuer', 'authority_proof_issuer', 'authority_doc_rotation'],
        validTo: '2026-05-01T00:00:00.000Z',
        continuityKey: issuer,
      });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'non_monotonic_document_time':
      docs = buildDocs({ doc1IssuedAt: '2025-12-01T00:00:00.000Z' });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'proof_organization_substitution':
      proof = { ...proof, organization_id: 'org-attacker' };
      break;
    case 'document_domain_substitution':
      docs = docs.map((doc) => ({ ...doc, org: { ...doc.org, domain: 'evil.example' } }));
      break;
    case 'proof_key_absent':
      proof = buildProof(docs, alternateIssuer);
      break;
    case 'wrong_key_usage':
      docs = buildDocs({ usages: ['evidence_issuer'] });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'later_document_adds_usage_retroactively':
      docs = buildDocs({
        initialUsages: ['evidence_issuer'],
        usages: ['evidence_issuer', 'authority_proof_issuer'],
      });
      proof = buildProof(docs, issuer, {
        authority_document: {
          head_digest: docCoreDigest(docs[0]),
          head_seq: docs[0].seq,
          issuer_kid: docs[0].issuer_keys[0].kid,
        },
        issued_at: '2026-05-01T00:00:00.000Z',
      });
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      opts.expectedProofIssuedAt = '2026-05-01T00:00:00.000Z';
      break;
    case 'key_not_yet_valid':
      docs = buildDocs({ validFrom: '2026-08-01T00:00:00.000Z' });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'key_revoked_at_proof_time':
      docs = buildDocs({ revokedAt: '2026-07-01T00:00:00.000Z', addRevocationDoc: true });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'later_key_revocation':
      docs = buildDocs({ revokedAt: '2026-08-01T00:00:00.000Z', addRevocationDoc: true });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'missing_proof_time_anchor':
      delete opts.expectedProofIssuedAt;
      break;
    case 'mismatched_proof_time_anchor':
      opts.expectedProofIssuedAt = '2026-07-11T00:00:00.000Z';
      break;
    case 'missing_registry_snapshot_pins':
      delete opts.expectRegistryHead;
      delete opts.expectMinEpoch;
      break;
    case 'wrong_registry_head_pin':
      opts.expectRegistryHead = `sha256:${'ff'.repeat(32)}`;
      break;
    case 'stale_registry_epoch':
      opts.expectMinEpoch = 18;
      break;
    case 'tamper_proof_scope':
      proof = { ...proof, scope: ['admin:*'] };
      break;
    case 'proof_registry_issuer_substitution':
      proof = { ...proof, registry_issuer_id: 'ep:authority-registry:attacker' };
      break;
    case 'document_registry_issuer_substitution':
      docs = buildDocs({ registryIssuerId: 'ep:authority-registry:attacker' });
      proof = buildProof(docs, issuer, { registry_issuer_id: REGISTRY_ISSUER_ID });
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'document_head_registry_head_confusion': {
      // buildProof() always sets authority_document with all three fields;
      // the compiler only sees it as optional because signAuthorityProof's
      // return type spreads it conditionally.
      const authorityDocument = /** @type {{head_digest:string,head_seq:number,issuer_kid:string}} */ (
        proof.authority_document
      );
      proof = {
        ...proof,
        authority_document: {
          ...authorityDocument,
          head_digest: (proof as any).registry_head as string,
        } as any,
      };
      break;
    }
    case 'full_issuer_kid_mismatch': {
      const authorityDocument = (proof.authority_document as any) as {head_digest:string,head_seq:number,issuer_kid:string};
      proof = {
        ...proof,
        authority_document: {
          ...authorityDocument,
          issuer_kid: `ep:authority-issuer-key:sha256:${'ff'.repeat(32)}`,
        },
      };
      break;
    }
    default: throw new Error(`unknown mutation ${mutation}`);
  }
  return { proof, docs, opts };
}

const catalogue = JSON.parse(fs.readFileSync(
  new URL('./authority-document-proof-join.v1.json', import.meta.url),
  'utf8',
));
const vectors = catalogue.vectors.map((entry) => {
  const value = fixture(entry.mutation);
  const result = verifyAuthorityProofViaDocument(value.proof, value.docs, value.opts);
  if (result.accepted !== entry.expect.accepted
      || (entry.expect.reason
        && (!('reason' in result) || result.reason !== entry.expect.reason))) {
    throw new Error(`${entry.id}: generator self-check failed: ${JSON.stringify(result)}`);
  }
  const machineResult = { ...result } as Record<string, any>;
  delete (machineResult as any).limitations;
  const exactResult = {
    ...machineResult,
    proof_input_digest: digest(value.proof),
    document_chain_digest: digest(value.docs),
  };
  return {
    id: entry.id,
    ...value,
    expect: {
      ...exactResult,
      result_digest: digest(exactResult),
    },
  };
});
const suite = {
  suite: 'EP-AUTHORITY-DOC-PROOF-JOIN-v1',
  vectors_version: '1.1.0',
  profile: 'Fixed serialized Authority Document, Authority Proof, relying-party pin, and complete typed result/check/reason/input/result-digest fixtures. A passing join accepts the registry issuer only; grant/action and delegation evaluation remain separate.',
  count: vectors.length,
  vectors,
};
fs.writeFileSync(
  new URL('./authority-document-proof-join.exec.v1.json', import.meta.url),
  `${JSON.stringify(suite, null, 2)}\n`,
);
console.log(`wrote authority-document-proof-join.exec.v1.json (${vectors.length})`);
