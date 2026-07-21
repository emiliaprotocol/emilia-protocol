// SPDX-License-Identifier: Apache-2.0
// Executable Authority Document -> Authority Proof trust-join vectors.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { createAuthorityDoc, docCoreDigest } from '../lib/authority/authority-doc.js';
import {
  AUTHORITY_PROOF_DOMAIN,
  authorityProofDigest,
  signAuthorityProof,
} from '../lib/authority/proof.js';
import { verifyAuthorityProofViaDocument } from '../lib/authority/document-proof-join.js';
import { canonicalize } from '../lib/canonical-json.js';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const suite = JSON.parse(fs.readFileSync(
  path.join(here, '..', 'conformance', 'vectors', 'authority-document-proof-join.v1.json'),
  'utf8',
));
const staticSuite = JSON.parse(fs.readFileSync(
  path.join(here, '..', 'conformance', 'vectors', 'authority-document-proof-join.exec.v1.json'),
  'utf8',
));

function keyFromByte(byte) {
  const seed = Buffer.alloc(32, byte);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const pub = (privateKey) => crypto.createPublicKey(privateKey)
  .export({ type: 'spki', format: 'der' }).toString('base64url');

const root0 = keyFromByte(0x41);
const root1 = keyFromByte(0x42);
const issuer = keyFromByte(0x43);
const alternateIssuer = keyFromByte(0x44);
const mallory = keyFromByte(0x45);
const REGISTRY_HEAD = `sha256:${'11'.repeat(32)}`;
const REGISTRY_ISSUER_ID = 'ep:authority-registry:acme-payments';
const PROOF_TIME = '2026-07-10T00:00:00.000Z';

function buildDocs({
  usages = ['evidence_issuer', 'authority_proof_issuer'],
  initialUsages = usages,
  validFrom = '2026-01-01T00:00:00.000Z',
  validTo = '2027-01-01T00:00:00.000Z',
  revokedAt,
  continuityKey = root0,
  doc1IssuedAt = '2026-06-01T00:00:00.000Z',
  addRevocationDoc = false,
  registryIssuerId = REGISTRY_ISSUER_ID,
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
  const revokedEntry = { ...issuerEntry, revoked_at: revokedAt };
  const doc2 = createAuthorityDoc({
    org,
    issuer_keys: [revokedEntry],
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

function resignProof(proof, privateKey, changes) {
  const { signature: oldSignature, ...oldBody } = proof;
  const body = { ...oldBody, ...changes };
  const proofDigest = authorityProofDigest(body);
  return {
    ...body,
    signature: {
      ...oldSignature,
      proof_digest: proofDigest,
      signature_b64u: crypto.sign(
        null,
        Buffer.from(AUTHORITY_PROOF_DOMAIN + canonicalize(body), 'utf8'),
        privateKey,
      ).toString('base64url'),
    },
  };
}

function fixture(mutation) {
  let docs = buildDocs();
  let proof = buildProof(docs);
  const opts = {
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
    case 'none':
      break;
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
      docs = buildDocs({
        revokedAt: '2026-07-01T00:00:00.000Z',
        addRevocationDoc: true,
      });
      proof = buildProof(docs);
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    case 'later_key_revocation':
      docs = buildDocs({
        revokedAt: '2026-08-01T00:00:00.000Z',
        addRevocationDoc: true,
      });
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
    case 'document_registry_issuer_substitution': {
      docs = buildDocs({ registryIssuerId: 'ep:authority-registry:attacker' });
      proof = buildProof(docs, issuer, { registry_issuer_id: REGISTRY_ISSUER_ID });
      opts.expectedDocumentHead = docCoreDigest(docs.at(-1));
      opts.expectedBootstrapDigest = docCoreDigest(docs[0]);
      break;
    }
    case 'document_head_registry_head_confusion':
      proof = {
        ...proof,
        authority_document: {
          ...proof.authority_document,
          head_digest: proof.registry_head,
        },
      };
      break;
    case 'full_issuer_kid_mismatch':
      proof = {
        ...proof,
        authority_document: {
          ...proof.authority_document,
          issuer_kid: `ep:authority-issuer-key:sha256:${'ff'.repeat(32)}`,
        },
      };
      break;
    default:
      throw new Error(`unknown mutation ${mutation}`);
  }
  return { proof, docs, opts };
}

describe(`conformance suite ${suite.suite} (${suite.vectors.length} vectors)`, () => {
  for (const vector of suite.vectors) {
    it(vector.id, () => {
      const { proof, docs, opts } = fixture(vector.mutation);
      const result = verifyAuthorityProofViaDocument(proof, docs, opts);
      expect(result.accepted).toBe(vector.expect.accepted);
      expect(result.issuer_accepted).toBe(vector.expect.accepted);
      if (vector.expect.reason) expect(result.reason).toBe(vector.expect.reason);
    });
  }

  it('requires every load-bearing join check on acceptance', () => {
    const { proof, docs, opts } = fixture('none');
    const result = verifyAuthorityProofViaDocument(proof, docs, opts);
    expect(result.accepted).toBe(true);
    expect(result.issuer_accepted).toBe(true);
    expect(result.authority_evaluated).toBe(false);
    expect(result.delegation_evaluated).toBe(false);
    expect(Object.values(result.checks).every(Boolean)).toBe(true);
    expect(result.document_head).toBe(opts.expectedDocumentHead);
    expect(result.bootstrap_digest).toBe(opts.expectedBootstrapDigest);
  });

  it('preserves cryptographic verification when document acceptance fails', () => {
    const { proof, docs, opts } = fixture('remove_document_anchors');
    const result = verifyAuthorityProofViaDocument(proof, docs, opts);

    expect(result.verified).toBe(true);
    expect(result.accepted).toBe(false);
    expect(result.issuer_accepted).toBe(false);
    expect(result.checks.proof_signature).toBe(true);
  });

  it('preserves proof verification but refuses absent registry and epoch pins', () => {
    const { proof, docs, opts } = fixture('missing_registry_snapshot_pins');
    const result = verifyAuthorityProofViaDocument(proof, docs, opts);

    expect(result).toMatchObject({
      verified: true,
      accepted: false,
      issuer_accepted: false,
      reason: 'registry_snapshot_pins_required',
    });
    expect(result.checks.registry_head).toBe(false);
    expect(result.checks.epoch_fresh).toBe(false);
  });

  it('requires the relying-party proof-time anchor to be a strict instant', () => {
    const { proof, docs, opts } = fixture('none');
    const malformedTime = '2026-02-30T00:00:00.000Z';
    const malformedProof = resignProof(proof, issuer, { issued_at: malformedTime });
    opts.expectedProofIssuedAt = malformedTime;

    const result = verifyAuthorityProofViaDocument(malformedProof, docs, opts);
    expect(result).toMatchObject({
      verified: true,
      accepted: false,
      reason: 'authority_proof_time_anchor_invalid',
    });
  });

  it('does not resolve a proof signer through a key omitted by the effective document', () => {
    const docs = buildDocs();
    const proof = buildProof(docs);
    const org = { id: 'org1', name: 'Acme Payments', domain: 'acme.example' };
    const doc2 = createAuthorityDoc({
      org,
      issuer_keys: [{
        key: pub(alternateIssuer),
        registry_issuer_id: 'ep:authority-registry:alternate',
        usages: ['authority_proof_issuer'],
        custody_class: 'A',
        valid_from: '2026-07-01T00:00:00.000Z',
        valid_to: '2027-07-01T00:00:00.000Z',
      }],
      issued_at: '2026-07-01T00:00:00.000Z',
    }, root1, { doc: docs[1], continuityPrivateKey: root1 });
    docs.push(doc2);
    const opts = {
      expectedDocumentHead: docCoreDigest(doc2),
      expectedBootstrapDigest: docCoreDigest(docs[0]),
      expectedOrganizationId: 'org1',
      expectedOrganizationDomain: 'acme.example',
      expectedRegistryIssuerId: REGISTRY_ISSUER_ID,
      expectedProofIssuedAt: PROOF_TIME,
      expectRegistryHead: REGISTRY_HEAD,
      expectMinEpoch: 17,
    };

    const result = verifyAuthorityProofViaDocument(proof, docs, opts);
    expect(result).toMatchObject({
      verified: true,
      accepted: false,
      reason: 'authority_proof_key_unresolvable',
    });
  });
});

describe(`fixed serialized suite ${staticSuite.suite} (${staticSuite.vectors.length} vectors)`, () => {
  for (const vector of staticSuite.vectors) {
    it(vector.id, () => {
      const result = verifyAuthorityProofViaDocument(vector.proof, vector.docs, vector.opts);
      expect(result.issuer_accepted).toBe(vector.expect.accepted);
      if (vector.expect.reason) expect(result.reason).toBe(vector.expect.reason);
    });
  }
});

describe('malformed native inputs', () => {
  it('fails closed without throwing on malformed document chains', () => {
    for (const docs of [null, {}, [null], [42], [{ '@version': 'EP-AUTHORITY-DOC-v1' }]]) {
      expect(() => verifyAuthorityProofViaDocument({}, docs, {})).not.toThrow();
      expect(verifyAuthorityProofViaDocument({}, docs, {})).toMatchObject({
        verified: false,
        issuer_accepted: false,
        reason: 'authority_document_chain_invalid',
      });
    }
  });
});
