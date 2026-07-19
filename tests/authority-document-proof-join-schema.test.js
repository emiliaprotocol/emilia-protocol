// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { authorityInstantMs } from '../lib/authority/authority-doc.js';
import { verifyAuthorityProofViaDocument } from '../lib/authority/document-proof-join.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schema = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'public/schemas/ep-authority-document-proof-join.schema.json'),
  'utf8',
));
const suite = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'conformance/vectors/authority-document-proof-join.exec.v1.json'),
  'utf8',
));
const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addFormat('date-time', (value) => Number.isFinite(authorityInstantMs(value)));
ajv.addSchema(schema);

const validateArtifact = ajv.getSchema(schema.$id);
const validateInput = ajv.compile({
  $ref: `${schema.$id}#/$defs/joinInput`,
});
const validateOutput = ajv.compile({
  $ref: `${schema.$id}#/$defs/joinOutput`,
});
const clone = (value) => JSON.parse(JSON.stringify(value));
const errors = (validate) => JSON.stringify(validate.errors, null, 2);

const acceptedVector = suite.vectors.find(
  (vector) => vector.id === 'accept_anchored_document_key_at_issuance',
);
const acceptedInput = {
  proof: acceptedVector.proof,
  docs: acceptedVector.docs,
  opts: acceptedVector.opts,
};
const acceptedOutput = verifyAuthorityProofViaDocument(
  acceptedVector.proof,
  acceptedVector.docs,
  acceptedVector.opts,
);

describe('public Authority Document to Proof join schema', () => {
  it('validates the closed runtime input and issuer-acceptance output', () => {
    expect(validateInput(acceptedInput), errors(validateInput)).toBe(true);
    expect(validateArtifact(acceptedInput), errors(validateArtifact)).toBe(true);
    expect(validateOutput(acceptedOutput), errors(validateOutput)).toBe(true);
    expect(validateArtifact(acceptedOutput), errors(validateArtifact)).toBe(true);
  });

  it('requires stable grant, organization, and registry issuer identifiers', () => {
    for (const mutate of [
      (value) => { value.proof.authority_id = ' grant'; },
      (value) => { value.proof.organization_id = 'org 1'; },
      (value) => { value.proof.registry_issuer_id = 'ep:authority-registry:acme payments'; },
      (value) => { value.opts.expectedOrganizationId = 'org\n1'; },
      (value) => { value.opts.expectedRegistryIssuerId = ' issuer'; },
    ]) {
      const input = clone(acceptedInput);
      mutate(input);
      expect(validateInput(input)).toBe(false);
    }

    const boundary = clone(acceptedInput);
    boundary.opts.expectedOrganizationId = '😀'.repeat(512);
    expect(validateInput(boundary), errors(validateInput)).toBe(true);
    boundary.opts.expectedOrganizationId += '😀';
    expect(validateInput(boundary)).toBe(false);
  });

  it('requires independent proof-time, document, and registry snapshot anchors', () => {
    const noProofTime = clone(acceptedInput);
    delete noProofTime.opts.expectedProofIssuedAt;
    expect(validateInput(noProofTime)).toBe(false);

    const impossibleProofTime = clone(acceptedInput);
    impossibleProofTime.opts.expectedProofIssuedAt = '2026-02-30T00:00:00.000Z';
    expect(validateInput(impossibleProofTime)).toBe(false);

    const noDocumentAnchor = clone(acceptedInput);
    delete noDocumentAnchor.opts.expectedDocumentHead;
    delete noDocumentAnchor.opts.expectedBootstrapDigest;
    expect(validateInput(noDocumentAnchor)).toBe(false);

    const noRegistryHead = clone(acceptedInput);
    delete noRegistryHead.opts.expectRegistryHead;
    expect(validateInput(noRegistryHead)).toBe(false);

    const noRegistryEpoch = clone(acceptedInput);
    delete noRegistryEpoch.opts.expectMinEpoch;
    expect(validateInput(noRegistryEpoch)).toBe(false);
  });

  it('rejects unknown members at every load-bearing input boundary', () => {
    for (const mutate of [
      (value) => { value.ignored = true; },
      (value) => { value.proof.ignored = true; },
      (value) => { value.proof.authority_document.ignored = true; },
      (value) => { value.docs[0].ignored = true; },
      (value) => { value.docs[0].org.ignored = true; },
      (value) => { value.docs[0].issuer_keys[0].ignored = true; },
      (value) => { value.opts.ignored = true; },
    ]) {
      const input = clone(acceptedInput);
      mutate(input);
      expect(validateInput(input)).toBe(false);
    }
  });

  it('represents key-usage refusal and keeps issuer acceptance distinct from authority', () => {
    const wrongUsage = suite.vectors.find((vector) => vector.id === 'reject_key_wrong_usage');
    const input = { proof: wrongUsage.proof, docs: wrongUsage.docs, opts: wrongUsage.opts };
    const output = verifyAuthorityProofViaDocument(
      wrongUsage.proof,
      wrongUsage.docs,
      wrongUsage.opts,
    );

    expect(validateInput(input), errors(validateInput)).toBe(true);
    expect(output).toMatchObject({
      accepted: false,
      issuer_accepted: false,
      authority_evaluated: false,
      delegation_evaluated: false,
      reason: 'authority_proof_key_wrong_usage',
    });
    expect(output.checks.issuer_key_usage).toBe(false);
    expect(validateOutput(output), errors(validateOutput)).toBe(true);

    const overclaim = clone(acceptedOutput);
    overclaim.authority_evaluated = true;
    expect(validateOutput(overclaim)).toBe(false);

    const mismatchedAlias = clone(acceptedOutput);
    mismatchedAlias.issuer_accepted = false;
    expect(validateOutput(mismatchedAlias)).toBe(false);
  });

  it('keeps output verdict facts and members closed', () => {
    const extraResult = clone(acceptedOutput);
    extraResult.authorized = true;
    expect(validateOutput(extraResult)).toBe(false);

    const missingUsageFact = clone(acceptedOutput);
    delete missingUsageFact.checks.issuer_key_usage;
    expect(validateOutput(missingUsageFact)).toBe(false);

    const missingDocumentHead = clone(acceptedOutput);
    delete missingDocumentHead.document_head;
    expect(validateOutput(missingDocumentHead)).toBe(false);
  });
});
