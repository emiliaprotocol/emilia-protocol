// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { canonicalize } from './index.js';
import {
  DOCUMENT_ACTION_BINDING_DOMAIN,
  computeDocumentActionBindingDigest,
  computeDocumentSha256,
  computeReleaseActionDigest,
  signDocumentActionBinding,
  verifyDocumentActionBinding,
} from './document-action-binding.js';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const FINAL_DOCUMENT = Buffer.from(
  '%PDF-1.7\n% EP DAB final agreement\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n',
  'utf8',
);
const NOW = '2026-07-17T12:00:00Z';
const ACTION = Object.freeze({
  action_type: 'settlement.funds_release',
  agreement_id: 'agreement:settlement-2026-001',
  amount: '125000.00',
  currency: 'USD',
  destination_digest: `sha256:${'ab'.repeat(32)}`,
});
const PARTIES = Object.freeze([
  Object.freeze({ party_id: 'party:contractor-acme', role: 'contractor' }),
  Object.freeze({ party_id: 'party:homeowner-alex', role: 'homeowner' }),
  Object.freeze({ party_id: 'party:homeowner-jordan', role: 'homeowner' }),
]);

function keypair(seedByte) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.alloc(32, seedByte)]),
    format: 'der',
    type: 'pkcs8',
  });
  return {
    privateKey,
    publicKey: crypto.createPublicKey(privateKey),
  };
}

const ISSUER = keypair(0x11);
const ATTACKER = keypair(0x22);

function publicKeyB64u(pair) {
  return pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function baseSpec() {
  return {
    binding_id: 'dab:settlement-2026-001:v1',
    agreement_id: 'agreement:settlement-2026-001',
    document: {
      bytes: Buffer.from(FINAL_DOCUMENT),
      media_type: 'application/pdf',
    },
    material_terms: [
      { term_id: 'release_scope', type: 'string', value: 'Final settlement payment' },
      { term_id: 'release_amount', type: 'amount', value: '125000.00', currency: 'USD' },
      { term_id: 'effective_date', type: 'date', value: '2026-07-15' },
    ],
    release_action_template: structuredClone(ACTION),
    parties: structuredClone(PARTIES),
    required_parties: structuredClone(PARTIES),
    validity: {
      not_before: '2026-07-15T00:00:00Z',
      not_after: '2026-08-15T00:00:00Z',
    },
  };
}

function sign(spec = baseSpec(), pair = ISSUER, issuer = 'issuer:document-mapper') {
  return signDocumentActionBinding(spec, {
    issuer_id: issuer,
    key_id: `key:${issuer}:2026-01`,
    privateKey: pair.privateKey,
  });
}

function options(overrides = {}) {
  return {
    issuerKeys: {
      'key:issuer:document-mapper:2026-01': {
        issuer_id: 'issuer:document-mapper',
        public_key: publicKeyB64u(ISSUER),
      },
    },
    now: NOW,
    allowedMediaTypes: ['application/pdf'],
    allowedPartyRoles: ['contractor', 'homeowner'],
    allowedActionTypes: ['settlement.funds_release'],
    requiredMaterialTermIds: ['effective_date', 'release_amount', 'release_scope'],
    expectedBindingId: 'dab:settlement-2026-001:v1',
    expectedAgreementId: 'agreement:settlement-2026-001',
    documentBytes: Buffer.from(FINAL_DOCUMENT),
    documentMediaType: 'application/pdf',
    releaseActionTemplate: structuredClone(ACTION),
    expectedRequiredParties: structuredClone(PARTIES),
    ...overrides,
  };
}

function resign(binding, pair = ISSUER) {
  const core = structuredClone(binding);
  delete core.binding_digest;
  delete core.issuer_signatures;
  const bytes = Buffer.from(DOCUMENT_ACTION_BINDING_DOMAIN + canonicalize(core), 'utf8');
  return {
    ...core,
    binding_digest: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
    issuer_signatures: [{
      algorithm: 'Ed25519',
      signature_b64u: crypto.sign(null, bytes, pair.privateKey).toString('base64url'),
    }],
  };
}

test('authenticates a mapping without asserting acceptance and returns both join IDs', () => {
  const binding = sign();
  const result = verifyDocumentActionBinding(binding, options());

  assert.deepEqual(Object.keys(result), [
    'valid',
    'reason',
    'binding_id',
    'agreement_id',
    'supersedes_digest',
    'binding_digest',
    'document_digest',
    'action_digest',
    'required_parties',
  ]);
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'valid');
  assert.equal(result.binding_id, 'dab:settlement-2026-001:v1');
  assert.equal(result.agreement_id, 'agreement:settlement-2026-001');
  assert.equal(result.supersedes_digest, null);
  assert.equal(result.binding_digest, binding.binding_digest);
  assert.equal(result.document_digest, computeDocumentSha256(FINAL_DOCUMENT));
  assert.equal(result.action_digest, computeReleaseActionDigest(ACTION));
  assert.deepEqual(result.required_parties, PARTIES);
  assert.equal(binding.document.byte_length, FINAL_DOCUMENT.byteLength);
  assert.equal(Object.hasOwn(result, 'accepted'), false);
  assert.equal(Object.hasOwn(result, 'provider_status'), false);
});

test('returns only the verified supersedes digest for amendment-chain joins', () => {
  const spec = baseSpec();
  spec.binding_id = 'dab:settlement-2026-001:v2';
  spec.supersedes_digest = `sha256:${'cd'.repeat(32)}`;
  const binding = sign(spec);
  const result = verifyDocumentActionBinding(binding, options({
    expectedBindingId: spec.binding_id,
    expectedSupersedesDigest: spec.supersedes_digest,
  }));

  assert.equal(result.valid, true);
  assert.equal(result.supersedes_digest, spec.supersedes_digest);
  const unpinned = verifyDocumentActionBinding(binding, options({
    issuerKeys: {},
    expectedBindingId: spec.binding_id,
  }));
  assert.equal(unpinned.valid, false);
  assert.equal(unpinned.supersedes_digest, null);
  assert.equal(
    verifyDocumentActionBinding(binding, options({
      expectedBindingId: spec.binding_id,
      expectedSupersedesDigest: `sha256:${'ef'.repeat(32)}`,
    })).reason,
    'supersedes_digest_mismatch',
  );
});

test('agreement_id is required, signed, returned, and independently pinnable', () => {
  const missing = structuredClone(sign());
  delete missing.agreement_id;
  assert.equal(verifyDocumentActionBinding(missing, options()).reason, 'malformed_binding');

  const wrongAgreement = structuredClone(sign());
  wrongAgreement.agreement_id = 'agreement:other';
  const resigned = resign(wrongAgreement);
  const result = verifyDocumentActionBinding(resigned, options());
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'agreement_id_mismatch');
  assert.equal(result.binding_id, 'dab:settlement-2026-001:v1');
  assert.equal(result.agreement_id, 'agreement:other');
});

test('document byte_length is signed and checked against supplied final bytes', () => {
  const binding = structuredClone(sign());
  binding.document.byte_length += 1;
  const resigned = resign(binding);
  const result = verifyDocumentActionBinding(resigned, options());

  assert.equal(result.valid, false);
  assert.equal(result.reason, 'document_byte_length_mismatch');
  assert.equal(result.document_digest, computeDocumentSha256(FINAL_DOCUMENT));
});

test('distinct parties may share a role, while duplicate party IDs refuse', () => {
  const valid = verifyDocumentActionBinding(sign(), options());
  assert.equal(valid.valid, true);
  assert.deepEqual(valid.required_parties.filter((party) => party.role === 'homeowner'), [
    { party_id: 'party:homeowner-alex', role: 'homeowner' },
    { party_id: 'party:homeowner-jordan', role: 'homeowner' },
  ]);

  const duplicate = baseSpec();
  duplicate.parties[2].party_id = duplicate.parties[1].party_id;
  assert.throws(() => sign(duplicate), /duplicate_party_id/);
});

test('money fields accept decimal strings only and reject minor-unit vocabulary in v1', () => {
  for (const template of [
    { ...ACTION, amount: 125000 },
    { ...ACTION, amount_minor: 12500000 },
    { ...ACTION, release_amount_minor: 12500000 },
  ]) {
    const spec = baseSpec();
    spec.release_action_template = template;
    assert.throws(() => sign(spec), /invalid_release_action/);
    assert.equal(computeReleaseActionDigest(template), null);
  }

  const numericTerm = baseSpec();
  numericTerm.material_terms[1].value = 125000;
  assert.throws(() => sign(numericTerm), /invalid_material_terms/);

  const minorTerm = baseSpec();
  minorTerm.material_terms[1] = { term_id: 'release_amount_minor', type: 'integer', value: 12500000 };
  assert.throws(() => sign(minorTerm), /invalid_material_terms/);
});

test('required-party omission refuses even under an otherwise valid pinned issuer signature', () => {
  const omitted = baseSpec();
  omitted.required_parties = omitted.required_parties.filter(
    (party) => party.party_id !== 'party:homeowner-jordan',
  );
  const result = verifyDocumentActionBinding(sign(omitted), options());
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'required_party_roster_mismatch');
});

test('document, media type, action, and binding substitutions refuse', () => {
  const binding = sign();
  const substitutedDocument = Buffer.from(FINAL_DOCUMENT);
  substitutedDocument[20] ^= 1;
  assert.equal(
    verifyDocumentActionBinding(binding, options({ documentBytes: substitutedDocument })).reason,
    'document_digest_mismatch',
  );
  assert.equal(
    verifyDocumentActionBinding(binding, options({ documentMediaType: 'text/plain' })).reason,
    'document_media_type_mismatch',
  );
  assert.equal(
    verifyDocumentActionBinding(
      binding,
      options({ releaseActionTemplate: { ...ACTION, amount: '125001.00' } }),
    ).reason,
    'action_digest_mismatch',
  );
  assert.equal(
    verifyDocumentActionBinding(binding, options({ expectedBindingId: 'dab:other' })).reason,
    'binding_id_mismatch',
  );
});

test('unknown members and vocabulary, omitted terms, and duplicate signatures refuse', () => {
  const binding = sign();

  const unknownMember = structuredClone(binding);
  unknownMember.provider_completion_status = 'complete';
  assert.equal(verifyDocumentActionBinding(unknownMember, options()).reason, 'malformed_binding');

  const embeddedKey = structuredClone(binding);
  embeddedKey.issuer_signatures[0].public_key = publicKeyB64u(ATTACKER);
  assert.equal(verifyDocumentActionBinding(embeddedKey, options()).reason, 'malformed_issuer_signature');

  const duplicateSignature = structuredClone(binding);
  duplicateSignature.issuer_signatures.push(structuredClone(duplicateSignature.issuer_signatures[0]));
  assert.equal(
    verifyDocumentActionBinding(duplicateSignature, options()).reason,
    'duplicate_issuer_signatures',
  );

  assert.equal(
    verifyDocumentActionBinding(binding, options({ allowedPartyRoles: ['contractor'] })).reason,
    'unknown_party_role',
  );
  assert.equal(
    verifyDocumentActionBinding(binding, options({ allowedActionTypes: ['escrow.release'] })).reason,
    'unknown_action_type',
  );
  assert.equal(
    verifyDocumentActionBinding(
      binding,
      options({ requiredMaterialTermIds: ['effective_date', 'missing_term'] }),
    ).reason,
    'required_material_term_missing',
  );

  const omittedField = structuredClone(binding);
  delete omittedField.material_terms[0].value;
  assert.equal(verifyDocumentActionBinding(omittedField, options()).reason, 'invalid_material_terms');
});

test('stale windows and unpinned or attacker-signed issuers refuse', () => {
  assert.equal(
    verifyDocumentActionBinding(sign(), options({ now: '2026-09-01T00:00:00Z' })).reason,
    'binding_expired',
  );

  const attackerBinding = sign(baseSpec(), ATTACKER, 'issuer:attacker');
  assert.equal(
    verifyDocumentActionBinding(attackerBinding, options()).reason,
    'issuer_key_not_pinned',
  );
  assert.equal(
    verifyDocumentActionBinding(sign(), options({ issuerKeys: {} })).reason,
    'issuer_key_not_pinned',
  );
});

test('binding digest commits to the complete core and excludes only digest/signature fields', () => {
  const binding = sign();
  assert.equal(computeDocumentActionBindingDigest(binding), binding.binding_digest);

  const changed = structuredClone(binding);
  changed.material_terms[1].value = '125000.01';
  assert.notEqual(computeDocumentActionBindingDigest(changed), binding.binding_digest);

  const signatureOnly = structuredClone(binding);
  signatureOnly.issuer_signatures[0].signature_b64u = 'A'.repeat(86);
  assert.equal(computeDocumentActionBindingDigest(signatureOnly), binding.binding_digest);
});

test('verification never throws for hostile JavaScript inputs', () => {
  const cyclic = structuredClone(sign());
  cyclic.release_action.template.loop = cyclic.release_action.template;

  const getter = structuredClone(sign());
  Object.defineProperty(getter, 'document', {
    enumerable: true,
    get() {
      throw new Error('hostile getter');
    },
  });

  const proxy = new Proxy({}, {
    getPrototypeOf() {
      throw new Error('hostile proxy');
    },
  });

  for (const candidate of [
    undefined,
    null,
    true,
    1,
    'binding',
    [],
    Object.create(null),
    cyclic,
    getter,
    proxy,
  ]) {
    assert.doesNotThrow(() => verifyDocumentActionBinding(candidate, options()));
    assert.equal(verifyDocumentActionBinding(candidate, options()).valid, false);
  }
  assert.doesNotThrow(() => verifyDocumentActionBinding(sign(), null));
  assert.equal(verifyDocumentActionBinding(sign(), null).valid, false);
});

test('public schema exposes the join, byte length, single pinned issuer signature, and no acceptance claim', () => {
  const schema = JSON.parse(fs.readFileSync(
    new URL('../../public/schemas/ep-document-action-binding.schema.json', import.meta.url),
    'utf8',
  ));
  assert.equal(schema.additionalProperties, false);
  assert.ok(schema.required.includes('agreement_id'));
  assert.ok(schema.properties.document.required.includes('byte_length'));
  assert.equal(schema.properties.issuer_signatures.maxItems, 1);
  assert.equal(Object.hasOwn(schema.properties, 'acceptance'), false);
  assert.match(schema.properties.required_parties.description, /not evidence of acceptance/i);
  assert.match(
    schema.$defs.canonicalObject.propertyNames.not.pattern,
    /amount_minor/,
  );
});

test('static real-crypto conformance vectors produce their declared verdicts', () => {
  const suite = JSON.parse(fs.readFileSync(
    new URL('../../conformance/vectors/document-action-binding.v1.json', import.meta.url),
    'utf8',
  ));
  assert.equal(suite.suite, 'EP-DOCUMENT-ACTION-BINDING-v1');
  assert.equal(suite.count, suite.vectors.length);

  for (const vector of suite.vectors) {
    const verify = {
      ...suite.defaults.verify,
      ...(vector.verify || {}),
    };
    const vectorOptions = {
      issuerKeys: suite.fixtures.issuer_keys,
      now: verify.now,
      allowedMediaTypes: verify.allowed_media_types,
      allowedPartyRoles: verify.allowed_party_roles,
      allowedActionTypes: verify.allowed_action_types,
      requiredMaterialTermIds: verify.required_material_term_ids,
      expectedBindingId: verify.expected_binding_id,
      expectedAgreementId: verify.expected_agreement_id,
      ...(verify.document === undefined
        ? {}
        : { documentBytes: Buffer.from(suite.fixtures.documents[verify.document], 'base64url') }),
      ...(verify.document_media_type === undefined
        ? {}
        : { documentMediaType: verify.document_media_type }),
      ...(verify.release_action === undefined
        ? {}
        : { releaseActionTemplate: suite.fixtures.actions[verify.release_action] }),
      ...(verify.expected_required_parties !== true
        ? {}
        : { expectedRequiredParties: suite.fixtures.required_parties }),
    };
    const result = verifyDocumentActionBinding(
      suite.fixtures.bindings[vector.binding],
      vectorOptions,
    );
    assert.equal(result.valid, vector.expect.valid, vector.id);
    assert.equal(result.reason, vector.expect.reason, vector.id);
    if (vector.expect.binding_digest !== undefined) {
      assert.equal(result.binding_digest, vector.expect.binding_digest, vector.id);
    }
  }
});
