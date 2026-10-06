// SPDX-License-Identifier: Apache-2.0
// Deterministically regenerate the EP-SD-v1 conformance corpus.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createSelectiveDisclosurePresentation,
  prepareSelectiveDisclosure,
  sdCommitmentDigest,
  sdPresentationBindingDigest,
} from '../../packages/verify/dist/receipt-selective-disclosure.js';
import { canonicalizeStrictJson } from '../../packages/verify/dist/strict-json.js';

const vectorPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vectors.json');
const vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function privateKeyFrom(pkcs8B64u) {
  return crypto.createPrivateKey({
    key: Buffer.from(pkcs8B64u, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
}

const issuerPrivate = privateKeyFrom(vectors.keys.issuer.pkcs8_b64u);
const holderPrivate = privateKeyFrom(vectors.keys.holder.pkcs8_b64u);

function signedReceipt(payload) {
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(
        null,
        Buffer.from(canonicalizeStrictJson(payload), 'utf8'),
        issuerPrivate,
      ).toString('base64url'),
    },
  };
}

vectors.source_payload.caid = vectors.source_payload.caid.replace(/^caid:/, 'canactid:');
const prepared = prepareSelectiveDisclosure(
  vectors.source_payload,
  vectors.disclosable_paths,
  vectors.salts,
);
if (!prepared.ok) throw new Error(`preparation failed: ${prepared.refusals.join(', ')}`);

const receipt = signedReceipt(prepared.payload);
vectors.disclosure_ready_receipt = receipt;
vectors.openings = prepared.openings;

for (const entry of vectors.presentations) {
  const withHolder = entry.name === 'full-disclosure-with-holder-proof';
  const rebuilt = createSelectiveDisclosurePresentation(
    receipt,
    prepared.openings,
    entry.presentation.disclosed.map(({ path: disclosurePath }) => disclosurePath),
    entry.presentation.binding,
    withHolder
      ? {
          holder: {
            privateKey: holderPrivate,
            publicKeySpkiB64u: vectors.keys.holder.spki_b64u,
          },
        }
      : {},
  );
  if (!rebuilt.ok) throw new Error(`${entry.name} failed: ${rebuilt.refusals.join(', ')}`);
  entry.presentation = rebuilt.presentation;
  entry.binding_digest_hex = sdPresentationBindingDigest(
    rebuilt.presentation.receipt,
    rebuilt.presentation.disclosed,
    rebuilt.presentation.binding,
  ).toString('hex');
  entry.expect.caid = vectors.source_payload.caid;
}

const full = vectors.presentations.find(({ name }) => name === 'full-disclosure-with-holder-proof').presentation;
const partial = vectors.presentations.find(({ name }) => name === 'amount-and-currency-only').presentation;
const zero = vectors.presentations.find(({ name }) => name === 'zero-disclosure').presentation;

for (const entry of vectors.hostile) {
  switch (entry.name) {
    case 'forged-opening-wrong-value': {
      entry.presentation = clone(partial);
      entry.presentation.disclosed[0].value = '1.00';
      break;
    }
    case 'swapped-opening-across-fields': {
      entry.presentation = clone(full);
      entry.presentation.disclosed = [{
        path: 'action.parameters.memo',
        ...clone(prepared.openings['action.parameters.amount']),
      }];
      break;
    }
    case 'non-redactable-caid-committed': {
      const payload = clone(prepared.payload);
      payload.caid = `ep-sd-commit:${sdCommitmentDigest(
        'caid',
        vectors.salts['action.parameters.amount'],
        vectors.source_payload.caid,
      )}`;
      payload.disclosure.paths = ['action.parameters.amount', 'caid'];
      entry.presentation = {
        '@version': 'EP-SD-PRESENTATION-v1',
        receipt: signedReceipt(payload),
        disclosed: [],
        binding: clone(entry.presentation.binding),
      };
      break;
    }
    case 'audience-replay':
      entry.presentation = clone(full);
      break;
    case 'nonce-replay':
      entry.presentation = clone(partial);
      break;
    case 'opening-without-salt':
      entry.presentation = clone(partial);
      delete entry.presentation.disclosed[0].salt;
      break;
    case 'salt-below-128-bits':
      entry.presentation = clone(partial);
      entry.presentation.disclosed[0].salt = 'AAAA';
      break;
    case 'salt-reuse-across-fields':
      entry.presentation = clone(partial);
      entry.presentation.disclosed[1].salt = entry.presentation.disclosed[0].salt;
      break;
    case 'tampered-signed-payload':
      entry.presentation = clone(zero);
      entry.presentation.receipt.payload.action.parameters.amount =
        `ep-sd-commit:sha256:${'0'.repeat(64)}`;
      break;
    case 'required-field-not-disclosed':
      entry.presentation = clone(zero);
      break;
    default:
      throw new Error(`unknown hostile vector: ${entry.name}`);
  }
}

fs.writeFileSync(vectorPath, `${JSON.stringify(vectors, null, 2)}\n`);
