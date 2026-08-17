// SPDX-License-Identifier: Apache-2.0
/**
 * EP-COSE-ENCODING-v0.1 - encoding-equivalence profile tests.
 *
 * Regenerates every artifact in conformance/encoding-equivalence/vectors.json
 * from the recorded test seeds and asserts byte equality (Ed25519 signing and
 * the deterministic encoders are both deterministic, so the whole pipeline is
 * reproducible bit-for-bit), then runs the hostile vectors and the fail-closed
 * edges. The CAID leg is cross-checked against the reference implementation in
 * caid/impl/js/caid.mjs with the registry definition for payment.release.1,
 * and the deterministic CBOR bytes are cross-checked against cbor-x's decoder
 * (an independent codebase agreeing on the semantics of our bytes).
 *
 * Placement note: this suite lives in tests/ (not next to the module in
 * packages/verify) because vitest.config.js excludes packages/** - package
 * suites run on Node's built-in runner via each package's own test script,
 * which is enumerated in packages/verify/package.json and out of scope here.
 * Importing the src .ts directly from tests/ is the established pattern
 * (e.g. tests/aec-platform-attestation.test.ts).
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { decode as cborxDecode } from 'cbor-x';

import {
  COSE_ENCODING_PROFILE,
  CBOR_DETERMINISTIC_ORDER,
  COSE_RECEIPT_CONTENT_TYPE,
  COSE_ALG_EDDSA,
  COSE_HEADER_EP_CAID,
  encodeDeterministicCbor8949,
  decodeDeterministicCbor8949,
  receiptToCborBytes,
  receiptFromCborBytes,
  receiptActionCaid,
  buildReceiptCoseSign1,
  verifyReceiptCoseSign1,
} from '../packages/verify/src/receipt-cose-encoding.ts';
import { canonicalize, verifyReceipt } from '../packages/verify/src/index.ts';
// Reference CAID implementation (jcs-sha256 suite) + registry definitions.
// @ts-expect-error plain .mjs reference implementation without types
import { computeCaid } from '../caid/impl/js/caid.mjs';

const ROOT = path.join(__dirname, '..');
const suite = JSON.parse(
  readFileSync(path.join(ROOT, 'conformance', 'encoding-equivalence', 'vectors.json'), 'utf8'),
);
const registry = JSON.parse(
  readFileSync(path.join(ROOT, 'caid', 'registry', 'action-types.json'), 'utf8'),
);

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function privateKeyFromSeedHex(seedHex: string): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

const issuerKey = privateKeyFromSeedHex(suite.keys.issuer.seed_hex);
const envelopeKey = privateKeyFromSeedHex(suite.keys.envelope.seed_hex);
const issuerPub = suite.keys.issuer.public_key_spki_b64u as string;
const envelopePub = suite.keys.envelope.public_key_spki_b64u as string;
const receipt = suite.receipt;
const expected = suite.expected;

function vectorById(id: string) {
  const v = suite.vectors.find((entry: any) => entry.id === id);
  expect(v, `vector ${id} present`).toBeTruthy();
  return v;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

describe('suite metadata', () => {
  it('names the profile and the exact ordering rule it ships', () => {
    expect(suite.suite).toBe(COSE_ENCODING_PROFILE);
    expect(CBOR_DETERMINISTIC_ORDER).toBe('rfc8949-4.2.1-bytewise-encoded-key');
    expect(suite.deterministic_encoding.rule).toBe('RFC 8949 Section 4.2.1');
    expect(suite.deterministic_encoding.map_key_order).toContain('NOT the RFC 7049');
  });

  it('recorded public keys derive from the recorded seeds', () => {
    for (const role of ['issuer', 'envelope'] as const) {
      const priv = privateKeyFromSeedHex(suite.keys[role].seed_hex);
      const spki = crypto.createPublicKey(priv)
        .export({ type: 'spki', format: 'der' }).toString('base64url');
      expect(spki).toBe(suite.keys[role].public_key_spki_b64u);
    }
  });

  it('the recorded receipt reproduces from the issuer seed and verifies', () => {
    const sig = crypto
      .sign(null, Buffer.from(canonicalize(receipt.payload), 'utf8'), issuerKey)
      .toString('base64url');
    expect(sig).toBe(receipt.signature.value);
    expect(verifyReceipt(receipt, issuerPub).valid).toBe(true);
  });
});

describe('canonical JSON leg', () => {
  it('canonical bytes and digest match the recorded vector', () => {
    const canonical = canonicalize(receipt);
    expect(canonical).toBe(expected.receipt_canonical_json);
    expect(crypto.createHash('sha256').update(canonical, 'utf8').digest('hex'))
      .toBe(expected.receipt_canonical_sha256_hex);
  });

  it('the CAID matches the reference implementation under the registry definition', () => {
    const local = receiptActionCaid(receipt.payload.action);
    expect(local.ok).toBe(true);
    if (!local.ok) return;
    expect(local.value.caid).toBe(expected.caid);
    expect(local.value.digest).toBe(expected.caid_action_digest);
    const ref = computeCaid(receipt.payload.action, {
      suite: 'jcs-sha256',
      definitions: registry.types,
    });
    expect(ref.caid).toBe(expected.caid);
    expect(ref.digest).toBe(expected.caid_action_digest);
  });
});

describe('deterministic CBOR mapping leg', () => {
  it('encodes to the recorded deterministic bytes', () => {
    const cbor = receiptToCborBytes(receipt);
    expect(cbor.ok).toBe(true);
    if (!cbor.ok) return;
    expect(hex(cbor.value)).toBe(expected.receipt_cbor_hex);
  });

  it('round-trips: CBOR -> JSON value -> identical canonical bytes -> identical CBOR bytes', () => {
    const bytes = new Uint8Array(Buffer.from(expected.receipt_cbor_hex, 'hex'));
    const back = receiptFromCborBytes(bytes);
    expect(back.ok).toBe(true);
    if (!back.ok) return;
    expect(canonicalize(back.value)).toBe(expected.receipt_canonical_json);
    const again = receiptToCborBytes(back.value);
    expect(again.ok).toBe(true);
    if (!again.ok) return;
    expect(hex(again.value)).toBe(expected.receipt_cbor_hex);
  });

  it('the CAID is byte-identical when recomputed from the CBOR-decoded action', () => {
    const bytes = new Uint8Array(Buffer.from(expected.receipt_cbor_hex, 'hex'));
    const back = receiptFromCborBytes(bytes);
    expect(back.ok).toBe(true);
    if (!back.ok) return;
    const caid = receiptActionCaid((back.value as any).payload.action);
    expect(caid.ok).toBe(true);
    if (!caid.ok) return;
    expect(caid.value.caid).toBe(vectorById('caid-encoding-invariance').expect.caid);
    expect(caid.value.caid).toBe(expected.caid);
  });

  it('an independent decoder (cbor-x) reads our deterministic bytes to the same value', () => {
    const decoded = cborxDecode(Buffer.from(expected.receipt_cbor_hex, 'hex'));
    expect(isDeepStrictEqual(decoded, receipt)).toBe(true);
  });

  it('JCS member order and RFC 8949 key order genuinely differ for this receipt', () => {
    // JCS: '@version' first (UTF-16 order). RFC 8949: 'payload' first, because
    // its 7-byte key encodes with header 0x67 < '@version' header 0x68. The
    // profile proves value-level equivalence across the two orders.
    expect(expected.receipt_canonical_json.startsWith('{"@version"')).toBe(true);
    const firstKey = encodeDeterministicCbor8949('payload');
    expect(firstKey.ok).toBe(true);
    if (!firstKey.ok) return;
    expect(expected.receipt_cbor_hex.startsWith('a3' + hex(firstKey.value))).toBe(true);
  });
});

describe('COSE_Sign1 transport envelope', () => {
  it('builds the recorded envelope byte-for-byte and its payload IS the canonical JSON bytes', () => {
    const built = buildReceiptCoseSign1(receipt, {
      envelopePrivateKey: envelopeKey,
      kid: expected.cose_kid,
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(hex(built.value.cose)).toBe(expected.cose_sign1_hex);
    expect(hex(built.value.protectedHeaderBytes)).toBe(expected.cose_protected_header_hex);
    expect(built.value.caid).toBe(expected.caid);
    const payloadSha = crypto.createHash('sha256').update(built.value.payload).digest('hex');
    expect(payloadSha).toBe(expected.cose_payload_sha256_hex);
    // The equality the profile exists for: envelope payload digest ==
    // canonical JSON digest, so the receipt's own signature keeps verifying
    // over exactly the carried bytes.
    expect(payloadSha).toBe(expected.receipt_canonical_sha256_hex);
    expect(Buffer.from(built.value.payload).toString('utf8'))
      .toBe(expected.receipt_canonical_json);
  });

  it('accept vector: verifies under both pinned keys with every check true', () => {
    const vector = vectorById('cose-verify-accept');
    const result = verifyReceiptCoseSign1(
      new Uint8Array(Buffer.from(expected.cose_sign1_hex, 'hex')),
      {
        envelopePublicKeyBase64url: envelopePub,
        receiptIssuerPublicKeyBase64url: issuerPub,
        expectedCaid: expected.caid,
      },
    );
    expect(result.valid).toBe(true);
    expect(result.checks).toEqual(vector.expect.checks);
    expect(result.caid).toBe(expected.caid);
    expect(result.payloadSha256).toBe(expected.receipt_canonical_sha256_hex);
  });

  it('protected headers carry alg EdDSA, the content type, and the caid label', () => {
    const headers = decodeDeterministicCbor8949(
      new Uint8Array(Buffer.from(expected.cose_protected_header_hex, 'hex')),
      { textKeysOnly: false },
    );
    expect(headers.ok).toBe(true);
    if (!headers.ok) return;
    const map = headers.value as Map<unknown, unknown>;
    expect(map.get(1)).toBe(COSE_ALG_EDDSA);
    expect(map.get(3)).toBe(COSE_RECEIPT_CONTENT_TYPE);
    expect(map.get(COSE_HEADER_EP_CAID)).toBe(expected.caid);
  });
});

describe('hostile vectors (fail-closed, named reasons)', () => {
  it.each([
    ['hostile-unsorted-map-keys'],
    ['hostile-non-shortest-int'],
    ['hostile-indefinite-length-map'],
  ])('%s refuses with non_deterministic_encoding', (id) => {
    const vector = vectorById(id);
    const result = decodeDeterministicCbor8949(
      new Uint8Array(Buffer.from(vector.input_cbor_hex, 'hex')),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('non_deterministic_encoding');
  });

  it('tampered payload under intact headers refuses at the envelope signature', () => {
    const vector = vectorById('hostile-tampered-payload-intact-headers');
    const result = verifyReceiptCoseSign1(
      new Uint8Array(Buffer.from(vector.input_cose_hex, 'hex')),
      {
        envelopePublicKeyBase64url: envelopePub,
        receiptIssuerPublicKeyBase64url: issuerPub,
      },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('envelope_signature_invalid');
    expect(result.checks.envelope_signature).toBe(false);
    // The tampered bytes really do differ from the accepted envelope.
    expect(vector.input_cose_hex).not.toBe(expected.cose_sign1_hex);
  });
});

describe('fail-closed edges beyond the recorded vectors', () => {
  const goodCose = () => new Uint8Array(Buffer.from(expected.cose_sign1_hex, 'hex'));

  function resignEnvelope(mutate: (parts: {
    prot: Uint8Array; payload: Uint8Array;
  }) => { prot?: Uint8Array; payload?: Uint8Array }): Uint8Array {
    // Build a structurally valid, correctly SIGNED envelope with mutated
    // contents, so verification proceeds past the envelope signature and the
    // later checks are exercised on their own.
    const decoded = decodeDeterministicCbor8949(goodCose().subarray(1), { textKeysOnly: false });
    if (!decoded.ok) throw new Error('fixture decode failed');
    const [prot, , payload] = decoded.value as [Uint8Array, Map<unknown, unknown>, Uint8Array, Uint8Array];
    const mutated = mutate({ prot, payload });
    const newProt = mutated.prot ?? prot;
    const newPayload = mutated.payload ?? payload;
    const sigStruct = encodeDeterministicCbor8949(['Signature1', newProt, new Uint8Array(0), newPayload]);
    if (!sigStruct.ok) throw new Error('sig structure encode failed');
    const signature = new Uint8Array(crypto.sign(null, sigStruct.value, envelopeKey));
    const body = encodeDeterministicCbor8949([newProt, new Map(), newPayload, signature]);
    if (!body.ok) throw new Error('body encode failed');
    return new Uint8Array(Buffer.concat([Buffer.from([0xd2]), Buffer.from(body.value)]));
  }

  const pins = {
    envelopePublicKeyBase64url: envelopePub,
    receiptIssuerPublicKeyBase64url: issuerPub,
  };

  it('trailing bytes refuse', () => {
    const withTrailer = new Uint8Array(Buffer.concat([
      Buffer.from(expected.receipt_cbor_hex, 'hex'), Buffer.from([0x00]),
    ]));
    const result = decodeDeterministicCbor8949(withTrailer);
    expect(result).toEqual({ ok: false, reason: 'trailing_bytes' });
  });

  it('truncated input refuses as malformed', () => {
    const truncated = new Uint8Array(Buffer.from(expected.receipt_cbor_hex, 'hex')).subarray(0, 40);
    const result = decodeDeterministicCbor8949(truncated);
    expect(result).toEqual({ ok: false, reason: 'malformed_cbor' });
  });

  it('floats and tags are outside the profile domain', () => {
    // f94800 = half-precision 8.0; c26161 = tag 2 around "a".
    expect(decodeDeterministicCbor8949(new Uint8Array(Buffer.from('f94800', 'hex'))))
      .toEqual({ ok: false, reason: 'unsupported_item' });
    expect(decodeDeterministicCbor8949(new Uint8Array(Buffer.from('c26161', 'hex'))))
      .toEqual({ ok: false, reason: 'unsupported_item' });
  });

  it('duplicate map keys refuse as malformed', () => {
    // {"a":1,"a":2} with identical encoded keys.
    const dup = new Uint8Array(Buffer.from('a2616101616102', 'hex'));
    expect(decodeDeterministicCbor8949(dup)).toEqual({ ok: false, reason: 'malformed_cbor' });
  });

  it('non-integer numbers refuse at the encoding boundary', () => {
    expect(receiptToCborBytes({ amount: 1.25 }))
      .toEqual({ ok: false, reason: 'outside_canonical_profile' });
  });

  it('unpaired surrogates refuse at the encoding boundary', () => {
    expect(encodeDeterministicCbor8949('\ud800'))
      .toEqual({ ok: false, reason: 'unsupported_item' });
  });

  it('a wrong envelope key refuses the envelope signature', () => {
    const wrongKey = crypto.generateKeyPairSync('ed25519')
      .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = verifyReceiptCoseSign1(goodCose(), {
      ...pins, envelopePublicKeyBase64url: wrongKey,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('envelope_signature_invalid');
  });

  it('a wrong issuer key refuses the inner receipt, even under a valid envelope', () => {
    const wrongKey = crypto.generateKeyPairSync('ed25519')
      .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = verifyReceiptCoseSign1(goodCose(), {
      ...pins, receiptIssuerPublicKeyBase64url: wrongKey,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_invalid');
    expect(result.checks.envelope_signature).toBe(true);
  });

  it('a validly re-signed envelope over NON-canonical payload JSON refuses', () => {
    const spaced = new TextEncoder().encode(
      JSON.stringify(JSON.parse(expected.receipt_canonical_json), null, 1),
    );
    const result = verifyReceiptCoseSign1(
      resignEnvelope(() => ({ payload: spaced })), pins,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('payload_not_canonical_json');
    expect(result.checks.envelope_signature).toBe(true);
  });

  it('a caid header not matching the carried action refuses caid_mismatch', () => {
    const headers = decodeDeterministicCbor8949(
      new Uint8Array(Buffer.from(expected.cose_protected_header_hex, 'hex')),
      { textKeysOnly: false },
    );
    if (!headers.ok) throw new Error('header decode failed');
    const map = new Map(headers.value as Map<unknown, unknown>);
    map.set(COSE_HEADER_EP_CAID, expected.caid.slice(0, -4) + 'AAAA');
    const encoded = encodeDeterministicCbor8949(map);
    if (!encoded.ok) throw new Error('header encode failed');
    const result = verifyReceiptCoseSign1(
      resignEnvelope(() => ({ prot: encoded.value })), pins,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('caid_mismatch');
    expect(result.checks.receipt_signature).toBe(true);
  });

  it('a pinned expectedCaid that differs refuses caid_mismatch', () => {
    const result = verifyReceiptCoseSign1(goodCose(), {
      ...pins,
      expectedCaid: 'caid:1:payment.release.1:jcs-sha256:' + 'A'.repeat(43),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('caid_mismatch');
  });

  it('an untagged COSE_Sign1 refuses (the profile requires tag 18)', () => {
    const result = verifyReceiptCoseSign1(goodCose().subarray(1), pins);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('cose_structure_invalid');
  });

  it('junk inputs refuse instead of throwing', () => {
    for (const junk of [undefined, null, 'text', 42, {}, new Uint8Array(0), new Uint8Array([0xff])]) {
      const result = verifyReceiptCoseSign1(junk as any, pins);
      expect(result.valid).toBe(false);
      expect(typeof result.reason).toBe('string');
    }
  });
});
