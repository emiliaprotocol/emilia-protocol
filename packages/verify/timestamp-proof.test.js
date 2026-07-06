// SPDX-License-Identifier: Apache-2.0
//
// verifyTimestampProof() test. The happy-path vectors are REAL RFC 3161
// TimeStampTokens minted locally with `openssl ts` (RSA/SHA-256, CMS SignedData
// with the RFC 5652 signed-attributes form: contentType + messageDigest +
// signingCertificateV2). This exercises the full parse-and-verify path against a
// standards-conformant token, not a mock. The signer's SPKI DER (the pinned key)
// and a second, unrelated valid RSA SPKI (the "wrong pin") are embedded so the
// test is self-contained and reproducible offline.
//
// Provenance of the vectors (so a maintainer can regenerate them):
//   openssl req -new -newkey rsa:2048 -keyout tsa.key -nodes -x509 -days 3650 \
//     -subj "/CN=EP Test TSA/O=EMILIA Test" \
//     -addext "extendedKeyUsage=critical,timeStamping" -out tsa.crt
//   printf 'emilia-protocol checkpoint root test' > data.txt
//   openssl ts -query -data data.txt -sha256 -no_nonce -out req.tsq
//   openssl ts -reply -queryfile req.tsq -signer tsa.crt -inkey tsa.key -token_out -out token.der
//   (TOKEN1 covers SHA-256(data.txt) = DIGEST1; TOKEN2 covers a different file = DIGEST2)
//
// PATHS EXERCISED (each asserted below):
//   accept:  authentic, pinned, RSA-SHA256, signed-attrs, digest match, genTime extracted
//   accept:  pinned key supplied as array and as { id: key } object map
//   accept:  expectedDigest given as "sha256:<hex>", bare hex, and raw Buffer
//   refuse:  missing_token, missing_or_malformed_expected_digest, unpinned_tsa,
//            digest_mismatch, bad_signature (wrong valid key), bad_signature
//            (tampered token), unparseable_token (garbage + non-token DER),
//            not_signed_data (well-formed ContentInfo, wrong content OID)
//
// NOT exercised by a live vector (documented boundary, refused by construction):
//   ECDSA tokens, RSASSA-PSS, multi-signer tokens, no-signed-attrs tokens
//   (openssl always emits signed attributes). The parser supports the
//   no-signed-attrs shape (signature directly over eContent) and ECDSA; those
//   remain covered by code review + the structural refusals, not a mint.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { verifyTimestampProof, TIMESTAMP_PROOF_ALG } from './timestamp-proof.js';

const V = {
  DIGEST1: '8c554d22ef5028ca8314bcae8f6bd6b1d1b8717f366be3b582fbac3ec1a4b0bb',
  DIGEST2: '6636484c254cc7ec97be06d43f687d6e7cfbd9e188807b44b6c1253f70bbcd7f',
  GEN_TIME: '2026-07-06T03:54:49Z',
  TOKEN1: 'MIIC6wYJKoZIhvcNAQcCoIIC3DCCAtgCAQMxDzANBglghkgBZQMEAgEFADCBpwYLKoZIhvcNAQkQAQSggZcEgZQwgZECAQEGBCoDBAEwMTANBglghkgBZQMEAgEFAAQgjFVNIu9QKMqDFLyuj2vWsdG4cX82a+O1gvusPsGksLsCAQIYDzIwMjYwNzA2MDM1NDQ5WjAKAgEBgAIB9IEBZAEB/6AwpC4wLDEUMBIGA1UEAwwLRVAgVGVzdCBUU0ExFDASBgNVBAoMC0VNSUxJQSBUZXN0MYICFjCCAhICAQEwRDAsMRQwEgYDVQQDDAtFUCBUZXN0IFRTQTEUMBIGA1UECgwLRU1JTElBIFRlc3QCFApPxUFPArNHXcoEjcCGW8713Ip8MA0GCWCGSAFlAwQCAQUAoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MDM1NDQ5WjAvBgkqhkiG9w0BCQQxIgQgAal5/9QEFRIYpPzNpW+Y499A9LzP0OEs1nyu3ImgSNYwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgXypn8plPJ9pykPrEQFWOZ0ApgZP47wX1qBov7/hNFFowDQYJKoZIhvcNAQEBBQAEggEAEpJbOrSfII6AE3p9ewZAQgSwV6dKLTxMPu5rge7HCPHlbCTdhSV+jjlNK2F9RUdB4DqYRGvPzbu+mMRzFIXAGBEnePPwPUjuQWmlqczR8TN7fkEAWsFGmskrL4MVwaNIjhyFrRkVWpYMzdGV3Xduufq3q5XUPRxnASRa/0ZflOCblb3qhgHasSsc4R6gMjO4SonRibmDUVSjId4igSSQsxn5ekrsJ7IxN9vuoERaCj03rLh1Tp/6M9wT34eyke0IfjaOLVrfjWDKPrSmT++Jbgt6aWsXNHaLNcIEE4JUGgfziNcV74eIqGUHQRZRmo57noEAmz7dzQoZmG6cxt1gLw==',
  TOKEN2: 'MIIC6wYJKoZIhvcNAQcCoIIC3DCCAtgCAQMxDzANBglghkgBZQMEAgEFADCBpwYLKoZIhvcNAQkQAQSggZcEgZQwgZECAQEGBCoDBAEwMTANBglghkgBZQMEAgEFAAQgZjZITCVMx+yXvgbUP2h9bnz72eGIgHtEtsElP3C7zX8CAQMYDzIwMjYwNzA2MDM1NTIwWjAKAgEBgAIB9IEBZAEB/6AwpC4wLDEUMBIGA1UEAwwLRVAgVGVzdCBUU0ExFDASBgNVBAoMC0VNSUxJQSBUZXN0MYICFjCCAhICAQEwRDAsMRQwEgYDVQQDDAtFUCBUZXN0IFRTQTEUMBIGA1UECgwLRU1JTElBIFRlc3QCFApPxUFPArNHXcoEjcCGW8713Ip8MA0GCWCGSAFlAwQCAQUAoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MDM1NTIwWjAvBgkqhkiG9w0BCQQxIgQgrhFtUo93Tot0QWqbJtHyiTZQBQ8KmaL1CvSni1HkbIIwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgXypn8plPJ9pykPrEQFWOZ0ApgZP47wX1qBov7/hNFFowDQYJKoZIhvcNAQEBBQAEggEAq0NWMcCH31UgzdO1rZnz94xfvbUQdaIGgi1bhUDYa+LigwmWLUvFtZ3ep7UT4Udu7IdbC/Y2bmPRvmaQjjkkgme2WvPH9FyP+EkwEr2VOND7k099iavOyD9L3fF6OeJFAEJOxB0FMDbz1BnRXSm2XuwKoNRGUCfRF6bRN9olJC7NU+Yny0GEVQ+aTijGYRKIWrJEOZpAHN4UgQBFH4O5qKtAJ7cFQlTxESVBvS2fHWuRdFzxHQm+9KI5wIZ3FjIHqSxE+HXB4Y652PZ1FAVXv1DnvKFnRRBGuQrlEEiQGhGgRbZURNQpHveUHGMsDsY05YIYzcMV8T0/SsLsJhbPYQ==',
  TOKEN1_TAMPERED: 'MIIC6wYJKoZIhvcNAQcCoIIC3DCCAtgCAQMxDzANBglghkgBZQMEAgEFADCBpwYLKoZIhvcNAQkQAQSggZcEgZQwgZECAQEGBCoDBAEwMTANBglghkgBZQMEAgEFAAQgjFVNIu9QKMqDFLyuj2vWsdG4cX82a+O1gvusPsGksLsCAQIYDzIwMjYwNzA2MDM1NDQ5WjAKAgEBgAIB9IEBZAEB/6AwpC4wLDEUMBIGA1UEAwwLRVAgVGVzdCBUU0ExFDASBgNVBAoMC0VNSUxJQSBUZXN0MYICFjCCAhICAQEwRDAsMRQwEgYDVQQDDAtFUCBUZXN0IFRTQTEUMBIGA1UECgwLRU1JTElBIFRlc3QCFApPxUFPArNHXcoEjcCGW8713Ip8MA0GCWCGSAFlAwQCAQUAoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MDM1NDQ5WjAvBgkqhkiG9w0BCQQxIgQgAal5/9QEFRIYpPzNpW+Y499A9LzP0OEs1nyu3ImgSNYwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgXypn8plPJ9pykPrEQFWOZ0ApgZP47wX1qBov7/hNFFowDQYJKoZIhvcNAQEBBQAEggEAEpJbOrSfII6AE3p9ewZAQgSwV6dKLTxMPu5rge7HCPHlbCTdhSV+jjlNK2F9RUdB4DqYRGvPzbu+mMRzFIXAGBEnePPwPUjuQWmlqczR8TN7fkEAWsFGmskrL4MVwaNIjhyFrRkVWpYMzdGV3Xduufq3q5XUPRxnASRa/0ZflOCblb3qhgHasSsc4R6gMjO4SonRibmDUVSjId4igSSQsxn5ekrsJ7IxN9vuoERaCj03rLh1Tp/6M9wT34eyke0IfjaOLVrfjWDKPrSmT++Jbgt6aWsXNHaLNcIEE4JUGgfziNcV74eIqGUHQRZRmo57noEAmz7dzQoZmG5jxt1gLw==',
  SIGNER_SPKI: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtqo1wQcRsO9Cdm1fsyL7Cbi+rpgg4ayBykXrDy+P2Irj/0qiudo2D9SCjCB1dHAdgPSzAJ52GI16iP7WxRlL0SDEJE1XIE5qjy9YKZzGZjXBuuE4paD4k9Zna7bDoCYbxdTVN1NMJ4OGkC4BjV9Pte2h+4DnNziMdA0bqCeXMQlD87d64+AejpUtA2ed5RhClhyf8oEXjlFAEFDvgVY74N5lDzNBcUDnNHfpl8/S5XPfAl1y3IV++sEnwtgZA+uYnuIzcuyv9E+MT1/CvuFBkmgB4hJIsEhrK2TkR7LesHgP4Hq4TQ3CKsHvlymcteUfySwTCYgehoOWGxR0pVb7+wIDAQAB',
  OTHER_SPKI: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0FywTQRuaag9edMFvNLt/zmcA00akTynIoeRqxo6lIEiRRjMg/ociI/py+p3c4AamtOMs03qQBV/hrp6e4dySZYsKt6XPymXMf7+W1l8PEOn7lBjy/9lFVIcSedsvbii185S4Vx0WuWMZ6dIx/Iq9ngWV8agaJTEKg+Kfo3HHb/Rb0t7O5KDUFXUj8g4RrQpS9MgWFOmhbcX3zqw4SXkWjFH3bbyH4tLg/9OqOkYLtkFH+nMOHmx0zJbx9ROWkEUKTc+vdRiPXIaPi8VJ4RU2SXKAVXJ/NjkxOlxrSdYmvkWsv0CA6XARZ5iJ60r6t5ZDDciKlZYhc2kaQYQeTmIzwIDAQAB',
};

// ── ACCEPT ────────────────────────────────────────────────────────────────

test('exports the RFC3161 algorithm identifier', () => {
  assert.strictEqual(TIMESTAMP_PROOF_ALG, 'RFC3161');
});

test('accepts an authentic, pinned RFC 3161 token over the expected digest', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, true, r.reason);
  assert.strictEqual(r.gen_time, V.GEN_TIME);
  assert.match(r.tsa_key_id, /^sha256:[0-9a-f]{64}$/);
  assert.strictEqual(r.reason, undefined);
});

test('accepts a second token bound to a different digest (imprint binds per-token)', () => {
  const r = verifyTimestampProof(V.TOKEN2, 'sha256:' + V.DIGEST2, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, true, r.reason);
});

test('accepts when pinned keys are supplied as an array (one correct key present)', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, [V.OTHER_SPKI, V.SIGNER_SPKI]);
  assert.strictEqual(r.verified, true, r.reason);
});

test('accepts when pinned keys are supplied as an { id: key } object map', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, { alt: V.OTHER_SPKI, tsa: V.SIGNER_SPKI });
  assert.strictEqual(r.verified, true, r.reason);
});

test('accepts the expected digest as bare hex and as a raw Buffer', () => {
  const bare = verifyTimestampProof(V.TOKEN1, V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(bare.verified, true, bare.reason);
  const buf = verifyTimestampProof(V.TOKEN1, Buffer.from(V.DIGEST1, 'hex'), V.SIGNER_SPKI);
  assert.strictEqual(buf.verified, true, buf.reason);
});

// ── REFUSE (each with its distinct reason string) ───────────────────────────

test('refuses a missing token (fail-closed)', () => {
  for (const bad of [undefined, null, '', '   ']) {
    const r = verifyTimestampProof(bad, 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, 'missing_token');
    assert.strictEqual(r.gen_time, null);
    assert.strictEqual(r.tsa_key_id, null);
  }
});

test('refuses a missing or malformed expected digest', () => {
  for (const bad of ['', undefined, 'sha256:xyz', 'sha256:' + 'a'.repeat(10)]) {
    const r = verifyTimestampProof(V.TOKEN1, bad, V.SIGNER_SPKI);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, 'missing_or_malformed_expected_digest');
  }
});

test('refuses an unpinned TSA (empty / absent trust set)', () => {
  for (const bad of [undefined, null, [], {}]) {
    const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, bad);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, 'unpinned_tsa');
  }
});

test('refuses an unloadable pinned key as unpinned_tsa (fail-closed, no trust anchor survives)', () => {
  // A truncated/garbage "key" fails to load; the pinned set is then empty.
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, 'not-a-real-spki-key');
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'unpinned_tsa');
});

test('refuses a token whose messageImprint is not the expected digest', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST2, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'digest_mismatch');
});

test('refuses a token signed by a different (valid) key than the pinned one', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, V.OTHER_SPKI);
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'bad_signature');
});

test('refuses a token with a tampered signature under the correct pinned key', () => {
  const r = verifyTimestampProof(V.TOKEN1_TAMPERED, 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'bad_signature');
});

test('refuses unparseable DER (garbage bytes)', () => {
  const r = verifyTimestampProof('!!!!not base64 at all????', 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'unparseable_token');
});

test('refuses a well-formed ContentInfo whose contentType OID is not signedData', () => {
  // SEQUENCE { OID 1.2.840.113549.1.7.1 (pkcs7-data), [0] {} } — valid DER,
  // valid ContentInfo shape, but NOT a SignedData -> distinct not_signed_data.
  const dataOid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
  const explicit0 = Buffer.from([0xa0, 0x00]);
  const body = Buffer.concat([dataOid, explicit0]);
  const der = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  const r = verifyTimestampProof(der.toString('base64'), 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.reason, 'not_signed_data');
});

test('binds the digest BEFORE reporting a signature verdict (wrong digest refuses even with a valid signer)', () => {
  // Correct signer key, but the caller expected the OTHER token's digest:
  // must refuse with digest_mismatch, never leak a signature-based verdict.
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST2, V.SIGNER_SPKI);
  assert.strictEqual(r.reason, 'digest_mismatch');
});

test('gen_time is a well-formed RFC 3339 UTC instant that parses', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  assert.strictEqual(r.verified, true, r.reason);
  assert.ok(!Number.isNaN(Date.parse(r.gen_time)));
  assert.match(r.gen_time, /Z$/);
});

test('tsa_key_id is the SHA-256 fingerprint of the pinned SPKI that verified', () => {
  const r = verifyTimestampProof(V.TOKEN1, 'sha256:' + V.DIGEST1, V.SIGNER_SPKI);
  const expected = 'sha256:' + crypto.createHash('sha256')
    .update(Buffer.from(V.SIGNER_SPKI, 'base64')).digest('hex');
  assert.strictEqual(r.tsa_key_id, expected);
});
