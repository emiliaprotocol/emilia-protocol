// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  parseTpm2Quote,
  parseTpm2Signature,
  verifyTpm2Quote,
} from './tpm-quote-verifier.js';

const fixture = JSON.parse(readFileSync(
  new URL('./tpm2-tools-swtpm-quote.fixture.json', import.meta.url),
  'utf8',
));

function options(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    expectedNonce: fixture.expected_nonce,
    trustedAkFingerprints: fixture.trusted_ak_fingerprints,
    expectedPcrSelection: fixture.expected_pcr_selection,
    expectedPcrValues: fixture.expected_pcr_values,
    ...overrides,
  };
}

function clone(value: any): any {
  return structuredClone(value);
}

function mutateBase64(value: string, mutate: (bytes: Buffer) => void): string {
  const bytes = Buffer.from(value, 'base64');
  mutate(bytes);
  return bytes.toString('base64');
}

describe('TPM 2.0 quote parser', () => {
  it('parses the tpm2-tools/swtpm interoperability fixture', () => {
    const parsed = parseTpm2Quote(Buffer.from(fixture.quote.quoted, 'base64'));
    expect(parsed.magic).toBe(0xff544347);
    expect(parsed.type).toBe(0x8018);
    expect(parsed.extraData.toString('hex')).toBe(fixture.expected_nonce);
    expect(parsed.pcrSelection).toEqual([
      { algorithm: 0x000b, bank: 'sha256', indices: [0, 1, 2] },
    ]);
    expect(parsed.pcrDigest.toString('hex')).toBe('d44d88b4b87054c652a3ae6f9754e9d4886b8f2d3a0ca47846dc24d7811a8a8c');
  });

  it('parses an RSASSA/SHA-256 TPMT_SIGNATURE', () => {
    const parsed = parseTpm2Signature(Buffer.from(fixture.quote.signature, 'base64'));
    expect(parsed.algorithm).toBe(0x0014);
    expect(parsed.hashAlgorithm).toBe(0x000b);
    expect(parsed.keyType).toBe('rsa');
    expect(parsed.value).toHaveLength(256);
  });

  it('rejects bad magic, non-quote attestations, and trailing bytes', () => {
    const message = Buffer.from(fixture.quote.quoted, 'base64');
    const badMagic = Buffer.from(message);
    badMagic[0] ^= 0xff;
    expect(() => parseTpm2Quote(badMagic)).toThrow(/magic/);

    const badType = Buffer.from(message);
    badType.writeUInt16BE(0x8017, 4);
    expect(() => parseTpm2Quote(badType)).toThrow(/TPM_ST_ATTEST_QUOTE/);

    expect(() => parseTpm2Quote(Buffer.concat([message, Buffer.from([0])]))).toThrow(/trailing bytes/);
  });

  it('explicitly rejects unsupported signature and hash algorithms', () => {
    const signature = Buffer.from(fixture.quote.signature, 'base64');
    const unsupportedSignature = Buffer.from(signature);
    unsupportedSignature.writeUInt16BE(0x0016, 0);
    expect(() => parseTpm2Signature(unsupportedSignature)).toThrow(/unsupported TPM signature algorithm 0x0016/);

    const unsupportedHash = Buffer.from(signature);
    unsupportedHash.writeUInt16BE(0x000c, 2);
    expect(() => parseTpm2Signature(unsupportedHash)).toThrow(/unsupported TPM signature hash algorithm 0x000c/);
  });
});

describe('fail-closed TPM 2.0 evidence verification', () => {
  it('verifies structure, challenge, PCR composite, signature, and pinned AK', () => {
    expect(fixture.source.hardware_backed).toBe(false);
    const result = verifyTpm2Quote(fixture.quote, options());
    expect(result).toMatchObject({
      ok: true,
      reason: 'tpm_quote_verified',
      akFingerprint: fixture.trusted_ak_fingerprints[0],
      pcrDigest: 'd44d88b4b87054c652a3ae6f9754e9d4886b8f2d3a0ca47846dc24d7811a8a8c',
      selection: fixture.expected_pcr_selection,
      clockSafe: true,
    });
  });

  it('requires verifier-supplied freshness and AK trust inputs', () => {
    expect(verifyTpm2Quote(fixture.quote, options({ expectedNonce: undefined }))).toMatchObject({
      ok: false,
      reason: 'tpm_quote_malformed',
    });
    expect(verifyTpm2Quote(fixture.quote, options({ trustedAkFingerprints: [] }))).toMatchObject({
      ok: false,
      reason: 'tpm_quote_malformed',
    });
    expect(verifyTpm2Quote(fixture.quote, options({
      trustedAkFingerprints: [`sha256:${'00'.repeat(32)}`],
    }))).toMatchObject({
      ok: false,
      reason: 'tpm_ak_not_trusted',
    });
  });

  it('rejects both metadata and signed challenge mismatches', () => {
    expect(verifyTpm2Quote(fixture.quote, options({
      expectedNonce: 'ff'.repeat(16),
    }))).toMatchObject({
      ok: false,
      reason: 'tpm_nonce_metadata_mismatch',
    });

    const quote = clone(fixture.quote);
    quote.nonce = 'ff'.repeat(16);
    expect(verifyTpm2Quote(quote, options())).toMatchObject({
      ok: false,
      reason: 'tpm_nonce_metadata_mismatch',
    });
  });

  it('rejects a PCR-selection policy mismatch before accepting evidence', () => {
    expect(verifyTpm2Quote(fixture.quote, options({
      expectedPcrSelection: { sha256: [0, 1, 7] },
      expectedPcrValues: {
        sha256: {
          0: fixture.expected_pcr_values.sha256[0],
          1: fixture.expected_pcr_values.sha256[1],
          7: '00'.repeat(32),
        },
      },
    }))).toMatchObject({
      ok: false,
      reason: 'tpm_pcr_selection_mismatch',
    });
  });

  it('rejects unapproved PCR values and PCR-composite substitution', () => {
    const expected = clone(fixture.expected_pcr_values);
    expected.sha256[1] = '00'.repeat(32);
    expect(verifyTpm2Quote(fixture.quote, options({ expectedPcrValues: expected }))).toMatchObject({
      ok: false,
      reason: 'tpm_pcr_value_not_allowed',
    });

    const quote = clone(fixture.quote);
    quote.pcr_values.sha256[1] = '00'.repeat(32);
    expect(verifyTpm2Quote(quote, options({
      expectedPcrValues: quote.pcr_values,
    }))).toMatchObject({
      ok: false,
      reason: 'tpm_pcr_digest_mismatch',
    });
  });

  it('rejects signature substitution', () => {
    const quote = clone(fixture.quote);
    quote.signature = mutateBase64(quote.signature, (bytes) => {
      bytes[bytes.length - 1] ^= 0x01;
    });
    expect(verifyTpm2Quote(quote, options())).toMatchObject({
      ok: false,
      reason: 'tpm_quote_signature_invalid',
    });
  });

  it('rejects unsupported algorithms before treating the evidence as verified', () => {
    const quote = clone(fixture.quote);
    quote.signature = mutateBase64(quote.signature, (bytes) => {
      bytes.writeUInt16BE(0x0016, 0);
    });
    const result = verifyTpm2Quote(quote, options());
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('tpm_quote_malformed');
    expect(result.detail).toMatch(/unsupported TPM signature algorithm/);
  });

  it('uses a closed outer schema and strict base64', () => {
    const withUnknown = { ...fixture.quote, trusted: true };
    expect(verifyTpm2Quote(withUnknown, options())).toMatchObject({
      ok: false,
      reason: 'tpm_quote_malformed',
    });

    const nonCanonical = clone(fixture.quote);
    nonCanonical.quoted = `${nonCanonical.quoted}\n`;
    expect(verifyTpm2Quote(nonCanonical, options())).toMatchObject({
      ok: false,
      reason: 'tpm_quote_malformed',
    });
  });
});
