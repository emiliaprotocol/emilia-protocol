// SPDX-License-Identifier: Apache-2.0

/**
 * Strict TPM 2.0 quote verifier for EP-TPM-QUOTE-v1 evidence.
 *
 * This verifier is intentionally narrow:
 * - TPMS_ATTEST quote structures only;
 * - SHA-256 PCR banks and SHA-256 signatures only;
 * - RSASSA-PKCS1-v1_5 or ECDSA signatures;
 * - a caller-pinned Attestation Key (AK) SPKI fingerprint;
 * - an explicit verifier challenge and expected PCR selection/value allowlist.
 *
 * It does not claim that an AK is hardware-backed or manufacturer-endorsed.
 * Enrollment of the pinned AK, including any AK-to-EK credential ceremony, is
 * a separate trust-establishment step.
 */

import crypto from 'node:crypto';

export const TPM_QUOTE_FORMAT = 'EP-TPM-QUOTE-v1';

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_QUOTE = 0x8018;
const TPM_ALG_SHA256 = 0x000b;
const TPM_ALG_RSASSA = 0x0014;
const TPM_ALG_ECDSA = 0x0018;
const SHA256_BYTES = 32;
const MAX_ATTEST_BYTES = 16 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_PCR_BANKS = 16;
const MAX_PCR_SELECT_BYTES = 4;
const MAX_NONCE_BYTES = 64;
const QUOTE_FIELDS = new Set([
  '@format',
  'quoted',
  'signature',
  'ak_public',
  'nonce',
  'pcr_values',
]);

function fail(reason, detail) {
  return {
    ok: false,
    reason,
    ...(detail === undefined ? {} : { detail }),
  };
}

function hexAlgorithm(value) {
  return `0x${value.toString(16).padStart(4, '0')}`;
}

function isPlainRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function strictBase64(value, field, maxBytes) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError(`${field} must be canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.length > maxBytes || decoded.toString('base64') !== value) {
    throw new TypeError(`${field} must be canonical base64 within ${maxBytes} bytes`);
  }
  return decoded;
}

function strictHex(value, field, bytes = null) {
  const pattern = bytes === null
    ? /^(?:[0-9a-f]{2})+$/
    : new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new TypeError(`${field} must be lowercase hexadecimal${bytes === null ? '' : ` (${bytes} bytes)`}`);
  }
  return Buffer.from(value, 'hex');
}

class Cursor {
  constructor(buffer, label) {
    this.buffer = buffer;
    this.label = label;
    this.offset = 0;
  }

  take(length, field) {
    if (!Number.isInteger(length) || length < 0 || this.offset + length > this.buffer.length) {
      throw new TypeError(`${this.label}.${field} is truncated`);
    }
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  u8(field) {
    return this.take(1, field).readUInt8(0);
  }

  u16(field) {
    return this.take(2, field).readUInt16BE(0);
  }

  u32(field) {
    return this.take(4, field).readUInt32BE(0);
  }

  u64(field) {
    return this.take(8, field).readBigUInt64BE(0);
  }

  tpm2b(field, maxBytes) {
    const length = this.u16(`${field}.size`);
    if (length > maxBytes) throw new TypeError(`${this.label}.${field} exceeds ${maxBytes} bytes`);
    return this.take(length, field);
  }

  done() {
    if (this.offset !== this.buffer.length) {
      throw new TypeError(`${this.label} has ${this.buffer.length - this.offset} trailing bytes`);
    }
  }
}

function parsePcrSelection(cursor) {
  const count = cursor.u32('pcr_selection.count');
  if (count < 1 || count > MAX_PCR_BANKS) {
    throw new TypeError(`TPMS_ATTEST PCR selection count must be 1..${MAX_PCR_BANKS}`);
  }
  const seen = new Set();
  const selections = [];
  for (let bank = 0; bank < count; bank += 1) {
    const algorithm = cursor.u16(`pcr_selection[${bank}].hash`);
    if (algorithm !== TPM_ALG_SHA256) {
      throw new TypeError(`unsupported PCR hash algorithm ${hexAlgorithm(algorithm)}`);
    }
    if (seen.has(algorithm)) throw new TypeError('TPMS_ATTEST contains a duplicate PCR bank');
    seen.add(algorithm);
    const size = cursor.u8(`pcr_selection[${bank}].sizeofSelect`);
    if (size < 1 || size > MAX_PCR_SELECT_BYTES) {
      throw new TypeError(`TPMS_ATTEST PCR select size must be 1..${MAX_PCR_SELECT_BYTES}`);
    }
    const bitmap = cursor.take(size, `pcr_selection[${bank}].pcrSelect`);
    const indices = [];
    for (let index = 0; index < size * 8; index += 1) {
      if ((bitmap[Math.floor(index / 8)] & (1 << (index % 8))) !== 0) indices.push(index);
    }
    if (indices.length === 0) throw new TypeError('TPMS_ATTEST PCR selection must not be empty');
    selections.push({ algorithm, bank: 'sha256', indices });
  }
  return selections;
}

export function parseTpm2Quote(quoted) {
  const cursor = new Cursor(quoted, 'TPMS_ATTEST');
  const magic = cursor.u32('magic');
  if (magic !== TPM_GENERATED_VALUE) {
    throw new TypeError(`TPMS_ATTEST magic must be 0x${TPM_GENERATED_VALUE.toString(16)}`);
  }
  const type = cursor.u16('type');
  if (type !== TPM_ST_ATTEST_QUOTE) {
    throw new TypeError(`TPMS_ATTEST type must be TPM_ST_ATTEST_QUOTE (${hexAlgorithm(TPM_ST_ATTEST_QUOTE)})`);
  }
  const qualifiedSigner = cursor.tpm2b('qualifiedSigner', 128);
  const extraData = cursor.tpm2b('extraData', MAX_NONCE_BYTES);
  if (extraData.length === 0) throw new TypeError('TPMS_ATTEST extraData challenge must not be empty');
  const clock = cursor.u64('clockInfo.clock');
  const resetCount = cursor.u32('clockInfo.resetCount');
  const restartCount = cursor.u32('clockInfo.restartCount');
  const safe = cursor.u8('clockInfo.safe');
  if (safe !== 0 && safe !== 1) throw new TypeError('TPMS_ATTEST clockInfo.safe must be 0 or 1');
  const firmwareVersion = cursor.u64('firmwareVersion');
  const pcrSelection = parsePcrSelection(cursor);
  const pcrDigest = cursor.tpm2b('attested.quote.pcrDigest', SHA256_BYTES);
  if (pcrDigest.length !== SHA256_BYTES) {
    throw new TypeError('TPMS_ATTEST quote PCR digest must be SHA-256');
  }
  cursor.done();
  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo: { clock, resetCount, restartCount, safe: safe === 1 },
    firmwareVersion,
    pcrSelection,
    pcrDigest,
  };
}

function derInteger(integer) {
  let value = Buffer.from(integer);
  while (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) value = value.subarray(1);
  if ((value[0] & 0x80) !== 0) value = Buffer.concat([Buffer.from([0]), value]);
  if (value.length > 127) throw new TypeError('ECDSA integer is too large');
  return Buffer.concat([Buffer.from([0x02, value.length]), value]);
}

function ecdsaDer(r, s) {
  const body = Buffer.concat([derInteger(r), derInteger(s)]);
  if (body.length > 127) throw new TypeError('ECDSA signature is too large');
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

export function parseTpm2Signature(signature) {
  const cursor = new Cursor(signature, 'TPMT_SIGNATURE');
  const algorithm = cursor.u16('sigAlg');
  const hashAlgorithm = cursor.u16('hash');
  if (hashAlgorithm !== TPM_ALG_SHA256) {
    throw new TypeError(`unsupported TPM signature hash algorithm ${hexAlgorithm(hashAlgorithm)}`);
  }
  let value;
  let keyType;
  if (algorithm === TPM_ALG_RSASSA) {
    value = cursor.tpm2b('signature.rsassa.sig', MAX_SIGNATURE_BYTES);
    if (value.length < 128) throw new TypeError('TPM RSASSA signature is too short');
    keyType = 'rsa';
  } else if (algorithm === TPM_ALG_ECDSA) {
    const r = cursor.tpm2b('signature.ecdsa.r', 66);
    const s = cursor.tpm2b('signature.ecdsa.s', 66);
    if (r.length === 0 || s.length === 0) throw new TypeError('TPM ECDSA signature parameters must not be empty');
    value = ecdsaDer(r, s);
    keyType = 'ec';
  } else {
    throw new TypeError(`unsupported TPM signature algorithm ${hexAlgorithm(algorithm)}`);
  }
  cursor.done();
  return { algorithm, hashAlgorithm, keyType, value };
}

function normalizeExpectedSelection(selection) {
  if (!isPlainRecord(selection) || Object.keys(selection).length !== 1 || !Array.isArray(selection.sha256)) {
    throw new TypeError('expectedPcrSelection must contain exactly one sha256 index array');
  }
  if (selection.sha256.length === 0
      || selection.sha256.some((index) => !Number.isInteger(index) || index < 0 || index > 31)
      || new Set(selection.sha256).size !== selection.sha256.length) {
    throw new TypeError('expectedPcrSelection.sha256 must be a non-empty unique PCR index array');
  }
  return [...selection.sha256].sort((left, right) => left - right);
}

function normalizePcrValues(values, selected, field) {
  if (!isPlainRecord(values) || Object.keys(values).length !== 1 || !isPlainRecord(values.sha256)) {
    throw new TypeError(`${field} must contain exactly one sha256 PCR-value object`);
  }
  const keys = Object.keys(values.sha256);
  const expectedKeys = selected.map(String);
  if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !Object.hasOwn(values.sha256, key))) {
    throw new TypeError(`${field}.sha256 keys must exactly match the PCR selection`);
  }
  return selected.map((index) => strictHex(values.sha256[String(index)], `${field}.sha256.${index}`, SHA256_BYTES));
}

function sameBytes(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function normalizeTrustedFingerprints(fingerprints) {
  if (!Array.isArray(fingerprints) || fingerprints.length === 0) {
    throw new TypeError('trustedAkFingerprints must be a non-empty array');
  }
  return fingerprints.map((value) => {
    if (typeof value !== 'string') throw new TypeError('trusted AK fingerprints must be strings');
    const normalized = value.startsWith('sha256:') ? value.slice(7) : value;
    strictHex(normalized, 'trusted AK fingerprint', SHA256_BYTES);
    return normalized;
  });
}

/**
 * Verify one EP-TPM-QUOTE-v1 object.
 *
 * @param {object} quote
 * @param {object} options
 * @param {string|Buffer} [options.expectedNonce] - verifier challenge, not quote-supplied state
 * @param {string[]} [options.trustedAkFingerprints] - SHA-256 SPKI pins
 * @param {{sha256:number[]}} [options.expectedPcrSelection] - exact PCR policy
 * @param {{sha256:Record<string,string>}} [options.expectedPcrValues] - known-good PCR values
 * @param {boolean} [options.requireSafeClock=true]
 * @returns {{ok:boolean, reason:string, pcrDigest?:string, akFingerprint?:string, selection?:object, clockSafe?:boolean}}
 */
export function verifyTpm2Quote(quote, options = {}) {
  try {
    if (!isPlainRecord(quote)) return fail('tpm_quote_malformed', 'quote must be an object');
    const unknownFields = Object.keys(quote).filter((field) => !QUOTE_FIELDS.has(field));
    if (unknownFields.length > 0) return fail('tpm_quote_malformed', `unknown field: ${unknownFields[0]}`);
    if (quote['@format'] !== TPM_QUOTE_FORMAT) return fail('tpm_quote_format_unsupported');
    if (typeof quote.ak_public !== 'string' || !quote.ak_public.includes('-----BEGIN PUBLIC KEY-----')) {
      return fail('tpm_ak_public_malformed');
    }

    const expectedNonce = Buffer.isBuffer(options.expectedNonce)
      ? Buffer.from(options.expectedNonce)
      : strictHex(options.expectedNonce, 'expectedNonce');
    if (expectedNonce.length === 0 || expectedNonce.length > MAX_NONCE_BYTES) {
      return fail('tpm_nonce_invalid', `expected nonce must be 1..${MAX_NONCE_BYTES} bytes`);
    }
    const declaredNonce = strictHex(quote.nonce, 'quote.nonce');
    if (!sameBytes(declaredNonce, expectedNonce)) return fail('tpm_nonce_metadata_mismatch');

    const trustedFingerprints = normalizeTrustedFingerprints(options.trustedAkFingerprints);
    const expectedSelection = normalizeExpectedSelection(options.expectedPcrSelection);
    const quoted = strictBase64(quote.quoted, 'quote.quoted', MAX_ATTEST_BYTES);
    const parsedQuote = parseTpm2Quote(quoted);
    if (!sameBytes(parsedQuote.extraData, expectedNonce)) return fail('tpm_nonce_mismatch');
    if ((options.requireSafeClock ?? true) && !parsedQuote.clockInfo.safe) return fail('tpm_clock_not_safe');

    if (parsedQuote.pcrSelection.length !== 1
        || parsedQuote.pcrSelection[0].bank !== 'sha256'
        || parsedQuote.pcrSelection[0].indices.length !== expectedSelection.length
        || expectedSelection.some((index, position) => parsedQuote.pcrSelection[0].indices[position] !== index)) {
      return fail('tpm_pcr_selection_mismatch');
    }

    const suppliedPcrValues = normalizePcrValues(quote.pcr_values, expectedSelection, 'quote.pcr_values');
    const expectedPcrValues = normalizePcrValues(options.expectedPcrValues, expectedSelection, 'expectedPcrValues');
    for (let index = 0; index < suppliedPcrValues.length; index += 1) {
      if (!sameBytes(suppliedPcrValues[index], expectedPcrValues[index])) {
        return fail('tpm_pcr_value_not_allowed', `sha256 PCR ${expectedSelection[index]}`);
      }
    }
    const calculatedPcrDigest = crypto.createHash('sha256')
      .update(Buffer.concat(suppliedPcrValues))
      .digest();
    if (!sameBytes(parsedQuote.pcrDigest, calculatedPcrDigest)) return fail('tpm_pcr_digest_mismatch');

    const parsedSignature = parseTpm2Signature(
      strictBase64(quote.signature, 'quote.signature', MAX_SIGNATURE_BYTES),
    );
    const ak = crypto.createPublicKey(quote.ak_public);
    if (ak.asymmetricKeyType !== parsedSignature.keyType) return fail('tpm_ak_type_mismatch');
    const akDer = ak.export({ format: 'der', type: 'spki' });
    const akFingerprint = crypto.createHash('sha256').update(akDer).digest('hex');
    if (!trustedFingerprints.some((trusted) => sameBytes(Buffer.from(trusted, 'hex'), Buffer.from(akFingerprint, 'hex')))) {
      return fail('tpm_ak_not_trusted', undefined);
    }

    const signatureOptions = parsedSignature.keyType === 'rsa'
      ? { key: ak, padding: crypto.constants.RSA_PKCS1_PADDING }
      : ak;
    const signatureValid = crypto.verify('sha256', quoted, signatureOptions, parsedSignature.value);
    if (!signatureValid) return fail('tpm_quote_signature_invalid');

    return {
      ok: true,
      reason: 'tpm_quote_verified',
      pcrDigest: parsedQuote.pcrDigest.toString('hex'),
      akFingerprint: `sha256:${akFingerprint}`,
      selection: { sha256: expectedSelection },
      clockSafe: parsedQuote.clockInfo.safe,
    };
  } catch (error) {
    return fail('tpm_quote_malformed', error?.message || String(error));
  }
}

export default verifyTpm2Quote;
