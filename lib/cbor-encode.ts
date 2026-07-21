// SPDX-License-Identifier: Apache-2.0
import cbor from 'cbor';

/**
 * Encode a complete CBOR item synchronously by draining the Encoder stream.
 *
 * cbor@10's static encode helpers can read the piped stream before every chunk
 * has arrived on Node 26, returning only the initial type byte. The Encoder
 * itself still emits every chunk synchronously for finite in-memory values, so
 * collecting its data events preserves the existing synchronous verifier API.
 */
export function encodeCborSync(
  value: any,
  { canonical = false }: any = {},
): Buffer {
  const chunks: Buffer[] = [];
  const encoder = new cbor.Encoder({ canonical });
  let failure: any = null;
  encoder.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
  encoder.once('error', (error) => { failure = error; });
  try {
    encoder.pushAny(value);
    encoder.end();
  } catch (error) {
    failure = error;
  }
  if (failure) throw failure;
  const encoded = Buffer.concat(chunks);
  if (encoded.length === 0) throw new TypeError('CBOR encoder produced no bytes');
  return encoded;
}

export function encodeCanonicalCborSync(value: any): Buffer {
  return encodeCborSync(value, { canonical: true });
}
