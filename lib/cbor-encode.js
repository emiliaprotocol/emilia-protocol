// SPDX-License-Identifier: Apache-2.0
// Generated from cbor-encode.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import cbor from 'cbor';
/**
 * Encode a complete CBOR item synchronously by draining the Encoder stream.
 *
 * cbor@10's static encode helpers can read the piped stream before every chunk
 * has arrived on Node 26, returning only the initial type byte. The Encoder
 * itself still emits every chunk synchronously for finite in-memory values, so
 * collecting its data events preserves the existing synchronous verifier API.
 */
export function encodeCborSync(value, { canonical = false } = {}) {
    const chunks = [];
    const encoder = new cbor.Encoder({ canonical });
    let failure = null;
    encoder.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    encoder.once('error', (error) => { failure = error; });
    try {
        encoder.pushAny(value);
        encoder.end();
    }
    catch (error) {
        failure = error;
    }
    if (failure)
        throw failure;
    const encoded = Buffer.concat(chunks);
    if (encoded.length === 0)
        throw new TypeError('CBOR encoder produced no bytes');
    return encoded;
}
export function encodeCanonicalCborSync(value) {
    return encodeCborSync(value, { canonical: true });
}
