#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from caid-action-mapping.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Runnable Action-Mapping Profile demonstration. The second envelope is
// deliberately AP2-shaped for composition testing; it is not a claim of AP2
// conformance. Each envelope verifies natively before its integrity-protected
// payload reaches the CAID mapper.
import { generateKeyPairSync, sign as signBytes, verify as verifyBytes, } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../caid/impl/js/caid.mjs';
import { MAPPING_VERDICTS, compareMappedActions, mappingProfileHash, } from '../caid/impl/js/mapping.mjs';
const corpus = JSON.parse(readFileSync(new URL('../caid/conformance/mapping-vectors.json', import.meta.url), 'utf8'));
const clone = (value) => structuredClone(value);
function signedBytes(payload) {
    const encoded = canonicalize(payload);
    if (!encoded.ok)
        throw new Error(`native payload is not canonicalizable: ${encoded.refusals.join(',')}`);
    return Buffer.from(encoded.canonical, 'utf8');
}
function signNative(payload, privateKey, format) {
    return {
        format,
        payload: clone(payload),
        signature_b64u: signBytes(null, signedBytes(payload), privateKey).toString('base64url'),
    };
}
function verifyNative(envelope, publicKey, expectedFormat, sourceDescriptor) {
    if (!envelope || envelope.format !== expectedFormat || !envelope.payload
        || typeof envelope.signature_b64u !== 'string') {
        return { verified: false, reason: 'native_shape_invalid' };
    }
    let signature;
    try {
        signature = Buffer.from(envelope.signature_b64u, 'base64url');
    }
    catch {
        return { verified: false, reason: 'native_signature_malformed' };
    }
    if (!verifyBytes(null, signedBytes(envelope.payload), publicKey, signature)) {
        return { verified: false, reason: 'native_signature_invalid' };
    }
    return {
        verified: true,
        source: clone(envelope.payload),
        source_descriptor: clone(sourceDescriptor),
    };
}
function mappingSide(nativeResult, profile) {
    return {
        source: nativeResult.source,
        profile,
        source_descriptor: nativeResult.source_descriptor,
        expected_profile_hash: mappingProfileHash(profile),
        native_verified: nativeResult.verified === true,
    };
}
export function runCaidActionMappingDemo() {
    const epKeys = generateKeyPairSync('ed25519');
    const checkoutKeys = generateKeyPairSync('ed25519');
    const epProfile = clone(corpus.profiles['ep-action-v1']);
    const checkoutProfile = clone(corpus.profiles['ap2-checkout-v1']);
    const epEnvelope = signNative(corpus.sources['ep-order'], epKeys.privateKey, 'example-ep-action-v1');
    const checkoutEnvelope = signNative(corpus.sources['ap2-order'], checkoutKeys.privateKey, 'example-ap2-shaped-checkout-v1');
    const epNative = verifyNative(epEnvelope, epKeys.publicKey, 'example-ep-action-v1', epProfile.source_format);
    const checkoutNative = verifyNative(checkoutEnvelope, checkoutKeys.publicKey, 'example-ap2-shaped-checkout-v1', checkoutProfile.source_format);
    const equivalent = compareMappedActions(mappingSide(epNative, epProfile), mappingSide(checkoutNative, checkoutProfile), 
    /** @type {any} */ ({ definitions: corpus.definitions, suite: corpus.suite }));
    const tampered = clone(checkoutEnvelope);
    tampered.payload.checkout.total_amount = '0.01';
    const tamperedNative = verifyNative(tampered, checkoutKeys.publicKey, 'example-ap2-shaped-checkout-v1', checkoutProfile.source_format);
    const wrongMerchantPayload = clone(corpus.sources['ap2-order']);
    wrongMerchantPayload.checkout.merchant_id = 'merch_evil_twin';
    const wrongMerchantEnvelope = signNative(wrongMerchantPayload, checkoutKeys.privateKey, 'example-ap2-shaped-checkout-v1');
    const wrongMerchantNative = verifyNative(wrongMerchantEnvelope, checkoutKeys.publicKey, 'example-ap2-shaped-checkout-v1', checkoutProfile.source_format);
    const wrongMerchant = compareMappedActions(mappingSide(epNative, epProfile), mappingSide(wrongMerchantNative, checkoutProfile), 
    /** @type {any} */ ({ definitions: corpus.definitions, suite: corpus.suite }));
    const substitutedProfile = clone(checkoutProfile);
    substitutedProfile.profile_id = 'urn:attacker:weaker-map:1';
    const profileSubstitutionSide = mappingSide(checkoutNative, substitutedProfile);
    profileSubstitutionSide.expected_profile_hash = mappingProfileHash(checkoutProfile);
    const profileSubstitution = compareMappedActions(mappingSide(epNative, epProfile), profileSubstitutionSide, 
    /** @type {any} */ ({ definitions: corpus.definitions, suite: corpus.suite }));
    const unsignedShadow = clone(checkoutEnvelope);
    unsignedShadow.checkout = { ...unsignedShadow.payload.checkout, total_amount: '0.01' };
    const shadowNative = verifyNative(unsignedShadow, checkoutKeys.publicKey, 'example-ap2-shaped-checkout-v1', checkoutProfile.source_format);
    const shadowIgnored = compareMappedActions(mappingSide(epNative, epProfile), mappingSide(shadowNative, checkoutProfile), 
    /** @type {any} */ ({ definitions: corpus.definitions, suite: corpus.suite }));
    const missingNativeVerification = compareMappedActions(mappingSide(epNative, epProfile), {
        ...mappingSide(checkoutNative, checkoutProfile),
        native_verified: false,
    }, 
    /** @type {any} */ ({ definitions: corpus.definitions, suite: corpus.suite }));
    return {
        equivalent: equivalent.verdict,
        tampered_native: tamperedNative,
        wrong_merchant: wrongMerchant.verdict,
        profile_substitution: profileSubstitution.verdict,
        unsigned_shadow: shadowIgnored.verdict,
        missing_native_verification: missingNativeVerification.verdict,
    };
}
if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
    const result = runCaidActionMappingDemo();
    const expected = {
        equivalent: MAPPING_VERDICTS.equivalent,
        tampered_native: { verified: false, reason: 'native_signature_invalid' },
        wrong_merchant: MAPPING_VERDICTS.different,
        profile_substitution: MAPPING_VERDICTS.indeterminate,
        unsigned_shadow: MAPPING_VERDICTS.equivalent,
        missing_native_verification: MAPPING_VERDICTS.indeterminate,
    };
    console.log(JSON.stringify(result, null, 2));
    if (JSON.stringify(result) !== JSON.stringify(expected))
        process.exitCode = 1;
}
