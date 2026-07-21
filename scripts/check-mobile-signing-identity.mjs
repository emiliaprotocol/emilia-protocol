// SPDX-License-Identifier: Apache-2.0
// Generated from check-mobile-signing-identity.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { normalizeAndroidSigningCertificate } from '../lib/mobile/config.js';
const args = [...process.argv.slice(2), 'Android artifact'];
const expectedValue = args[0];
const actualValue = args[1];
const artifact = args[2] ?? 'Android artifact';
const expected = normalizeAndroidSigningCertificate(expectedValue, 'canonical Android signing certificate');
const actual = normalizeAndroidSigningCertificate(actualValue, `${artifact} signing certificate`);
assert.equal(actual.hex, expected.hex, `${artifact} signing certificate does not match the canonical mobile identity`);
console.log(`${artifact} signing identity: ${actual.assetLinks}`);
