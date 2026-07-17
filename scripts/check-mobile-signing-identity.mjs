// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';

import { normalizeAndroidSigningCertificate } from '../lib/mobile/config.js';

const [expectedValue, actualValue, artifact = 'Android artifact'] = process.argv.slice(2);
const expected = normalizeAndroidSigningCertificate(expectedValue, 'canonical Android signing certificate');
const actual = normalizeAndroidSigningCertificate(actualValue, `${artifact} signing certificate`);

assert.equal(
  actual.hex,
  expected.hex,
  `${artifact} signing certificate does not match the canonical mobile identity`,
);

console.log(`${artifact} signing identity: ${actual.assetLinks}`);
