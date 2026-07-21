// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';

import { normalizeAndroidSigningCertificate } from '../lib/mobile/config.js';

const args: (string | undefined)[] = [...process.argv.slice(2), 'Android artifact'];
const expectedValue: string | undefined = args[0];
const actualValue: string | undefined = args[1];
const artifact: string = args[2] ?? 'Android artifact';
const expected: any = normalizeAndroidSigningCertificate(expectedValue, 'canonical Android signing certificate');
const actual: any = normalizeAndroidSigningCertificate(actualValue, `${artifact} signing certificate`);

assert.equal(
  actual.hex,
  expected.hex,
  `${artifact} signing certificate does not match the canonical mobile identity`,
);

console.log(`${artifact} signing identity: ${actual.assetLinks}`);
