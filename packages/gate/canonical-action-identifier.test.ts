// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { RISK_CAID } from './dist/reliance-risk-crypto.js';

const DIGEST = 'A'.repeat(43);

test('Gate accepts current canactid identifiers and refuses legacy caid identifiers', () => {
  assert.equal(
    RISK_CAID.test(`canactid:1:payment.release.1:jcs-sha256:${DIGEST}`),
    true,
  );
  assert.equal(
    RISK_CAID.test(`caid:1:payment.release.1:jcs-sha256:${DIGEST}`),
    false,
  );
});
