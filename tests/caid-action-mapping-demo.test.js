// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import { MAPPING_VERDICTS } from '../caid/impl/js/mapping.mjs';
import { runCaidActionMappingDemo } from '../examples/caid-action-mapping.mjs';

describe('CAID signed native-artifact mapping demo', () => {
  it('matches only verified, materially equivalent actions', () => {
    const result = runCaidActionMappingDemo();

    expect(result).toEqual({
      equivalent: MAPPING_VERDICTS.equivalent,
      tampered_native: { verified: false, reason: 'native_signature_invalid' },
      wrong_merchant: MAPPING_VERDICTS.different,
      profile_substitution: MAPPING_VERDICTS.indeterminate,
      unsigned_shadow: MAPPING_VERDICTS.equivalent,
      missing_native_verification: MAPPING_VERDICTS.indeterminate,
    });
  });
});
