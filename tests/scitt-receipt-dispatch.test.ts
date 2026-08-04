// SPDX-License-Identifier: Apache-2.0

import { describe, expect, test, vi } from 'vitest';
import {
  SCITT_VDS,
  verifyScittReceiptByVds,
} from '../examples/scitt/scitt-receipt-dispatch.mjs';

function receiptWithVds(vds: number) {
  // tag(18), COSE_Sign1([bstr({395: vds}), {}, null, h''])
  const encodedVds = vds < 24 ? [vds] : [0x18, vds];
  const protectedMap = [0xa1, 0x19, 0x01, 0x8b, ...encodedVds];
  return Buffer.from([
    0xd2,
    0x84,
    0x40 + protectedMap.length,
    ...protectedMap,
    0xa0,
    0xf6,
    0x40,
  ]);
}

describe('RFC 9942 receipt VDS dispatch', () => {
  test.each([
    ['RFC9162_SHA256', SCITT_VDS.RFC9162_SHA256],
    ['CCF', SCITT_VDS.CCF],
    ['MMR', SCITT_VDS.MMR],
  ])('dispatches %s to only its pinned native verifier', (_name, vds) => {
    const selected = vi.fn(() => ({ native_verification: 'VERIFIED', reasons: [] }));
    const wrong = vi.fn(() => ({ native_verification: 'VERIFIED', reasons: [] }));
    const profiles = new Map([
      [vds, { id: `profile:${vds}`, verify: selected }],
      [99, { id: 'profile:wrong', verify: wrong }],
    ]);

    const result = verifyScittReceiptByVds({
      receipt: receiptWithVds(vds),
      statement: Buffer.from('signed-statement'),
      profiles,
    });

    expect(result).toMatchObject({
      native_verification: 'VERIFIED',
      vds,
      profile_id: `profile:${vds}`,
    });
    expect(selected).toHaveBeenCalledOnce();
    expect(wrong).not.toHaveBeenCalled();
  });

  test('fails closed when the protected vds is unsupported', () => {
    const verifier = vi.fn();
    const result = verifyScittReceiptByVds({
      receipt: receiptWithVds(99),
      statement: Buffer.from('signed-statement'),
      profiles: new Map([[SCITT_VDS.RFC9162_SHA256, { id: 'rfc9162', verify: verifier }]]),
    });

    expect(result).toEqual({
      native_verification: 'INDETERMINATE',
      vds: 99,
      profile_id: null,
      reasons: ['unsupported_vds'],
    });
    expect(verifier).not.toHaveBeenCalled();
  });

  test('fails closed when vds is missing from the protected header', () => {
    const missingVds = Buffer.from([0xd2, 0x84, 0x41, 0xa0, 0xa0, 0xf6, 0x40]);
    const result = verifyScittReceiptByVds({
      receipt: missingVds,
      statement: Buffer.from('signed-statement'),
      profiles: new Map(),
    });

    expect(result).toMatchObject({
      native_verification: 'FAILED',
      vds: null,
      reasons: ['missing_vds'],
    });
  });
});
