import { describe, expect, it } from 'vitest';
import { canonicalize, isCanonicalizable } from '@/lib/canonical-json';
import {
  canonicalize as verifierCanonicalize,
  isCanonicalizable as verifierIsCanonicalizable,
} from '../packages/verify/index.js';

describe('canonical JSON', () => {
  it('sorts object keys recursively while preserving array order', () => {
    const left = {
      z: 1,
      nested: { b: 'two', a: 'one' },
      list: [{ y: 2, x: 1 }],
    };
    const right = {
      list: [{ x: 1, y: 2 }],
      nested: { a: 'one', b: 'two' },
      z: 1,
    };

    expect(canonicalize(left)).toBe(canonicalize(right));
    expect(canonicalize(left)).toBe(
      '{"list":[{"x":1,"y":2}],"nested":{"a":"one","b":"two"},"z":1}',
    );
  });

  it('matches the verifier on the cross-language consensus vector', () => {
    const value = {
      '@version': 'EP-RECEIPT-v1',
      action: { action_type: 'payment.release', amount_usd: 1.0, risk_score: -0.0 },
      context: { '\uFFFD': 'replacement_char', '🙂': 'slight_smile' },
      entity_id: 'ep_entity_poc_test',
      signoffs: [],
    };
    const expected = '{"@version":"EP-RECEIPT-v1","action":{"action_type":"payment.release","amount_usd":1,"risk_score":0},"context":{"🙂":"slight_smile","�":"replacement_char"},"entity_id":"ep_entity_poc_test","signoffs":[]}';

    expect(isCanonicalizable(value)).toBe(true);
    expect(verifierIsCanonicalizable(value)).toBe(true);
    expect(canonicalize(value)).toBe(expected);
    expect(canonicalize(value)).toBe(verifierCanonicalize(value));
  });

  it('rejects undefined and other values outside the shared profile', () => {
    for (const value of [
      undefined,
      { nested: undefined },
      [undefined],
      { fractional: 1.25 },
      { unsafe: Number.MAX_SAFE_INTEGER + 1 },
      { bigint: 1n },
    ]) {
      expect(isCanonicalizable(value)).toBe(false);
      expect(() => canonicalize(value)).toThrow(/canonicalization profile/);
    }
  });
});
