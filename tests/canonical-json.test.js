import { describe, expect, it } from 'vitest';
import { canonicalize } from '@/lib/canonical-json';

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
});
