// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  MAX_JSON_DEPTH,
  canonicalizeStrictJson,
  isStrictCanonicalJson,
  strictJsonGate,
} from '../lib/strict-json.js';

describe('strict JSON gate', () => {
  it('refuses non-text, malformed JSON, and duplicate names', () => {
    expect(strictJsonGate(null)).toEqual({ ok: false, reason: 'JSON input must be text' });
    expect(strictJsonGate('{')).toEqual({ ok: false, reason: 'invalid JSON syntax' });
    expect(strictJsonGate('{"role":"user","role":"admin"}'))
      .toEqual({ ok: false, reason: 'duplicate object member name' });
    expect(strictJsonGate(String.raw`{"origin":"safe","\u006frigin":"attacker"}`))
      .toEqual({ ok: false, reason: 'duplicate object member name' });
  });

  it('accepts valid escapes and a paired Unicode surrogate', () => {
    expect(strictJsonGate(String.raw`{"value":"\"\\\/\b\f\n\r\t"}`)).toEqual({ ok: true });
    expect(strictJsonGate(String.raw`{"emoji":"\ud83d\ude00"}`)).toEqual({ ok: true });
    expect(strictJsonGate('[{"nested":true},"value",null]')).toEqual({ ok: true });
  });

  it.each([
    [String.raw`{"value":"\ud800"}`, 'unpaired high surrogate escape'],
    [String.raw`{"value":"\ud800x"}`, 'unpaired high surrogate escape'],
    [String.raw`{"value":"\ud800\u0041"}`, 'unpaired high surrogate escape'],
    [String.raw`{"value":"\udc00"}`, 'unpaired low surrogate escape'],
  ])('refuses invalid Unicode scalar input %#', (raw, reason) => {
    expect(strictJsonGate(raw)).toEqual({ ok: false, reason });
  });

  it('enforces the same depth limit for objects and arrays', () => {
    const deepObject = `${'{"next":'.repeat(MAX_JSON_DEPTH + 1)}null${'}'.repeat(MAX_JSON_DEPTH + 1)}`;
    const deepArray = `${'['.repeat(MAX_JSON_DEPTH + 1)}null${']'.repeat(MAX_JSON_DEPTH + 1)}`;
    expect(strictJsonGate(deepObject)).toEqual({
      ok: false,
      reason: `nesting depth exceeds ${MAX_JSON_DEPTH}`,
    });
    expect(strictJsonGate(deepArray)).toEqual({
      ok: false,
      reason: `nesting depth exceeds ${MAX_JSON_DEPTH}`,
    });
  });
});

describe('strict canonical JSON domain', () => {
  it('canonicalizes the closed JSON scalar, array, and object domain', () => {
    expect(canonicalizeStrictJson(null)).toBe('null');
    expect(canonicalizeStrictJson('value')).toBe('"value"');
    expect(canonicalizeStrictJson(true)).toBe('true');
    expect(canonicalizeStrictJson(false)).toBe('false');
    expect(canonicalizeStrictJson(42)).toBe('42');
    expect(canonicalizeStrictJson({ z: 1, a: [true, null, 'x'] }))
      .toBe('{"a":[true,null,"x"],"z":1}');

    const nullPrototype = Object.create(null) as Record<string, unknown>;
    nullPrototype.z = 2;
    nullPrototype.a = 1;
    expect(canonicalizeStrictJson(nullPrototype)).toBe('{"a":1,"z":2}');
    expect(isStrictCanonicalJson(nullPrototype)).toBe(true);
  });

  it.each([
    [undefined, 'undefined is not a JSON value'],
    [1n, 'bigint is not a JSON value'],
    [Symbol('value'), 'symbol is not a JSON value'],
    [() => true, 'function is not a JSON value'],
    [Number.NaN, 'numbers must be safe integers'],
    [Number.POSITIVE_INFINITY, 'numbers must be safe integers'],
    [1.25, 'numbers must be safe integers'],
    [Number.MAX_SAFE_INTEGER + 1, 'numbers must be safe integers'],
    [new Date(0), 'only plain objects are permitted'],
    [new Map(), 'only plain objects are permitted'],
    [new Set(), 'only plain objects are permitted'],
    [/value/u, 'only plain objects are permitted'],
  ])('refuses a value that JSON would erase or collapse %#', (value, reason) => {
    expect(() => canonicalizeStrictJson(value)).toThrow(reason);
    expect(isStrictCanonicalJson(value)).toBe(false);
  });

  it('refuses cycles, malformed Unicode, and excessive nesting', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeStrictJson(cyclic)).toThrow('cyclic reference');
    expect(() => canonicalizeStrictJson('\uD800')).toThrow('unpaired Unicode surrogate');
    expect(() => canonicalizeStrictJson({ ['\uDC00']: true }))
      .toThrow('member name contains an unpaired Unicode surrogate');

    let deep: unknown = null;
    for (let index = 0; index <= MAX_JSON_DEPTH; index += 1) deep = [deep];
    expect(() => canonicalizeStrictJson(deep))
      .toThrow(`nesting depth exceeds ${MAX_JSON_DEPTH}`);
  });

  it('refuses sparse, extended, accessor, and symbol-bearing arrays', () => {
    const sparse = Array(2);
    sparse[1] = 'present';
    expect(() => canonicalizeStrictJson(sparse)).toThrow('sparse arrays');

    const extended = ['value'] as unknown[] & { extra?: boolean };
    extended.extra = true;
    expect(() => canonicalizeStrictJson(extended)).toThrow('arrays with extra members');

    let reads = 0;
    const accessor = ['safe'];
    Object.defineProperty(accessor, '0', {
      enumerable: true,
      get() {
        reads += 1;
        return 'attacker';
      },
    });
    expect(() => canonicalizeStrictJson(accessor)).toThrow('array holes and accessors');
    expect(reads).toBe(0);

    const symbolArray = ['value'];
    Object.defineProperty(symbolArray, Symbol('hidden'), { value: 'secret' });
    expect(() => canonicalizeStrictJson(symbolArray)).toThrow('symbol members are not JSON');
  });

  it('refuses hidden, accessor, and symbol-bearing object members without executing code', () => {
    const hidden = { visible: true };
    Object.defineProperty(hidden, 'hidden', { value: 'secret', enumerable: false });
    expect(() => canonicalizeStrictJson(hidden)).toThrow('non-enumerable members');

    let reads = 0;
    const accessor = {};
    Object.defineProperty(accessor, 'value', {
      enumerable: true,
      get() {
        reads += 1;
        return 'attacker';
      },
    });
    expect(() => canonicalizeStrictJson(accessor)).toThrow('accessors are not permitted');
    expect(reads).toBe(0);

    const symbolObject = { visible: true } as Record<PropertyKey, unknown>;
    symbolObject[Symbol('hidden')] = 'secret';
    expect(() => canonicalizeStrictJson(symbolObject)).toThrow('symbol members are not JSON');
  });

  it('turns hostile object-inspection failures into a closed-domain refusal', () => {
    const hostile = new Proxy({}, {
      ownKeys() {
        throw new Error('trap fired');
      },
    });
    expect(() => canonicalizeStrictJson(hostile))
      .toThrow('object inspection failed: trap fired');
  });
});
