// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { MAX_JSON_DEPTH, strictJsonGate } from '../lib/strict-json.js';

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
