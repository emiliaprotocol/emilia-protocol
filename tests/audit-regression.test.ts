// SPDX-License-Identifier: Apache-2.0
// Regression tests for the malformed-input / null-guard bug class surfaced by the
// PR #616 review and the follow-on surface audit. Each case reproduces an input
// that previously threw an uncaught exception (a crash where the fail-closed
// contract requires a clean refusal verdict).
import { describe, it, expect } from 'vitest';
import { evaluateReliance } from '../packages/verify/reliance.js';
import { evaluateRxReliance } from '../lib/ncpdp/rx-reliance.js';

describe('audit regression: fail-closed on malformed input (no crash)', () => {
  it('evaluateReliance(null) refuses instead of throwing', () => {
    // JSON.parse('null') reaches the destructure; the `= {}` default only guards
    // undefined, so a literal null used to throw "Cannot read properties of null".
    let r;
    expect(() => { r = evaluateReliance(null); }).not.toThrow();
    expect(r.rely).toBe(false);
  });

  it('evaluateReliance on non-object inputs refuses instead of throwing', () => {
    for (const bad of [42, 'x', true]) {
      let r;
      expect(() => { r = evaluateReliance(bad); }).not.toThrow();
      expect(r.rely).toBe(false);
    }
  });

  it('evaluateRxReliance with required:null refuses (typeof null === object trap)', () => {
    // typeof null === 'object' let null through the guard; req became null and
    // req.prescriber_authority threw. Must return a closed rx refusal instead.
    let r;
    const challenge = { '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', required: null };
    const packet = { '@type': 'EP-RX-RELIANCE-PACKET-v1' };
    expect(() => { r = evaluateRxReliance({ challenge, packet }); }).not.toThrow();
    expect(r.rely).toBe(false);
    expect(r.verdict.startsWith('rx_do_not_rely')).toBe(true);
  });
});
