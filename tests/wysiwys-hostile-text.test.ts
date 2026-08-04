// SPDX-License-Identifier: Apache-2.0
/**
 * Presentation-attack refusal for WYSIWYS-rendered action fields.
 *
 * The defect these lock: a bidirectional override inside an initiator-supplied
 * action field (target_resource_id, actor_id, policy_id) survived into the
 * rendering shown to a human approver. Both action_hash and display_hash cover
 * the hostile bytes, so verification passed and the display attestation was
 * "faithful" while the approver read a different account than the one signed.
 *
 * Codepoints are written as \u escapes throughout, never as literals. A test
 * file that embeds a live RIGHT-TO-LEFT OVERRIDE is itself a review-time hazard
 * (the repository's own scanner flags it), and embedding a NUL makes git treat
 * the file as binary so it stops being diffable.
 */
import { describe, it, expect } from 'vitest';
import {
  findHostileRenderedFields,
  hostileRenderedFieldRefusal,
  RENDERED_ACTION_FIELDS,
} from '@/lib/wysiwys/neutralize';
import { validateGuardActionInput } from '@/lib/guard-action-inputs';
import VECTORS from '@/conformance/vectors/wysiwys-hostile-text.v1.json';

const RLO = '\u202E';  // RIGHT-TO-LEFT OVERRIDE
const PDF = '\u202C';  // POP DIRECTIONAL FORMATTING
const ZWSP = '\u200B'; // ZERO WIDTH SPACE
const NUL = '\u0000';  // C0 control
const NEL = '\u0085';  // C1 control

function baseAction(overrides: Record<string, unknown> = {}) {
  return {
    action_type: 'payment.transfer',
    actor_id: 'agent-1',
    target_resource_id: 'acct-9931',
    policy_id: 'p1',
    amount: 500,
    currency: 'USD',
    requested_at: '2026-08-03T00:00:00Z',
    ...overrides,
  };
}

describe('hostile codepoints in rendered action fields', () => {
  it('refuses the account-spoofing bidi override that motivated this guard', () => {
    const action = baseAction({ target_resource_id: `acct-9931${RLO}live${PDF}` });
    const findings = findHostileRenderedFields(action);
    expect(findings).toHaveLength(1);
    expect(findings[0].field).toBe('target_resource_id');
    expect(findings[0].codepoints).toContain(0x202e);

    const refusal = hostileRenderedFieldRefusal(action);
    expect(refusal?.code).toBe('hostile_display_codepoints');
    expect(refusal?.status).toBe(400);
    // The refusal names the field and codepoint without echoing hostile bytes
    // back into whatever surface displays the error.
    expect(refusal?.detail).toContain('target_resource_id');
    expect(refusal?.detail).toContain('U+202E');
    expect(refusal?.detail).not.toContain(RLO);
  });

  it.each([
    ['bidi override', RLO],
    ['pop directional formatting', PDF],
    ['zero width space', ZWSP],
    ['C0 control', NUL],
    ['C1 control', NEL],
  ])('refuses %s in a rendered string field', (_label, ch) => {
    expect(hostileRenderedFieldRefusal(baseAction({ actor_id: `agent${ch}1` }))).not.toBeNull();
  });

  it('refuses hostile codepoints nested inside structured rendered fields', () => {
    expect(hostileRenderedFieldRefusal(baseAction({ risk_flags: [`high${RLO}risk`] }))).not.toBeNull();
    expect(
      hostileRenderedFieldRefusal(baseAction({ rollout_metadata: { note: `ok${ZWSP}` } })),
    ).not.toBeNull();
    // Object KEYS render too, once the object is canonicalized into a line, so
    // a hostile key must be refused as well as a hostile value.
    expect(
      hostileRenderedFieldRefusal(baseAction({ rollout_metadata: { [`k${RLO}`]: 'v' } })),
    ).not.toBeNull();
  });

  it('accepts ordinary actions, including legitimate right-to-left script', () => {
    expect(hostileRenderedFieldRefusal(baseAction())).toBeNull();
    // Arabic and Hebrew are ordinary content. Refusing them would be a bug: the
    // attack is the OVERRIDE codepoint, never the script itself.
    expect(hostileRenderedFieldRefusal(baseAction({ target_resource_id: 'حساب-9931' }))).toBeNull();
    expect(hostileRenderedFieldRefusal(baseAction({ actor_id: 'סוכן-1' }))).toBeNull();
    // Everyday whitespace must keep passing.
    expect(hostileRenderedFieldRefusal(baseAction({ policy_id: 'p1\tstrict\nv2' }))).toBeNull();
  });

  it('ignores hostile bytes in fields the renderer never displays', () => {
    // No security gain from refusing these, and refusing would reject
    // legitimate payloads. The guard is scoped to what a human actually sees.
    expect(hostileRenderedFieldRefusal(baseAction({ internal_note: `x${RLO}` }))).toBeNull();
  });

  it('guards every field the WYSIWYS profile renders', () => {
    // Negative control against drift: if render.ts gains a rendered field and
    // RENDERED_ACTION_FIELDS is not updated, that field ships unguarded.
    for (const field of RENDERED_ACTION_FIELDS) {
      const refusal = hostileRenderedFieldRefusal({ [field]: `v${RLO}` });
      expect(refusal, `field ${field} is rendered but unguarded`).not.toBeNull();
    }
  });
});

// Catalogue/test parity, mirroring the gate in tests/wysiwys.test.ts: a vector
// that exists in the JSON but is exercised by no named assertion is a vector
// nobody runs.
describe('EP-WYSIWYS-HOSTILE-TEXT-v1 — vector catalogue parity', () => {
  const ASSERTED = new Set([
    'e_bidi_override_in_target_resource_id',
    'f_zero_width_and_control_in_rendered_fields',
    'g_hostile_codepoint_nested_in_structured_field',
    'z_legitimate_rtl_script_is_not_an_attack',
    'z2_everyday_whitespace_passes',
    'z3_unrendered_field_is_not_guarded',
  ]);

  it('is the expected wire tag and every id is asserted by name above', () => {
    expect(VECTORS.wire_tag).toBe('EP-WYSIWYS-HOSTILE-TEXT-v1');
    expect(VECTORS.must_reject).toHaveLength(3);
    expect(VECTORS.must_accept).toHaveLength(3);
    for (const v of [...VECTORS.must_reject, ...VECTORS.must_accept]) {
      expect(ASSERTED.has(v.id), `vector ${v.id} is catalogued but unasserted`).toBe(true);
    }
  });

  it('every refusal vector names the refusal code the implementation returns', () => {
    for (const v of VECTORS.must_reject) {
      expect(v.expected.valid).toBe(false);
      expect(v.expected.failing_check).toBe('hostile_display_codepoints');
    }
  });
});

describe('validateGuardActionInput refuses before anything is minted', () => {
  it('rejects the hostile action at the shared choke point', () => {
    const result = validateGuardActionInput(
      baseAction({ target_resource_id: `acct-9931${RLO}live` }) as never,
      { actionType: 'payment.transfer' as never, changedFields: [] },
    );
    expect(result).toBeTruthy();
    expect(result?.code).toBe('hostile_display_codepoints');
  });

  it('still accepts the same action once the override is removed', () => {
    const result = validateGuardActionInput(
      baseAction({ target_resource_id: 'acct-9931live' }) as never,
      { actionType: 'payment.transfer' as never, changedFields: [] },
    );
    expect(result?.code).not.toBe('hostile_display_codepoints');
  });
});
