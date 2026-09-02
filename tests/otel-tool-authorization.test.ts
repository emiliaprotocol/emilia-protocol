// SPDX-License-Identifier: Apache-2.0
/**
 * gen_ai.tool.authorization.* attribute mapping.
 *
 * Two things are under test and they are different:
 *
 *   1. The MAPPING is honest. A runtime whose approval slot is a boolean must
 *      not produce a status that asserts more than a boolean carries, and an
 *      evidence grade above self_attested must not appear without something a
 *      third party could check.
 *   2. The builder FAILS CLOSED. Malformed, hostile or over-claiming input
 *      returns a refusal naming the reason and sets NOTHING on the span. It does
 *      not throw, it does not truncate, and it does not emit a partial map. A
 *      wrong authorization status on an exported span is worse than none.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  TOOL_AUTHORIZATION_STATUS,
  TOOL_AUTHORIZATION_STATUS_VALUES,
  EVIDENCE_GRADE,
  EVIDENCE_GRADE_VALUES,
  REGISTRY_ATTRIBUTE_KEYS,
  FALLBACK_ATTRIBUTE_KEYS,
  buildToolAuthorizationAttributes,
  setToolAuthorizationAttributes,
  emitToolAuthorization,
  mapOpenAIAgentsDecision,
  mapLangGraphDecision,
  mapLangChainDecision,
  mapMcpGuardDecision,
  mapClaudeCodeHookDecision,
} from '../packages/otel-authorization/index.js';
import { requireReceiptForOpenAIAgent, _resetConsumed } from '../packages/openai-agents/index.js';
import { bindToolAction } from '../packages/require-receipt/index.js';

const DIGEST = 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const VERIFIABLE = {
  evidence_digest: DIGEST,
  evidence_format: 'application/vnd.emilia.receipt.v1+json',
  evidence_locator: 'emilia-receipt:rcp_01J8ZC4W6H',
};

function recorder() {
  const attributes: Record<string, unknown> = {};
  return {
    attributes,
    span: { setAttributes: (map: Record<string, unknown>) => Object.assign(attributes, map) },
  };
}

describe('vocabulary', () => {
  it('carries exactly the nine decided status values', () => {
    expect([...TOOL_AUTHORIZATION_STATUS_VALUES].sort()).toEqual([
      'authorized_in_scope',
      'authorized_out_of_scope',
      'authorized_without_standing',
      'auto_approved',
      'edited_then_approved',
      'no_authorization_step',
      'rejected',
      'standing_preauthorization',
      'step_bypassed',
    ]);
  });

  it('carries exactly the three evidence grades', () => {
    expect([...EVIDENCE_GRADE_VALUES].sort()).toEqual([
      'independently_verifiable',
      'self_attested',
      'third_party_logged',
    ]);
  });

  it('keeps the registry and fallback namespaces one-for-one', () => {
    expect(Object.keys(REGISTRY_ATTRIBUTE_KEYS)).toEqual(Object.keys(FALLBACK_ATTRIBUTE_KEYS));
    for (const slot of Object.keys(REGISTRY_ATTRIBUTE_KEYS) as Array<keyof typeof REGISTRY_ATTRIBUTE_KEYS>) {
      expect(REGISTRY_ATTRIBUTE_KEYS[slot]).toMatch(/^gen_ai\.tool\.authorization\./);
      expect(FALLBACK_ATTRIBUTE_KEYS[slot]).toBe(
        REGISTRY_ATTRIBUTE_KEYS[slot].replace(/^gen_ai\./, 'emilia.'),
      );
    }
  });
});

describe('namespace selection', () => {
  it('defaults to the vendor-prefixed namespace, not the registry one', () => {
    const built = buildToolAuthorizationAttributes({
      status: TOOL_AUTHORIZATION_STATUS.REJECTED,
      evidence_grade: EVIDENCE_GRADE.SELF_ATTESTED,
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.attributes['emilia.tool.authorization.status']).toBe('rejected');
    expect(built.attributes['gen_ai.tool.authorization.status']).toBeUndefined();
  });

  it('emits both namespaces when asked, and nothing else', () => {
    const built = buildToolAuthorizationAttributes(
      { status: TOOL_AUTHORIZATION_STATUS.AUTO_APPROVED, evidence_grade: EVIDENCE_GRADE.SELF_ATTESTED },
      { namespace: 'both' },
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(Object.keys(built.attributes).sort()).toEqual([
      'emilia.tool.authorization.evidence.grade',
      'emilia.tool.authorization.status',
      'gen_ai.tool.authorization.evidence.grade',
      'gen_ai.tool.authorization.status',
    ]);
  });

  it('refuses an unknown namespace rather than defaulting', () => {
    const built = buildToolAuthorizationAttributes(
      { status: 'rejected', evidence_grade: 'self_attested' },
      { namespace: 'registry-ish' as any },
    );
    expect(built).toEqual({ ok: false, reason: 'unknown_attribute_namespace' });
  });
});

describe('fail-closed: the builder refuses rather than guessing', () => {
  const cases: Array<[string, unknown, string]> = [
    ['input is not an object', 'authorized_in_scope', 'input_not_an_object'],
    ['input is null', null, 'input_not_an_object'],
    ['input is an array', [], 'input_not_an_object'],
    ['status missing', { evidence_grade: 'self_attested' }, 'status_not_a_string'],
    ['status is not a string', { status: 1, evidence_grade: 'self_attested' }, 'status_not_a_string'],
    ['status outside the vocabulary', { status: 'approved', evidence_grade: 'self_attested' }, 'unknown_status_value'],
    ['status differs only in case', { status: 'Rejected', evidence_grade: 'self_attested' }, 'unknown_status_value'],
    ['grade missing', { status: 'rejected' }, 'evidence_grade_not_a_string'],
    ['grade outside the vocabulary', { status: 'rejected', evidence_grade: 'E3' }, 'unknown_evidence_grade_value'],
  ];
  for (const [label, input, reason] of cases) {
    it(label, () => {
      expect(buildToolAuthorizationAttributes(input)).toEqual({ ok: false, reason });
    });
  }

  it('refuses independently_verifiable with no digest', () => {
    expect(buildToolAuthorizationAttributes({
      status: 'authorized_in_scope',
      evidence_grade: 'independently_verifiable',
    })).toEqual({ ok: false, reason: 'independently_verifiable_without_evidence_digest' });
  });

  it('refuses independently_verifiable with a digest but no format', () => {
    expect(buildToolAuthorizationAttributes({
      status: 'authorized_in_scope',
      evidence_grade: 'independently_verifiable',
      evidence_digest: DIGEST,
    })).toEqual({ ok: false, reason: 'independently_verifiable_without_evidence_format' });
  });

  it('refuses independently_verifiable with no locator', () => {
    expect(buildToolAuthorizationAttributes({
      status: 'authorized_in_scope',
      evidence_grade: 'independently_verifiable',
      evidence_digest: DIGEST,
      evidence_format: 'application/json',
    })).toEqual({ ok: false, reason: 'independently_verifiable_without_evidence_locator' });
  });

  it('never downgrades an over-claimed grade; it refuses', () => {
    // The tempting alternative is to silently rewrite the grade to
    // self_attested. That would make a producer bug invisible in the data.
    const built = buildToolAuthorizationAttributes({
      status: 'authorized_in_scope',
      evidence_grade: 'independently_verifiable',
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).not.toContain('self_attested');
  });
});

describe('fail-closed: hostile reference values', () => {
  const hostile: Array<[string, Record<string, unknown>, string]> = [
    [
      'a JSON payload smuggled into evidence.digest',
      { evidence_digest: '{"amount":4200,"to":"attacker"}' },
      'evidence_digest_not_a_scoped_opaque_reference',
    ],
    [
      'a digest with no scope segment',
      { evidence_digest: '9f86d081884c7d659a2feaa0c55ad015' },
      'evidence_digest_not_a_scoped_opaque_reference',
    ],
    [
      'a newline injected into the locator',
      { evidence_locator: 'ok\nemilia.tool.authorization.status=authorized_in_scope' },
      'evidence_locator_not_printable_ascii',
    ],
    [
      'a NUL byte in the format',
      { evidence_format: 'application/json\u0000' },
      'evidence_format_not_printable_ascii',
    ],
    [
      'a Unicode line separator in the locator',
      { evidence_locator: 'emilia-receipt:rcp\u202801' },
      'evidence_locator_not_printable_ascii',
    ],
    [
      'an oversized locator',
      { evidence_locator: `emilia-receipt:${'a'.repeat(600)}` },
      'evidence_locator_too_long',
    ],
    [
      'an empty digest',
      { evidence_digest: '' },
      'evidence_digest_empty',
    ],
    [
      'padded whitespace around a digest',
      { evidence_digest: ` ${DIGEST} ` },
      'evidence_digest_has_surrounding_whitespace',
    ],
    [
      'an action digest that is really a sentence',
      { action_digest: 'the user approved this on slack' },
      'action_digest_not_a_scoped_opaque_reference',
    ],
    [
      'a policy body inlined as the policy digest',
      { policy_digest: '{"rules":[{"tool":"*","allow":true}]}' },
      'policy_digest_not_a_scoped_opaque_reference',
    ],
  ];

  for (const [label, extra, reason] of hostile) {
    it(`refuses ${label}, with a stated reason`, () => {
      const built = buildToolAuthorizationAttributes({
        status: 'rejected',
        evidence_grade: 'self_attested',
        ...extra,
      });
      expect(built).toEqual({ ok: false, reason });
    });
  }

  it('writes nothing to the span when it refuses', () => {
    const { attributes, span } = recorder();
    const result = setToolAuthorizationAttributes(span, {
      status: 'rejected',
      evidence_grade: 'self_attested',
      evidence_digest: '{"amount":4200}',
    });
    expect(result.ok).toBe(false);
    expect(Object.keys(attributes)).toHaveLength(0);
  });

  it('accepts the digest and CAID forms this repository actually produces', () => {
    const shapes = [
      DIGEST,
      'receipt:sha256:d813438b91796e1d045c3262e05e648388a939883466c6d13457d543d7f8461b',
      'send_payment:sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
      'caid:v1:tool.call.1:sha256:LNJrRmj_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564',
    ];
    for (const shape of shapes) {
      const built = buildToolAuthorizationAttributes({
        status: 'authorized_in_scope',
        evidence_grade: 'self_attested',
        action_digest: shape,
      });
      expect(built.ok, shape).toBe(true);
    }
  });
});

describe('setToolAuthorizationAttributes', () => {
  it('validates without a span and reports that nothing was written', () => {
    const result = setToolAuthorizationAttributes(null, {
      status: 'auto_approved',
      evidence_grade: 'self_attested',
    });
    expect(result).toMatchObject({ ok: true, written: false });
  });

  it('falls back to setAttribute when setAttributes is absent', () => {
    const attributes: Record<string, unknown> = {};
    const result = setToolAuthorizationAttributes(
      { setAttribute: (k: string, v: unknown) => { attributes[k] = v; } },
      { status: 'rejected', evidence_grade: 'self_attested' },
    );
    expect(result).toMatchObject({ ok: true, written: true });
    expect(attributes['emilia.tool.authorization.status']).toBe('rejected');
  });

  it('reports a throwing span as a telemetry refusal, not an exception', () => {
    const result = setToolAuthorizationAttributes(
      { setAttributes: () => { throw new Error('exporter is down'); } },
      { status: 'rejected', evidence_grade: 'self_attested' },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('span_setter_threw');
  });

  it('refuses a span-like object with no setter at all', () => {
    const result = setToolAuthorizationAttributes({} as any, {
      status: 'rejected',
      evidence_grade: 'self_attested',
    });
    expect(result).toEqual({ ok: false, reason: 'span_has_no_attribute_setter' });
  });
});

describe('mapping: OpenAI Agents SDK (boolean slot)', () => {
  it('maps a receipt-backed approve to authorized_in_scope, independently_verifiable', () => {
    const mapped = mapOpenAIAgentsDecision('approve', VERIFIABLE);
    expect(mapped).toEqual({
      ok: true,
      input: {
        status: 'authorized_in_scope',
        evidence_grade: 'independently_verifiable',
        ...VERIFIABLE,
      },
    });
  });

  it('maps a bare approve to auto_approved at self_attested, never authorized_in_scope', () => {
    const mapped = mapOpenAIAgentsDecision('approve_no_receipt');
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('auto_approved');
    expect(mapped.input.evidence_grade).toBe('self_attested');
  });

  it('maps a reject to rejected at self_attested', () => {
    const mapped = mapOpenAIAgentsDecision('reject');
    expect(mapped).toEqual({
      ok: true,
      input: { status: 'rejected', evidence_grade: 'self_attested' },
    });
  });

  it('refuses a decision it does not recognise', () => {
    expect(mapOpenAIAgentsDecision('maybe')).toEqual({ ok: false, reason: 'unknown_openai_agents_decision' });
    expect(mapOpenAIAgentsDecision(null)).toEqual({ ok: false, reason: 'openai_agents_decision_not_a_string' });
  });
});

describe('mapping: LangGraph (typed response slot)', () => {
  it('is the only runtime that can report edited_then_approved', () => {
    const mapped = mapLangGraphDecision('resume', 'edit', VERIFIABLE);
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('edited_then_approved');
  });

  it('maps an accepted resume to authorized_in_scope', () => {
    const mapped = mapLangGraphDecision('resume', 'accept', VERIFIABLE);
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('authorized_in_scope');
  });

  it('maps reauthorize to authorized_out_of_scope', () => {
    // The human edited the call; the authority on hand covers the pre-edit call.
    const mapped = mapLangGraphDecision('reauthorize', 'edit');
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('authorized_out_of_scope');
    expect(mapped.input.evidence_grade).toBe('self_attested');
  });

  it('maps a non-authorizing human response to no_authorization_step, not approval', () => {
    for (const responseType of ['ignore', 'response']) {
      const mapped = mapLangGraphDecision('pass', responseType);
      expect(mapped.ok).toBe(true);
      if (!mapped.ok) return;
      expect(mapped.input.status).toBe('no_authorization_step');
    }
  });

  it('refuses an unknown decision or a non-string response type', () => {
    expect(mapLangGraphDecision('continue', 'accept')).toEqual({ ok: false, reason: 'unknown_langgraph_decision' });
    expect(mapLangGraphDecision('resume', 7)).toEqual({ ok: false, reason: 'langgraph_response_type_not_a_string' });
  });
});

describe('mapping: LangChain (boolean slot)', () => {
  it('maps allowed without a receipt to auto_approved at self_attested', () => {
    const mapped = mapLangChainDecision(true, false);
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('auto_approved');
    expect(mapped.input.evidence_grade).toBe('self_attested');
  });

  it('maps allowed with a receipt to authorized_in_scope, independently_verifiable', () => {
    const mapped = mapLangChainDecision(true, true, VERIFIABLE);
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('authorized_in_scope');
    expect(mapped.input.evidence_grade).toBe('independently_verifiable');
  });

  it('maps a refusal to rejected', () => {
    const mapped = mapLangChainDecision(false, false);
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('rejected');
  });

  it('refuses non-boolean input rather than coercing it', () => {
    expect(mapLangChainDecision('yes', false)).toEqual({ ok: false, reason: 'langchain_allowed_not_a_boolean' });
    expect(mapLangChainDecision(true, 'yes')).toEqual({ ok: false, reason: 'langchain_receipt_bound_not_a_boolean' });
  });
});

describe('mapping: MCP guard', () => {
  it('reports an irreversible allow with no receipt as no_authorization_step', () => {
    const mapped = mapMcpGuardDecision('allow', { irreversible: true, receipt_consumed: false });
    expect(mapped).toEqual({
      ok: true,
      input: { status: 'no_authorization_step', evidence_grade: 'self_attested' },
    });
  });

  it('reports a reversible allow as auto_approved, not as a missing step', () => {
    const mapped = mapMcpGuardDecision('allow', { irreversible: false, receipt_consumed: false });
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('auto_approved');
  });

  it('reports a signoff path that consumed nothing as step_bypassed', () => {
    const mapped = mapMcpGuardDecision('allow_with_signoff', { irreversible: true, receipt_consumed: false });
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('step_bypassed');
  });

  it('reports a consumed receipt as authorized_in_scope', () => {
    const mapped = mapMcpGuardDecision(
      'allow_with_signoff',
      { irreversible: true, receipt_consumed: true },
      VERIFIABLE,
    );
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('authorized_in_scope');
    expect(mapped.input.evidence_grade).toBe('independently_verifiable');
  });

  it('reports a deny as rejected', () => {
    const mapped = mapMcpGuardDecision('deny', { irreversible: true, receipt_consumed: false });
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.input.status).toBe('rejected');
  });

  it('refuses facts it cannot read rather than assuming reversible', () => {
    expect(mapMcpGuardDecision('allow', null)).toEqual({ ok: false, reason: 'mcp_guard_facts_not_an_object' });
    expect(mapMcpGuardDecision('allow', { receipt_consumed: false }))
      .toEqual({ ok: false, reason: 'mcp_guard_irreversible_not_a_boolean' });
    expect(mapMcpGuardDecision('allow', { irreversible: true }))
      .toEqual({ ok: false, reason: 'mcp_guard_receipt_consumed_not_a_boolean' });
    expect(mapMcpGuardDecision('escalate', { irreversible: true, receipt_consumed: false }))
      .toEqual({ ok: false, reason: 'unknown_mcp_guard_decision' });
  });
});

describe('mapping: Claude Code PreToolUse hook', () => {
  it('refuses to give a pending "ask" any status at all', () => {
    // The single most important refusal in this file. An unresolved human step
    // recorded as auto_approved is the exact false negative the attribute group
    // exists to expose.
    expect(mapClaudeCodeHookDecision('ask')).toEqual({
      ok: false,
      reason: 'claude_code_ask_is_not_a_resolved_authorization_status',
    });
  });

  it('maps deny to rejected and allow to auto_approved, both self_attested', () => {
    expect(mapClaudeCodeHookDecision('deny')).toEqual({
      ok: true,
      input: { status: 'rejected', evidence_grade: 'self_attested' },
    });
    expect(mapClaudeCodeHookDecision('allow')).toEqual({
      ok: true,
      input: { status: 'auto_approved', evidence_grade: 'self_attested' },
    });
  });
});

describe('emitToolAuthorization', () => {
  it('passes a mapper refusal through to onEmit and writes nothing', () => {
    const { attributes, span } = recorder();
    const seen: any[] = [];
    return emitToolAuthorization(
      { span, useActiveSpan: false, onEmit: (r) => seen.push(r) },
      mapClaudeCodeHookDecision('ask'),
      { runtime: 'claude-code' },
    ).then((result) => {
      expect(result.ok).toBe(false);
      expect(Object.keys(attributes)).toHaveLength(0);
      expect(seen).toHaveLength(1);
    });
  });

  it('is a no-op when disabled', async () => {
    const { attributes, span } = recorder();
    const result = await emitToolAuthorization(
      { span, enabled: false, useActiveSpan: false },
      mapLangChainDecision(false, false),
    );
    expect(result).toEqual({ ok: false, reason: 'telemetry_disabled' });
    expect(Object.keys(attributes)).toHaveLength(0);
  });

  it('never lets a throwing onEmit or spanFor reach the caller', async () => {
    const result = await emitToolAuthorization(
      {
        useActiveSpan: false,
        spanFor: () => { throw new Error('resolver exploded'); },
        onEmit: () => { throw new Error('observer exploded'); },
      },
      mapLangChainDecision(false, false),
    );
    expect(result).toMatchObject({ ok: true, written: false });
  });
});

describe('adapter emission: openai-agents end to end', () => {
  function canonicalize(v: any): string {
    if (v === null || v === undefined) return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
    if (typeof v === 'object') {
      return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
    }
    return JSON.stringify(v);
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const TRUSTED_KEY = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

  function mintReceipt(action: string) {
    const payload = {
      receipt_id: `rcpt_${crypto.randomUUID()}`,
      subject: 'alice@example.test',
      created_at: new Date().toISOString(),
      claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'alice@example.test' },
    };
    const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
    return {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
      public_key: TRUSTED_KEY,
    };
  }

  function interruptionFor(callId: string, args: Record<string, unknown>) {
    const argStr = JSON.stringify(args);
    return {
      type: 'tool_approval_item',
      name: 'send_payment',
      arguments: argStr,
      agent: { name: 'TreasuryAgent' },
      rawItem: { type: 'function_call', name: 'send_payment', arguments: argStr, callId, status: 'in_progress' },
    };
  }

  it('sets authorized_in_scope with a checkable evidence digest on a driven approve', async () => {
    _resetConsumed();
    const args = { to: 'vendor@example.test', amount_usd: 4200 };
    const callId = `call_${crypto.randomUUID()}`;
    const action = bindToolAction('send_payment', args, 'openai.tool.send_payment', callId);
    const receipt = mintReceipt(action);
    const { attributes, span } = recorder();

    const adapter = requireReceiptForOpenAIAgent({
      trustedKeys: [TRUSTED_KEY],
      maxAgeSec: 900,
      otelAuthorization: { span, useActiveSpan: false },
    });
    const out = await adapter.resolve(
      { interruptions: [interruptionFor(callId, args)], state: { approve: async () => {}, reject: async () => {} } },
      { receipts: { [callId]: receipt } },
    );

    expect(out.decisions[0].decision).toBe('approve');
    expect(attributes['emilia.tool.authorization.status']).toBe('authorized_in_scope');
    expect(attributes['emilia.tool.authorization.evidence.grade']).toBe('independently_verifiable');
    expect(attributes['emilia.tool.authorization.evidence.digest']).toMatch(/^receipt:sha256:[0-9a-f]{64}$/);
    expect(attributes['emilia.tool.authorization.evidence.format'])
      .toBe('application/vnd.emilia.receipt.v1+json');
    expect(attributes['emilia.tool.authorization.action.digest']).toBe(action);
    // The approver's identity is deliberately absent from the span.
    expect(JSON.stringify(attributes)).not.toContain('alice@example.test');
  });

  it('sets rejected at self_attested when no receipt is presented', async () => {
    _resetConsumed();
    const args = { to: 'vendor@example.test', amount_usd: 4200 };
    const callId = `call_${crypto.randomUUID()}`;
    const { attributes, span } = recorder();

    const adapter = requireReceiptForOpenAIAgent({
      trustedKeys: [TRUSTED_KEY],
      maxAgeSec: 900,
      otelAuthorization: { span, useActiveSpan: false },
    });
    const out = await adapter.resolve(
      { interruptions: [interruptionFor(callId, args)], state: { approve: async () => {}, reject: async () => {} } },
      { receipts: {} },
    );

    expect(out.decisions[0].decision).toBe('reject');
    expect(attributes['emilia.tool.authorization.status']).toBe('rejected');
    expect(attributes['emilia.tool.authorization.evidence.grade']).toBe('self_attested');
    expect(attributes['emilia.tool.authorization.evidence.digest']).toBeUndefined();
  });

  it('emits nothing when the adapter is configured without telemetry', async () => {
    _resetConsumed();
    const args = { to: 'vendor@example.test', amount_usd: 1 };
    const callId = `call_${crypto.randomUUID()}`;
    const { attributes, span } = recorder();

    const adapter = requireReceiptForOpenAIAgent({ trustedKeys: [TRUSTED_KEY], maxAgeSec: 900 });
    await adapter.resolve(
      { interruptions: [interruptionFor(callId, args)], state: { approve: async () => {}, reject: async () => {} } },
      { receipts: {} },
    );
    void span;
    expect(Object.keys(attributes)).toHaveLength(0);
  });
});
