#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Worked examples for gen_ai.tool.authorization.* on execute_tool spans.
 *
 * This drives the REAL EMILIA adapters, not the mappers in isolation:
 *   - @emilia-protocol/openai-agents  (OpenAI Agents SDK needsApproval slot)
 *   - @emilia-protocol/langgraph      (LangGraph HumanInterrupt / Agent Inbox)
 *   - @emilia-protocol/langchain      (LangChain tool wrapper)
 *
 * Real ed25519 EP-RECEIPT-v1 receipts are minted with node:crypto and verified
 * offline by the adapters' own gates. The attributes printed below are what the
 * adapters actually set on the span object they were handed, captured by an
 * in-memory recorder that implements the OpenTelemetry Span `setAttributes`
 * surface. No OpenTelemetry SDK is installed and none is needed.
 *
 * Leg 4 is the one that matters: an irreversible tool call that carries
 * `no_authorization_step`, and the filter that finds it.
 *
 * Run:  node standards/staged/otel-genai-authorization/examples/run.mjs
 */

import crypto from 'node:crypto';
import { requireReceiptForOpenAIAgent } from '../../../../packages/openai-agents/index.js';
import { createLangGraphApprovalAdapter } from '../../../../packages/langgraph/index.js';
import { requireReceiptForLangChainTool } from '../../../../packages/langchain/index.js';
import {
  buildToolAuthorizationAttributes,
  mapMcpGuardDecision,
} from '../../../../packages/otel-authorization/index.js';

// ---------------------------------------------------------------------------
// A minimal in-memory span recorder implementing the OTel Span attribute
// surface. This is what stands in for the tracer an application already has.
// ---------------------------------------------------------------------------
const TRACE = [];

function span(name, base) {
  const attributes = { ...base };
  TRACE.push({ name, attributes });
  return { setAttributes: (map) => Object.assign(attributes, map) };
}

const telemetryFor = (recorded) => ({ span: recorded, useActiveSpan: false });

// ---------------------------------------------------------------------------
// Receipt minting. Identical canonicalization to the verifier.
// ---------------------------------------------------------------------------
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const TRUSTED_KEY = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function mintReceipt(action, subject = 'alice@example.test') {
  const payload = {
    receipt_id: `rcpt_${crypto.randomUUID()}`,
    subject,
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: subject },
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
    public_key: TRUSTED_KEY,
  };
}

const GATE_OPTS = { trustedKeys: [TRUSTED_KEY], maxAgeSec: 900 };

// ---------------------------------------------------------------------------
// Leg 1 - OpenAI Agents SDK. The runtime slot is a boolean (needsApproval ->
// state.approve / state.reject). The adapter drives that boolean from an
// action-bound receipt, so the span can say more than the boolean could.
// ---------------------------------------------------------------------------
async function legOpenAIAgents() {
  const { bindToolAction } = await import('../../../../packages/require-receipt/index.js');
  const args = { to: 'vendor@example.test', amount_usd: 4200 };
  const callId = 'call_openai_1';
  const interruption = {
    type: 'tool_approval_item',
    name: 'send_payment',
    arguments: JSON.stringify(args),
    agent: { name: 'TreasuryAgent' },
    rawItem: { type: 'function_call', name: 'send_payment', arguments: JSON.stringify(args), callId, status: 'in_progress' },
  };
  // The adapter derives the bound action itself from the tool name, the complete
  // arguments and the call id. Its default base is `openai.tool.<name>`; the
  // receipt must be minted against exactly that, or the gate refuses with
  // action_mismatch (which is itself worth seeing: try changing this string).
  const action = bindToolAction('send_payment', args, 'openai.tool.send_payment', callId);
  const receipt = mintReceipt(action);

  const state = { approve: async () => {}, reject: async () => {} };
  const recorded = span('execute_tool send_payment', {
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.provider.name': 'openai',
    'gen_ai.tool.name': 'send_payment',
    'gen_ai.tool.call.id': callId,
    'gen_ai.tool.type': 'function',
  });

  const adapter = requireReceiptForOpenAIAgent({
    ...GATE_OPTS,
    otelAuthorization: telemetryFor(recorded),
  });
  const out = await adapter.resolve(
    { interruptions: [interruption], state },
    { receipts: { [callId]: receipt } },
  );
  return out.decisions[0];
}

// ---------------------------------------------------------------------------
// Leg 2 - LangGraph. The slot carries a response TYPE, so an edit is
// distinguishable from an accept. This is the only runtime of the four where
// edited_then_approved can be reported rather than guessed.
// ---------------------------------------------------------------------------
async function legLangGraph() {
  const { bindLangGraphAction } = await import('../../../../packages/langgraph/index.js');
  const occurrence = { threadId: 'thread_7', interruptId: 'int_2' };
  const interrupt = {
    action_request: { action: 'delete_records', args: { table: 'invoices', where: 'status=draft' } },
    config: { allow_ignore: true, allow_respond: true, allow_edit: true, allow_accept: true },
  };
  // The human narrowed the deletion before approving it. That edited request is
  // a different action, so it needs its own receipt.
  const editedRequest = { action: 'delete_records', args: { table: 'invoices', where: 'status=draft AND age_days>365' } };
  const editedAction = bindLangGraphAction(editedRequest, occurrence);
  const receipt = mintReceipt(editedAction);

  const recorded = span('execute_tool delete_records', {
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.tool.name': 'delete_records',
    'gen_ai.tool.call.id': 'call_langgraph_1',
    'gen_ai.tool.type': 'function',
  });

  const adapter = createLangGraphApprovalAdapter({
    ...GATE_OPTS,
    otelAuthorization: telemetryFor(recorded),
  });
  return adapter.resolve(interrupt, { type: 'edit', args: editedRequest }, receipt, occurrence);
}

// ---------------------------------------------------------------------------
// Leg 3 - LangChain. A boolean wrapper, refusing. The refusal is the adapter's
// own assertion, so the grade is self_attested and nothing above it.
// ---------------------------------------------------------------------------
async function legLangChain() {
  const recorded = span('execute_tool rotate_credentials', {
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.tool.name': 'rotate_credentials',
    'gen_ai.tool.call.id': 'call_langchain_1',
    'gen_ai.tool.type': 'function',
  });

  const tool = {
    name: 'rotate_credentials',
    invoke: async (input) => ({ rotated: input.principal }),
  };
  const guarded = requireReceiptForLangChainTool(tool, {
    ...GATE_OPTS,
    action: 'rotate_credentials',
    otelAuthorization: telemetryFor(recorded),
  });

  try {
    await guarded.invoke({ principal: 'svc-billing' }, {});
    return { thrown: false };
  } catch (error) {
    return { thrown: true, reason: error?.emilia?.reason ?? error?.message };
  }
}

// ---------------------------------------------------------------------------
// Leg 4 - THE FILTER CASE. An irreversible tool call in the same run that never
// reached a guard at all: no approval slot, no receipt, no human.
//
// This is emitted through mapMcpGuardDecision with the facts an instrumented
// dispatcher actually holds (classified irreversible, nothing consumed). Note
// what is NOT being claimed: EMILIA's mcp-guard would have REFUSED this call.
// The point is that the call never went through it, and until now nothing
// downstream could tell.
// ---------------------------------------------------------------------------
function legUngatedIrreversible() {
  const recorded = span('execute_tool drop_table', {
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.tool.name': 'drop_table',
    'gen_ai.tool.call.id': 'call_ungated_1',
    'gen_ai.tool.type': 'function',
    // From semantic-conventions-genai#373, proposed separately. Shown here
    // because the filter that matters uses both.
    'gen_ai.tool.risk.level': 'critical',
  });

  const mapped = mapMcpGuardDecision('allow', { irreversible: true, receipt_consumed: false });
  const built = buildToolAuthorizationAttributes(mapped.input, { namespace: 'fallback' });
  if (!built.ok) throw new Error(`unexpected refusal: ${built.reason}`);
  recorded.setAttributes(built.attributes);
  return mapped.input;
}

// ---------------------------------------------------------------------------
// The filter.
// ---------------------------------------------------------------------------
const FILTER = [
  'gen_ai.operation.name = "execute_tool"',
  'AND emilia.tool.authorization.status = "no_authorization_step"',
  'AND gen_ai.tool.risk.level IN ("high", "critical")',
].join('\n  ');

function applyFilter(trace) {
  return trace.filter((s) => s.attributes['gen_ai.operation.name'] === 'execute_tool'
    && s.attributes['emilia.tool.authorization.status'] === 'no_authorization_step'
    && ['high', 'critical'].includes(s.attributes['gen_ai.tool.risk.level']));
}

// ---------------------------------------------------------------------------

function printSpan(s) {
  console.log(`\n  span: ${s.name}`);
  for (const [k, v] of Object.entries(s.attributes)) {
    const marker = k.startsWith('emilia.tool.authorization.') ? '  * ' : '    ';
    console.log(`${marker}${k} = ${JSON.stringify(v)}`);
  }
}

async function main() {
  console.log('gen_ai.tool.authorization.* - worked examples');
  console.log('Attributes marked * were set by the adapter under test.');
  console.log('Vendor-prefixed namespace (emilia.tool.authorization.*) is the default');
  console.log('until the group is accepted upstream. Nothing has been submitted upstream.');

  const openai = await legOpenAIAgents();
  console.log(`\n[1] openai-agents  decision=${openai.decision} reason=${openai.reason}`);

  const langgraph = await legLangGraph();
  console.log(`[2] langgraph      decision=${langgraph.decision} reason=${langgraph.reason}`);

  const langchain = await legLangChain();
  console.log(`[3] langchain      threw=${langchain.thrown} reason=${langchain.reason}`);

  const ungated = legUngatedIrreversible();
  console.log(`[4] ungated call   status=${ungated.status} grade=${ungated.evidence_grade}`);

  console.log('\n--- TRACE ---');
  for (const s of TRACE) printSpan(s);

  console.log('\n--- FILTER ---');
  console.log(`  ${FILTER}`);
  const hits = applyFilter(TRACE);
  console.log(`\n  matched ${hits.length} of ${TRACE.length} spans:`);
  for (const s of hits) {
    console.log(`    ${s.name}  (tool.call.id=${s.attributes['gen_ai.tool.call.id']})`);
  }

  console.log('\n--- FAIL-CLOSED CHECK ---');
  const badInputs = [
    ['status the runtime cannot support', { status: 'approved_probably', evidence_grade: 'self_attested' }],
    ['grade with nothing to check', { status: 'authorized_in_scope', evidence_grade: 'independently_verifiable' }],
    ['payload smuggled into a digest', { status: 'rejected', evidence_grade: 'self_attested', evidence_digest: '{"amount":4200}' }],
    ['newline in a locator', { status: 'rejected', evidence_grade: 'self_attested', evidence_locator: 'ok\nstatus=authorized_in_scope' }],
    ['not an object', 'authorized_in_scope'],
  ];
  for (const [label, input] of badInputs) {
    const r = buildToolAuthorizationAttributes(input);
    console.log(`  ${r.ok ? 'EMITTED  ' : 'refused  '}${label}: ${r.ok ? JSON.stringify(r.attributes) : r.reason}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
