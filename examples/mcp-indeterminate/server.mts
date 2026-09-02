// SPDX-License-Identifier: Apache-2.0
//
// A real MCP server on the official TypeScript SDK, stdio transport.
//
//   node examples/mcp-indeterminate/server.mjs
//
// Driven by three environment variables so the demo is deterministic:
//
//   EP_STORE_DIR   directory holding the boundary journal and the provider
//                  record. Survives the injected crash. Required.
//   EP_MCP_MODE    "legacy"     - today's MCP: content + isError, no replay
//                                 unit, no dedup, no outcome value. This is
//                                 not a straw man; it is what the schema
//                                 gives a server author to work with.
//                  "fieldgroup" - the same server plus EP-MCP-OUTCOME-v1.
//   EP_CRASH       "none" | "after-effect" | "before-effect".
//                  The crash is process.exit(70) at a fixed line, so the
//                  same input crashes at the same point every run.
//
// The tool is annotated idempotentHint:false and destructiveHint:true, which
// is exactly the case MCP has no vocabulary for: a host that reads those
// hints still has nothing in the result telling it whether the effect landed.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeCaid } from '../../caid/impl/js/caid.mjs';
import {
  FIELD_GROUP_VERSION,
  META_AUTHORITY,
  META_OUTCOME,
  META_REPLAY_UNIT,
  deriveReplayUnit,
  type OutcomeEnvelope,
} from './field-group.mjs';
import { Stores } from './ledger.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REGISTRY = JSON.parse(
  readFileSync(join(here, '..', '..', 'caid', 'registry', 'action-types.json'), 'utf8'),
) as { types: unknown[] };

const STORE_DIR = process.env.EP_STORE_DIR;
if (!STORE_DIR) {
  process.stderr.write('server: EP_STORE_DIR is required\n');
  process.exit(64);
}
const MODE = process.env.EP_MCP_MODE === 'fieldgroup' ? 'fieldgroup' : 'legacy';
const CRASH = process.env.EP_CRASH ?? 'none';
const RECONCILE_TOOL = 'reconcile_effect';

const stores = new Stores(STORE_DIR);
const log = (line: string): void => {
  process.stderr.write(`[server ${MODE}] ${line}\n`);
};

/** Deterministic clock so two runs of the demo produce identical bytes. */
let tick = 0;
const now = (): string => {
  tick += 1;
  return new Date(Date.UTC(2026, 8, 2, 0, 0, tick)).toISOString();
};

interface PaymentArgs {
  amount: string;
  currency: string;
  beneficiary_account: string;
  payment_instruction_id: string;
}

function caidFor(args: PaymentArgs): { ok: true; caid: string } | { ok: false; refusals: string[] } {
  const result = computeCaid(
    {
      action_type: 'payment.release.1',
      amount: args.amount,
      currency: args.currency,
      beneficiary_account: args.beneficiary_account,
      payment_instruction_id: args.payment_instruction_id,
    },
    { suite: 'jcs-sha256', definitions: REGISTRY.types },
  );
  if (!result.caid) return { ok: false, refusals: result.refusals ?? ['caid_computation_failed'] };
  return { ok: true, caid: result.caid };
}

function textResult(text: string, extra?: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text }], ...extra };
}

function refuse(reasons: string[], envelope?: OutcomeEnvelope) {
  return {
    content: [{ type: 'text' as const, text: `refused: ${reasons.join(', ')}` }],
    isError: true,
    structuredContent: { refusals: reasons },
    ...(envelope ? { _meta: { [META_OUTCOME]: envelope } } : {}),
  };
}

// ---------------------------------------------------------------------------
// The effect
// ---------------------------------------------------------------------------

function performEffect(args: PaymentArgs, caid: string, operationId: string): void {
  if (CRASH === 'before-effect') {
    log(`CRASH INJECTED before effect, operation_id=${operationId}`);
    process.exit(70);
  }
  stores.applyEffect({
    operation_id: operationId,
    caid,
    amount: args.amount,
    currency: args.currency,
    beneficiary_account: args.beneficiary_account,
    at: now(),
  });
  log(`effect applied at provider, operation_id=${operationId}`);
  if (CRASH === 'after-effect') {
    log('CRASH INJECTED after effect, before the CallToolResult is written');
    process.exit(70);
  }
}

// ---------------------------------------------------------------------------
// Tool list
// ---------------------------------------------------------------------------

const paymentTool = {
  name: 'release_payment',
  title: 'Release a payment to settlement',
  description:
    'Releases a payment instruction to settlement. Irreversible. '
    + (MODE === 'fieldgroup'
      ? `Requires the ${META_REPLAY_UNIT} and ${META_AUTHORITY} entries in request _meta.`
      : ''),
  inputSchema: {
    type: 'object',
    properties: {
      amount: { type: 'string' },
      currency: { type: 'string' },
      beneficiary_account: { type: 'string' },
      payment_instruction_id: { type: 'string' },
    },
    required: ['amount', 'currency', 'beneficiary_account', 'payment_instruction_id'],
  },
  annotations: {
    title: 'Release a payment to settlement',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
};

const reconcileTool = {
  name: RECONCILE_TOOL,
  title: 'Reconcile an indeterminate effect',
  description:
    'Authenticated reconciliation for one replay unit. Reads the provider system '
    + 'of record. Never causes an effect and never releases the replay unit.',
  inputSchema: {
    type: 'object',
    properties: { replay_unit: { type: 'string' } },
    required: ['replay_unit'],
  },
  annotations: {
    title: 'Reconcile an indeterminate effect',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const server = new Server(
  { name: 'ep-mcp-indeterminate', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: MODE === 'fieldgroup' ? [paymentTool, reconcileTool] : [paymentTool],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  const args = (request.params.arguments ?? {}) as unknown as PaymentArgs;
  const meta = (request.params._meta ?? {}) as Record<string, unknown>;

  if (name === RECONCILE_TOOL) {
    if (MODE !== 'fieldgroup') return refuse(['unknown_tool']);
    return handleReconcile((request.params.arguments ?? {}) as { replay_unit?: unknown });
  }
  if (name !== 'release_payment') return refuse(['unknown_tool']);

  const computed = caidFor(args);
  if (!computed.ok) return refuse(computed.refusals);
  const caid = computed.caid;

  // ---- legacy mode: exactly what MCP gives a server author today ----------
  if (MODE === 'legacy') {
    const operationId = `op-legacy-${stores.providerEntries().length + 1}`;
    log(`tools/call release_payment (no replay unit on the wire) caid=${caid}`);
    performEffect(args, caid, operationId);
    return textResult(`released ${args.amount} ${args.currency} (operation ${operationId})`);
  }

  // ---- field-group mode ---------------------------------------------------
  const authority = meta[META_AUTHORITY] as { instance_digest?: unknown } | undefined;
  const presented = meta[META_REPLAY_UNIT];
  if (typeof presented !== 'string') return refuse(['missing_replay_unit']);
  if (!authority || typeof authority.instance_digest !== 'string') {
    return refuse(['missing_authority_instance_digest']);
  }

  // The server RECOMPUTES the replay unit from the authority it was shown and
  // the action it actually froze. A unit the model picked, or a unit derived
  // over different arguments, does not survive this line.
  const derived = deriveReplayUnit({
    authority_instance_digest: authority.instance_digest,
    caid,
  });
  if (!derived.ok) return refuse(derived.refusals);
  if (derived.replay_unit !== presented) {
    log('REFUSED: presented replay unit is not the derivation over this action');
    return refuse(['replay_unit_not_derived_from_authority_and_action']);
  }
  const replayUnit = derived.replay_unit;

  // Dedup and restart promotion, AEB-04 section 5.10.
  const prior = stores.latestFor(replayUnit);
  if (prior !== null) {
    if (prior.state === 'DISPATCH_PENDING') {
      // A dispatch that never reached a terminal record. The process cannot
      // establish that dispatch did not begin, so it is INDETERMINATE, not
      // "try again".
      const promoted: OutcomeEnvelope = {
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnit,
        outcome: 'indeterminate',
        retry: 'refuse',
        reconciliation: 'required',
        reason_codes: ['stranded_dispatch_pending_promoted_on_restart'],
        reconcile: { method: 'tools/call', tool: RECONCILE_TOOL, replay_unit: replayUnit },
        operation_id: prior.operation_id,
        caid,
      };
      stores.appendBoundary({ ...prior, state: 'INDETERMINATE', at: now() });
      log(`promoted stranded DISPATCH_PENDING to INDETERMINATE for ${prior.operation_id}`);
      return textResult(
        'outcome is indeterminate: this replay unit has a dispatch with no terminal record. '
        + 'Do not retry. Reconcile.',
        { structuredContent: promoted, _meta: { [META_OUTCOME]: promoted } },
      );
    }
    // Already terminal. The replay unit is spent either way.
    const spent: OutcomeEnvelope = {
      version: FIELD_GROUP_VERSION,
      replay_unit: replayUnit,
      outcome: prior.state === 'EXECUTED' ? 'executed' : 'failed',
      retry: prior.state === 'EXECUTED' ? 'not_applicable' : 'requires_new_admission',
      reconciliation: 'not_applicable',
      reason_codes: ['replay_unit_already_terminal'],
      operation_id: prior.operation_id,
      caid,
    };
    log(`replay unit already terminal (${prior.state}); no second effect`);
    return textResult(`replay unit already ${prior.state}; no second effect`, {
      structuredContent: spent,
      _meta: { [META_OUTCOME]: spent },
    });
  }

  const operationId = `op-${replayUnit.slice(7, 19)}`;
  const seqFloor = stores.providerEntries().length;
  stores.appendBoundary({
    replay_unit: replayUnit,
    state: 'DISPATCH_PENDING',
    caid,
    operation_id: operationId,
    authority_instance_digest: authority.instance_digest,
    seq_floor: seqFloor,
    at: now(),
  });
  log(`DISPATCH_PENDING written for ${operationId}, replay_unit=${replayUnit.slice(0, 23)}...`);

  performEffect(args, caid, operationId);

  stores.appendBoundary({
    replay_unit: replayUnit,
    state: 'EXECUTED',
    caid,
    operation_id: operationId,
    authority_instance_digest: authority.instance_digest,
    seq_floor: seqFloor,
    at: now(),
  });
  const executed: OutcomeEnvelope = {
    version: FIELD_GROUP_VERSION,
    replay_unit: replayUnit,
    outcome: 'executed',
    retry: 'not_applicable',
    reconciliation: 'not_applicable',
    reason_codes: [],
    operation_id: operationId,
    caid,
  };
  return textResult(`released ${args.amount} ${args.currency} (operation ${operationId})`, {
    structuredContent: executed,
    _meta: { [META_OUTCOME]: executed },
  });
});

function handleReconcile(args: { replay_unit?: unknown }) {
  const replayUnit = args.replay_unit;
  if (typeof replayUnit !== 'string') return refuse(['missing_replay_unit']);
  const prior = stores.latestFor(replayUnit);
  if (prior === null) return refuse(['unknown_replay_unit']);

  const statement = stores.statementFor(prior.operation_id);
  const found = statement.statement.found;
  const watermark = statement.statement.watermark;

  if (found !== null) {
    if (found.caid !== prior.caid) {
      // Something landed under this operation id but it is not the action we
      // froze. AEB-04 section 5.11: action-mismatched observations leave the
      // operation INDETERMINATE.
      const stuck: OutcomeEnvelope = {
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnit,
        outcome: 'indeterminate',
        retry: 'refuse',
        reconciliation: 'required',
        reason_codes: ['reconciliation_action_mismatch'],
        reconcile: { method: 'tools/call', tool: RECONCILE_TOOL, replay_unit: replayUnit },
        operation_id: prior.operation_id,
        caid: prior.caid,
      };
      return textResult('reconciliation found a mismatched action; still indeterminate', {
        structuredContent: stuck,
        _meta: { [META_OUTCOME]: stuck },
      });
    }
    stores.appendBoundary({ ...prior, state: 'EXECUTED', at: now() });
    const executed: OutcomeEnvelope = {
      version: FIELD_GROUP_VERSION,
      replay_unit: replayUnit,
      outcome: 'executed',
      retry: 'not_applicable',
      reconciliation: 'applied',
      reason_codes: ['provider_record_matched'],
      operation_id: prior.operation_id,
      caid: prior.caid,
    };
    log(`reconciled ${prior.operation_id} to EXECUTED against a signed provider record`);
    return textResult(`reconciled: the effect landed at seq ${found.seq}`, {
      structuredContent: { ...executed, provider_statement: statement },
      _meta: { [META_OUTCOME]: executed },
    });
  }

  // Absence. Authoritative only if the provider's completeness watermark
  // covers the window in which this dispatch could have landed.
  if (watermark.complete_through_seq >= prior.seq_floor) {
    stores.appendBoundary({ ...prior, state: 'FAILED', at: now() });
    const failed: OutcomeEnvelope = {
      version: FIELD_GROUP_VERSION,
      replay_unit: replayUnit,
      outcome: 'failed',
      retry: 'requires_new_admission',
      reconciliation: 'applied',
      reason_codes: ['provider_record_absent_under_complete_watermark'],
      operation_id: prior.operation_id,
      caid: prior.caid,
    };
    log(`reconciled ${prior.operation_id} to FAILED; retry requires a new admission`);
    return textResult(
      'reconciled: no effect landed, and the provider record is complete through this window. '
      + 'A later attempt is a new action instance under a new admission.',
      { structuredContent: { ...failed, provider_statement: statement }, _meta: { [META_OUTCOME]: failed } },
    );
  }

  const stillUnknown: OutcomeEnvelope = {
    version: FIELD_GROUP_VERSION,
    replay_unit: replayUnit,
    outcome: 'indeterminate',
    retry: 'refuse',
    reconciliation: 'required',
    reason_codes: ['provider_watermark_does_not_cover_dispatch_window'],
    reconcile: { method: 'tools/call', tool: RECONCILE_TOOL, replay_unit: replayUnit },
    operation_id: prior.operation_id,
    caid: prior.caid,
  };
  log(`reconciliation inconclusive for ${prior.operation_id}; stays INDETERMINATE`);
  return textResult('reconciliation inconclusive; the operation stays indeterminate', {
    structuredContent: { ...stillUnknown, provider_statement: statement },
    _meta: { [META_OUTCOME]: stillUnknown },
  });
}

await server.connect(new StdioServerTransport());
