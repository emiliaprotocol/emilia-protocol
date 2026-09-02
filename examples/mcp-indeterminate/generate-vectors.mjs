// SPDX-License-Identifier: Apache-2.0
// Generated from generate-vectors.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
//   node examples/mcp-indeterminate/generate-vectors.mjs --check   (CI)
//   node examples/mcp-indeterminate/generate-vectors.mjs --write
//
// The vector pack. Each vector is a complete MCP tools/call exchange plus the
// AEB-04 state it maps to, so a reader can implement the field group without
// running this repository's code. Vector 5 is the harm: it carries the two
// provider entries a naive retry produces, not a claim that it would.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { AEB_MAPPING, FIELD_GROUP_VERSION, META_AUTHORITY, META_OUTCOME, META_REPLAY_UNIT, OUTCOME_VALUES, RECONCILIATION_VALUES, REPLAY_UNIT_DOMAIN, RETRY_VALUES, deriveReplayUnit, parseOutcomeEnvelope, } from './field-group.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, 'vectors.v1.json');
const REGISTRY = JSON.parse(readFileSync(join(here, '..', '..', 'caid', 'registry', 'action-types.json'), 'utf8'));
const AUTHORITY = 'sha256:11ac1caa1b6f24e2f4b0e6a5f9a1a2c3d4e5f60718293a4b5c6d7e8f90a1b2c3';
const ACTION = {
    action_type: 'payment.release.1',
    amount: '82000.00',
    currency: 'USD',
    beneficiary_account: `sha256:${'4'.repeat(64)}`,
    payment_instruction_id: 'pi-2026-09-02-0001',
};
const caidResult = computeCaid(ACTION, { suite: 'jcs-sha256', definitions: REGISTRY.types });
if (!caidResult.caid)
    throw new Error(`caid refused: ${(caidResult.refusals ?? []).join(',')}`);
const CAID = caidResult.caid;
const derived = deriveReplayUnit({ authority_instance_digest: AUTHORITY, caid: CAID });
if (!derived.ok)
    throw new Error(`derivation refused: ${derived.refusals.join(',')}`);
const REPLAY_UNIT = derived.replay_unit;
const OPERATION_ID = `op-${REPLAY_UNIT.slice(7, 19)}`;
const callArguments = {
    amount: ACTION.amount,
    currency: ACTION.currency,
    beneficiary_account: ACTION.beneficiary_account,
    payment_instruction_id: ACTION.payment_instruction_id,
};
const reconcileHandle = {
    method: 'tools/call',
    tool: 'reconcile_effect',
    replay_unit: REPLAY_UNIT,
};
function callRequest(meta) {
    return {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
            name: 'release_payment',
            arguments: callArguments,
            ...(meta ? { _meta: meta } : {}),
        },
    };
}
const conformantMeta = {
    [META_AUTHORITY]: { instance_digest: AUTHORITY },
    [META_REPLAY_UNIT]: REPLAY_UNIT,
};
const vectors = [
    {
        id: 'EPMCP-01-executed',
        aeb_state: 'EXECUTED',
        aeb_locator: 'draft-schrock-action-evidence-boundary-04 section 5.10',
        summary: 'The clean path. An authoritative response matched to the exact action. '
            + 'The replay unit is spent and no retry is invited.',
        request: callRequest(conformantMeta),
        result: {
            content: [{ type: 'text', text: `released 82000.00 USD (operation ${OPERATION_ID})` }],
            structuredContent: {
                version: FIELD_GROUP_VERSION,
                replay_unit: REPLAY_UNIT,
                outcome: 'executed',
                retry: 'not_applicable',
                reconciliation: 'not_applicable',
                reason_codes: [],
                operation_id: OPERATION_ID,
                caid: CAID,
            },
            _meta: {
                [META_OUTCOME]: {
                    version: FIELD_GROUP_VERSION,
                    replay_unit: REPLAY_UNIT,
                    outcome: 'executed',
                    retry: 'not_applicable',
                    reconciliation: 'not_applicable',
                    reason_codes: [],
                    operation_id: OPERATION_ID,
                    caid: CAID,
                },
            },
        },
        host_obligation: 'Stop. The action is complete.',
    },
    {
        id: 'EPMCP-02-indeterminate',
        aeb_state: 'INDETERMINATE',
        aeb_locator: 'draft-schrock-action-evidence-boundary-04 section 5.10, restart promotion of a '
            + 'DISPATCH_PENDING record with no authoritative terminal record',
        summary: 'The state MCP cannot express today. The server restarted holding a dispatch '
            + 'record with no terminal record, so it cannot establish that dispatch did not '
            + 'begin. isError is false: the call did not fail, the OUTCOME is unknown.',
        request: callRequest(conformantMeta),
        result: {
            content: [
                {
                    type: 'text',
                    text: 'outcome is indeterminate: this replay unit has a dispatch with no terminal '
                        + 'record. Do not retry. Reconcile.',
                },
            ],
            structuredContent: {
                version: FIELD_GROUP_VERSION,
                replay_unit: REPLAY_UNIT,
                outcome: 'indeterminate',
                retry: 'refuse',
                reconciliation: 'required',
                reason_codes: ['stranded_dispatch_pending_promoted_on_restart'],
                reconcile: reconcileHandle,
                operation_id: OPERATION_ID,
                caid: CAID,
            },
            _meta: {
                [META_OUTCOME]: {
                    version: FIELD_GROUP_VERSION,
                    replay_unit: REPLAY_UNIT,
                    outcome: 'indeterminate',
                    retry: 'refuse',
                    reconciliation: 'required',
                    reason_codes: ['stranded_dispatch_pending_promoted_on_restart'],
                    reconcile: reconcileHandle,
                    operation_id: OPERATION_ID,
                    caid: CAID,
                },
            },
        },
        host_obligation: 'MUST NOT call release_payment again for a second effect. MUST call the tool named '
            + 'in the reconcile handle with the identical replay unit.',
    },
    {
        id: 'EPMCP-03-failed-requires-new-admission',
        aeb_state: 'REQUIRES_NEW_ADMISSION',
        aeb_locator: 'draft-schrock-action-evidence-boundary-04 section 5.11: reconciliation MUST NOT '
            + 'resurrect the original authorization or silently release its one-time replay unit',
        summary: 'Reconciliation moved INDETERMINATE to FAILED. The absence of a provider entry is '
            + 'authoritative only because the provider stated a completeness watermark covering '
            + 'the dispatch window. Retry is permitted by policy only as a new action instance.',
        request: {
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: { name: 'reconcile_effect', arguments: { replay_unit: REPLAY_UNIT } },
        },
        result: {
            content: [
                {
                    type: 'text',
                    text: 'reconciled: no effect landed, and the provider record is complete through '
                        + 'this window. A later attempt is a new action instance under a new admission.',
                },
            ],
            structuredContent: {
                version: FIELD_GROUP_VERSION,
                replay_unit: REPLAY_UNIT,
                outcome: 'failed',
                retry: 'requires_new_admission',
                reconciliation: 'applied',
                reason_codes: ['provider_record_absent_under_complete_watermark'],
                operation_id: OPERATION_ID,
                caid: CAID,
            },
            _meta: {
                [META_OUTCOME]: {
                    version: FIELD_GROUP_VERSION,
                    replay_unit: REPLAY_UNIT,
                    outcome: 'failed',
                    retry: 'requires_new_admission',
                    reconciliation: 'applied',
                    reason_codes: ['provider_record_absent_under_complete_watermark'],
                    operation_id: OPERATION_ID,
                    caid: CAID,
                },
            },
        },
        host_obligation: 'MUST NOT reuse this replay unit or this authorization. A later attempt is a new '
            + 'action instance that completes the authorization lifecycle again.',
    },
    {
        id: 'EPMCP-04-reconciliation-inconclusive',
        aeb_state: 'INDETERMINATE',
        aeb_locator: 'draft-schrock-action-evidence-boundary-04 section 5.11: missing, stale, conflicting, '
            + 'unauthenticated or action-mismatched observations MUST leave the operation INDETERMINATE',
        summary: 'Reconciliation ran and did not settle anything: the provider saw no entry but its '
            + 'completeness watermark does not cover the dispatch window. Absence is not evidence. '
            + 'The operation stays indeterminate, which is a correct answer, not a failure.',
        request: {
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'reconcile_effect', arguments: { replay_unit: REPLAY_UNIT } },
        },
        result: {
            content: [
                { type: 'text', text: 'reconciliation inconclusive; the operation stays indeterminate' },
            ],
            structuredContent: {
                version: FIELD_GROUP_VERSION,
                replay_unit: REPLAY_UNIT,
                outcome: 'indeterminate',
                retry: 'refuse',
                reconciliation: 'required',
                reason_codes: ['provider_watermark_does_not_cover_dispatch_window'],
                reconcile: reconcileHandle,
                operation_id: OPERATION_ID,
                caid: CAID,
            },
            _meta: {
                [META_OUTCOME]: {
                    version: FIELD_GROUP_VERSION,
                    replay_unit: REPLAY_UNIT,
                    outcome: 'indeterminate',
                    retry: 'refuse',
                    reconciliation: 'required',
                    reason_codes: ['provider_watermark_does_not_cover_dispatch_window'],
                    reconcile: reconcileHandle,
                    operation_id: OPERATION_ID,
                    caid: CAID,
                },
            },
        },
        host_obligation: 'MUST NOT retry. MAY reconcile again later. MUST surface to an operator.',
    },
    {
        id: 'EPMCP-05-naive-retry-duplicate',
        aeb_state: 'NOT REPRESENTABLE IN MCP TODAY',
        aeb_locator: 'no MCP field carries this; see the transcript in README.md',
        summary: 'The harm, demonstrated. Two tools/call exchanges exactly as MCP defines them today, '
            + 'with the crash injected between the effect and the response on the first. The '
            + 'result the host never received and the result it did receive are both here, and '
            + 'so is the provider ledger afterwards: one authorization, two settled payments.',
        request: callRequest(null),
        first_attempt: {
            note: 'The server applied the effect and then the process died. No JSON-RPC result was '
                + 'ever written. The host observes a transport error, which is all MCP gives it.',
            observed_by_host: { error: { code: -32000, message: 'Connection closed' } },
        },
        retry_attempt: {
            note: 'The host reconnects and re-issues the call. Nothing on the wire forbids this.',
            request: callRequest(null),
            result: {
                content: [{ type: 'text', text: 'released 82000.00 USD (operation op-legacy-2)' }],
            },
        },
        provider_record_after: [
            {
                seq: 1,
                operation_id: 'op-legacy-1',
                caid: CAID,
                amount: '82000.00',
                currency: 'USD',
                beneficiary_account: ACTION.beneficiary_account,
            },
            {
                seq: 2,
                operation_id: 'op-legacy-2',
                caid: CAID,
                amount: '82000.00',
                currency: 'USD',
                beneficiary_account: ACTION.beneficiary_account,
            },
        ],
        host_obligation: 'None available. The host behaved correctly given the vocabulary it has. That is the '
            + 'point: the gap is in the wire, not in the host.',
    },
    {
        id: 'EPMCP-06-model-chosen-replay-unit-refused',
        aeb_state: 'REFUSED BEFORE DISPATCH',
        aeb_locator: 'draft-schrock-action-evidence-boundary-04 section 5.8: the key MUST be derived from '
            + 'verified evidence or the executor-owned observed action and operation identifier, '
            + 'never from a presenter-selected decoy',
        summary: 'A replay unit that is not the derivation over the authority and the frozen action. '
            + 'The server recomputes and refuses before any effect. This is what makes the unit '
            + 'caller-supplied-but-not-model-chosen enforceable rather than advisory.',
        request: callRequest({
            [META_AUTHORITY]: { instance_digest: AUTHORITY },
            [META_REPLAY_UNIT]: `sha256:${'ab'.repeat(32)}`,
        }),
        result: {
            content: [
                {
                    type: 'text',
                    text: 'refused: replay_unit_not_derived_from_authority_and_action',
                },
            ],
            isError: true,
            structuredContent: { refusals: ['replay_unit_not_derived_from_authority_and_action'] },
        },
        host_obligation: 'Stop. No effect occurred and no replay unit was consumed.',
    },
];
const pack = {
    '@version': FIELD_GROUP_VERSION,
    generated_by: 'examples/mcp-indeterminate/generate-vectors.mts',
    what_this_is: 'A mapping of draft-schrock-action-evidence-boundary-04 sections 5.10 and 5.11 onto a '
        + 'three-field group carried in MCP _meta. Not an MCP protocol change and not a SEP.',
    mcp: {
        schema_revision_read: '2026-07-28',
        call_tool_result_fields_today: ['content', 'structuredContent', 'isError'],
        tasks_extension_statuses_today: [
            'working',
            'input_required',
            'completed',
            'failed',
            'cancelled',
        ],
        meta_prefix_used: 'ai.emiliaprotocol/',
        meta_prefix_note: 'A prefix whose second label is modelcontextprotocol or mcp is reserved for MCP use; '
            + 'ai.emiliaprotocol/ is not reserved, per the MetaObject key rules in schema.ts.',
    },
    field_group: {
        replay_unit: {
            meta_key: META_REPLAY_UNIT,
            supplied_by: 'the caller',
            derivation: `SHA-256("${REPLAY_UNIT_DOMAIN}" || " " || authority_instance_digest || " " || caid)`,
            never: 'chosen by the model, and never minted by the server',
        },
        outcome: { meta_key: META_OUTCOME, values: OUTCOME_VALUES },
        retry: { values: RETRY_VALUES },
        reconciliation: { values: RECONCILIATION_VALUES },
        reconcile_handle: {
            shape: reconcileHandle,
            rule: 'the handle MUST carry the same replay unit as the envelope that contains it',
        },
    },
    aeb_mapping: AEB_MAPPING,
    worked_example: {
        authority_instance_digest: AUTHORITY,
        action: ACTION,
        caid: CAID,
        replay_unit: REPLAY_UNIT,
        operation_id: OPERATION_ID,
    },
    vectors,
};
// Self-check: every envelope in the pack must survive the closed-set parser.
for (const vector of vectors) {
    const result = vector.result;
    const envelope = result?._meta?.[META_OUTCOME];
    if (envelope === undefined)
        continue;
    const parsed = parseOutcomeEnvelope(envelope);
    if (!parsed.ok) {
        throw new Error(`${vector.id}: envelope fails its own parser: ${parsed.refusals.join(',')}`);
    }
}
const rendered = `${JSON.stringify(pack, null, 2)}\n`;
const mode = process.argv.includes('--check') ? 'check' : 'write';
if (mode === 'check') {
    const current = readFileSync(OUT, 'utf8');
    if (current !== rendered) {
        process.stderr.write('vectors.v1.json is out of date; run generate-vectors.mjs --write\n');
        process.exit(1);
    }
    process.stdout.write(`vectors.v1.json is current (${vectors.length} vectors)\n`);
}
else {
    writeFileSync(OUT, rendered, 'utf8');
    process.stdout.write(`wrote ${OUT} (${vectors.length} vectors)\n`);
}
