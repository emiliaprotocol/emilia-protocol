// SPDX-License-Identifier: Apache-2.0
// Generated from client.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// The host side. Two host loops over the SAME official-SDK client:
//
//   runNaiveHost      - what a conformant MCP host can do today. The wire
//                       says nothing about whether the effect landed, the
//                       connection dropped, so it retries. The retry is the
//                       duplicate.
//   runConformantHost - the same crash, with EP-MCP-OUTCOME-v1 on the wire.
//                       The host is structurally unable to retry: the only
//                       move `nextLegalMove` returns for `indeterminate` is
//                       the reconcile handle, bound to the same replay unit.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { META_AUTHORITY, META_OUTCOME, META_REPLAY_UNIT, deriveReplayUnit, mappingFor, parseOutcomeEnvelope, } from './field-group.mjs';
import { Stores } from './ledger.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const SERVER = join(here, 'server.mjs');
const REGISTRY = JSON.parse(readFileSync(join(here, '..', '..', 'caid', 'registry', 'action-types.json'), 'utf8'));
/**
 * The authority instance. In a deployment this is the digest of the
 * authorization the human actually granted; here it is a fixed value so the
 * transcript is byte-stable. What matters is that it is NOT model output:
 * the host receives it from the authorization step, and derives the replay
 * unit from it.
 */
export const AUTHORITY_INSTANCE_DIGEST = 'sha256:11ac1caa1b6f24e2f4b0e6a5f9a1a2c3d4e5f60718293a4b5c6d7e8f90a1b2c3';
export const PAYMENT_ARGS = Object.freeze({
    amount: '82000.00',
    currency: 'USD',
    beneficiary_account: `sha256:${'4'.repeat(64)}`,
    payment_instruction_id: 'pi-2026-09-02-0001',
});
export function actionCaid() {
    const result = computeCaid({ action_type: 'payment.release.1', ...PAYMENT_ARGS }, { suite: 'jcs-sha256', definitions: REGISTRY.types });
    if (!result.caid)
        throw new Error(`caid computation refused: ${(result.refusals ?? []).join(',')}`);
    return result.caid;
}
export function replayUnitForRun() {
    const derived = deriveReplayUnit({
        authority_instance_digest: AUTHORITY_INSTANCE_DIGEST,
        caid: actionCaid(),
    });
    if (!derived.ok)
        throw new Error(`replay unit derivation refused: ${derived.refusals.join(',')}`);
    return derived.replay_unit;
}
async function connect(opts) {
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: [SERVER],
        env: {
            PATH: process.env.PATH ?? '',
            EP_STORE_DIR: opts.storeDir,
            EP_MCP_MODE: opts.mode,
            EP_CRASH: opts.crash,
        },
        stderr: 'pipe',
    });
    const buffered = [];
    const client = new Client({ name: 'ep-indeterminate-host', version: '0.1.0' }, {});
    await client.connect(transport);
    transport.stderr?.on('data', (chunk) => {
        for (const line of chunk.toString('utf8').split('\n')) {
            if (line.trim().length > 0)
                buffered.push(line.trim());
        }
    });
    return {
        client,
        transport,
        drainStderr: () => buffered.splice(0, buffered.length),
        close: async () => {
            try {
                await client.close();
            }
            catch {
                /* the process may already be gone; that is the case under test */
            }
        },
    };
}
/** Let the piped stderr of a crashed child reach us before we print. */
const settle = () => new Promise((r) => setTimeout(r, 60));
function envelopeOf(result) {
    const meta = result._meta;
    const parsed = parseOutcomeEnvelope(meta?.[META_OUTCOME]);
    return parsed.ok ? parsed.envelope : null;
}
export function nextLegalMove(envelope) {
    if (envelope.outcome === 'executed')
        return { kind: 'done', outcome: 'executed' };
    if (envelope.outcome === 'failed')
        return { kind: 'new_admission_required', outcome: 'failed' };
    return { kind: 'reconcile', handle: envelope.reconcile };
}
// ---------------------------------------------------------------------------
// Naive host: today's MCP
// ---------------------------------------------------------------------------
export async function runNaiveHost(storeDir) {
    const lines = [];
    const say = (who, text) => {
        lines.push({ who, text });
    };
    say('host', 'connecting to the server (EP_MCP_MODE=legacy, EP_CRASH=after-effect)');
    let session = await connect({ storeDir, mode: 'legacy', crash: 'after-effect' });
    const tools = await session.client.listTools();
    const tool = tools.tools.find((t) => t.name === 'release_payment');
    say('wire', `tools/list -> release_payment annotations: idempotentHint=${String(tool?.annotations?.idempotentHint)} destructiveHint=${String(tool?.annotations?.destructiveHint)}`);
    say('host', 'the tool is marked non-idempotent and destructive. I read that hint and proceed.');
    say('wire', 'tools/call release_payment {"amount":"82000.00","currency":"USD",...}');
    let failure = '';
    try {
        await session.client.callTool({ name: 'release_payment', arguments: { ...PAYMENT_ARGS } });
        say('wire', 'unexpected: the call returned');
    }
    catch (err) {
        failure = err instanceof Error ? err.message : String(err);
    }
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    say('wire', `tools/call rejected: ${failure}`);
    await session.close();
    say('host', 'CallToolResult is content + structuredContent + isError. I received none of them. '
        + 'Nothing on the wire distinguishes "never dispatched" from "already settled".');
    say('host', 'RETRYING. This is the only move the current vocabulary leaves me.');
    session = await connect({ storeDir, mode: 'legacy', crash: 'none' });
    const retry = (await session.client.callTool({
        name: 'release_payment',
        arguments: { ...PAYMENT_ARGS },
    }));
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    const content = retry.content ?? [];
    say('wire', `tools/call -> ${content[0]?.text ?? ''}`);
    await session.close();
    const stores = new Stores(storeDir);
    const entries = stores.providerEntries();
    say('ledger', `provider record now holds ${entries.length} entries:`);
    for (const e of entries) {
        say('ledger', `  seq=${e.seq} operation_id=${e.operation_id} amount=${e.amount} ${e.currency}`);
    }
    say('ledger', entries.length > 1
        ? `HARM: ${entries.length} payments of ${entries[0].amount} ${entries[0].currency} `
            + 'settled from one authorization. The retry was the duplicate.'
        : 'no duplicate');
    return { lines, effects: entries.length };
}
// ---------------------------------------------------------------------------
// Conformant host: the same crash with EP-MCP-OUTCOME-v1 on the wire
// ---------------------------------------------------------------------------
export async function runConformantHost(storeDir) {
    const lines = [];
    const say = (who, text) => {
        lines.push({ who, text });
    };
    const caid = actionCaid();
    const replayUnit = replayUnitForRun();
    say('host', `authority instance digest: ${AUTHORITY_INSTANCE_DIGEST}`);
    say('host', `frozen action: ${caid}`);
    say('host', `replay unit = SHA-256("EP-MCP-REPLAY-UNIT-v1" || authority || caid) = ${replayUnit}`);
    say('host', 'the model chose none of those three values.');
    const callMeta = {
        [META_AUTHORITY]: { instance_digest: AUTHORITY_INSTANCE_DIGEST },
        [META_REPLAY_UNIT]: replayUnit,
    };
    say('host', 'connecting to the server (EP_MCP_MODE=fieldgroup, EP_CRASH=after-effect)');
    let session = await connect({ storeDir, mode: 'fieldgroup', crash: 'after-effect' });
    say('wire', `tools/call release_payment _meta.${META_REPLAY_UNIT}=${replayUnit.slice(0, 23)}...`);
    let failure = '';
    try {
        await session.client.callTool({
            name: 'release_payment',
            arguments: { ...PAYMENT_ARGS },
            _meta: callMeta,
        });
    }
    catch (err) {
        failure = err instanceof Error ? err.message : String(err);
    }
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    say('wire', `tools/call rejected: ${failure}`);
    await session.close();
    say('host', 'reconnecting. I re-send the SAME request bound to the SAME replay unit.');
    session = await connect({ storeDir, mode: 'fieldgroup', crash: 'none' });
    const resumed = (await session.client.callTool({
        name: 'release_payment',
        arguments: { ...PAYMENT_ARGS },
        _meta: callMeta,
    }));
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    const envelope = envelopeOf(resumed);
    if (envelope === null) {
        say('host', 'the outcome envelope did not parse. Refusing to proceed.');
        await session.close();
        return { lines, effects: new Stores(storeDir).providerEntries().length, finalOutcome: 'refused' };
    }
    say('wire', `_meta["${META_OUTCOME}"] -> outcome=${envelope.outcome} retry=${envelope.retry} `
        + `reconciliation=${envelope.reconciliation} reason=${envelope.reason_codes.join(',')}`);
    const row = mappingFor(envelope.outcome, envelope.retry, envelope.reconciliation);
    say('host', `AEB-04 state: ${row?.aeb_state ?? 'unmapped'} (${row?.aeb_locator ?? ''})`);
    let move = nextLegalMove(envelope);
    say('host', `legal moves for this outcome: ${move.kind}. Retry is not among them.`);
    if (move.kind !== 'reconcile') {
        await session.close();
        return {
            lines,
            effects: new Stores(storeDir).providerEntries().length,
            finalOutcome: envelope.outcome,
        };
    }
    say('wire', `tools/call ${move.handle.tool} {"replay_unit":"${move.handle.replay_unit.slice(0, 23)}..."}`);
    const reconciled = (await session.client.callTool({
        name: move.handle.tool,
        arguments: { replay_unit: move.handle.replay_unit },
    }));
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    const settledEnvelope = envelopeOf(reconciled);
    if (settledEnvelope === null) {
        say('host', 'the reconciliation envelope did not parse. Refusing to proceed.');
        await session.close();
        return { lines, effects: new Stores(storeDir).providerEntries().length, finalOutcome: 'refused' };
    }
    say('wire', `_meta["${META_OUTCOME}"] -> outcome=${settledEnvelope.outcome} retry=${settledEnvelope.retry} `
        + `reconciliation=${settledEnvelope.reconciliation} reason=${settledEnvelope.reason_codes.join(',')}`);
    const settledRow = mappingFor(settledEnvelope.outcome, settledEnvelope.retry, settledEnvelope.reconciliation);
    say('host', `AEB-04 state: ${settledRow?.aeb_state ?? 'unmapped'}`);
    move = nextLegalMove(settledEnvelope);
    say('host', `legal moves now: ${move.kind}`);
    await session.close();
    const stores = new Stores(storeDir);
    const entries = stores.providerEntries();
    say('ledger', `provider record holds ${entries.length} entry:`);
    for (const e of entries) {
        say('ledger', `  seq=${e.seq} operation_id=${e.operation_id} amount=${e.amount} ${e.currency}`);
    }
    say('ledger', `one authorization, ${entries.length} effect. No duplicate.`);
    return { lines, effects: entries.length, finalOutcome: settledEnvelope.outcome };
}
/**
 * The FAILED / REQUIRES_NEW_ADMISSION path: the crash lands before the
 * effect, the provider's completeness watermark covers the window, and
 * reconciliation settles the operation as FAILED. The replay unit is not
 * released; a later attempt is a new action instance.
 */
export async function runFailedPath(storeDir) {
    const lines = [];
    const say = (who, text) => {
        lines.push({ who, text });
    };
    const replayUnit = replayUnitForRun();
    const callMeta = {
        [META_AUTHORITY]: { instance_digest: AUTHORITY_INSTANCE_DIGEST },
        [META_REPLAY_UNIT]: replayUnit,
    };
    let session = await connect({ storeDir, mode: 'fieldgroup', crash: 'before-effect' });
    try {
        await session.client.callTool({
            name: 'release_payment',
            arguments: { ...PAYMENT_ARGS },
            _meta: callMeta,
        });
    }
    catch (err) {
        say('wire', `tools/call rejected: ${err instanceof Error ? err.message : String(err)}`);
    }
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    await session.close();
    // The provider closes its window: nothing further landed. Only this makes
    // the absence authoritative rather than merely unobserved.
    const stores = new Stores(storeDir);
    stores.advanceWatermark(new Date(Date.UTC(2026, 8, 2, 0, 1, 0)).toISOString());
    say('server', 'provider advanced its completeness watermark over the dispatch window');
    session = await connect({ storeDir, mode: 'fieldgroup', crash: 'none' });
    const resumed = (await session.client.callTool({
        name: 'release_payment',
        arguments: { ...PAYMENT_ARGS },
        _meta: callMeta,
    }));
    const envelope = envelopeOf(resumed);
    if (envelope === null || nextLegalMove(envelope).kind !== 'reconcile') {
        await session.close();
        return { lines, effects: stores.providerEntries().length, finalOutcome: 'refused', retry: 'refuse' };
    }
    say('wire', `outcome=${envelope.outcome} retry=${envelope.retry}`);
    const handle = nextLegalMove(envelope).handle;
    const reconciled = (await session.client.callTool({
        name: handle.tool,
        arguments: { replay_unit: handle.replay_unit },
    }));
    await settle();
    for (const l of session.drainStderr())
        say('server', l);
    await session.close();
    const settledEnvelope = envelopeOf(reconciled);
    if (settledEnvelope === null) {
        return { lines, effects: stores.providerEntries().length, finalOutcome: 'refused', retry: 'refuse' };
    }
    say('wire', `outcome=${settledEnvelope.outcome} retry=${settledEnvelope.retry}`);
    const row = mappingFor(settledEnvelope.outcome, settledEnvelope.retry, settledEnvelope.reconciliation);
    say('host', `AEB-04 state: ${row?.aeb_state ?? 'unmapped'}`);
    return {
        lines,
        effects: stores.providerEntries().length,
        finalOutcome: settledEnvelope.outcome,
        retry: settledEnvelope.retry,
    };
}
/**
 * Fail-closed probe: a replay unit the model picked, presented on a call
 * whose action does not derive it. The server must refuse with a stated
 * reason. It must not execute, and it must not throw.
 */
export async function runModelChosenKeyProbe(storeDir) {
    const session = await connect({ storeDir, mode: 'fieldgroup', crash: 'none' });
    const result = (await session.client.callTool({
        name: 'release_payment',
        arguments: { ...PAYMENT_ARGS },
        _meta: {
            [META_AUTHORITY]: { instance_digest: AUTHORITY_INSTANCE_DIGEST },
            [META_REPLAY_UNIT]: `sha256:${'ab'.repeat(32)}`,
        },
    }));
    await session.close();
    const structured = (result.structuredContent ?? {});
    return {
        isError: result.isError === true,
        refusals: structured.refusals ?? [],
        effects: new Stores(storeDir).providerEntries().length,
    };
}
