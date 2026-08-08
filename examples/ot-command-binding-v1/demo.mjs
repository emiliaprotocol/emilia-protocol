#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Narrated run of the OT Command Binding lab.
 *
 *   node examples/ot-command-binding-v1/demo.mjs
 *   node examples/ot-command-binding-v1/demo.mjs --json
 */
import { runOtCommandBindingLab } from './scenario.mjs';
const WIDTH = 78;
const rule = (char = '-') => char.repeat(WIDTH);
const yn = (value) => (value === true ? 'yes' : value === false ? 'no' : String(value));
function printCanonicalDerivation(scene) {
    console.log(`\n1. ${scene.title}`);
    console.log(rule());
    for (const entry of scene.transports) {
        const capacity = entry.metadata_octets_available === null
            ? 'extensible'
            : `${entry.metadata_octets_available} octets free`;
        console.log(`\n   ${entry.transport}  ·  ${entry.wire_octets} octets on the wire  ·  ${capacity}`);
        console.log(`   carries the authorization inline: ${yn(entry.carries_authorization_inline)}`);
        console.log(`   digest derived from the decoded wire: ${yn(entry.derived_from_wire)}`);
        console.log(`   authorized  ${entry.digest}`);
        for (const drift of entry.drift) {
            const changed = drift.digest_changed ? 'DIFFERENT' : 'SAME     ';
            console.log(`     ${changed}  ${drift.field.padEnd(19)} ${drift.digest}`);
            console.log(`                ${drift.note}; binding refuses on ${drift.mismatched_fields.join(', ') || 'nothing'}`);
        }
    }
    console.log(`\n   distinct digests across every shape and variant: ${scene.distinct_digest_count} of ${scene.expected_digest_count}`);
    const inv = scene.correlation_invariance;
    console.log(`   two frames differing only in transaction id: frames differ ${yn(inv.frames_differ)}, digests equal ${yn(inv.digests_equal)}`);
}
function printAuthorized(scene) {
    console.log(`\n2. ${scene.title}`);
    console.log(rule());
    for (const entry of scene.transports) {
        console.log(`\n   ${entry.transport}  ·  binding mode: ${entry.binding_mode}`);
        if (entry.binding_mode === 'inline') {
            console.log(`   authorization rode with the call: ${yn(entry.authorization_carried_inline)}`);
            console.log(`   ${entry.wire_octets} octets on the wire, ${entry.authorization_octets_on_wire} of them the authorization`);
        }
        else {
            console.log(`   ${entry.wire_octets} octets on the wire, ${entry.authorization_octets_on_wire} of them the authorization`);
            console.log(`   authorization held out of band, keyed by ${entry.out_of_band_key}`);
        }
        console.log(`   gate allowed: ${yn(entry.allowed)}   device entered: ${yn(entry.device_entered)} (${entry.device_command_count} command)`);
        console.log(`   gate recorded the digest it authorized: ${yn(entry.gate_authorized_the_digest)}`);
        console.log(`   execution proof binds the decision: ${yn(entry.execution_binds_authorization)}   reliance: ${entry.reliance_verdict}`);
        console.log(`   receipt verifies offline (issuer key only): ${yn(entry.offline_verification.valid)}`);
    }
}
function printDrift(scene) {
    console.log(`\n3. ${scene.title}`);
    console.log(rule());
    for (const item of scene.cases) {
        console.log(`\n   ${item.transport}  ·  ${item.drifted_field} drifted (${item.note})`);
        console.log(`   authorized ${item.authorized_digest}`);
        console.log(`   presented  ${item.presented_digest}`);
        console.log(`   allowed: ${yn(item.allowed)}   refusal names: ${item.reason}`);
        console.log(`   mismatched fields: ${item.mismatched_fields.join(', ')}`);
        console.log(`   device entered: ${yn(item.device_entered)}   store state after the refusal: ${item.store_state_after_refusal}`);
        console.log(`   authorization survived the refusal: ${yn(item.authorization_survived_refusal)}   exact command still admitted afterwards: ${yn(item.exact_command_still_admitted)}`);
    }
    console.log('\n   out-of-band lookup is keyed by the digest, so an unauthorized command finds nothing:');
    for (const item of scene.out_of_band_lookup) {
        console.log(`     ${item.transport.padEnd(11)} ${item.drifted_field} drifted, index holds ${item.index_size}, authorization found: ${yn(item.authorization_found)}`);
        console.log(`                 allowed: ${yn(item.allowed)}   refusal names: ${item.reason}   device entered: ${yn(item.device_entered)}`);
    }
}
function printUnresolved(scene) {
    console.log(`\n4. ${scene.title}`);
    console.log(rule());
    console.log(`   device entered: ${yn(scene.dispatch.device_entered)}   terminal outcome: ${scene.dispatch.terminal_outcome}`);
    console.log(`   reason: ${scene.dispatch.reason}`);
    console.log(`   consumption store state for ${scene.consumption_store.receipt_id}: ${scene.consumption_store.state}`);
    console.log(`   authorization returned to the pool: ${yn(scene.consumption_store.returned_to_pool)}`);
    console.log(`   evidence record: outcome=${scene.evidence.recorded_outcome} detail=${scene.evidence.recorded_detail_code}`);
    console.log(`   evidence chain verifies: ${yn(scene.evidence.chain_ok)}`);
    console.log(`   blind retry allowed: ${yn(scene.blind_retry.allowed)}   refusal names: ${scene.blind_retry.reason}`);
    console.log(`   device command count after the retry: ${scene.device_command_count} (unchanged: ${yn(scene.blind_retry.device_command_count_unchanged)})`);
    const recovery = scene.recovery_is_reauthorization;
    console.log(`   recovery is a new human authorization, not a retry: allowed ${yn(recovery.allowed)}, device entered ${yn(recovery.device_entered)}`);
}
function printSpentOnce(scene) {
    const fresh = scene.fresh_but_spent;
    const stale = scene.stale_but_unspent;
    console.log(`\n5. ${scene.title}`);
    console.log(rule());
    console.log(`   freshness window: ${fresh.max_age_sec}s`);
    console.log(`\n   fresh but spent   age ${fresh.age_seconds_at_replay}s, inside the window: ${yn(fresh.still_inside_freshness_window)}`);
    console.log(`     freshness verifier says ok: ${yn(fresh.freshness_verdict_ok)}`);
    console.log(`     gate allowed: ${yn(fresh.replay_allowed)}   refusal names: ${fresh.replay_reason}`);
    console.log(`     store state: ${fresh.store_state}   device re-entered: ${yn(fresh.device_entered_on_replay)}`);
    console.log(`\n   stale but unspent  age ${stale.age_seconds_at_use}s, never consumed: ${yn(stale.never_consumed_before_use)}`);
    console.log(`     freshness verifier says ok: ${yn(stale.freshness_verdict_ok)} (${stale.freshness_reason})`);
    console.log(`     gate allowed: ${yn(stale.allowed)}   refusal names: ${stale.reason}`);
    console.log(`\n   the two refusals are named differently: ${yn(scene.reasons_are_distinct)}`);
}
function print(result) {
    console.log('\nOT COMMAND BINDING LAB');
    console.log(rule('='));
    console.log(result.scenario);
    const [derivation, authorized, drift, unresolved, spent] = result.scenes;
    printCanonicalDerivation(derivation);
    printAuthorized(authorized);
    printDrift(drift);
    printUnresolved(unresolved);
    printSpentOnce(spent);
    console.log(`\n${rule('=')}`);
    console.log(result.invariant);
    console.log('Synthetic local demonstration. No live PLC, RTU, or DCS was involved.\n');
}
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
    const result = await runOtCommandBindingLab();
    if (process.argv.includes('--json'))
        console.log(JSON.stringify(result, null, 2));
    else
        print(result);
}
