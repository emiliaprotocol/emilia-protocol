// SPDX-License-Identifier: Apache-2.0
// Generated from provider-replay-key.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Vectors for the shared provider replay-key derivation.
//
// The vectors are the five the thesis names plus the refusal paths: the same
// call id retried, a different call id with identical content inside and
// outside the server window, argument reordering, numeric edge cases, a target
// mismatch, and a slot whose charset cannot carry the encoding. Every refusal
// is asserted to be a returned reason, never a thrown error.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MCP_META_REPLAY_KEY, PROVIDER_CARRIAGE_TABLE, PROVIDER_KEY_RETENTION_MEASUREMENT, PROVIDER_REPLAY_KEY_VERSION, PROVIDER_SLOT_SPECS, authorizationInstanceDigest, createMcpReplayLedger, deriveMcpToolCallReplayKey, deriveProviderReplayKey, getCarriageRow, matchesProviderReplayKey, } from './provider-replay-key.js';
const AUTH = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const OTHER_AUTH = 'sha256:2222222222222222222222222222222222222222222222222222222222222222';
function base(overrides = {}) {
    return {
        authorization_digest: AUTH,
        caid: 'payment.release.1',
        provider_env: 'stripe:live:acct_authorized',
        attempt_group: '1',
        slot_spec: PROVIDER_SLOT_SPECS['stripe.idempotency-key'],
        ...overrides,
    };
}
// ---------------------------------------------------------------------------
// Determinism and separation
// ---------------------------------------------------------------------------
test('derivation is deterministic and pinned to the version label', () => {
    const first = deriveProviderReplayKey(base());
    const second = deriveProviderReplayKey(base());
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.equal(second.ok, true);
    assert.equal(first.key, second.key);
    assert.match(first.key, /^ep1_[A-Za-z0-9]{43}$/);
    assert.equal(first.derivation.version, PROVIDER_REPLAY_KEY_VERSION);
    // 62^43 exceeds 2^256, so the slot carries the whole MAC and the reported
    // figure is capped at the 256 bits the MAC actually holds.
    assert.equal(first.entropy_bits, 256);
});
test('the positional signature and the object signature agree', () => {
    const positional = deriveProviderReplayKey(AUTH, 'payment.release.1', 'stripe:live:acct_authorized', '1', PROVIDER_SLOT_SPECS['stripe.idempotency-key']);
    const object = deriveProviderReplayKey(base());
    assert.equal(positional.ok, true);
    assert.equal(object.ok, true);
    assert.equal(positional.key, object.key);
});
test('a different authorization instance yields a different key', () => {
    const a = deriveProviderReplayKey(base());
    const b = deriveProviderReplayKey(base({ authorization_digest: OTHER_AUTH }));
    assert.notEqual(a.key, b.key);
});
test('a value derived for one slot cannot be replayed into another', () => {
    const stripe = deriveProviderReplayKey(base());
    const aws = deriveProviderReplayKey(base({
        slot_spec: PROVIDER_SLOT_SPECS['aws.ec2.run-instances.client-token'],
    }));
    assert.equal(aws.ok, true);
    assert.notEqual(stripe.key.slice(4), aws.key.slice(4));
});
test('changing only the attempt group mints a new provider key', () => {
    const first = deriveProviderReplayKey(base({ attempt_group: '1' }));
    const second = deriveProviderReplayKey(base({ attempt_group: '2' }));
    assert.notEqual(first.key, second.key);
});
test('matchesProviderReplayKey recomputes and refuses a foreign value', () => {
    const derived = deriveProviderReplayKey(base());
    assert.deepEqual(matchesProviderReplayKey(derived.key, base()), { ok: true });
    const mismatch = matchesProviderReplayKey(derived.key, base({ authorization_digest: OTHER_AUTH }));
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.reason, 'replay_key_mismatch');
});
// ---------------------------------------------------------------------------
// Slot encoding, including the slot that cannot carry the encoding
// ---------------------------------------------------------------------------
test('every shipped slot spec encodes inside its own charset and length', () => {
    for (const [id, spec] of Object.entries(PROVIDER_SLOT_SPECS)) {
        const derived = deriveProviderReplayKey(base({ slot_spec: spec }));
        assert.equal(derived.ok, true, `${id}: ${JSON.stringify(derived)}`);
        assert.ok(derived.key.length <= spec.max_length, `${id} exceeds max_length`);
        const prefix = spec.prefix || '';
        assert.ok(derived.key.startsWith(prefix), `${id} lost its prefix`);
        const encoded = derived.key.slice(prefix.length);
        assert.equal(encoded.length, spec.encoded_length, `${id} wrong encoded length`);
        for (const character of encoded) {
            assert.ok(spec.charset.includes(character), `${id} emitted ${character} outside its charset`);
        }
    }
});
test('the ISO 20022 slot fits Max35Text and carries no character SEPA forbids', () => {
    const derived = deriveProviderReplayKey(base({
        slot_spec: PROVIDER_SLOT_SPECS['iso20022.end-to-end-id'],
    }));
    assert.equal(derived.ok, true);
    assert.equal(derived.key.length, 34);
    assert.ok(derived.key.length <= 35);
    assert.match(derived.key, /^EP1[A-Za-z0-9]{31}$/);
    assert.ok(!derived.key.includes('/'));
});
test('the ERC-3009 slot is a full 32-byte hex nonce', () => {
    const derived = deriveProviderReplayKey(base({
        slot_spec: PROVIDER_SLOT_SPECS['eip3009.nonce'],
    }));
    assert.equal(derived.ok, true);
    assert.match(derived.key, /^0x[0-9a-f]{64}$/);
    assert.equal(derived.entropy_bits, 256);
});
test('a slot whose charset cannot carry the encoding refuses with a stated reason', () => {
    // Binary charset, 8 characters: 8 bits, far below the 96-bit floor.
    const narrow = deriveProviderReplayKey(base({
        slot_spec: {
            slot_id: 'toy.binary',
            charset: '01',
            encoded_length: 8,
            max_length: 8,
        },
    }));
    assert.equal(narrow.ok, false);
    assert.equal(narrow.reason, 'slot_capacity_insufficient');
    assert.match(narrow.detail, /8 bits, below the 96 bits/);
    // A decimal slot long enough by character count but short on entropy for a
    // caller that demanded 256 bits.
    const shortOfDemand = deriveProviderReplayKey(base({
        slot_spec: {
            slot_id: 'toy.decimal',
            charset: '0123456789',
            encoded_length: 20,
            max_length: 20,
            min_entropy_bits: 256,
        },
    }));
    assert.equal(shortOfDemand.ok, false);
    assert.equal(shortOfDemand.reason, 'slot_capacity_insufficient');
});
test('a prefix outside a charset-constrained slot refuses rather than emitting it', () => {
    const bad = deriveProviderReplayKey(base({
        slot_spec: {
            ...PROVIDER_SLOT_SPECS['iso20022.end-to-end-id'],
            prefix: 'EP/1',
        },
    }));
    assert.equal(bad.ok, false);
    assert.equal(bad.reason, 'slot_prefix_charset_violation');
});
test('a prefix plus encoding longer than the provider field refuses', () => {
    const tooLong = deriveProviderReplayKey(base({
        slot_spec: {
            slot_id: 'toy.tight',
            charset: '0123456789abcdef',
            encoded_length: 40,
            max_length: 35,
            prefix: 'EP1',
        },
    }));
    assert.equal(tooLong.ok, false);
    assert.equal(tooLong.reason, 'slot_length_exceeds_max');
});
// ---------------------------------------------------------------------------
// Malformed input: refusals, not throws
// ---------------------------------------------------------------------------
test('malformed input returns a stated reason and never throws', () => {
    const cases = [
        ['missing digest', base({ authorization_digest: undefined }), 'authorization_digest_invalid'],
        ['unprefixed digest', base({ authorization_digest: 'a'.repeat(64) }), 'authorization_digest_invalid'],
        ['uppercase hex digest', base({ authorization_digest: `sha256:${'A'.repeat(64)}` }), 'authorization_digest_invalid'],
        ['digest of the wrong length', base({ authorization_digest: 'sha256:abc' }), 'authorization_digest_invalid'],
        ['digest as an object', base({ authorization_digest: { toString: () => AUTH } }), 'authorization_digest_invalid'],
        ['empty caid', base({ caid: '' }), 'caid_invalid'],
        ['caid with a space', base({ caid: 'payment release 1' }), 'caid_invalid'],
        ['malformed caid string', base({ caid: 'caid:9:payment.release.1:jcs-sha256:AAA' }), 'caid_invalid'],
        ['provider_env with a newline', base({ provider_env: 'stripe\nlive' }), 'provider_env_invalid'],
        ['provider_env too long', base({ provider_env: 'a'.repeat(200) }), 'provider_env_invalid'],
        ['empty attempt group', base({ attempt_group: '' }), 'attempt_group_invalid'],
        ['attempt group with a slash', base({ attempt_group: 'retry/2' }), 'attempt_group_invalid'],
        ['null slot spec', base({ slot_spec: null }), 'slot_spec_invalid'],
        ['slot spec as an array', base({ slot_spec: [] }), 'slot_spec_invalid'],
        ['charset with a repeated character', base({ slot_spec: { ...PROVIDER_SLOT_SPECS['eip3009.nonce'], charset: '0011' } }), 'slot_charset_invalid'],
        ['single-character charset', base({ slot_spec: { ...PROVIDER_SLOT_SPECS['eip3009.nonce'], charset: '0' } }), 'slot_charset_invalid'],
        ['fractional encoded length', base({ slot_spec: { ...PROVIDER_SLOT_SPECS['eip3009.nonce'], encoded_length: 12.5 } }), 'slot_encoded_length_invalid'],
        ['zero encoded length', base({ slot_spec: { ...PROVIDER_SLOT_SPECS['eip3009.nonce'], encoded_length: 0 } }), 'slot_encoded_length_invalid'],
        ['slot id with an underscore', base({ slot_spec: { ...PROVIDER_SLOT_SPECS['eip3009.nonce'], slot_id: 'bad_slot' } }), 'slot_id_invalid'],
    ];
    for (const [label, input, reason] of cases) {
        let outcome;
        assert.doesNotThrow(() => { outcome = deriveProviderReplayKey(input); }, `${label} threw`);
        assert.equal(outcome.ok, false, `${label} was accepted`);
        assert.equal(outcome.reason, reason, `${label} gave ${outcome.reason}`);
        assert.equal(typeof outcome.detail, 'string');
        assert.ok(outcome.detail.length > 0, `${label} gave an empty detail`);
    }
});
test('a completely non-object argument refuses rather than throwing', () => {
    for (const junk of [null, undefined, 42, 'string', [], () => { }, Symbol('x')]) {
        let outcome;
        assert.doesNotThrow(() => { outcome = deriveProviderReplayKey(junk); });
        assert.equal(outcome.ok, false);
        assert.equal(typeof outcome.reason, 'string');
    }
});
// ---------------------------------------------------------------------------
// Authorization instance digest: argument reordering and numeric edge cases
// ---------------------------------------------------------------------------
test('argument reordering does not change the authorization instance digest', () => {
    const forwards = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { action_type: 'tool.call.1', args: { alpha: 1, beta: 2, gamma: [1, 2, 3] }, target: 'svc', tool: 'wire' },
    });
    const backwards = authorizationInstanceDigest({
        profile: 'mcp.tools-call',
        material_action: { tool: 'wire', target: 'svc', args: { gamma: [1, 2, 3], beta: 2, alpha: 1 }, action_type: 'tool.call.1' },
        authorization_digest: AUTH,
    });
    assert.equal(forwards.ok, true, JSON.stringify(forwards));
    assert.equal(backwards.ok, true);
    assert.equal(forwards.digest, backwards.digest);
});
test('array order is material and does change the digest', () => {
    const a = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { args: { ids: [1, 2, 3] } },
    });
    const b = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { args: { ids: [3, 2, 1] } },
    });
    assert.notEqual(a.digest, b.digest);
});
test('numeric edge cases refuse with a stated reason rather than silently coercing', () => {
    const uncanonicalizable = [
        ['fractional', 0.5],
        ['above the safe integer range', 2 ** 53],
        ['exponent form beyond safe range', 1e21],
        ['NaN', Number.NaN],
        ['Infinity', Number.POSITIVE_INFINITY],
        ['negative Infinity', Number.NEGATIVE_INFINITY],
    ];
    for (const [label, value] of uncanonicalizable) {
        let outcome;
        assert.doesNotThrow(() => {
            outcome = authorizationInstanceDigest({
                authorization_digest: AUTH,
                profile: 'mcp.tools-call',
                material_action: { args: { amount: value } },
            });
        }, `${label} threw`);
        assert.equal(outcome.ok, false, `${label} was accepted`);
        assert.equal(outcome.reason, 'material_action_uncanonicalizable', label);
    }
    // The largest safe integer is inside the profile and must be accepted.
    const safe = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { args: { amount: Number.MAX_SAFE_INTEGER } },
    });
    assert.equal(safe.ok, true);
    // Negative zero canonicalizes to 0 and therefore digests the same. Recorded
    // as observed behaviour, not asserted as desirable: a rail that distinguishes
    // -0 from 0 would need its own field type, not this digest.
    const negativeZero = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { args: { amount: -0 } },
    });
    const positiveZero = authorizationInstanceDigest({
        authorization_digest: AUTH,
        profile: 'mcp.tools-call',
        material_action: { args: { amount: 0 } },
    });
    assert.equal(negativeZero.ok, true);
    assert.equal(negativeZero.digest, positiveZero.digest);
});
test('the instance digest refuses non-JSON material without throwing', () => {
    for (const junk of [undefined, null, 42, 'text', [], new Date(0), { fn() { return 1; } }]) {
        let outcome;
        assert.doesNotThrow(() => {
            outcome = authorizationInstanceDigest({
                authorization_digest: AUTH,
                profile: 'mcp.tools-call',
                material_action: junk,
            });
        });
        assert.equal(outcome.ok, false, JSON.stringify(junk));
        assert.ok(['material_action_invalid', 'material_action_uncanonicalizable'].includes(outcome.reason));
    }
});
// ---------------------------------------------------------------------------
// MCP tools/call: retry, duplicate content, window, target mismatch
// ---------------------------------------------------------------------------
const CALL = {
    authorization_digest: AUTH,
    target: 'https://payments.example/mcp',
    tool: 'create_payout',
    args: { amount: 4000, currency: 'USD', destination: 'acct_known' },
    call_id: 'call_a1',
    server_env: 'mcp:payments.example',
};
test('vector: the same call id retried yields the same key and the stored result', () => {
    const first = deriveMcpToolCallReplayKey(CALL);
    const retry = deriveMcpToolCallReplayKey({ ...CALL });
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.equal(first.key, retry.key);
    const ledger = createMcpReplayLedger({ windowMs: 60_000 });
    const t0 = 1_000_000;
    assert.equal(ledger.evaluate({ key: first.key, contentDigest: first.content_digest, now: t0 }).outcome, 'fresh');
    ledger.begin({ key: first.key, contentDigest: first.content_digest, now: t0 });
    // In flight: the second arrival is refused, not executed and not deduped.
    const inFlight = ledger.evaluate({ key: retry.key, contentDigest: retry.content_digest, now: t0 + 10 });
    assert.equal(inFlight.outcome, 'in_flight_refused');
    assert.match(inFlight.reason, /still in flight/);
    ledger.complete({ key: first.key, result: { id: 'po_1' }, now: t0 + 20 });
    const replayed = ledger.evaluate({ key: retry.key, contentDigest: retry.content_digest, now: t0 + 30 });
    assert.equal(replayed.outcome, 'stored_result');
    assert.deepEqual(replayed.result, { id: 'po_1' });
});
test('vector: a different call id with identical content, inside and outside the window', () => {
    const first = deriveMcpToolCallReplayKey(CALL);
    const second = deriveMcpToolCallReplayKey({ ...CALL, call_id: 'call_b2' });
    assert.equal(second.ok, true);
    // Different occurrence, so a different key; identical content, so the same
    // content digest. That pair is exactly what makes the flag possible.
    assert.notEqual(first.key, second.key);
    assert.equal(first.content_digest, second.content_digest);
    const windowMs = 60_000;
    const ledger = createMcpReplayLedger({ windowMs });
    const t0 = 5_000_000;
    ledger.begin({ key: first.key, contentDigest: first.content_digest, now: t0 });
    ledger.complete({ key: first.key, result: { id: 'po_1' }, now: t0 });
    const inside = ledger.evaluate({ key: second.key, contentDigest: second.content_digest, now: t0 + windowMs - 1 });
    assert.equal(inside.outcome, 'probable_duplicate_flagged');
    assert.deepEqual(inside.priorKeys, [first.key]);
    const outside = ledger.evaluate({ key: second.key, contentDigest: second.content_digest, now: t0 + windowMs + 1 });
    assert.equal(outside.outcome, 'fresh');
});
test('vector: argument reordering is the same call, not a duplicate', () => {
    const forwards = deriveMcpToolCallReplayKey(CALL);
    const reordered = deriveMcpToolCallReplayKey({
        ...CALL,
        args: { destination: 'acct_known', currency: 'USD', amount: 4000 },
    });
    assert.equal(reordered.ok, true);
    assert.equal(forwards.key, reordered.key);
    assert.equal(forwards.content_digest, reordered.content_digest);
});
test('vector: a target mismatch produces a different key and a stated refusal', () => {
    const authorized = deriveMcpToolCallReplayKey(CALL);
    const elsewhere = deriveMcpToolCallReplayKey({ ...CALL, target: 'https://attacker.example/mcp' });
    assert.equal(elsewhere.ok, true);
    assert.notEqual(authorized.key, elsewhere.key);
    assert.notEqual(authorized.content_digest, elsewhere.content_digest);
    // A server that has seen the authorized key refuses the same key presented
    // with different content, which is the replay that matters.
    const ledger = createMcpReplayLedger();
    ledger.begin({ key: authorized.key, contentDigest: authorized.content_digest, now: 1 });
    const refused = ledger.evaluate({ key: authorized.key, contentDigest: elsewhere.content_digest, now: 2 });
    assert.equal(refused.outcome, 'key_content_mismatch_refused');
    assert.match(refused.reason, /different call content/);
});
test('vector: MCP numeric edge cases refuse with a stated reason', () => {
    const refused = deriveMcpToolCallReplayKey({ ...CALL, args: { amount: 1e21 } });
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, 'derivation_input_uncanonicalizable');
    assert.ok(refused.detail.length > 0);
    const badTarget = deriveMcpToolCallReplayKey({ ...CALL, target: '' });
    assert.equal(badTarget.ok, false);
    assert.equal(badTarget.reason, 'derivation_input_uncanonicalizable');
    const badAuth = deriveMcpToolCallReplayKey({ ...CALL, authorization_digest: 'nope' });
    assert.equal(badAuth.ok, false);
    assert.equal(badAuth.reason, 'authorization_digest_invalid');
});
test('the MCP _meta key name satisfies the specified grammar and is not reserved', () => {
    const [prefix, name] = MCP_META_REPLAY_KEY.split('/');
    assert.equal(typeof name, 'string');
    // Prefix: dot-separated labels, each starting with a letter and ending with
    // a letter or digit, interior letters digits or hyphens.
    for (const label of prefix.split('.')) {
        assert.match(label, /^[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$/, label);
    }
    // Reserved when the SECOND label is modelcontextprotocol or mcp.
    assert.ok(!['modelcontextprotocol', 'mcp'].includes(prefix.split('.')[1]));
    // Name: begins and ends alphanumeric, hyphens underscores dots between.
    assert.match(name, /^[a-z0-9A-Z]([-_.a-z0-9A-Z]*[a-z0-9A-Z])?$/);
});
// ---------------------------------------------------------------------------
// Carriage table hygiene
// ---------------------------------------------------------------------------
test('the carriage table has the five carrier rows and every row resolves', () => {
    assert.equal(PROVIDER_CARRIAGE_TABLE.length, 5);
    const ids = PROVIDER_CARRIAGE_TABLE.map((row) => row.id).sort();
    assert.deepEqual(ids, [
        'aws.ec2.run-instances.client-token',
        'eip3009.nonce',
        'iso20022.end-to-end-id',
        'mcp.tools-call.meta',
        'stripe.idempotency-key',
    ]);
    for (const row of PROVIDER_CARRIAGE_TABLE) {
        assert.equal(getCarriageRow(row.id), row);
        assert.ok(row.sources.length > 0, `${row.id} cites no source`);
        for (const field of ['slot_length', 'slot_charset', 'retention', 'scope', 'intermediary_rewrite', 'echo', 'mismatch_behaviour']) {
            assert.equal(typeof row[field], 'string');
            assert.ok(row[field].length > 0, `${row.id}.${field} is empty`);
        }
        // A field that is neither verified nor marked unverified is a guess.
        const derived = deriveProviderReplayKey(base({ slot_spec: row.slot_spec }));
        assert.equal(derived.ok, true, `${row.id} cannot carry the encoding`);
    }
});
test('unverified facts are marked, and the ones we did verify are not', () => {
    const stripe = getCarriageRow('stripe.idempotency-key');
    assert.match(stripe.retention, /^Verified:/);
    assert.match(stripe.scope, /ENDPOINT scope unverified/);
    assert.match(stripe.slot_charset, /^unverified:/);
    const erc = getCarriageRow('eip3009.nonce');
    assert.match(erc.retention, /^Verified: permanent/);
    const iso = getCarriageRow('iso20022.end-to-end-id');
    assert.match(iso.retention, /^unverified:/);
    assert.match(iso.slot_length, /Max35Text/);
    const aws = getCarriageRow('aws.ec2.run-instances.client-token');
    assert.match(aws.retention, /^unverified:/);
    assert.match(aws.echo, /^unverified/);
    const mcp = getCarriageRow('mcp.tools-call.meta');
    assert.match(mcp.retention, /^unverified:/);
});
test('the retention measurement records a row for every carriage row', () => {
    const measured = PROVIDER_KEY_RETENTION_MEASUREMENT.rows.map((row) => row.id).sort();
    const carried = PROVIDER_CARRIAGE_TABLE.map((row) => row.id).sort();
    assert.deepEqual(measured, carried);
    const stripe = PROVIDER_KEY_RETENTION_MEASUREMENT.rows.find((row) => row.id === 'stripe.idempotency-key');
    assert.equal(stripe.provider_retention_hours, 24);
    assert.equal(stripe.verdict, 'join_only_beyond_24h');
    const erc = PROVIDER_KEY_RETENTION_MEASUREMENT.rows.find((row) => row.id === 'eip3009.nonce');
    assert.equal(erc.verdict, 'consumption_and_join');
    assert.match(PROVIDER_KEY_RETENTION_MEASUREMENT.verdict, /adapter-feature on the money rail/);
});
