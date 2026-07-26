// SPDX-License-Identifier: Apache-2.0
// Generated from discovery-permit-resolver.hostile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { DISCOVERY_PERMIT_BINDING_VERSION, DISCOVERY_PERMIT_DISCOVERY_VERSION, digestDiscoveryPermit, } from '@emilia-protocol/verify/discovery-permit-contract';
import { DiscoveryPermitResolver, } from './discovery-permit-resolver.js';
const NOW = Date.parse('2026-07-24T12:00:00Z');
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
    action_type: 'payment.release.1',
    amount: '125000.00',
    currency: 'USD',
});
const DISCOVERY_URL = 'https://authority.example/.well-known/emilia-discovery-permit.json';
const PERMIT_URL = 'https://authority.example/permits/payment-release.json';
const REDIRECTED_DISCOVERY_URL = 'https://cdn.authority.example/discovery/permit.json';
function pins(overrides = {}) {
    return {
        origin: 'https://authority.example',
        discovery_url: DISCOVERY_URL,
        permit_url: PERMIT_URL,
        discovery_schema_digest: `sha256:${'1'.repeat(64)}`,
        permit_schema_digest: `sha256:${'2'.repeat(64)}`,
        mapping_digest: `sha256:${'3'.repeat(64)}`,
        max_age_seconds: 300,
        redirect_map: {},
        ...overrides,
    };
}
function bodies(trustPins = pins(), overrides = {}) {
    const source = {
        origin: trustPins.origin,
        discovery_url: trustPins.discovery_url,
        permit_url: trustPins.permit_url,
    };
    const schemaDigests = {
        discovery: trustPins.discovery_schema_digest,
        permit_binding: trustPins.permit_schema_digest,
    };
    const common = {
        source,
        schema_digests: schemaDigests,
        mapping_digest: trustPins.mapping_digest,
        status: overrides.status ?? 'active',
        issued_at: overrides.issued_at ?? '2026-07-24T11:59:00Z',
    };
    return {
        discovery: {
            '@type': DISCOVERY_PERMIT_DISCOVERY_VERSION,
            ...common,
            ...overrides.discovery,
        },
        binding: {
            '@type': DISCOVERY_PERMIT_BINDING_VERSION,
            ...common,
            caid: CAID,
            action_digest: digestDiscoveryPermit(ACTION),
            ...overrides.binding,
        },
    };
}
function mockTransport(replies, options = {}) {
    return {
        async resolveAddresses() {
            return options.addresses ?? ['93.184.216.34'];
        },
        async fetchPinned(url, init, context) {
            options.calls?.push({ url, init, approved: context.approvedAddresses });
            const reply = replies[url];
            if (!reply)
                throw new Error(`unexpected URL ${url}`);
            const status = reply.status ?? 200;
            return {
                connectedAddress: options.connectedAddress ?? context.approvedAddresses[0],
                response: new Response(reply.body ?? '', {
                    status,
                    headers: reply.headers ?? {
                        'content-type': 'application/json; charset=utf-8',
                    },
                }),
            };
        },
    };
}
function resolver(trustPins, transport, limits = {}) {
    return new DiscoveryPermitResolver({
        pins: trustPins,
        transport,
        clock: () => NOW,
        timeout_ms: 500,
        max_body_bytes: limits.max_body_bytes ?? 4096,
        max_json_depth: limits.max_json_depth ?? 12,
    });
}
function happyReplies(trustPins = pins()) {
    const { discovery, binding } = bodies(trustPins);
    return {
        [trustPins.discovery_url]: { body: JSON.stringify(discovery) },
        [trustPins.permit_url]: { body: JSON.stringify(binding) },
    };
}
test('constructor snapshots origin, URLs, digests, max age, redirect map, and transport methods', async () => {
    const mutablePins = pins();
    const calls = [];
    const transport = mockTransport(happyReplies(mutablePins), { calls });
    const instance = resolver(mutablePins, transport);
    mutablePins.origin = 'https://attacker.example';
    mutablePins.discovery_url = 'https://attacker.example/discovery.json';
    mutablePins.permit_url = 'https://attacker.example/permit.json';
    mutablePins.mapping_digest = `sha256:${'9'.repeat(64)}`;
    mutablePins.max_age_seconds = 999999;
    mutablePins.redirect_map[DISCOVERY_URL] = 'https://attacker.example/discovery.json';
    transport.fetchPinned = async () => {
        throw new Error('mutated transport method was used');
    };
    const result = await instance.resolve({ caid: CAID, action: ACTION });
    assert.equal(result.disposition, 'current');
    assert.equal(result.source.origin, 'https://authority.example');
    assert.deepEqual(calls.map((call) => call.url), [DISCOVERY_URL, PERMIT_URL]);
    assert.ok(calls.every((call) => call.init.redirect === 'manual'));
});
test('executor CAID and action are snapshotted before any asynchronous transport work', async () => {
    const mutableAction = { ...ACTION };
    const trustPins = pins();
    const delegate = mockTransport(happyReplies(trustPins));
    const transport = {
        async resolveAddresses(hostname, context) {
            mutableAction.amount = '999999.00';
            return delegate.resolveAddresses(hostname, context);
        },
        fetchPinned: delegate.fetchPinned,
    };
    const result = await resolver(trustPins, transport).resolve({
        caid: CAID,
        action: mutableAction,
    });
    assert.equal(result.disposition, 'current');
    assert.equal(result.binding.action_digest, digestDiscoveryPermit(ACTION));
    assert.equal(mutableAction.amount, '999999.00');
});
test('transaction-scoped trust pins are rejected before address resolution or fetch', async () => {
    let touched = false;
    const transport = {
        async resolveAddresses() {
            touched = true;
            return ['93.184.216.34'];
        },
        async fetchPinned() {
            touched = true;
            throw new Error('must not fetch');
        },
    };
    const instance = resolver(pins(), transport);
    await assert.rejects(() => instance.resolve({
        caid: CAID,
        action: ACTION,
        mapping_digest: `sha256:${'9'.repeat(64)}`,
        origin: 'https://attacker.example',
        redirect_map: { [PERMIT_URL]: 'https://attacker.example/permit.json' },
    }), (error) => error?.code === 'transaction_fields_not_allowed');
    assert.equal(touched, false);
});
test('address resolution must be public and the transport must attest the connected address', async () => {
    const replies = happyReplies();
    let fetched = false;
    const privateTransport = mockTransport(replies, {
        addresses: ['169.254.169.254'],
        calls: [],
    });
    const originalFetch = privateTransport.fetchPinned;
    privateTransport.fetchPinned = async (...args) => {
        fetched = true;
        return originalFetch(...args);
    };
    await assert.rejects(() => resolver(pins(), privateTransport).resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'address_not_public');
    assert.equal(fetched, false);
    await assert.rejects(() => resolver(pins(), mockTransport(replies, {
        addresses: ['93.184.216.34'],
        connectedAddress: '93.184.216.35',
    })).resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'connected_address_not_approved');
});
test('only constructor-pinned exact manual redirects are followed', async () => {
    const trustPins = pins({
        redirect_map: { [DISCOVERY_URL]: REDIRECTED_DISCOVERY_URL },
    });
    const { discovery, binding } = bodies(trustPins);
    const calls = [];
    const instance = resolver(trustPins, mockTransport({
        [DISCOVERY_URL]: {
            status: 302,
            headers: { location: REDIRECTED_DISCOVERY_URL },
        },
        [REDIRECTED_DISCOVERY_URL]: { body: JSON.stringify(discovery) },
        [PERMIT_URL]: { body: JSON.stringify(binding) },
    }, { calls }));
    const result = await instance.resolve({ caid: CAID, action: ACTION });
    assert.deepEqual(result.provenance.discovery.redirect_chain, [DISCOVERY_URL, REDIRECTED_DISCOVERY_URL]);
    assert.equal(result.provenance.discovery.resolved_url, REDIRECTED_DISCOVERY_URL);
    assert.ok(calls.every((call) => call.init.redirect === 'manual'));
    const unmapped = resolver(pins(), mockTransport({
        [DISCOVERY_URL]: {
            status: 302,
            headers: { location: REDIRECTED_DISCOVERY_URL },
        },
    }));
    await assert.rejects(() => unmapped.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'redirect_not_pinned');
    const wrongTargetPins = pins({
        redirect_map: { [DISCOVERY_URL]: REDIRECTED_DISCOVERY_URL },
    });
    const wrongTarget = resolver(wrongTargetPins, mockTransport({
        [DISCOVERY_URL]: {
            status: 302,
            headers: { location: 'https://attacker.example/discovery.json' },
        },
    }));
    await assert.rejects(() => wrongTarget.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'redirect_target_mismatch');
});
test('body bytes, JSON depth, duplicate names, and content type are bounded before use', async () => {
    const trustPins = pins();
    const { discovery } = bodies(trustPins);
    const oversized = resolver(trustPins, mockTransport({
        [DISCOVERY_URL]: { body: `${JSON.stringify(discovery)}${' '.repeat(500)}` },
    }), { max_body_bytes: 128 });
    await assert.rejects(() => oversized.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'body_too_large');
    const wrongType = resolver(trustPins, mockTransport({
        [DISCOVERY_URL]: {
            body: JSON.stringify(discovery),
            headers: { 'content-type': 'text/html' },
        },
    }));
    await assert.rejects(() => wrongType.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'content_type_invalid');
    const duplicate = resolver(trustPins, mockTransport({
        [DISCOVERY_URL]: {
            body: '{"@type":"one","@type":"two"}',
        },
    }));
    await assert.rejects(() => duplicate.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'json_not_strict');
    const deep = resolver(trustPins, mockTransport({
        [DISCOVERY_URL]: { body: '{"a":{"b":{"c":{"d":1}}}}' },
    }), { max_json_depth: 3 });
    await assert.rejects(() => deep.resolve({ caid: CAID, action: ACTION }), (error) => error?.code === 'json_depth_exceeded');
});
test('resolver records raw and canonical digests and preserves closed dispositions', async () => {
    for (const [status, issued_at, disposition] of [
        ['active', '2026-07-24T11:59:00Z', 'current'],
        ['active', '2026-07-24T11:54:59Z', 'stale'],
        ['unknown', '2026-07-24T11:59:00Z', 'unknown'],
        ['deprecated', '2026-07-24T11:59:00Z', 'deprecated'],
    ]) {
        const trustPins = pins();
        const docs = bodies(trustPins, { status, issued_at });
        const result = await resolver(trustPins, mockTransport({
            [DISCOVERY_URL]: { body: JSON.stringify(docs.discovery, null, 2) },
            [PERMIT_URL]: { body: JSON.stringify(docs.binding, null, 2) },
        })).resolve({ caid: CAID, action: ACTION });
        assert.equal(result.disposition, disposition);
        assert.equal(result.usable_for_permit, disposition === 'current');
        assert.equal(result.authorizes_action, false);
        assert.notEqual(result.provenance.discovery.raw_digest, result.provenance.discovery.canonical_digest);
    }
});
test('source, schema, mapping, CAID, and action substitutions fail closed', async () => {
    const substitutions = [
        ['source_agreement_failed', {
                binding: {
                    source: {
                        origin: 'https://attacker.example',
                        discovery_url: DISCOVERY_URL,
                        permit_url: PERMIT_URL,
                    },
                },
            }],
        ['schema_digest_mismatch', {
                discovery: {
                    schema_digests: {
                        discovery: `sha256:${'9'.repeat(64)}`,
                        permit_binding: `sha256:${'2'.repeat(64)}`,
                    },
                },
            }],
        ['mapping_digest_mismatch', {
                binding: { mapping_digest: `sha256:${'9'.repeat(64)}` },
            }],
        ['caid_mismatch', {
                binding: { caid: `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}` },
            }],
        ['action_digest_mismatch', {
                binding: { action_digest: `sha256:${'9'.repeat(64)}` },
            }],
    ];
    for (const [code, overrides] of substitutions) {
        const trustPins = pins();
        const docs = bodies(trustPins, overrides);
        await assert.rejects(() => resolver(trustPins, mockTransport({
            [DISCOVERY_URL]: { body: JSON.stringify(docs.discovery) },
            [PERMIT_URL]: { body: JSON.stringify(docs.binding) },
        })).resolve({ caid: CAID, action: ACTION }), (error) => error?.code === code, code);
    }
});
