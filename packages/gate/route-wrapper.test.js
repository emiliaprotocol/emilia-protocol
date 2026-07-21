// SPDX-License-Identifier: Apache-2.0
// Generated from route-wrapper.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEg1Harness, createTrustedActionFirewall } from './index.js';
function fixture() {
    const harness = createEg1Harness();
    const gate = createTrustedActionFirewall({
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
    });
    return { gate, harness };
}
function response() {
    return {
        headers: {},
        statusCode: null,
        body: null,
        setHeader(name, value) { this.headers[name] = value; },
        status(value) { this.statusCode = value; return this; },
        json(value) { this.body = value; return value; },
    };
}
test('route wrapper owns execution and emits bound reliance evidence', async () => {
    const { gate, harness } = fixture();
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    const req = { headers: {} };
    let effects = 0;
    const wrapped = gate.route(async (_req, _res, authorization) => {
        effects++;
        assert.equal(authorization.allow, true);
        return 'route-result';
    }, {
        selector: { protocol: 'mcp', tool: 'release_payment' },
        receipt: () => receipt,
        observedAction: () => harness.action,
    });
    const result = await wrapped(req, response());
    assert.equal(result, 'route-result');
    assert.equal(effects, 1);
    assert.equal(req.emiliaGate.allow, true);
    assert.equal(req.emiliaGateExecution.kind, 'execution');
    assert.equal(req.emiliaReliancePacket.verdict, 'rely');
});
test('deprecated middleware refuses without consuming a valid receipt or calling next', async () => {
    const { gate, harness } = fixture();
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    const req = {
        headers: { 'x-emilia-receipt': Buffer.from(JSON.stringify(receipt)).toString('base64') },
        emiliaObservedAction: harness.action,
    };
    const res = response();
    let nextCalls = 0;
    await gate.middleware({ selector: { protocol: 'mcp', tool: 'release_payment' } })(req, res, () => { nextCalls++; });
    assert.equal(res.statusCode, 428);
    assert.equal(res.body.detail, 'unsafe_middleware_deprecated');
    assert.equal(nextCalls, 0);
    assert.equal(gate.store.size, 0);
    // The same receipt remains usable through an execution-owning API.
    const out = await gate.run({ selector: { protocol: 'mcp', tool: 'release_payment' }, receipt, observedAction: harness.action }, async () => 'executed');
    assert.equal(out.ok, true);
});
