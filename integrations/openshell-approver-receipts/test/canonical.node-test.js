// SPDX-License-Identifier: Apache-2.0
// Generated from canonical.node-test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import protobuf from 'protobufjs';
import { canonicalRule, fromB64u, jcs, ruleDigest } from '../src/canonical.ts';
import { chunkViewFromBytes } from '../src/gateway-client.ts';
import { PROTO_DIR, lookupType } from '../src/protos.ts';
import { structToJson } from '../src/struct-json.ts';
const here = path.dirname(fileURLToPath(import.meta.url));
test('vendored protos are byte-identical to the pinned upstream commit', () => {
    const upstream = JSON.parse(fs.readFileSync(path.join(PROTO_DIR, 'UPSTREAM.json'), 'utf8'));
    assert.equal(upstream.commit, '9cb72baa2e61a1b5f12407e6e82da7fdba0aa722');
    const onDisk = fs.readdirSync(PROTO_DIR).filter((f) => f.endsWith('.proto')).sort();
    assert.deepEqual(onDisk, Object.keys(upstream.files).sort());
    for (const [file, digest] of Object.entries(upstream.files)) {
        assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(PROTO_DIR, file))).digest('hex'), digest, file);
    }
    assert.ok(fs.existsSync(path.join(here, '..', 'NOTICE')));
});
test('JCS: sorted members, minimal escapes, safe integers only', () => {
    assert.equal(jcs({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: '\u0007' } }), '{"a":[true,null,"x"],"b":1,"c":{"y":"\\u0007","z":"é"}}');
    assert.throws(() => jcs({ a: 1.5 }));
    assert.throws(() => jcs({ a: Number.NaN }));
    assert.throws(() => jcs({ a: 2 ** 53 }));
    assert.throws(() => jcs({ a: undefined }));
    assert.throws(() => jcs({ a: '\ud800' }));
});
test('canonical rule: the digest of a live gateway rule is pinned', () => {
    // allow_www_w3_org_443 as the live gateway returned it (evidence captured by
    // a Python client with preserving_proto_field_name=True). The live
    // end-to-end run computed the same digest from the gateway's wire bytes.
    const rule = {
        binaries: [{ path: '/usr/bin/bash' }],
        endpoints: [{ advisor_proposed: true, host: 'www.w3.org', port: 443, ports: [443] }],
        name: 'allow_www_w3_org_443',
    };
    const canonical = canonicalRule(rule);
    assert.ok(canonical.ok);
    assert.equal(jcs(canonical.value), '{"binaries":[{"path":"/usr/bin/bash"}],"endpoints":[{"advisor_proposed":true,"host":"www.w3.org","port":443,"ports":[443]}],"name":"allow_www_w3_org_443"}');
    assert.deepEqual(ruleDigest(rule), { ok: true, value: 'sha256:55345c9100a723187df2614bc8240ebd4ce94f14e1772940f6d8a330e4041c00' });
});
test('canonical rule: proto3 JSON spellings collapse to one form; defaults drop out', () => {
    const snake = { name: 'r', endpoints: [{ host: 'h', port: 443, advisor_proposed: true, allow_encoded_slash: false, protocol: '' }] };
    const camel = { name: 'r', endpoints: [{ host: 'h', port: 443, advisorProposed: true, allowEncodedSlash: false }], binaries: [] };
    const minimal = { name: 'r', endpoints: [{ host: 'h', port: 443, advisor_proposed: true }] };
    const d = ruleDigest(minimal);
    assert.ok(d.ok);
    assert.deepEqual(ruleDigest(snake), d);
    assert.deepEqual(ruleDigest(camel), d);
    assert.deepEqual(ruleDigest({ ...minimal, binaries: null }), d, 'null means unset in proto3 JSON');
    // An enum may be given by number; the canonical form uses the name.
    const byNumber = ruleDigest({ name: 'r', endpoints: [{ host: 'h', tls: 1 }] });
    const tlsEnum = lookupType('openshell.sandbox.v1.NetworkEndpoint').fields.tls.resolvedType;
    assert.deepEqual(byNumber, ruleDigest({ name: 'r', endpoints: [{ host: 'h', tls: tlsEnum.valuesById[1] }] }));
    // The zero enum value is the default and drops out.
    assert.deepEqual(ruleDigest({ name: 'r', endpoints: [{ host: 'h', tls: tlsEnum.valuesById[0] }] }), ruleDigest({ name: 'r', endpoints: [{ host: 'h' }] }));
});
test('canonical rule: proto3 optional fields keep an explicit false', () => {
    const withFalse = canonicalRule({ name: 'r', endpoints: [{ host: 'h', mcp: { strict_tool_names: false } }] });
    assert.ok(withFalse.ok);
    assert.equal(jcs(withFalse.value), '{"endpoints":[{"host":"h","mcp":{"strict_tool_names":false}}],"name":"r"}');
    assert.notDeepEqual(ruleDigest({ name: 'r', endpoints: [{ host: 'h', mcp: { strict_tool_names: false } }] }), ruleDigest({ name: 'r', endpoints: [{ host: 'h', mcp: {} }] }));
});
test('canonical rule: anything outside the schema is refused with a reason', () => {
    const cases = [
        [{ name: 'r', bogus: 1 }, /bogus: not a field/],
        [{ name: 'r', endpoints: [{ host: 'h', port: 1.5 }] }, /port: expected an integer/],
        [{ name: 'r', endpoints: [{ host: 'h', port: -1 }] }, /port: expected an integer/],
        [{ name: 'r', endpoints: [{ host: 'h', port: '443' }] }, /port: expected an integer/],
        [{ name: 'r', endpoints: [{ host: 'h', port: 2 ** 32 }] }, /port: expected an integer/],
        [{ name: 7 }, /name: expected a string/],
        [{ name: 'r', endpoints: [{ host: 'h', tls: 'NOPE' }] }, /unknown NetworkTlsMode/],
        [{ name: 'r', endpoints: [{ host: 'h', tls: 99 }] }, /NetworkTlsMode/],
        [{ name: 'r', endpoints: {} }, /expected a list/],
        [{ name: 'r', endpoints: [{ host: 'h', advisor_proposed: true, advisorProposed: true }] }, /given twice/],
        [JSON.parse('{"name":"r","__proto__":{"polluted":true}}'), /__proto__: not a field/],
        [[], /expected an object/],
        [null, /expected an object/],
        ['rule', /expected an object/],
        [Object.create({ inherited: 1 }), /expected an object/],
    ];
    for (const [input, reason] of cases) {
        const result = canonicalRule(input);
        assert.equal(result.ok, false, JSON.stringify(input));
        if (!result.ok)
            assert.match(result.reason, reason);
    }
    assert.equal({}.polluted, undefined);
});
function encodeChunk(fields) {
    const chunkType = lookupType('openshell.v1.PolicyChunk');
    return chunkType.encode(chunkType.fromObject(fields)).finish();
}
test('chunk view: digest computed from gateway wire bytes', () => {
    const bytes = encodeChunk({
        id: 'c1', status: 'pending', rule_name: 'allow_www_w3_org_443', review_token: 'a'.repeat(64),
        proposed_rule: { name: 'allow_www_w3_org_443', endpoints: [{ host: 'www.w3.org', port: 443, ports: [443], advisor_proposed: true }], binaries: [{ path: '/usr/bin/bash' }] },
        candidate_effective_policy_hash: 'b'.repeat(64), decided_time: { seconds: 1790665000, nanos: 5_000_000 },
    });
    const view = chunkViewFromBytes(bytes);
    assert.equal(view.rule_error, undefined);
    assert.equal(view.rule_digest, 'sha256:55345c9100a723187df2614bc8240ebd4ce94f14e1772940f6d8a330e4041c00');
    assert.equal(view.review_token, 'a'.repeat(64));
    assert.equal(view.decided_time, '2026-09-29T06:56:40.005Z');
});
test('chunk view: a rule with fields this build does not model is refused, not truncated', () => {
    const ruleType = lookupType('openshell.sandbox.v1.NetworkPolicyRule');
    const ruleBytes = ruleType.encode(ruleType.fromObject({ name: 'r', endpoints: [{ host: 'h', port: 443 }] })).finish();
    // Field 99, varint 1: what a newer gateway schema would add.
    const writer = protobuf.Writer.create();
    writer.bytes(Buffer.concat([Buffer.from(ruleBytes), Buffer.from([0x98, 0x06, 0x01])]));
    const ruleField = writer.finish();
    const chunkBytes = Buffer.concat([Buffer.from(encodeChunk({ id: 'c1', status: 'pending' })), Buffer.from([0x22]), Buffer.from(ruleField)]);
    const view = chunkViewFromBytes(chunkBytes);
    assert.equal(view.rule_digest, null);
    assert.match(view.rule_error ?? '', /newer than the pinned protos/);
});
test('chunk view: two proposed_rule occurrences on the wire are refused', () => {
    const base = encodeChunk({ id: 'c1', proposed_rule: { name: 'a' } });
    const second = encodeChunk({ proposed_rule: { name: 'b' } });
    const view = chunkViewFromBytes(Buffer.concat([Buffer.from(base), Buffer.from(second)]));
    assert.equal(view.rule_digest, null);
    assert.match(view.rule_error ?? '', /more than once/);
});
test('base64url decoding is canonical only', () => {
    assert.deepEqual(fromB64u('AQID'), Buffer.from([1, 2, 3]));
    assert.deepEqual(fromB64u('AQI'), Buffer.from([1, 2]));
    for (const bad of ['', 'AQID=', 'AQ+D', 'A', 7, null, 'AR'])
        assert.equal(fromB64u(bad), null, String(bad));
});
test('Struct to JSON: real payload shape converts; hostile shapes refuse', () => {
    const structType = lookupType('google.protobuf.Struct');
    const toObject = (m) => structType.toObject(structType.decode(structType.encode(structType.fromObject(m)).finish()), { oneofs: true, enums: String, longs: String });
    const struct = toObject({
        fields: {
            chunkId: { stringValue: 'c1' },
            policyVersion: { numberValue: 2 },
            flagged: { boolValue: true },
            none: { nullValue: 'NULL_VALUE' },
            workspaceScope: { structValue: { fields: { workspace: { stringValue: 'default' } } } },
            approvals: { listValue: { values: [{ structValue: { fields: { chunkId: { stringValue: 'a' } } } }] } },
            ['__proto__']: { stringValue: 'stays data' },
        },
    });
    const json = structToJson(struct);
    assert.ok(json.ok);
    assert.equal(json.value.chunkId, 'c1');
    assert.equal(json.value.policyVersion, 2);
    assert.equal(json.value.flagged, true);
    assert.equal(json.value.none, null);
    assert.deepEqual({ ...json.value.workspaceScope }, { workspace: 'default' });
    assert.equal(Object.prototype.hasOwnProperty.call(json.value, '__proto__'), true);
    assert.equal({}.chunkId, undefined);
    assert.deepEqual(structToJson(undefined), { ok: true, value: {} });
    assert.equal(structToJson('x').ok, false);
    assert.equal(structToJson({ fields: { a: {} } }).ok, false);
    assert.equal(structToJson({ fields: { a: { kind: 'numberValue', numberValue: Infinity } } }).ok, false);
    assert.equal(structToJson({ fields: { a: { kind: 'listValue', listValue: { values: 'no' } } } }).ok, false);
    let deep = { kind: 'stringValue', stringValue: 'x' };
    for (let i = 0; i < 40; i += 1)
        deep = { kind: 'structValue', structValue: { fields: { d: deep } } };
    assert.match(structToJson({ fields: { d: deep } }).reason, /nesting deeper/);
    const wide = { fields: { l: { kind: 'listValue', listValue: { values: Array.from({ length: 25_000 }, () => ({ kind: 'nullValue' })) } } } };
    assert.match(structToJson(wide).reason, /more than 20000/);
});
