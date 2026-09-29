// SPDX-License-Identifier: Apache-2.0
// The two things the gateway hands us as text: its bearer JWT on every
// interceptor call, and its shorthand CONFIG:* audit lines.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { b64u } from '../src/canonical.ts';
import { verifyGatewayAuthorization } from '../src/gateway-jwt.ts';
import type { GatewayJwtPolicy } from '../src/gateway-jwt.ts';
import { parseGatewayLog } from '../src/gateway-log.ts';

const gw = crypto.generateKeyPairSync('ed25519');
const NOW = 1_790_665_000_000;
const policy: GatewayJwtPolicy = { publicKey: gw.publicKey, gatewayId: 'gw1', audience: 'urn:openshell:extension:interceptor:emilia-observer', now: () => NOW };

function jwt(header: Record<string, unknown>, claims: Record<string, unknown>, key: crypto.KeyObject = gw.privateKey): string {
  const h = b64u(Buffer.from(JSON.stringify(header)));
  const c = b64u(Buffer.from(JSON.stringify(claims)));
  const sig = crypto.sign(null, Buffer.from(`${h}.${c}`), key);
  return `Bearer ${h}.${c}.${b64u(sig)}`;
}

// The header and claims shape the gateway sent in the live run.
const HEADER = { alg: 'EdDSA', typ: 'openshell-ext+jwt', kid: 'oar-e2e-kid' };
const CLAIMS = {
  iss: 'openshell-gateway:gw1', sub: 'openshell-gateway:gw1', aud: policy.audience, caller_kind: 'gateway',
  jti: 'j-1', iat: NOW / 1000, exp: NOW / 1000 + 900,
};

test('gateway JWT: the live shape verifies under the pinned key', () => {
  assert.deepEqual(verifyGatewayAuthorization(jwt(HEADER, CLAIMS), policy), { mode: 'verified', jti: 'j-1', iss: 'openshell-gateway:gw1', exp: NOW / 1000 + 900 });
  assert.equal(verifyGatewayAuthorization(jwt(HEADER, { ...CLAIMS, aud: ['x', policy.audience] }), policy).mode, 'verified');
  assert.deepEqual(verifyGatewayAuthorization(undefined, null), { mode: 'not_configured' });
});

test('gateway JWT: every deviation is a refusal with a reason', () => {
  const other = crypto.generateKeyPairSync('ed25519');
  const h = b64u(Buffer.from(JSON.stringify(HEADER)));
  const c = b64u(Buffer.from(JSON.stringify(CLAIMS)));
  const hs256 = `Bearer ${b64u(Buffer.from(JSON.stringify({ ...HEADER, alg: 'HS256' })))}.${c}.${b64u(crypto.createHmac('sha256', 'k').update('x').digest())}`;
  const cases: [unknown, RegExp][] = [
    [undefined, /no authorization/],
    ['Basic abc', /not a Bearer/],
    ['Bearer a.b', /three segments/],
    [`Bearer ${h}.${c}.`, /64-byte/],
    [hs256, /64-byte|EdDSA/],
    [jwt({ ...HEADER, alg: 'none' }, CLAIMS), /pinned EdDSA/],
    [jwt({ ...HEADER, typ: 'JWT' }, CLAIMS), /typ/],
    [jwt({ ...HEADER, crit: ['exp'] }, CLAIMS), /crit/],
    [jwt(HEADER, CLAIMS, other.privateKey), /does not verify/],
    [jwt(HEADER, { ...CLAIMS, iss: 'openshell-gateway:gw2' }), /iss/],
    [jwt(HEADER, { ...CLAIMS, aud: 'urn:other' }), /aud/],
    [jwt(HEADER, { ...CLAIMS, aud: [] }), /aud/],
    [jwt(HEADER, { ...CLAIMS, caller_kind: 'user' }), /caller_kind/],
    [jwt(HEADER, { ...CLAIMS, exp: NOW / 1000 - 3600 }), /expired/],
    [jwt(HEADER, { ...CLAIMS, exp: undefined }), /exp is missing/],
    [jwt(HEADER, { ...CLAIMS, iat: NOW / 1000 + 3600 }), /future/],
    [jwt(HEADER, { ...CLAIMS, nbf: NOW / 1000 + 3600 }), /not yet valid/],
    [`Bearer ${b64u(Buffer.from('{"alg":"EdDSA","alg":"EdDSA","typ":"openshell-ext+jwt"}'))}.${c}.${b64u(Buffer.alloc(64))}`, /duplicate/],
    [`Bearer ${h}=.${c}.${b64u(Buffer.alloc(64))}`, /base64url/],
    [`Bearer ${b64u(Buffer.from('[1]'))}.${c}.${b64u(Buffer.alloc(64))}`, /not a JSON object/],
  ];
  for (const [header, reason] of cases) {
    const result = verifyGatewayAuthorization(header, policy);
    assert.equal(result.mode, 'failed', String(header).slice(0, 60));
    if (result.mode === 'failed') assert.match(result.reason, reason);
  }
});

// Lines in the exact form the gateway printed them in the live run.
const LIVE = [
  '2026-09-29T07:27:04.801024Z  INFO request{method=POST path="/openshell.v1.OpenShell/ApproveDraftChunk" request_id="x"}: ocsf: sandbox_id=eb7cf37c-ba10-4107-a7fc-52c2fe028253 CONFIG:APPROVED [INFO] gateway approved draft chunk 6290ac3b-d80a-425d-b867-bfedcbed788b: add-rule allow_example_com_443 endpoints=[example.com:443 ports=1] binaries=[/usr/bin/bash] [version:v2 hash:a324c73a87d070edc2869d5a1f514ac26e9333fbdb8d2dd8bdfae498d77666b0]',
  '2026-09-29T07:27:14.882424Z  INFO ocsf: sandbox_id=eb7cf37c-ba10-4107-a7fc-52c2fe028253 CONFIG:MERGED [INFO] gateway bulk-approved 2 draft chunk(s) and skipped 0 [version:v3 hash:5181cdabbbb7cae8ad0126b72c626ea376f1db51fa794d208ea0e9199942de43]',
  '2026-09-29T07:27:35.915319Z  INFO ocsf: sandbox_id=9aa6ec65-6095-4a84-b10d-f2a63c2777aa CONFIG:MERGED [INFO] gateway merged 1 incremental policy operation(s) [version:v6 hash:7c8c46e2dcf5d442bee0ef1ce83ae2af0989693068cbf00911b6b0da39e94d85]',
  '2026-09-29T07:28:06.577810Z  INFO ocsf: sandbox_id=2506088d-f035-4b48-a850-49141d86eef0 CONFIG:APPROVED [INFO] auto-approved: no new prover findings (source=mechanistic) \u2014 chunk c04a9098-1718-4010-95a0-4fe826ffc258: add-rule allow_example_com_443 endpoints=[example.com:443 ports=1] binaries=[/usr/bin/bash] [auto:true source:mechanistic prover_delta:empty resolved_from:sandbox version:v2 hash:a324c73a87d070edc2869d5a1f514ac26e9333fbdb8d2dd8bdfae498d77666b0]',
  '2026-09-29T06:44:11.519180Z  INFO ocsf: sandbox_id=c0975d36-55e6-47d4-be4a-5949118a4dbf CONFIG:MERGED [INFO] gateway bulk-approved 0 draft chunk(s) and skipped 2',
];

test('gateway log: live CONFIG lines parse into policy events', () => {
  const parsed = parseGatewayLog(`${LIVE.join('\n')}\nunrelated line\n`);
  assert.deepEqual(parsed.unparsed_config_lines, []);
  assert.equal(parsed.lines_without_sandbox_id, 0);
  const [approved, bulk, merged, auto] = parsed.events;
  assert.equal(parsed.events.length, 4, 'the zero-approval bulk line carries no version');
  assert.deepEqual([approved.state, approved.auto, approved.version, approved.chunk_id, approved.bulk_summary], ['APPROVED', false, 2, '6290ac3b-d80a-425d-b867-bfedcbed788b', false]);
  assert.deepEqual([bulk.state, bulk.bulk_summary, bulk.version], ['MERGED', true, 3]);
  assert.deepEqual([merged.state, merged.bulk_summary, merged.version], ['MERGED', false, 6]);
  assert.deepEqual([auto.state, auto.auto, auto.source, auto.chunk_id, auto.version], ['APPROVED', true, 'mechanistic', 'c04a9098-1718-4010-95a0-4fe826ffc258', 2]);
});

test('gateway log: ANSI colour, missing sandbox id and broken tags', () => {
  const colored = `\u001b[2m2026\u001b[0m \u001b[32mINFO\u001b[0m ${LIVE[0].slice(LIVE[0].indexOf('ocsf:'))}`;
  assert.equal(parseGatewayLog(colored).events.length, 1);
  // `openshell logs` form: no sandbox_id, so it cannot be attributed.
  const cliForm = '[gateway] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] gateway approved draft chunk c1: add-rule r [version:v2 hash:a324c73a87d070edc2869d5a1f514ac26e9333fbdb8d2dd8bdfae498d77666b0]';
  assert.deepEqual(parseGatewayLog(cliForm), { events: [], lines_without_sandbox_id: 1, unparsed_config_lines: [] });
  const broken = 'ocsf: sandbox_id=s1 CONFIG:APPROVED [INFO] gateway approved draft chunk c1: x [version:vX hash:nothex]';
  assert.deepEqual(parseGatewayLog(broken).unparsed_config_lines, [1]);
  assert.deepEqual(parseGatewayLog(undefined as unknown as string).events, []);
});

test('gateway log: hostile CONFIG lines parse in linear time; overlong lines are refused, not parsed', () => {
  // Each line used to cost time quadratic in its length (about 115 ms at 55 KB).
  const hostile = Array.from({ length: 100 }, () => `CONFIG:${'sandbox_id='.repeat(5_000)}`).join('\n');
  let started = performance.now();
  const parsed = parseGatewayLog(hostile);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 1_000, `100 hostile 55 KB lines took ${elapsed.toFixed(0)} ms`);
  assert.equal(parsed.unparsed_config_lines.length, 100);
  started = performance.now();
  assert.deepEqual(parseGatewayLog(`CONFIG:${'sandbox_id='.repeat(40_000)}`).unparsed_config_lines, [1]);
  assert.ok(performance.now() - started < 200);
  // A line past the cap is refused even when it would otherwise parse.
  const overlong = `ocsf: sandbox_id=s1 CONFIG:APPROVED [INFO] gateway approved draft chunk c1-aaaaaaaa: ${'x'.repeat(70 * 1024)} [version:v2 hash:${'a'.repeat(64)}]`;
  assert.deepEqual(parseGatewayLog(overlong), { events: [], lines_without_sandbox_id: 0, unparsed_config_lines: [1] });
  // An over-long sandbox id is not taken as an attribution.
  const longId = `ocsf: sandbox_id=${'s'.repeat(200)} CONFIG:APPROVED [INFO] gateway approved draft chunk c1-aaaaaaaa: x [version:v2 hash:${'a'.repeat(64)}]`;
  assert.deepEqual(parseGatewayLog(longId).events, []);
});

test('gateway log: only transition lines without sandbox_id are counted as unattributed', () => {
  const noTransition = '[gateway] [ocsf] CONFIG:MERGED [INFO] gateway bulk-approved 0 draft chunk(s) and skipped 2';
  assert.deepEqual(parseGatewayLog(noTransition), { events: [], lines_without_sandbox_id: 0, unparsed_config_lines: [] });
});
