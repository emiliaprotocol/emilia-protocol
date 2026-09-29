// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { b64u, jcs } from '../src/canonical.ts';
import { check } from '../src/check.ts';
import type { CheckInput, Report } from '../src/check.ts';
import {
  PRINCIPAL, RULE, T0, chain, configLine, hex, logText, newApprover, pins, postCommit, read, receiptFor,
  inventory, start, validate, validateBulk, webauthnReceiptFor,
} from './helpers.ts';

const alice = newApprover();
const mallory = newApprover();
const H1 = hex('policy-v1');
const H2 = hex('policy-v2');
const H3 = hex('policy-v3');
const TOK = hex('token-c1');
const RULE2 = { ...RULE, name: 'allow_example_org_443', endpoints: [{ ...RULE.endpoints[0], host: 'example.org' }] };

/** One human approval of chunk c1 at v2, observed and read back. */
function singleApprovalLog(opts: { readToken?: string; readRule?: object; noRead?: boolean; readError?: boolean } = {}): string {
  const records: Record<string, unknown>[] = [
    start(),
    validate(1000, { chunkId: 'c1', token: TOK }),
    postCommit(1005, { version: 2, hash: H2 }),
  ];
  if (opts.readError) records.push({ kind: 'gateway_read', t: new Date(T0 + 1010).toISOString(), for_seq: 3, workspace: 'default', sandbox: 'sb', error: '14 UNAVAILABLE' });
  else if (!opts.noRead) records.push(read(1010, 3, { chunks: [{ id: 'c1', token: opts.readToken ?? TOK, rule: opts.readRule ?? RULE }], revisions: [[1, H1], [2, H2]] }));
  return logText(records);
}

function run(input: Partial<CheckInput> & { logText: string }): Report {
  return check({ receiptTexts: [], pinsText: pins([{ spkiB64u: alice.spkiB64u }]), chainTexts: [chain([[1, H1], [2, H2]])], inventoryTexts: [inventory()], ...input });
}

const codes = (report: Report) => report.findings.map((f) => f.code).sort();

function invariants(report: Report): void {
  for (const a of report.approvals) {
    if (a.accepted) assert.ok(a.verified, 'accepted implies verified');
    for (const r of a.receipts) if (r.accepted) assert.ok(r.verified);
  }
  assert.equal(report.result === 'pass', report.findings.length === 0 && report.completeness.checked);
}

test('pass: one receipted approval, VERIFIED and ACCEPTED, chain complete', () => {
  const receipt = receiptFor(alice, { chunkId: 'c1', token: TOK });
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(receipt)] });
  invariants(report);
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  const [a] = report.approvals;
  assert.deepEqual([a.chunk_id, a.policy_version, a.pairing, a.verified, a.accepted, a.rule_name], ['c1', 2, 'confirmed', true, true, RULE.name]);
  assert.equal(a.approver?.kid, receipt.payload.approver_kid);
  assert.deepEqual(a.gateway_principal, PRINCIPAL);
  assert.deepEqual(report.chain.map((t) => t.classification), ['initial_policy', 'receipted_human_approval']);
});

test('incomplete: no policy chain supplied', () => {
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))], chainTexts: [] });
  assert.equal(report.result, 'incomplete');
  assert.equal(report.completeness.checked, false);
  assert.match(report.completeness.reason ?? '', /no policy chain/);
});

test('approval without receipt; the gateway principal does not stand in for one', () => {
  const report = run({ logText: singleApprovalLog() });
  invariants(report);
  assert.deepEqual(codes(report), ['approval_without_receipt']);
  assert.equal(report.approvals[0].verified, false);
  assert.equal(report.approvals[0].gateway_principal.subject, 'unauthenticated-local-dev');
  assert.deepEqual(report.chain.map((t) => t.classification), ['initial_policy', 'human_approval_not_accepted']);
});

test('receipt for a different chunk', () => {
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c9', token: TOK }))] });
  assert.deepEqual(codes(report), ['approval_without_receipt', 'receipt_without_committed_approval']);
});

test('receipt for different rule text, rule name, token, sandbox, workspace', () => {
  const cases: [Parameters<typeof receiptFor>[1], string, RegExp][] = [
    [{ chunkId: 'c1', token: TOK, rule: RULE2, ruleName: RULE.name }, 'receipt_rule_mismatch', /rule_digest/],
    [{ chunkId: 'c1', token: TOK, ruleName: 'allow_other' }, 'receipt_rule_mismatch', /rule_name/],
    [{ chunkId: 'c1', token: hex('stale') }, 'receipt_token_mismatch', /review_token/],
    [{ chunkId: 'c1', token: TOK, sandbox: 'other' }, 'receipt_scope_mismatch', /sandbox/],
    [{ chunkId: 'c1', token: TOK, workspace: 'team-b' }, 'receipt_scope_mismatch', /workspace/],
  ];
  for (const [spec, code, reason] of cases) {
    const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(receiptFor(alice, spec))] });
    invariants(report);
    assert.deepEqual(codes(report), [code], code);
    assert.match(report.findings[0].message, reason);
    assert.equal(report.approvals[0].verified, false);
    assert.equal(report.approvals[0].accepted, false);
  }
});

test('bad signature', () => {
  const receipt = receiptFor(alice, { chunkId: 'c1', token: TOK });
  const tampered = { ...receipt, payload: { ...receipt.payload, issued_at: '2026-09-29T06:00:00.000Z' } };
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(tampered)] });
  assert.deepEqual(codes(report), ['receipt_bad_signature']);
});

test('issued after the commit', () => {
  const late = receiptFor(alice, { chunkId: 'c1', token: TOK, issuedAt: new Date(T0 + 1005 + 301_000) });
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(late)] });
  assert.deepEqual(codes(report), ['receipt_issued_after_commit']);
  const withinSkew = receiptFor(alice, { chunkId: 'c1', token: TOK, issuedAt: new Date(T0 + 1005 + 299_000) });
  assert.equal(run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(withinSkew)] }).result, 'pass');
});

test('VERIFIED but not ACCEPTED: unknown key, or key pinned for another workspace', () => {
  const byMallory = receiptFor(mallory, { chunkId: 'c1', token: TOK });
  const unknown = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(byMallory)] });
  invariants(unknown);
  assert.deepEqual(codes(unknown), ['receipt_key_not_accepted']);
  assert.deepEqual([unknown.approvals[0].verified, unknown.approvals[0].accepted], [true, false]);
  assert.match(unknown.findings[0].message, /not pinned by the reader/);
  const elsewhere = run({
    logText: singleApprovalLog(),
    receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))],
    pinsText: pins([{ spkiB64u: alice.spkiB64u, workspaces: ['team-b'] }]),
  });
  assert.deepEqual(codes(elsewhere), ['receipt_key_not_accepted']);
  assert.match(elsewhere.findings[0].message, /not for workspace default/);
});

test('a stale receipt next to a fresh one is not a finding', () => {
  const stale = receiptFor(alice, { chunkId: 'c1', token: hex('older') });
  const fresh = receiptFor(alice, { chunkId: 'c1', token: TOK });
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(stale), JSON.stringify(fresh)] });
  assert.equal(report.result, 'pass');
  assert.deepEqual(report.approvals[0].receipts.map((r) => r.verified), [false, true]);
});

test('rule not observed: no gateway read, or the read failed', () => {
  const receipt = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  for (const opts of [{ noRead: true }, { readError: true }]) {
    const report = run({ logText: singleApprovalLog(opts), receiptTexts: [receipt] });
    invariants(report);
    assert.deepEqual(codes(report), ['commit_not_confirmed_by_gateway_read', 'rule_not_observed']);
    assert.equal(report.approvals[0].pairing, 'unconfirmed');
    assert.equal(report.approvals[0].verified, false);
  }
});

test('stale-token retry: the read-back token picks the validate that committed', () => {
  // The live pattern: approve with a stale token (refused, no post_commit),
  // then again with the refreshed one.
  const fresh = hex('fresh');
  const log = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK }),
    validate(1100, { chunkId: 'c1', token: fresh }),
    postCommit(1105, { version: 2, hash: H2 }),
    read(1110, 4, { chunks: [{ id: 'c1', token: fresh }], revisions: [[1, H1], [2, H2]] }),
  ]);
  const report = run({ logText: log, receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: fresh }))] });
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  assert.equal(report.approvals[0].validate_seq, 3);
  const staleOnly = run({ logText: log, receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))] });
  assert.deepEqual(codes(staleOnly), ['receipt_token_mismatch']);
});

test('ambiguous pairing is a finding, never a guess', () => {
  const log = logText([
    start(),
    validate(1000, { chunkId: 'a1', token: hex('a'), sandbox: 'sa' }),
    validate(1001, { chunkId: 'b1', token: hex('b'), sandbox: 'sb' }),
    postCommit(1005, { version: 2, hash: H2 }),
    read(1010, 4, { sandbox: 'sa', chunks: [{ id: 'a1', token: hex('a') }], revisions: [[2, H2]] }),
    read(1011, 4, { sandbox: 'sb', chunks: [{ id: 'b1', token: hex('b') }], revisions: [[2, H2]] }),
  ]);
  const report = run({ logText: log, chainTexts: [] });
  assert.deepEqual(codes(report), ['ambiguous_pairing']);
  assert.equal(report.approvals.length, 0);
});

test('commit without validate, and a read that contradicts the commit', () => {
  const orphan = logText([start(), postCommit(1005, { version: 2, hash: H2 })]);
  assert.deepEqual(codes(run({ logText: orphan, chainTexts: [] })), ['commit_without_validate']);
  // With the chain, the unattributed v2 is also an unexplained change.
  assert.deepEqual(codes(run({ logText: orphan })), ['commit_without_validate', 'unexplained_policy_change']);
  const contradicted = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK }),
    postCommit(1005, { version: 2, hash: H2 }),
    read(1010, 3, { chunks: [{ id: 'c1', token: TOK, status: 'pending' }], revisions: [[1, H1]] }),
  ]);
  assert.deepEqual(codes(run({ logText: contradicted, chainTexts: [] })), ['commit_inconsistent_with_gateway_read']);
});

test('validates outside the pairing window are not candidates', () => {
  const log = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK }),
    postCommit(40_000, { version: 2, hash: H2 }),
  ]);
  assert.deepEqual(codes(run({ logText: log, chainTexts: [] })), ['commit_without_validate']);
  assert.equal(run({ logText: log, pairingWindowMs: 60_000 }).approvals.length, 1);
});

test('different callers never pair', () => {
  const log = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK, principal: { ...PRINCIPAL, subject: 'someone-else' } }),
    postCommit(1005, { version: 2, hash: H2 }),
  ]);
  assert.deepEqual(codes(run({ logText: log, chainTexts: [] })), ['commit_without_validate']);
});

test('replayed request_id: the second validate is answered from the replay cache', () => {
  const log = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK, requestId: 'r-1' }),
    postCommit(1005, { version: 2, hash: H2 }),
    read(1010, 3, { chunks: [{ id: 'c1', token: TOK }], revisions: [[1, H1], [2, H2]] }),
    validate(1020, { chunkId: 'c1', token: TOK, requestId: 'r-1' }),
    validate(1030, { chunkId: 'c2', token: hex('c2') }),
    postCommit(1035, { version: 3, hash: H3 }),
    read(1040, 7, { chunks: [{ id: 'c1', token: TOK }, { id: 'c2', token: hex('c2') }], revisions: [[1, H1], [2, H2], [3, H3]] }),
  ]);
  const receipts = [receiptFor(alice, { chunkId: 'c1', token: TOK }), receiptFor(alice, { chunkId: 'c2', token: hex('c2') })].map((r) => JSON.stringify(r));
  const report = run({ logText: log, receiptTexts: receipts, chainTexts: [chain([[1, H1], [2, H2], [3, H3]])] });
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  assert.deepEqual(report.approvals.map((a) => [a.chunk_id, a.validate_seq]), [['c1', 2], ['c2', 6]]);
});

test('a double-submitted approval of an already approved chunk does not make the next commit ambiguous', () => {
  const tok2 = hex('c2');
  const log = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK }),
    postCommit(1005, { version: 2, hash: H2 }),
    read(1010, 3, { chunks: [{ id: 'c1', token: TOK }], revisions: [[1, H1], [2, H2]] }),
    validate(1020, { chunkId: 'c1', token: TOK }), // refused by the gateway: already approved
    validate(1030, { chunkId: 'c2', token: tok2 }),
    postCommit(1035, { version: 3, hash: H3 }),
    read(1040, 7, { chunks: [{ id: 'c1', token: TOK }, { id: 'c2', token: tok2 }], revisions: [[1, H1], [2, H2], [3, H3]] }),
  ]);
  const receipts = [receiptFor(alice, { chunkId: 'c1', token: TOK }), receiptFor(alice, { chunkId: 'c2', token: tok2 })].map((r) => JSON.stringify(r));
  const report = run({ logText: log, receiptTexts: receipts, chainTexts: [chain([[1, H1], [2, H2], [3, H3]])] });
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  assert.deepEqual(report.approvals.map((a) => [a.chunk_id, a.validate_seq]), [['c1', 2], ['c2', 6]]);
});

test('bulk approval: every approved chunk needs its own receipt; skipped chunks do not', () => {
  const tokB = hex('c2');
  const log = logText([
    start(),
    validateBulk(1000, { approvals: [{ chunkId: 'c1', reviewToken: TOK }, { chunkId: 'c2', reviewToken: tokB }] }),
    postCommit(1005, { method: 'ApproveAllDraftChunks', version: 2, hash: H2, approved: 1, skipped: 1 }),
    read(1010, 3, { chunks: [{ id: 'c1', token: TOK }, { id: 'c2', token: tokB, status: 'pending', rule: RULE2 }], revisions: [[1, H1], [2, H2]] }),
  ]);
  const report = run({ logText: log, receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))] });
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  assert.deepEqual(report.approvals.map((a) => a.chunk_id), ['c1']);
  const both = logText([
    start(),
    validateBulk(1000, { approvals: [{ chunkId: 'c1', reviewToken: TOK }, { chunkId: 'c2', reviewToken: tokB }] }),
    postCommit(1005, { method: 'ApproveAllDraftChunks', version: 2, hash: H2, approved: 2 }),
    read(1010, 3, { chunks: [{ id: 'c1', token: TOK }, { id: 'c2', token: tokB, rule: RULE2 }], revisions: [[1, H1], [2, H2]] }),
  ]);
  const one = run({ logText: both, receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))] });
  assert.deepEqual(codes(one), ['approval_without_receipt']);
  assert.equal(one.findings[0].chunk_id, 'c2');
});

test('bulk approval that approved nothing, and one that named no chunks', () => {
  const nothing = logText([
    start(),
    validateBulk(1000, { approvals: [{ chunkId: 'c1', reviewToken: TOK }] }),
    postCommit(1005, { method: 'ApproveAllDraftChunks', version: 0, hash: '', skipped: 1 }),
  ]);
  const r1 = run({ logText: nothing, chainTexts: [chain([[1, H1]])] });
  assert.deepEqual([r1.findings, r1.approvals.length], [[], 0]);
  const unnamed = logText([
    start(),
    validateBulk(1000, { approvals: [] }),
    postCommit(1005, { method: 'ApproveAllDraftChunks', version: 2, hash: H2, approved: 1 }),
    read(1010, 3, { chunks: [{ id: 'legacy', token: '' }], revisions: [[1, H1], [2, H2]] }),
  ]);
  assert.ok(codes(run({ logText: unnamed })).includes('commit_inconsistent_with_gateway_read'));
});

test('observation authentication', () => {
  const failed = logText([
    start(),
    validate(1000, { chunkId: 'c1', token: TOK, auth: { mode: 'failed', reason: 'JWT signature does not verify' } }),
    postCommit(1005, { version: 2, hash: H2 }),
  ]);
  assert.deepEqual(codes(run({ logText: failed, chainTexts: [] })), ['commit_without_validate', 'observation_auth_failed']);
  const unkeyed = logText([start(null), postCommit(1005, { version: 2, hash: H2 })]);
  assert.ok(codes(run({ logText: unkeyed })).includes('observer_without_gateway_key'));
});

test('completeness over the policy version chain', () => {
  const sbId = 'id-sb';
  const H4 = hex('v4');
  const H5 = hex('v5');
  const H6 = hex('v6');
  const H7 = hex('v7');
  const gatewayLog = [
    configLine(sbId, 'APPROVED', 'gateway approved draft chunk c1: add-rule r', `version:v2 hash:${H2}`),
    configLine(sbId, 'APPROVED', 'auto-approved: no new prover findings (source=mechanistic) \u2014 chunk c3: add-rule r', `auto:true source:mechanistic prover_delta:empty resolved_from:sandbox version:v3 hash:${H3}`),
    configLine(sbId, 'APPROVED', 'gateway approved draft chunk c4: add-rule r', `version:v4 hash:${H4}`),
    configLine(sbId, 'MERGED', 'gateway merged incremental policy op: add-endpoint x', `version:v5 hash:${H5}`),
    configLine(sbId, 'REMOVED', 'gateway reverted approved draft chunk c1: remove-binary r /usr/bin/bash', `version:v6 hash:${H6}`),
    configLine('other-sandbox', 'APPROVED', 'auto-approved chunk c9: add-rule r', `auto:true version:v8 hash:${hex('v8')}`),
  ].join('\n');
  const revisions: [number, string][] = [[1, H1], [2, H2], [3, H3], [4, H4], [5, H5], [6, H6], [7, H6], [8, hex('v8')], [9, 'bad'], [10, H7]];
  const report = run({
    logText: singleApprovalLog(),
    receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))],
    chainTexts: [chain(revisions)],
    gatewayLogText: gatewayLog,
  });
  invariants(report);
  assert.deepEqual(report.chain.map((t) => `v${t.version}:${t.classification}`), [
    'v1:initial_policy', 'v2:receipted_human_approval', 'v3:auto_approval', 'v4:approval_not_observed',
    'v5:policy_change_without_approval', 'v6:removal', 'v7:revision_without_policy_change',
    'v8:unexplained_policy_change', 'v9:invalid_revision', 'v10:unexplained_policy_change',
  ]);
  assert.deepEqual(codes(report), ['approval_not_observed', 'chain_revision_invalid', 'policy_change_without_approval', 'unexplained_policy_change', 'unexplained_policy_change']);
  assert.equal(report.summary.auto_approvals, 1);
});

test('chain gaps and commits the chain does not contain', () => {
  const receipt = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  const gap = run({ logText: singleApprovalLog(), receiptTexts: [receipt], chainTexts: [chain([[1, H1], [2, H2], [4, hex('v4')]])] });
  assert.ok(codes(gap).includes('chain_gap'));
  const missing = run({ logText: singleApprovalLog(), receiptTexts: [receipt], chainTexts: [chain([[1, H1], [2, hex('different')]])] });
  assert.ok(codes(missing).includes('commit_not_in_chain'));
  const late = run({ logText: singleApprovalLog(), receiptTexts: [receipt], chainTexts: [chain([[2, H2]])] });
  assert.ok(codes(late).includes('chain_gap'));
});

test('malformed log lines, a broken chain and a torn line are findings, not crashes', () => {
  const good = singleApprovalLog();
  const lines = good.trimEnd().split('\n');
  const edited = [...lines];
  edited[1] = edited[1].replace('"c1"', '"c2"');
  const report = run({ logText: `${edited.join('\n')}\n`, receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))] });
  assert.ok(codes(report).includes('log_chain_broken'));
  const junk = run({ logText: `${lines[0]}\nnot json\n{"a":1,"a":2}\n[1,2]\n{"seq":"x"}\n${lines[1]}\n${lines[2].slice(0, 40)}` });
  assert.ok(codes(junk).includes('log_malformed_line'));
  assert.ok(codes(junk).includes('log_chain_broken'));
  assert.equal(run({ logText: '', chainTexts: [] }).result, 'incomplete');
});

test('malformed observations, pins, chains and receipts are findings with reasons', () => {
  const badPayload = logText([
    start(),
    { ...validate(1000, { chunkId: 'c1', token: TOK }), payload: { chunkId: 7, sandbox: 'sb' } },
    { ...postCommit(1005, { version: 2, hash: H2 }), payload: { policyVersion: 2.5, policyHash: H2 } },
    { ...postCommit(1006, { version: 2, hash: H2 }), payload: { policyVersion: 2, policyHash: 'NOTHEX' } },
    { ...postCommit(1007, { version: 2, hash: H2 }), payload: undefined, payload_error: '$.x: Value has no kind' },
    { kind: 'gateway_read', for_seq: 'x' },
  ]);
  const r1 = run({ logText: badPayload });
  assert.equal(codes(r1).filter((c) => c === 'malformed_observation').length, 5);
  const badInputs = run({
    logText: singleApprovalLog(),
    pinsText: '{"format":"emilia.openshell.approver-pins.v1","approvers":[{"public_key_spki":"AAAA","workspaces":["default"]},{"public_key_spki":1},{"x":1}]}',
    chainTexts: ['{"format":"x"}', 'not json', chain([[1, H1], [1, H1]])],
    receiptTexts: ['{"payload":{},"proof":{}}\nnot json'],
  });
  const c = codes(badInputs);
  assert.equal(c.filter((x) => x === 'malformed_pins').length, 3);
  assert.equal(c.filter((x) => x === 'malformed_chain').length, 3);
  assert.equal(c.filter((x) => x === 'malformed_receipt').length, 2);
  assert.ok(badInputs.findings.every((f) => f.message.length > 0));
  assert.deepEqual(codes(run({ logText: singleApprovalLog(), pinsText: '{"approvers":[],"approvers":[]}' })).filter((x) => x === 'malformed_pins'), ['malformed_pins']);
});

test('hostile input fuzz: check() never throws and always returns a report', () => {
  let seed = 0x5eed;
  const rand = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const receipt = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  const gatewayLog = configLine('id-sb', 'APPROVED', 'gateway approved draft chunk c1-aaaaaaaa: add-rule r', `version:v2 hash:${H2}`);
  const base = [singleApprovalLog(), receipt, pins([{ spkiB64u: alice.spkiB64u }]), chain([[1, H1], [2, H2]]), inventory(), gatewayLog];
  const junk = ['', '\u0000', '{', '[]', 'null', '1e999', '"\ud800"', '{"__proto__":{"x":1}}', '{"seq":1,"prev":"0","t":"x","kind":"evaluation"}', '\n\n\n'];
  for (let i = 0; i < 400; i += 1) {
    const inputs = base.map((text) => {
      const chars = [...text];
      const edits = rand(4);
      for (let e = 0; e < edits; e += 1) {
        const at = rand(chars.length + 1);
        const op = rand(3);
        if (op === 0) chars.splice(at, 1);
        else if (op === 1) chars.splice(at, 0, junk[rand(junk.length)]);
        else chars.splice(at, 5, String.fromCharCode(rand(0x3000)));
      }
      return chars.join('');
    });
    let report: Report | undefined;
    assert.doesNotThrow(() => {
      report = check({ logText: inputs[0], receiptTexts: [inputs[1]], pinsText: inputs[2], chainTexts: [inputs[3]], inventoryTexts: [inputs[4]], gatewayLogText: inputs[5], trustGatewayLog: i % 2 === 0 });
    }, `iteration ${i}`);
    assert.ok(report && ['pass', 'fail', 'incomplete'].includes(report.result));
    invariants(report as Report);
  }
  assert.equal(({} as Record<string, unknown>).x, undefined);
});

test('a signature by another key over the same payload is refused', () => {
  const receipt = receiptFor(alice, { chunkId: 'c1', token: TOK });
  const forged = crypto.sign('sha256', Buffer.from(jcs(receipt.payload)), { key: mallory.privateKey, dsaEncoding: 'ieee-p1363' });
  const report = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify({ payload: receipt.payload, proof: { ...receipt.proof, signature: b64u(forged) } })] });
  assert.deepEqual(codes(report), ['receipt_bad_signature']);
});

const RP = { rp_id: 'approve.example.com', origins: ['https://approve.example.com'] };

test('WebAuthn proof: ACCEPTED only under a pin that names the relying party', () => {
  const base = receiptFor(alice, { chunkId: 'c1', token: TOK });
  // An assertion made on another origin and RP, in a cross-origin frame.
  const foreign = webauthnReceiptFor(alice, base, { origin: 'https://evil.example', rpId: 'evil.example', crossOrigin: true });
  const noRp = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(foreign)] });
  invariants(noRp);
  assert.deepEqual(codes(noRp), ['receipt_key_not_accepted']);
  assert.deepEqual([noRp.approvals[0].verified, noRp.approvals[0].accepted], [true, false]);
  assert.match(noRp.findings[0].message, /webauthn proof but the pin names no relying party/);
  // The same foreign assertion under a pin that names the relying party.
  const rpPins = pins([{ spkiB64u: alice.spkiB64u, webauthn: RP }]);
  const scoped = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(foreign)], pinsText: rpPins });
  assert.deepEqual(codes(scoped), ['receipt_key_not_accepted']);
  assert.match(scoped.findings[0].message, /relying-party scope/);
  // A same-origin assertion under that pin passes.
  const good = webauthnReceiptFor(alice, base);
  const ok = run({ logText: singleApprovalLog(), receiptTexts: [JSON.stringify(good)], pinsText: rpPins });
  assert.equal(ok.result, 'pass', JSON.stringify(ok.findings));
  assert.equal(ok.approvals[0].approver?.format, 'webauthn');
});

test('pin formats: a passkey pin does not accept an es256 proof unless it says so', () => {
  const es256 = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  const passkeyOnly = run({ logText: singleApprovalLog(), receiptTexts: [es256], pinsText: pins([{ spkiB64u: alice.spkiB64u, webauthn: RP }]) });
  assert.deepEqual(codes(passkeyOnly), ['receipt_key_not_accepted']);
  assert.match(passkeyOnly.findings[0].message, /es256 proof, but the pin allows only webauthn/);
  const both = run({ logText: singleApprovalLog(), receiptTexts: [es256], pinsText: pins([{ spkiB64u: alice.spkiB64u, webauthn: RP, formats: ['es256', 'webauthn'] }]) });
  assert.equal(both.result, 'pass', JSON.stringify(both.findings));
  for (const bad of [{ formats: ['webauthn'] }, { formats: [] }, { formats: ['rs256'] }, { formats: ['es256', 'es256'] }]) {
    const report = run({ logText: singleApprovalLog(), receiptTexts: [es256], pinsText: pins([{ spkiB64u: alice.spkiB64u, ...bad }]) });
    assert.ok(codes(report).includes('malformed_pins'), JSON.stringify(bad));
  }
});

test('auto-approval and removal rest on gateway log text: pass needs trustGatewayLog', () => {
  const H4 = hex('v4');
  const gatewayLog = [
    configLine('id-sb', 'APPROVED', 'gateway approved draft chunk c1-aaaaaaaa: add-rule r', `version:v2 hash:${H2}`),
    configLine('id-sb', 'APPROVED', 'auto-approved: no new prover findings (source=mechanistic) \u2014 chunk c3-cccccccc: add-rule r', `auto:true source:mechanistic version:v3 hash:${H3}`),
    configLine('id-sb', 'REMOVED', 'gateway reverted approved draft chunk c3-cccccccc: remove-rule r', `version:v4 hash:${H4}`),
  ].join('\n');
  const input = {
    logText: singleApprovalLog(),
    receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))],
    chainTexts: [chain([[1, H1], [2, H2], [3, H3], [4, H4]])],
    gatewayLogText: gatewayLog,
  };
  const untrusted = run(input);
  invariants(untrusted);
  assert.deepEqual(untrusted.findings, []);
  assert.equal(untrusted.result, 'incomplete');
  assert.deepEqual(untrusted.chain.map((t) => [t.version, t.classification, t.basis ?? null]), [
    [1, 'initial_policy', null], [2, 'receipted_human_approval', null], [3, 'auto_approval', 'gateway_log'], [4, 'removal', 'gateway_log'],
  ]);
  assert.equal(untrusted.completeness.gateway_log_trusted, false);
  assert.match(untrusted.completeness.reason ?? '', /gateway log/);
  const trusted = run({ ...input, trustGatewayLog: true });
  invariants(trusted);
  assert.equal(trusted.result, 'pass', JSON.stringify(trusted.findings));
  assert.equal(trusted.completeness.gateway_log_trusted, true);
  assert.ok(trusted.notes.some((n) => /unauthenticated/.test(n)));
});

test('a gateway-logged approval in a sandbox with no chain, or past the end of a chain, is not a pass', () => {
  const receipt = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  const inSb = configLine('id-sb', 'APPROVED', 'gateway approved draft chunk c1-aaaaaaaa: add-rule r', `version:v2 hash:${H2}`);
  // An approval made while the observer was down, in a sandbox with no observed approvals.
  const otherSandbox = run({
    logText: singleApprovalLog(), receiptTexts: [receipt],
    gatewayLogText: [inSb, configLine('id-sb2', 'APPROVED', 'gateway approved draft chunk c2-bbbbbbbb: add-rule r', `version:v2 hash:${H3}`)].join('\n'),
  });
  invariants(otherSandbox);
  assert.equal(otherSandbox.result, 'fail');
  assert.deepEqual(codes(otherSandbox), ['gateway_event_without_chain']);
  assert.ok(otherSandbox.completeness.unchecked_sandboxes.includes('sandbox_id=id-sb2'));
  // The same sandbox, one version past the chain the reader supplied.
  const pastEnd = run({
    logText: singleApprovalLog(), receiptTexts: [receipt],
    gatewayLogText: [inSb, configLine('id-sb', 'APPROVED', 'gateway approved draft chunk c3-cccccccc: add-rule r', `version:v3 hash:${H3}`)].join('\n'),
  });
  invariants(pastEnd);
  assert.deepEqual(codes(pastEnd), ['chain_stale']);
  // Inside the chain's range with a hash the chain does not have.
  const mismatch = run({
    logText: singleApprovalLog(), receiptTexts: [receipt],
    gatewayLogText: configLine('id-sb', 'APPROVED', 'gateway approved draft chunk c1-aaaaaaaa: add-rule r', `version:v2 hash:${H3}`),
  });
  assert.deepEqual(codes(mismatch), ['gateway_event_not_in_chain']);
  // An auto-approval in a sandbox with no chain: not a finding, but that sandbox was not checked.
  const autoElsewhere = run({
    logText: singleApprovalLog(), receiptTexts: [receipt], trustGatewayLog: true,
    gatewayLogText: configLine('id-sb3', 'APPROVED', 'auto-approved chunk c9-99999999: add-rule r', `auto:true version:v2 hash:${H3}`),
  });
  invariants(autoElsewhere);
  assert.deepEqual(autoElsewhere.findings, []);
  assert.equal(autoElsewhere.result, 'incomplete');
  assert.deepEqual(autoElsewhere.completeness.unchecked_sandboxes, ['sandbox_id=id-sb3']);
});

test('a transition line without sandbox_id is a finding, not silently dropped', () => {
  const report = run({
    logText: singleApprovalLog(),
    receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }))],
    chainTexts: [chain([[1, H1], [2, H2], [3, H3]])],
    gatewayLogText: `[gateway] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] auto-approved chunk c3-cccccccc: add-rule r [auto:true version:v3 hash:${H3}]`,
  });
  invariants(report);
  assert.deepEqual(codes(report), ['gateway_log_unattributed', 'unexplained_policy_change']);
  assert.match(report.findings.find((f) => f.code === 'gateway_log_unattributed')?.message ?? '', /1 CONFIG line/);
});

test('an unlogged approval in a sandbox neither log mentions is caught through the inventory', () => {
  // The observer was down and the gateway log line is gone: only the
  // workspace inventory names sb2, whose v2 nobody approved with a receipt.
  const receipt = JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOK }));
  const both = inventory([['sb', 'id-sb'], ['sb2', 'id-sb2']]);
  const noChain = run({ logText: singleApprovalLog(), receiptTexts: [receipt], inventoryTexts: [both] });
  invariants(noChain);
  assert.equal(noChain.result, 'incomplete');
  assert.deepEqual(noChain.completeness.unchecked_sandboxes, ['default/sb2']);
  const withChain = run({
    logText: singleApprovalLog(), receiptTexts: [receipt], inventoryTexts: [both],
    chainTexts: [chain([[1, H1], [2, H2]]), chain([[1, H1], [2, H3]], { sandbox: 'sb2', sandboxId: 'id-sb2' })],
  });
  invariants(withChain);
  assert.deepEqual(codes(withChain), ['unexplained_policy_change']);
  assert.equal(withChain.findings[0].sandbox, 'sb2');
  // No inventory: the check cannot say the logs mention every sandbox.
  const noInventory = run({ logText: singleApprovalLog(), receiptTexts: [receipt], inventoryTexts: [] });
  invariants(noInventory);
  assert.equal(noInventory.result, 'incomplete');
  assert.match(noInventory.completeness.reason ?? '', /no sandbox inventory was supplied for workspace default/);
  // A workspace with no sandboxes and nothing logged passes on its inventory.
  assert.equal(run({ logText: logText([start()]), chainTexts: [], inventoryTexts: [inventory([])] }).result, 'pass');
  const bad = run({ logText: singleApprovalLog(), receiptTexts: [receipt], inventoryTexts: ['{"format":"x"}', 'nope', inventory([['a', 'x'], ['b', 'x']])] });
  assert.equal(codes(bad).filter((c) => c === 'malformed_inventory').length, 3);
});
