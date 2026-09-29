// SPDX-License-Identifier: Apache-2.0
// Offline check: observer log + approver receipts + the reader's pinned
// approver keys (+ optional policy version chains and gateway log) in, one
// report out. No network. Never throws on bad input: every malformed piece
// becomes a finding with a reason, and the rest is still checked.
//
// For every committed approval the report carries two separate fields:
//   verified  the receipt's ES256 proof checks out, and its workspace,
//             sandbox, chunk_id, review_token, rule_name and rule digest are
//             the ones the gateway committed and the observer read back, and
//             it was issued no later than the commit (plus skew).
//   accepted  verified, AND the signing key is pinned by the reader for that
//             workspace and for the proof's format. A WebAuthn proof is
//             accepted only under a pin that names the relying party, and the
//             assertion must be scoped to it (rpIdHash, origin, not
//             crossOrigin).
// The gateway's caller principal is reported as context only. It is
// unsigned and never satisfies either field.
//
// The gateway log is unauthenticated text that whoever runs the gateway can
// edit. Chain versions it explains are tagged basis "gateway_log"; the ones
// it clears (auto_approval, removal) count toward `pass` only when the caller
// sets trustGatewayLog.

import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { parseLog } from './log.ts';
import type { LogRecord } from './log.ts';
import { parseGatewayLog } from './gateway-log.ts';
import type { GatewayPolicyEvent } from './gateway-log.ts';
import { p256PublicKey, parseReceiptsText, verifyReceiptSignature } from './receipt.ts';
import type { Receipt, SignatureCheck, WebAuthnPins } from './receipt.ts';

export const REPORT_FORMAT = 'emilia.openshell.approver-receipt-report.v1';
export const PINS_FORMAT = 'emilia.openshell.approver-pins.v1';
export const CHAIN_FORMAT = 'emilia.openshell.policy-chain.v1';
export const INVENTORY_FORMAT = 'emilia.openshell.sandbox-inventory.v1';

const OBSERVED = new Set(['ApproveDraftChunk', 'ApproveAllDraftChunks']);

export interface CheckInput {
  logText: string;
  receiptTexts: string[];
  pinsText: string;
  chainTexts?: string[];
  /**
   * Sandbox inventories (`chain --all`): every sandbox a workspace held when
   * the reader listed it. `pass` needs one for every workspace checked, and a
   * chain for every sandbox it lists.
   */
  inventoryTexts?: string[];
  gatewayLogText?: string;
  /**
   * Count auto_approval and removal versions, which rest only on gateway log
   * text, toward `pass`. Without it they leave the result `incomplete`.
   */
  trustGatewayLog?: boolean;
  pairingWindowMs?: number;
  issuedAfterCommitSkewSeconds?: number;
}

export interface Finding {
  code: string;
  message: string;
  commit_seq?: number;
  chunk_id?: string;
  receipt_index?: number;
  sandbox?: string;
  version?: number;
  line?: number;
}

export interface ReceiptVerdict {
  receipt_index: number;
  kid: string | null;
  label: string | null;
  format: string | null;
  verified: boolean;
  accepted: boolean;
  reasons: string[];
}

export interface ApprovalResult {
  commit_seq: number;
  validate_seq: number;
  method: string;
  workspace: string;
  sandbox: string;
  sandbox_id: string | null;
  chunk_id: string;
  review_token: string;
  policy_version: number;
  policy_hash: string;
  committed_at: string;
  rule_name: string | null;
  rule_digest: string | null;
  pairing: 'confirmed' | 'unconfirmed';
  verified: boolean;
  accepted: boolean;
  approver: { kid: string; label: string | null; format: string } | null;
  receipts: ReceiptVerdict[];
  gateway_principal: Record<string, string>;
}

export interface TransitionResult {
  workspace: string;
  sandbox: string;
  sandbox_id: string;
  version: number;
  policy_hash: string;
  classification:
    | 'initial_policy'
    | 'receipted_human_approval'
    | 'human_approval_not_accepted'
    | 'auto_approval'
    | 'removal'
    | 'revision_without_policy_change'
    | 'approval_not_observed'
    | 'policy_change_without_approval'
    | 'unexplained_policy_change'
    | 'invalid_revision';
  commit_seq?: number;
  gateway_log_line?: number;
  /** Set when the classification comes from a gateway log line (unauthenticated text). */
  basis?: 'gateway_log';
}

export interface Report {
  format: typeof REPORT_FORMAT;
  result: 'pass' | 'fail' | 'incomplete';
  summary: {
    committed_approvals: number;
    verified: number;
    accepted: number;
    auto_approvals: number;
    receipts_read: number;
    findings: number;
    policy_transitions_checked: number;
  };
  approvals: ApprovalResult[];
  chain: TransitionResult[];
  completeness: {
    checked: boolean;
    checked_sandboxes: string[];
    unchecked_sandboxes: string[];
    /** The newest version each supplied chain holds, and when it was read. */
    chain_heads: { sandbox: string; sandbox_id: string; last_version: number; read_at: string | null }[];
    /** Workspaces for which a sandbox inventory was supplied. */
    inventoried_workspaces: string[];
    gateway_log_trusted: boolean;
    reason?: string;
  };
  findings: Finding[];
  notes: string[];
}

type Obj = Record<string, unknown>;

interface Validate {
  seq: number;
  at: number;
  method: string;
  principal: Record<string, string>;
  principalKey: string;
  workspace: string;
  sandbox: string;
  approvals: { chunk_id: string; review_token: string }[];
  request_id: string;
}

interface PostCommit {
  seq: number;
  at: number;
  t: string;
  method: string;
  principal: Record<string, string>;
  principalKey: string;
  policy_version: number;
  policy_hash: string;
  chunks_approved: number;
  chunks_skipped: number;
}

interface ReadChunk {
  chunk_id: string;
  status: string;
  rule_name: string;
  review_token: string;
  rule_digest: string | null;
  decided_time: string | null;
}

interface GatewayRead {
  seq: number;
  for_seq: number;
  workspace: string;
  sandbox: string;
  sandbox_id: string | null;
  chunks: ReadChunk[];
  revisions: { version: number; policy_hash: string }[];
  error: string | null;
}

type ProofFormat = 'es256' | 'webauthn';

interface Pin {
  kid: string;
  label: string | null;
  workspaces: Set<string>;
  webauthn: WebAuthnPins | null;
  /** Proof formats this key is accepted in. Default: webauthn when the pin names a relying party, else es256. */
  formats: Set<ProofFormat>;
}

interface Chain {
  workspace: string;
  sandbox: string;
  sandbox_id: string;
  read_at: string | null;
  revisions: { version: number; policy_hash: string; status: string }[];
}

function isObj(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optString(value: unknown, what: string): string {
  if (value === undefined) return '';
  if (typeof value !== 'string') throw new Error(`${what} is not a string`);
  return value;
}

function optCount(value: unknown, what: string): number {
  if (value === undefined) return 0;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error(`${what} is not a non-negative integer`);
  return value;
}

function principalOf(value: unknown): { principal: Record<string, string>; key: string } {
  const principal: Record<string, string> = {};
  if (isObj(value)) {
    for (const key of Object.keys(value).sort()) {
      if (typeof value[key] === 'string') principal[key] = value[key] as string;
    }
  }
  return { principal, key: JSON.stringify(Object.entries(principal)) };
}

function strictParse(text: string, what: string): { ok: true; value: unknown } | { ok: false; reason: string } {
  if (typeof text !== 'string') return { ok: false, reason: `${what} is not text` };
  const gate = strictJsonGate(text);
  if (!gate.ok) return { ok: false, reason: `${what} is not strict JSON: ${gate.reason}` };
  return { ok: true, value: JSON.parse(text) };
}

function parsePins(text: string, findings: Finding[]): Map<string, Pin> {
  const pins = new Map<string, Pin>();
  const parsed = strictParse(text, 'pins');
  if (!parsed.ok) {
    findings.push({ code: 'malformed_pins', message: parsed.reason });
    return pins;
  }
  const doc = parsed.value;
  if (!isObj(doc) || doc.format !== PINS_FORMAT || !Array.isArray(doc.approvers)) {
    findings.push({ code: 'malformed_pins', message: `pins must be {"format":"${PINS_FORMAT}","approvers":[...]}` });
    return pins;
  }
  doc.approvers.forEach((entry: unknown, index: number) => {
    try {
      if (!isObj(entry)) throw new Error('entry is not an object');
      const allowed = new Set(['label', 'public_key_spki', 'workspaces', 'webauthn', 'formats']);
      const extra = Object.keys(entry).filter((k) => !allowed.has(k));
      if (extra.length > 0) throw new Error(`unknown member(s) ${extra.join(', ')}`);
      const key = p256PublicKey(entry.public_key_spki);
      if (!key.ok) throw new Error(key.reason);
      if (!Array.isArray(entry.workspaces) || entry.workspaces.length === 0 || !entry.workspaces.every((w) => typeof w === 'string' && w.length > 0)) {
        throw new Error('workspaces must be a non-empty list of workspace names');
      }
      if (entry.label !== undefined && typeof entry.label !== 'string') throw new Error('label is not a string');
      let webauthn: WebAuthnPins | null = null;
      if (entry.webauthn !== undefined) {
        const w = entry.webauthn;
        if (!isObj(w) || typeof w.rp_id !== 'string' || w.rp_id.length === 0 || !Array.isArray(w.origins) || w.origins.length === 0
            || !w.origins.every((o) => typeof o === 'string' && o.length > 0)) {
          throw new Error('webauthn must be {"rp_id": string, "origins": [string, ...]}');
        }
        webauthn = { rp_id: w.rp_id, origins: w.origins as string[] };
      }
      let formats: Set<ProofFormat>;
      if (entry.formats === undefined) {
        formats = new Set([webauthn ? 'webauthn' : 'es256']);
      } else {
        const list = entry.formats;
        if (!Array.isArray(list) || list.length === 0 || !list.every((f) => f === 'es256' || f === 'webauthn') || new Set(list).size !== list.length) {
          throw new Error('formats must be a non-empty list of distinct "es256" and "webauthn"');
        }
        formats = new Set(list as ProofFormat[]);
        if (formats.has('webauthn') && !webauthn) throw new Error('formats includes webauthn, so the pin must name the relying party (webauthn: {rp_id, origins})');
      }
      if (pins.has(key.value.kid)) throw new Error('the same key is pinned twice');
      pins.set(key.value.kid, { kid: key.value.kid, label: (entry.label as string | undefined) ?? null, workspaces: new Set(entry.workspaces as string[]), webauthn, formats });
    } catch (error) {
      findings.push({ code: 'malformed_pins', message: `approvers[${index}]: ${error instanceof Error ? error.message : String(error)}` });
    }
  });
  return pins;
}

function parseChain(text: string, index: number, findings: Finding[]): Chain | null {
  const parsed = strictParse(text, `chain[${index}]`);
  if (!parsed.ok) {
    findings.push({ code: 'malformed_chain', message: parsed.reason });
    return null;
  }
  const doc = parsed.value;
  try {
    if (!isObj(doc) || doc.format !== CHAIN_FORMAT) throw new Error(`format is not ${CHAIN_FORMAT}`);
    for (const k of ['workspace', 'sandbox', 'sandbox_id'] as const) {
      if (typeof doc[k] !== 'string' || (doc[k] as string).length === 0) throw new Error(`${k} is not a non-empty string`);
    }
    if (!Array.isArray(doc.revisions) || doc.revisions.length === 0) throw new Error('revisions is not a non-empty list');
    const seen = new Set<number>();
    const revisions = doc.revisions.map((r: unknown) => {
      if (!isObj(r) || typeof r.version !== 'number' || !Number.isSafeInteger(r.version) || r.version < 1
          || typeof r.policy_hash !== 'string' || typeof r.status !== 'string') {
        throw new Error('each revision needs integer version >= 1, string policy_hash and string status');
      }
      if (seen.has(r.version)) throw new Error(`version ${r.version} appears twice`);
      seen.add(r.version);
      return { version: r.version, policy_hash: r.policy_hash, status: r.status };
    }).sort((a, b) => a.version - b.version);
    return {
      workspace: doc.workspace as string, sandbox: doc.sandbox as string, sandbox_id: doc.sandbox_id as string,
      read_at: typeof doc.read_at === 'string' ? doc.read_at : null, revisions,
    };
  } catch (error) {
    findings.push({ code: 'malformed_chain', message: `chain[${index}]: ${error instanceof Error ? error.message : String(error)}` });
    return null;
  }
}

interface Inventory {
  workspace: string;
  sandboxes: { sandbox: string; sandbox_id: string }[];
}

function parseInventory(text: string, index: number, findings: Finding[]): Inventory | null {
  const parsed = strictParse(text, `inventory[${index}]`);
  if (!parsed.ok) {
    findings.push({ code: 'malformed_inventory', message: parsed.reason });
    return null;
  }
  const doc = parsed.value;
  try {
    if (!isObj(doc) || doc.format !== INVENTORY_FORMAT) throw new Error(`format is not ${INVENTORY_FORMAT}`);
    if (typeof doc.workspace !== 'string' || doc.workspace.length === 0) throw new Error('workspace is not a non-empty string');
    if (!Array.isArray(doc.sandboxes)) throw new Error('sandboxes is not a list');
    const seen = new Set<string>();
    const sandboxes = doc.sandboxes.map((entry: unknown) => {
      if (!isObj(entry) || typeof entry.sandbox !== 'string' || entry.sandbox.length === 0 || typeof entry.sandbox_id !== 'string' || entry.sandbox_id.length === 0) {
        throw new Error('each sandbox needs a non-empty sandbox and sandbox_id');
      }
      if (seen.has(entry.sandbox_id)) throw new Error(`sandbox_id ${entry.sandbox_id} appears twice`);
      seen.add(entry.sandbox_id);
      return { sandbox: entry.sandbox, sandbox_id: entry.sandbox_id };
    });
    return { workspace: doc.workspace, sandboxes };
  } catch (error) {
    findings.push({ code: 'malformed_inventory', message: `inventory[${index}]: ${error instanceof Error ? error.message : String(error)}` });
    return null;
  }
}

function parseValidate(record: LogRecord): Validate {
  const payload = record.payload;
  if (!isObj(payload)) throw new Error('validate payload is missing');
  const sandbox = optString(payload.sandbox, 'sandbox');
  const scope = payload.workspaceScope === undefined ? {} : payload.workspaceScope;
  if (!isObj(scope)) throw new Error('workspaceScope is not an object');
  const workspace = optString(scope.workspace, 'workspaceScope.workspace');
  const method = record.method as string;
  let approvals: { chunk_id: string; review_token: string }[];
  if (method === 'ApproveDraftChunk') {
    const chunkId = optString(payload.chunkId, 'chunkId');
    if (!chunkId) throw new Error('chunkId is empty');
    approvals = [{ chunk_id: chunkId, review_token: optString(payload.reviewToken, 'reviewToken') }];
  } else {
    const list = payload.approvals === undefined ? [] : payload.approvals;
    if (!Array.isArray(list)) throw new Error('approvals is not a list');
    approvals = list.map((a: unknown, i: number) => {
      if (!isObj(a)) throw new Error(`approvals[${i}] is not an object`);
      return { chunk_id: optString(a.chunkId, `approvals[${i}].chunkId`), review_token: optString(a.reviewToken, `approvals[${i}].reviewToken`) };
    });
  }
  const { principal, key } = principalOf(record.principal);
  return {
    seq: record.seq, at: Date.parse(record.t), method, principal, principalKey: key, workspace, sandbox, approvals,
    request_id: optString(payload.requestId, 'requestId'),
  };
}

function parsePostCommit(record: LogRecord): PostCommit {
  const payload = record.payload;
  if (!isObj(payload)) throw new Error('post_commit payload is missing');
  const policyHash = optString(payload.policyHash, 'policyHash');
  if (policyHash !== '' && !/^[0-9a-f]{64}$/.test(policyHash)) throw new Error('policyHash is not 64 lowercase hex');
  const { principal, key } = principalOf(record.principal);
  return {
    seq: record.seq, at: Date.parse(record.t), t: record.t, method: record.method as string, principal, principalKey: key,
    policy_version: optCount(payload.policyVersion, 'policyVersion'),
    policy_hash: policyHash,
    chunks_approved: record.method === 'ApproveDraftChunk' ? 1 : optCount(payload.chunksApproved, 'chunksApproved'),
    chunks_skipped: optCount(payload.chunksSkipped, 'chunksSkipped'),
  };
}

function parseRead(record: LogRecord): GatewayRead {
  if (typeof record.for_seq !== 'number') throw new Error('gateway_read has no for_seq');
  const read: GatewayRead = {
    seq: record.seq, for_seq: record.for_seq, workspace: optString(record.workspace, 'workspace'), sandbox: optString(record.sandbox, 'sandbox'),
    sandbox_id: typeof record.sandbox_id === 'string' ? record.sandbox_id : null, chunks: [], revisions: [],
    error: typeof record.error === 'string' ? record.error : null,
  };
  if (read.error) return read;
  if (!Array.isArray(record.chunks) || !Array.isArray(record.revisions)) throw new Error('gateway_read lacks chunks or revisions');
  read.chunks = record.chunks.map((c: unknown) => {
    if (!isObj(c)) throw new Error('gateway_read chunk is not an object');
    return {
      chunk_id: optString(c.chunk_id, 'chunk_id'), status: optString(c.status, 'status'), rule_name: optString(c.rule_name, 'rule_name'),
      review_token: optString(c.review_token, 'review_token'),
      rule_digest: typeof c.rule_digest === 'string' ? c.rule_digest : null,
      decided_time: typeof c.decided_time === 'string' ? c.decided_time : null,
    };
  });
  read.revisions = record.revisions.map((r: unknown) => {
    if (!isObj(r) || typeof r.version !== 'number' || typeof r.policy_hash !== 'string') throw new Error('gateway_read revision is malformed');
    return { version: r.version, policy_hash: r.policy_hash };
  });
  return read;
}

function sameApprovals(a: Validate, b: Validate): boolean {
  if (a.workspace !== b.workspace || a.sandbox !== b.sandbox || a.approvals.length !== b.approvals.length) return false;
  const key = (v: Validate) => v.approvals.map((x) => `${x.chunk_id}\u0000${x.review_token}`).sort().join('\u0001');
  return key(a) === key(b);
}

/**
 * Which of a validate's named approvals the gateway read shows as committed
 * with the same review token, or null when the read contradicts the commit.
 */
function committedApprovals(v: Validate, p: PostCommit, read: GatewayRead): { chunk_id: string; review_token: string; chunk: ReadChunk }[] | null {
  if (p.policy_version > 0 && !read.revisions.some((r) => r.version === p.policy_version && r.policy_hash === p.policy_hash)) return null;
  const committed: { chunk_id: string; review_token: string; chunk: ReadChunk }[] = [];
  for (const approval of v.approvals) {
    const chunk = read.chunks.find((c) => c.chunk_id === approval.chunk_id);
    if (chunk && chunk.status === 'approved' && approval.review_token !== '' && chunk.review_token === approval.review_token) {
      committed.push({ ...approval, chunk });
    }
  }
  if (committed.length !== p.chunks_approved) return null;
  if (p.chunks_approved > 0 && p.policy_version === 0) return null;
  return committed;
}

const NOTES = [
  'verified and accepted are separate: verified = signature and binding; accepted = verified under a key the reader pinned for that workspace and proof format (a WebAuthn proof also needs the pin\'s relying party).',
  'gateway_principal is the gateway-asserted caller identity. It is unsigned context and never satisfies verified or accepted.',
  'Completeness runs over the policy version chain, not over CONFIG:APPROVED lines. Auto-approvals are their own category, not failed receipts.',
  'The gateway log is unauthenticated text that whoever runs the gateway can edit. Chain versions classified from it carry basis "gateway_log"; auto_approval and removal count toward pass only with trust_gateway_log.',
  'A policy chain is only as complete as the read that produced it: supply chains the reader exported from the gateway itself. A chain cut short at the end hides later versions unless the gateway log shows them (chain_stale).',
  'pass covers the sandboxes in the supplied inventories (ListSandboxes at read time). A sandbox deleted before the inventory was read is not in it.',
  'This covers draft-chunk (network rule) approvals only. It does not cover direct operator policy writes or per-request business actions; the chain check lists the former as findings.',
];

export function check(input: CheckInput): Report {
  const findings: Finding[] = [];
  const windowMs = input.pairingWindowMs ?? 30_000;
  const skewMs = (input.issuedAfterCommitSkewSeconds ?? 300) * 1000;

  // 1. Log.
  const log = parseLog(input.logText);
  for (const problem of log.problems) findings.push({ code: problem.code, message: problem.reason, line: problem.line });
  const starts = log.records.filter((r) => r.kind === 'observer_start');
  if (starts.some((r) => r.gateway_jwt === null || r.gateway_jwt === undefined)) {
    findings.push({ code: 'observer_without_gateway_key', message: 'the observer ran without a pinned gateway JWT key, so its records are not authenticated as coming from the gateway' });
  }

  const validates: Validate[] = [];
  const commits: PostCommit[] = [];
  const reads = new Map<number, GatewayRead[]>();
  for (const record of log.records) {
    try {
      if (record.kind === 'gateway_read') {
        const read = parseRead(record);
        reads.set(read.for_seq, [...(reads.get(read.for_seq) ?? []), read]);
        continue;
      }
      if (record.kind !== 'evaluation' || !OBSERVED.has(record.method as string)) continue;
      const auth = record.gateway_auth as Obj | undefined;
      if (!isObj(auth) || (auth.mode !== 'verified' && auth.mode !== 'not_configured')) {
        findings.push({ code: 'observation_auth_failed', message: `record ${record.seq}: gateway JWT did not verify (${isObj(auth) ? String(auth.reason) : 'no auth result'}); record ignored`, line: record.seq });
        continue;
      }
      if (typeof record.payload_error === 'string') throw new Error(record.payload_error);
      if (record.phase === 'validate') validates.push(parseValidate(record));
      else if (record.phase === 'post_commit') commits.push(parsePostCommit(record));
    } catch (error) {
      findings.push({ code: 'malformed_observation', message: `record ${record.seq}: ${error instanceof Error ? error.message : String(error)}`, line: record.seq });
    }
  }

  // 2. Pair every post_commit with the validate it belongs to.
  interface PairedApproval { v: Validate; p: PostCommit; chunk_id: string; review_token: string; chunk: ReadChunk | null; read: GatewayRead | null; confirmed: boolean }
  const paired: PairedApproval[] = [];
  const consumed = new Set<number>();
  const pairedRequestIds = new Set<string>();
  // (workspace, sandbox, chunk, token) already attributed to a commit. The
  // gateway refuses to approve a chunk that is already approved, so a later
  // validate naming only such pairs (a double submit) cannot be the commit.
  const attributed = new Set<string>();
  const approvalKey = (v: Validate, a: { chunk_id: string; review_token: string }) => `${v.workspace}\u0000${v.sandbox}\u0000${a.chunk_id}\u0000${a.review_token}`;
  const events = [...validates.map((v) => ({ seq: v.seq, v })), ...commits.map((p) => ({ seq: p.seq, p }))].sort((a, b) => a.seq - b.seq);
  const pending: Validate[] = [];
  for (const event of events) {
    if ('v' in event && event.v) {
      const v = event.v;
      if (v.request_id && pairedRequestIds.has(`${v.method}\u0000${v.request_id}`)) {
        consumed.add(v.seq); // replay of an already committed request: the gateway answers from its replay cache
        continue;
      }
      pending.push(v);
      continue;
    }
    const p = (event as { p: PostCommit }).p;
    while (pending.length > 0 && p.at - pending[0].at > windowMs) pending.shift();
    const candidates = pending.filter((v) => !consumed.has(v.seq) && v.method === p.method && v.principalKey === p.principalKey
      && v.at <= p.at && p.at - v.at <= windowMs
      && !(v.approvals.length > 0 && v.approvals.every((a) => attributed.has(approvalKey(v, a)))));
    const commitReads = (reads.get(p.seq) ?? []).filter((r) => !r.error);
    const readFor = (v: Validate) => commitReads.find((r) => r.workspace === v.workspace && r.sandbox === v.sandbox) ?? null;
    if (p.method === 'ApproveAllDraftChunks' && p.chunks_approved === 0) {
      // A bulk call that approved nothing still reaches post_commit.
      const match = candidates.filter((v) => { const r = readFor(v); return r ? committedApprovals(v, p, r)?.length === 0 : false; });
      const chosen = match.length > 0 ? match : candidates;
      for (const v of chosen.filter((c) => sameApprovals(c, chosen[chosen.length - 1]))) consumed.add(v.seq);
      continue;
    }
    if (candidates.length === 0) {
      findings.push({ code: 'commit_without_validate', message: `post_commit ${p.seq} (${p.method}, v${p.policy_version}) has no validate from the same caller inside ${windowMs} ms`, commit_seq: p.seq, version: p.policy_version });
      continue;
    }
    const consistent = candidates
      .map((v) => ({ v, read: readFor(v) }))
      .map(({ v, read }) => ({ v, read, committed: read ? committedApprovals(v, p, read) : null }))
      .filter((c) => c.committed !== null);
    if (consistent.length > 0) {
      const last = consistent[consistent.length - 1];
      if (!consistent.every((c) => sameApprovals(c.v, last.v))) {
        findings.push({ code: 'ambiguous_pairing', message: `post_commit ${p.seq} matches ${consistent.length} different validates (${consistent.map((c) => c.v.seq).join(', ')}); no approval is attributed`, commit_seq: p.seq, version: p.policy_version });
        continue;
      }
      for (const c of consistent) consumed.add(c.v.seq);
      if (last.v.request_id) pairedRequestIds.add(`${last.v.method}\u0000${last.v.request_id}`);
      if (last.v.approvals.length === 0) {
        findings.push({ code: 'bulk_approval_without_named_chunks', message: `post_commit ${p.seq} approved ${p.chunks_approved} chunk(s) that the request did not name`, commit_seq: p.seq });
        continue;
      }
      for (const a of last.committed ?? []) {
        attributed.add(approvalKey(last.v, a));
        paired.push({ v: last.v, p, chunk_id: a.chunk_id, review_token: a.review_token, chunk: a.chunk, read: last.read, confirmed: true });
      }
      continue;
    }
    const anyRead = (reads.get(p.seq) ?? []).length > 0;
    const readErrors = (reads.get(p.seq) ?? []).filter((r) => r.error).map((r) => r.error);
    if (candidates.length === 1 && commitReads.length === 0) {
      const v = candidates[0];
      consumed.add(v.seq);
      if (v.request_id) pairedRequestIds.add(`${v.method}\u0000${v.request_id}`);
      findings.push({ code: 'commit_not_confirmed_by_gateway_read', message: `post_commit ${p.seq} was paired with validate ${v.seq} by elimination only; ${anyRead ? `the gateway read failed: ${readErrors.join('; ')}` : 'the observer made no gateway read'}`, commit_seq: p.seq });
      if (p.method === 'ApproveDraftChunk' || v.approvals.length === p.chunks_approved) {
        for (const a of v.approvals) {
          attributed.add(approvalKey(v, a));
          paired.push({ v, p, chunk_id: a.chunk_id, review_token: a.review_token, chunk: null, read: null, confirmed: false });
        }
      } else {
        findings.push({ code: 'bulk_chunks_unresolved', message: `post_commit ${p.seq} approved ${p.chunks_approved} of ${v.approvals.length} named chunks and no gateway read says which`, commit_seq: p.seq });
      }
      continue;
    }
    findings.push({
      code: commitReads.length > 0 ? 'commit_inconsistent_with_gateway_read' : 'ambiguous_pairing',
      message: `post_commit ${p.seq} (v${p.policy_version}) could not be attributed to any of validates ${candidates.map((v) => v.seq).join(', ')}`,
      commit_seq: p.seq, version: p.policy_version,
    });
  }

  // 3. Pins and receipts.
  const pins = parsePins(input.pinsText, findings);
  const receipts: { index: number; receipt: Receipt; sig: SignatureCheck }[] = [];
  let receiptIndex = 0;
  for (const text of input.receiptTexts) {
    for (const parsed of parseReceiptsText(text).receipts) {
      const index = receiptIndex;
      receiptIndex += 1;
      if (!parsed.ok) {
        findings.push({ code: 'malformed_receipt', message: `receipt ${index}: ${parsed.reason}`, receipt_index: index });
        continue;
      }
      receipts.push({ index, receipt: parsed.value, sig: verifyReceiptSignature(parsed.value) });
    }
  }

  const usedReceipts = new Set<number>();
  const approvals: ApprovalResult[] = paired.map((a) => {
    const matching = receipts.filter((r) => r.receipt.payload.chunk_id === a.chunk_id);
    const verdicts: ReceiptVerdict[] = matching.map((r) => {
      usedReceipts.add(r.index);
      const reasons: string[] = [];
      const payload = r.receipt.payload;
      if (!r.sig.ok) reasons.push(`signature: ${r.sig.reason}`);
      if (payload.workspace !== a.v.workspace) reasons.push(`workspace ${payload.workspace} is not the committed ${a.v.workspace}`);
      if (payload.sandbox !== a.v.sandbox) reasons.push(`sandbox ${payload.sandbox} is not the committed ${a.v.sandbox}`);
      if (payload.review_token !== a.review_token) reasons.push('review_token is not the token the gateway committed (stale or different review)');
      if (!a.chunk) reasons.push('rule text was not observed from the gateway for this commit');
      else if (!a.chunk.rule_digest) reasons.push('the gateway rule could not be canonicalized by the observer');
      else {
        if (payload.rule_digest !== a.chunk.rule_digest) reasons.push('rule_digest is not the digest of the committed rule');
        if (payload.rule_name !== a.chunk.rule_name) reasons.push(`rule_name ${payload.rule_name} is not the committed ${a.chunk.rule_name}`);
      }
      if (Date.parse(payload.issued_at) > a.p.at + skewMs) reasons.push(`issued_at ${payload.issued_at} is after the commit at ${a.p.t} (skew ${skewMs / 1000}s)`);
      const verified = reasons.length === 0;
      let accepted = false;
      const pin = r.sig.kid ? pins.get(r.sig.kid) : undefined;
      const format = r.receipt.proof.format;
      if (verified) {
        if (!pin) reasons.push('key is not pinned by the reader');
        else if (!pin.workspaces.has(a.v.workspace)) reasons.push(`key is pinned, but not for workspace ${a.v.workspace}`);
        else if (format === 'webauthn' && !pin.webauthn) reasons.push('webauthn proof but the pin names no relying party, so its origin and rpIdHash cannot be checked');
        else if (!pin.formats.has(format)) reasons.push(`${format} proof, but the pin allows only ${[...pin.formats].join(', ')} proofs for this key`);
        else if (format === 'webauthn' && pin.webauthn) {
          const scoped = verifyReceiptSignature(r.receipt, pin.webauthn);
          if (!scoped.ok) reasons.push(`relying-party scope: ${scoped.reason}`);
          else accepted = true;
        } else accepted = true;
      }
      return { receipt_index: r.index, kid: r.sig.kid ?? null, label: pin?.label ?? null, format: r.sig.format ?? null, verified, accepted, reasons };
    });
    const best = verdicts.find((x) => x.accepted) ?? verdicts.find((x) => x.verified) ?? null;
    const result: ApprovalResult = {
      commit_seq: a.p.seq, validate_seq: a.v.seq, method: a.p.method, workspace: a.v.workspace, sandbox: a.v.sandbox,
      sandbox_id: a.read?.sandbox_id ?? null, chunk_id: a.chunk_id, review_token: a.review_token,
      policy_version: a.p.policy_version, policy_hash: a.p.policy_hash, committed_at: a.p.t,
      rule_name: a.chunk?.rule_name ?? null, rule_digest: a.chunk?.rule_digest ?? null,
      pairing: a.confirmed ? 'confirmed' : 'unconfirmed',
      verified: verdicts.some((x) => x.verified), accepted: verdicts.some((x) => x.accepted),
      approver: best && best.kid ? { kid: best.kid, label: best.label, format: best.format ?? 'unknown' } : null,
      receipts: verdicts, gateway_principal: a.p.principal,
    };
    const where = { commit_seq: a.p.seq, chunk_id: a.chunk_id, sandbox: a.v.sandbox, version: a.p.policy_version };
    if (verdicts.length === 0) {
      findings.push({ code: 'approval_without_receipt', message: `chunk ${a.chunk_id} committed at v${a.p.policy_version} has no approver receipt`, ...where });
    } else if (!result.verified) {
      for (const v of verdicts) {
        const code = v.reasons.some((x) => x.startsWith('signature:')) ? 'receipt_bad_signature'
          : v.reasons.some((x) => x.startsWith('review_token')) ? 'receipt_token_mismatch'
          : v.reasons.some((x) => x.startsWith('rule_digest') || x.startsWith('rule_name')) ? 'receipt_rule_mismatch'
          : v.reasons.some((x) => x.startsWith('workspace') || x.startsWith('sandbox')) ? 'receipt_scope_mismatch'
          : v.reasons.some((x) => x.startsWith('issued_at')) ? 'receipt_issued_after_commit'
          : 'rule_not_observed';
        findings.push({ code, message: `receipt ${v.receipt_index} for chunk ${a.chunk_id}: ${v.reasons.join('; ')}`, receipt_index: v.receipt_index, ...where });
      }
    } else if (!result.accepted) {
      for (const v of verdicts.filter((x) => x.verified)) {
        findings.push({ code: 'receipt_key_not_accepted', message: `receipt ${v.receipt_index} for chunk ${a.chunk_id} is verified but not accepted: ${v.reasons.join('; ')}`, receipt_index: v.receipt_index, ...where });
      }
    }
    return result;
  });

  for (const r of receipts) {
    if (!usedReceipts.has(r.index)) {
      findings.push({ code: 'receipt_without_committed_approval', message: `receipt ${r.index} names chunk ${r.receipt.payload.chunk_id}, which no observed commit approved`, receipt_index: r.index, chunk_id: r.receipt.payload.chunk_id });
    }
  }

  // 4. Completeness over the policy version chain.
  const chain: TransitionResult[] = [];
  const chains = (input.chainTexts ?? []).map((text, index) => parseChain(text, index, findings)).filter((c): c is Chain => c !== null);
  let gatewayEvents: GatewayPolicyEvent[] = [];
  if (input.gatewayLogText !== undefined) {
    const parsed = parseGatewayLog(input.gatewayLogText);
    gatewayEvents = parsed.events;
    if (parsed.unparsed_config_lines.length > 0) {
      findings.push({ code: 'gateway_log_unparsed', message: `gateway log CONFIG lines ${parsed.unparsed_config_lines.slice(0, 10).join(', ')} could not be parsed` });
    }
    if (parsed.lines_without_sandbox_id > 0) {
      findings.push({ code: 'gateway_log_unattributed', message: `${parsed.lines_without_sandbox_id} CONFIG line(s) record a policy version but carry no sandbox_id, so they cannot be attributed to a sandbox (supply the gateway's own output, not \`openshell logs\`)` });
    }
  }
  const trustGatewayLog = input.trustGatewayLog === true;
  const checkedSandboxes: string[] = [];
  const approvalsBySandbox = (c: Chain) => approvals.filter((a) => (a.sandbox_id ? a.sandbox_id === c.sandbox_id : a.workspace === c.workspace && a.sandbox === c.sandbox));
  for (const c of chains) {
    checkedSandboxes.push(`${c.workspace}/${c.sandbox}`);
    const mine = approvalsBySandbox(c);
    const byVersion = new Map(c.revisions.map((r) => [r.version, r]));
    for (const a of mine) {
      const rev = byVersion.get(a.policy_version);
      if (!rev || rev.policy_hash !== a.policy_hash) {
        findings.push({ code: 'commit_not_in_chain', message: `commit ${a.commit_seq} reports v${a.policy_version} ${a.policy_hash.slice(0, 12)}, which the policy chain does not contain`, commit_seq: a.commit_seq, sandbox: c.sandbox, version: a.policy_version });
      }
    }
    const first = c.revisions[0];
    for (let i = 0; i < c.revisions.length; i += 1) {
      const rev = c.revisions[i];
      const base = { workspace: c.workspace, sandbox: c.sandbox, sandbox_id: c.sandbox_id, version: rev.version, policy_hash: rev.policy_hash };
      if (i > 0 && rev.version !== c.revisions[i - 1].version + 1) {
        findings.push({ code: 'chain_gap', message: `policy chain for ${c.sandbox} skips from v${c.revisions[i - 1].version} to v${rev.version}`, sandbox: c.sandbox, version: rev.version });
      }
      if (!/^[0-9a-f]{64}$/.test(rev.policy_hash)) {
        chain.push({ ...base, classification: 'invalid_revision' });
        findings.push({ code: 'chain_revision_invalid', message: `v${rev.version} of ${c.sandbox} has no valid policy hash (status ${rev.status})`, sandbox: c.sandbox, version: rev.version });
        continue;
      }
      if (rev === first) {
        chain.push({ ...base, classification: first.version === 1 ? 'initial_policy' : 'unexplained_policy_change' });
        if (first.version !== 1) findings.push({ code: 'chain_gap', message: `policy chain for ${c.sandbox} starts at v${first.version}`, sandbox: c.sandbox, version: first.version });
        continue;
      }
      const atVersion = mine.filter((a) => a.policy_version === rev.version && a.policy_hash === rev.policy_hash);
      if (atVersion.length > 0) {
        const allAccepted = atVersion.every((a) => a.accepted);
        chain.push({ ...base, classification: allAccepted ? 'receipted_human_approval' : 'human_approval_not_accepted', commit_seq: atVersion[0].commit_seq });
        continue;
      }
      const logged = gatewayEvents.filter((e) => e.sandbox_id === c.sandbox_id && e.version === rev.version && e.policy_hash === rev.policy_hash);
      const auto = logged.find((e) => e.state === 'APPROVED' && e.auto);
      const human = logged.find((e) => e.state === 'APPROVED' && !e.auto);
      const merged = logged.find((e) => e.state === 'MERGED' && !e.bulk_summary);
      const removed = logged.find((e) => e.state === 'REMOVED');
      const fromLog = { basis: 'gateway_log' as const };
      if (human) {
        chain.push({ ...base, classification: 'approval_not_observed', gateway_log_line: human.line, ...fromLog });
        findings.push({ code: 'approval_not_observed', message: `the gateway logged a human approval of chunk ${human.chunk_id ?? '?'} at v${rev.version} of ${c.sandbox}, but no observed commit is attributed to it`, sandbox: c.sandbox, version: rev.version, line: human.line });
      } else if (auto && !merged) {
        chain.push({ ...base, classification: 'auto_approval', gateway_log_line: auto.line, ...fromLog });
      } else if (merged) {
        chain.push({ ...base, classification: 'policy_change_without_approval', gateway_log_line: merged.line, ...fromLog });
        findings.push({ code: 'policy_change_without_approval', message: `v${rev.version} of ${c.sandbox} is an operator policy merge (${merged.message}); no approver receipt covers it`, sandbox: c.sandbox, version: rev.version, line: merged.line });
      } else if (removed) {
        chain.push({ ...base, classification: 'removal', gateway_log_line: removed.line, ...fromLog });
      } else if (rev.policy_hash === c.revisions[i - 1].policy_hash) {
        chain.push({ ...base, classification: 'revision_without_policy_change' });
      } else {
        chain.push({ ...base, classification: 'unexplained_policy_change' });
        findings.push({ code: 'unexplained_policy_change', message: `v${rev.version} of ${c.sandbox} changed the policy with no observed approval and no gateway approval line (for example \`openshell policy set\`)`, sandbox: c.sandbox, version: rev.version });
      }
    }
  }

  // Gateway log events no supplied chain accounts for: a sandbox the reader
  // did not check, or a version the chain was read too early to contain.
  const namesById = new Map<string, string>();
  for (const a of approvals) if (a.sandbox_id && !namesById.has(a.sandbox_id)) namesById.set(a.sandbox_id, `${a.workspace}/${a.sandbox}`);
  const sandboxName = (sandboxId: string): string => namesById.get(sandboxId) ?? `sandbox_id=${sandboxId}`;
  const add = (map: Map<string, GatewayPolicyEvent[]>, e: GatewayPolicyEvent) => {
    const list = map.get(e.sandbox_id);
    if (list) list.push(e);
    else map.set(e.sandbox_id, [e]);
  };
  const uncheckedFromLog = new Set<string>();
  const withoutChain = new Map<string, GatewayPolicyEvent[]>();
  const pastEnd = new Map<string, GatewayPolicyEvent[]>();
  for (const e of gatewayEvents) {
    const own = chains.filter((c) => c.sandbox_id === e.sandbox_id);
    if (own.length === 0) {
      uncheckedFromLog.add(sandboxName(e.sandbox_id));
      if (!(e.state === 'APPROVED' && e.auto)) add(withoutChain, e);
      continue;
    }
    if (own.some((c) => c.revisions.some((r) => r.version === e.version && r.policy_hash === e.policy_hash))) continue;
    const last = Math.max(...own.map((c) => c.revisions[c.revisions.length - 1].version));
    if (e.version > last) {
      add(pastEnd, e);
    } else {
      findings.push({ code: 'gateway_event_not_in_chain', message: `the gateway log records ${e.state} at v${e.version} ${e.policy_hash.slice(0, 12)} of ${own[0].sandbox}, which the policy chain does not contain`, sandbox: own[0].sandbox, version: e.version, line: e.line });
    }
  }
  const versions = (events: GatewayPolicyEvent[]) => {
    const all = [...new Set(events.map((e) => `v${e.version}`))];
    return all.length > 20 ? `${all.slice(0, 20).join(', ')} and ${all.length - 20} more` : all.join(', ');
  };
  for (const [sandboxId, events] of withoutChain) {
    findings.push({ code: 'gateway_event_without_chain', message: `the gateway log records policy changes (${[...new Set(events.map((e) => (e.state === 'APPROVED' ? 'human approval' : e.state)))].join(', ')}) at ${versions(events)} of ${sandboxName(sandboxId)}, and no policy chain was supplied for that sandbox`, version: events[0].version, line: events[0].line });
  }
  for (const [sandboxId, events] of pastEnd) {
    const own = chains.find((c) => c.sandbox_id === sandboxId) as Chain;
    findings.push({ code: 'chain_stale', message: `the gateway log records ${versions(events)} of ${own.sandbox}, past the newest version in the supplied chain; export the chain again`, sandbox: own.sandbox, version: events[0].version, line: events[0].line });
  }

  // Sandboxes the logs never mention: the inventory lists them all.
  const inventories = (input.inventoryTexts ?? []).map((text, index) => parseInventory(text, index, findings)).filter((i): i is Inventory => i !== null);
  const inventoried = new Set(inventories.map((i) => i.workspace));
  const uninventoried = [...new Set([...approvals.map((a) => a.workspace), ...chains.map((c) => c.workspace)])].filter((w) => !inventoried.has(w)).sort();
  const unchecked = [...new Set([
    ...approvals
      .filter((a) => !chains.some((c) => (a.sandbox_id ? a.sandbox_id === c.sandbox_id : a.workspace === c.workspace && a.sandbox === c.sandbox)))
      .map((a) => `${a.workspace}/${a.sandbox}`),
    ...uncheckedFromLog,
    ...inventories.flatMap((i) => i.sandboxes.filter((sb) => !chains.some((c) => c.sandbox_id === sb.sandbox_id)).map((sb) => `${i.workspace}/${sb.sandbox}`)),
  ])];
  const logOnly = chain.filter((t) => t.basis === 'gateway_log' && (t.classification === 'auto_approval' || t.classification === 'removal'));
  const reason = chains.length === 0 && inventories.length === 0 ? 'no policy chain was supplied'
    : unchecked.length > 0 ? `no policy chain was supplied for ${unchecked.join(', ')}`
    : uninventoried.length > 0
      ? `no sandbox inventory was supplied for workspace ${uninventoried.join(', ')}, so sandboxes neither log mentions are not covered (export one with \`chain --all\`)`
    : logOnly.length > 0 && !trustGatewayLog
      ? `${logOnly.length} version(s) (${logOnly.map((t) => `${t.sandbox} v${t.version} ${t.classification}`).join(', ')}) are explained only by the gateway log, which is unauthenticated; pass needs trust_gateway_log`
      : undefined;
  const completenessChecked = reason === undefined;

  const result: Report['result'] = findings.length > 0 ? 'fail' : completenessChecked ? 'pass' : 'incomplete';
  return {
    format: REPORT_FORMAT,
    result,
    summary: {
      committed_approvals: approvals.length,
      verified: approvals.filter((a) => a.verified).length,
      accepted: approvals.filter((a) => a.accepted).length,
      auto_approvals: chain.filter((t) => t.classification === 'auto_approval').length,
      receipts_read: receiptIndex,
      findings: findings.length,
      policy_transitions_checked: chain.filter((t) => t.classification !== 'initial_policy').length,
    },
    approvals,
    chain,
    completeness: {
      checked: completenessChecked,
      checked_sandboxes: checkedSandboxes,
      unchecked_sandboxes: unchecked,
      chain_heads: chains.map((c) => ({ sandbox: `${c.workspace}/${c.sandbox}`, sandbox_id: c.sandbox_id, last_version: c.revisions[c.revisions.length - 1].version, read_at: c.read_at })),
      inventoried_workspaces: [...inventoried].sort(),
      gateway_log_trusted: trustGatewayLog,
      ...(reason !== undefined ? { reason } : {}),
    },
    findings,
    notes: NOTES,
  };
}
