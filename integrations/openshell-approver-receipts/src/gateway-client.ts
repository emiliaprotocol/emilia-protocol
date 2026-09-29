// SPDX-License-Identifier: Apache-2.0
// Minimal OpenShell gateway client: the reads the observer, the approver CLI
// and the policy-chain export need, plus the two approval calls the end-to-end
// test drives. It uses the caller's own credential; nothing here is privileged.

import fs from 'node:fs';
import grpc from '@grpc/grpc-js';
import protobuf from 'protobufjs';
import { canonicalRule, jcs, sha256Hex } from './canonical.ts';
import type { Json } from './struct-json.ts';
import { OPENSHELL_SERVICE, TO_OBJECT, lookupType, serviceDefinition } from './protos.ts';

export interface GatewayClientOptions {
  /** host:port, http://host:port, https://host:port, or unix:///path */
  endpoint: string;
  /** Bearer token sent as `authorization` metadata (OIDC or similar). */
  bearerToken?: string;
  /** PEM CA bundle for https endpoints; platform roots when omitted. */
  caPem?: Buffer;
  deadlineMs?: number;
}

/** What the observer, the approver and the checker need to know about a chunk. */
export interface ChunkView {
  chunk_id: string;
  status: string;
  rule_name: string;
  review_token: string;
  candidate_effective_policy_hash: string;
  current_effective_policy_hash: string;
  security_notes: string;
  decided_time: string | null;
  /** Canonical proposed_rule, or null when it could not be canonicalized. */
  proposed_rule: { [key: string]: Json } | null;
  rule_digest: string | null;
  rule_error?: string;
}

export interface PolicyRevisionView {
  version: number;
  policy_hash: string;
  status: string;
}

type Obj = Record<string, unknown>;

function parseEndpoint(endpoint: string, caPem?: Buffer): { target: string; credentials: grpc.ChannelCredentials } {
  if (endpoint.startsWith('unix:')) return { target: endpoint, credentials: grpc.credentials.createInsecure() };
  if (endpoint.startsWith('https://')) {
    return { target: endpoint.slice('https://'.length).replace(/\/$/, ''), credentials: grpc.credentials.createSsl(caPem ?? null) };
  }
  const target = endpoint.startsWith('http://') ? endpoint.slice('http://'.length).replace(/\/$/, '') : endpoint;
  return { target, credentials: grpc.credentials.createInsecure() };
}

function timestampToIso(value: unknown): string | null {
  if (!value || typeof value !== 'object') return null;
  const { seconds, nanos } = value as { seconds?: unknown; nanos?: unknown };
  const s = typeof seconds === 'string' ? Number(seconds) : typeof seconds === 'number' ? seconds : 0;
  const n = typeof nanos === 'number' ? nanos : 0;
  if (!Number.isFinite(s)) return null;
  return new Date(s * 1000 + Math.floor(n / 1e6)).toISOString();
}

/**
 * Split a length-delimited protobuf message into the raw bytes of every
 * occurrence of one field number. Used to hold the exact proposed_rule bytes
 * the gateway sent next to what this build decodes from them.
 */
function rawFieldOccurrences(bytes: Uint8Array, fieldNumber: number): Uint8Array[] {
  const reader = protobuf.Reader.create(bytes);
  const found: Uint8Array[] = [];
  while (reader.pos < reader.len) {
    const tag = reader.uint32();
    const wireType = tag & 7;
    if ((tag >>> 3) === fieldNumber && wireType === 2) {
      found.push(reader.bytes());
    } else {
      reader.skipType(wireType);
    }
  }
  return found;
}

const policyChunkType = (): protobuf.Type => lookupType('openshell.v1.PolicyChunk');
const ruleType = (): protobuf.Type => lookupType('openshell.sandbox.v1.NetworkPolicyRule');

/**
 * Decode one PolicyChunk from its wire bytes. The rule digest is computed only
 * when this build decodes the rule without losing bytes: if re-encoding the
 * decoded rule is shorter or longer than what the gateway sent, the gateway
 * sent fields this build does not model (for example after an upstream
 * schema change) and the rule is refused instead of silently truncated.
 */
export function chunkViewFromBytes(chunkBytes: Uint8Array): ChunkView {
  const chunk = policyChunkType().toObject(policyChunkType().decode(chunkBytes), TO_OBJECT) as Obj;
  const view: ChunkView = {
    chunk_id: typeof chunk.id === 'string' ? chunk.id : '',
    status: typeof chunk.status === 'string' ? chunk.status : '',
    rule_name: typeof chunk.rule_name === 'string' ? chunk.rule_name : '',
    review_token: typeof chunk.review_token === 'string' ? chunk.review_token : '',
    candidate_effective_policy_hash: typeof chunk.candidate_effective_policy_hash === 'string' ? chunk.candidate_effective_policy_hash : '',
    current_effective_policy_hash: typeof chunk.current_effective_policy_hash === 'string' ? chunk.current_effective_policy_hash : '',
    security_notes: typeof chunk.security_notes === 'string' ? chunk.security_notes : '',
    decided_time: timestampToIso(chunk.decided_time),
    proposed_rule: null,
    rule_digest: null,
  };
  const ruleOccurrences = rawFieldOccurrences(chunkBytes, 4);
  if (ruleOccurrences.length !== 1) {
    view.rule_error = ruleOccurrences.length === 0 ? 'chunk has no proposed_rule' : 'proposed_rule occurs more than once on the wire';
    return view;
  }
  const ruleBytes = ruleOccurrences[0];
  const decoded = ruleType().decode(ruleBytes);
  const reEncoded = ruleType().encode(decoded).finish();
  if (reEncoded.length !== ruleBytes.length) {
    view.rule_error = `proposed_rule wire size ${ruleBytes.length} differs from the ${reEncoded.length} bytes this build models; the gateway schema is newer than the pinned protos`;
    return view;
  }
  const canonical = canonicalRule(ruleType().toObject(decoded, TO_OBJECT));
  if (!canonical.ok) {
    view.rule_error = canonical.reason;
    return view;
  }
  view.proposed_rule = canonical.value;
  view.rule_digest = `sha256:${sha256Hex(jcs(canonical.value))}`;
  return view;
}


export class GatewayClient {
  private client: grpc.Client;
  private opts: GatewayClientOptions;
  private definition = serviceDefinition(OPENSHELL_SERVICE);

  constructor(opts: GatewayClientOptions) {
    this.opts = opts;
    const { target, credentials } = parseEndpoint(opts.endpoint, opts.caPem);
    this.client = new grpc.Client(target, credentials);
  }

  static fromCli(endpoint: string, tokenFile?: string, caFile?: string): GatewayClient {
    return new GatewayClient({
      endpoint,
      bearerToken: tokenFile ? fs.readFileSync(tokenFile, 'utf8').trim() : undefined,
      caPem: caFile ? fs.readFileSync(caFile) : undefined,
    });
  }

  close(): void {
    this.client.close();
  }

  private metadata(): grpc.Metadata {
    const md = new grpc.Metadata();
    if (this.opts.bearerToken) md.set('authorization', `Bearer ${this.opts.bearerToken}`);
    return md;
  }

  private unary<T>(method: string, request: object, raw = false): Promise<T> {
    const def = (this.definition as unknown as Record<string, { path: string; requestSerialize: (v: object) => Buffer; responseDeserialize: (b: Buffer) => unknown }>)[method];
    const deserialize = raw ? (bytes: Buffer) => bytes : def.responseDeserialize;
    return new Promise((resolve, reject) => {
      this.client.makeUnaryRequest(
        def.path,
        def.requestSerialize,
        deserialize,
        request,
        this.metadata(),
        { deadline: Date.now() + (this.opts.deadlineMs ?? 5000) },
        (error, value) => (error ? reject(error) : resolve(value as T)),
      );
    });
  }

  async getSandboxId(workspace: string, name: string): Promise<string> {
    const response = await this.unary<Obj>('GetSandbox', { name, workspace_scope: { workspace } });
    const sandbox = response.sandbox as Obj | undefined;
    const metadata = sandbox?.metadata as Obj | undefined;
    const id = metadata?.id;
    if (typeof id !== 'string' || id.length === 0) throw new Error(`GetSandbox returned no id for ${workspace}/${name}`);
    return id;
  }

  async getDraftChunks(workspace: string, sandbox: string, statusFilter = ''): Promise<ChunkView[]> {
    const bytes = await this.unary<Buffer>('GetDraftPolicy', { sandbox, status_filter: statusFilter, workspace_scope: { workspace } }, true);
    return rawFieldOccurrences(bytes, 1).map((chunkBytes) => chunkViewFromBytes(chunkBytes));
  }

  async listPolicyRevisions(workspace: string, sandbox: string, maxPages = 50): Promise<PolicyRevisionView[]> {
    const revisions: PolicyRevisionView[] = [];
    let pageToken = '';
    for (let page = 0; page < maxPages; page += 1) {
      const response = await this.unary<Obj>('ListSandboxPolicies', {
        sandbox, page_size: 1000, page_token: pageToken, workspace_scope: { workspace },
      });
      for (const revision of (response.revisions as Obj[] | undefined) ?? []) {
        revisions.push({
          version: typeof revision.version === 'number' ? revision.version : 0,
          policy_hash: typeof revision.policy_hash === 'string' ? revision.policy_hash : '',
          status: typeof revision.status === 'string' ? revision.status : 'POLICY_STATUS_UNSPECIFIED',
        });
      }
      pageToken = typeof response.next_page_token === 'string' ? response.next_page_token : '';
      if (!pageToken) return revisions.sort((a, b) => a.version - b.version);
    }
    throw new Error(`ListSandboxPolicies did not finish within ${maxPages} pages`);
  }

  async approveDraftChunk(workspace: string, sandbox: string, chunkId: string, reviewToken: string, requestId = ''): Promise<{ policy_version: number; policy_hash: string }> {
    const response = await this.unary<Obj>('ApproveDraftChunk', {
      sandbox, chunk_id: chunkId, review_token: reviewToken, request_id: requestId, workspace_scope: { workspace },
    });
    return {
      policy_version: typeof response.policy_version === 'number' ? response.policy_version : 0,
      policy_hash: typeof response.policy_hash === 'string' ? response.policy_hash : '',
    };
  }

  async approveAllDraftChunks(workspace: string, sandbox: string, approvals: { chunk_id: string; review_token: string }[]): Promise<Obj> {
    return this.unary<Obj>('ApproveAllDraftChunks', { sandbox, approvals, workspace_scope: { workspace } });
  }
}
