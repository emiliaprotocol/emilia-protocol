// SPDX-License-Identifier: Apache-2.0
// Observe-mode OpenShell gateway interceptor.
//
// It binds the `validate` and `post_commit` phases of ApproveDraftChunk and
// ApproveAllDraftChunks with failure_policy fail_open, and it answers every
// evaluation with allowed=true, no patches, and a log annotation carrying its
// own sequence number. It never denies and never modifies an operation.
//
// Why two phases: `validate` carries the prepared operation after any
// interceptor patches, which names the chunk and the review token
// (`modify_operation` sees it before those patches, and this observer does not
// bind it); `post_commit` is the only phase that proves the gateway committed. No correlation id reaches an interceptor, so after each
// post_commit the observer reads the gateway (GetSandbox, GetDraftPolicy,
// ListSandboxPolicies) with its OWN credential and logs what it saw. The
// offline checker joins validate, post_commit and those reads.

import crypto from 'node:crypto';
import grpc from '@grpc/grpc-js';
import { AppendOnlyLog, LOG_FORMAT } from './log.ts';
import { loadGatewayPublicKey, verifyGatewayAuthorization } from './gateway-jwt.ts';
import type { GatewayAuth, GatewayJwtPolicy } from './gateway-jwt.ts';
import { structToJson } from './struct-json.ts';
import type { Json } from './struct-json.ts';
import { INTERCEPTOR_SERVICE, serviceDefinition } from './protos.ts';
import type { GatewayClient } from './gateway-client.ts';

export const OBSERVED_METHODS = ['ApproveDraftChunk', 'ApproveAllDraftChunks'] as const;
export const CONTRACT_CAPABILITY = 'openshell.gateway-interceptor.contract';
export const IMPLEMENTATION_NAME = 'emilia/openshell-approver-receipts';
export const IMPLEMENTATION_VERSION = '0.1.0';

export interface ObserverOptions {
  /** unix:///absolute/path.sock or host:port */
  listen: string;
  logPath: string;
  name?: string;
  audience?: string;
  /** Pinned gateway JWT key. Null records every call as not_configured. */
  gatewayJwt?: { publicKeyPem: string; gatewayId: string } | null;
  /** The observer's own gateway client for post-commit reads. */
  reader?: GatewayClient | null;
  /** How far back a validate may precede its post_commit (ms). */
  readWindowMs?: number;
  /** Serve TLS (for https:// grpc_endpoint). Plaintext when omitted: use a unix socket. */
  tls?: { certPem: Buffer; keyPem: Buffer } | null;
  /** Test hook: called after every post-commit read finishes. */
  onReadDone?: (seq: number) => void;
}

export interface RunningObserver {
  address: string;
  log: AppendOnlyLog;
  audience: string;
  close(): Promise<void>;
  /** Resolves when all scheduled post-commit reads have been logged. */
  idle(): Promise<void>;
}

interface PendingValidate {
  seq: number;
  at: number;
  method: string;
  principalKey: string;
  workspace: string;
  sandbox: string;
  chunkIds: string[];
}

type Obj = Record<string, unknown>;

function principalKey(principal: unknown): string {
  if (!principal || typeof principal !== 'object') return '{}';
  const entries = Object.entries(principal as Obj).filter(([, v]) => typeof v === 'string').sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(entries);
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function defaultAudience(name: string): string {
  return `urn:openshell:extension:interceptor:${name}`;
}

export async function startObserver(options: ObserverOptions): Promise<RunningObserver> {
  const name = options.name ?? 'emilia-observer';
  const audience = options.audience ?? defaultAudience(name);
  const readWindowMs = options.readWindowMs ?? 30_000;
  const jwtPolicy: GatewayJwtPolicy | null = options.gatewayJwt
    ? { publicKey: loadGatewayPublicKey(options.gatewayJwt.publicKeyPem), gatewayId: options.gatewayJwt.gatewayId, audience }
    : null;
  const log = new AppendOnlyLog(options.logPath);
  const pending: PendingValidate[] = [];
  const inFlight = new Set<Promise<void>>();

  log.append('observer_start', {
    format: LOG_FORMAT,
    implementation: `${IMPLEMENTATION_NAME}@${IMPLEMENTATION_VERSION}`,
    interceptor_name: name,
    audience,
    methods: [...OBSERVED_METHODS],
    gateway_jwt: jwtPolicy
      ? { gateway_id: jwtPolicy.gatewayId, public_key_sha256: crypto.createHash('sha256').update(jwtPolicy.publicKey.export({ format: 'der', type: 'spki' })).digest('hex') }
      : null,
    gateway_reads: Boolean(options.reader),
  });

  function authOf(call: { metadata: grpc.Metadata }): GatewayAuth {
    const values = call.metadata.get('authorization');
    const header = values.length === 1 ? values[0].toString() : values.length === 0 ? undefined : null;
    if (header === null) return { mode: 'failed', reason: 'more than one authorization header' };
    return verifyGatewayAuthorization(header, jwtPolicy);
  }

  function scheduleReads(commitSeq: number, method: string, key: string): void {
    const reader = options.reader;
    if (!reader) return;
    const now = Date.now();
    while (pending.length > 0 && now - pending[0].at > readWindowMs) pending.shift();
    const targets = new Map<string, { workspace: string; sandbox: string }>();
    for (const v of pending) {
      if (v.method === method && v.principalKey === key && v.sandbox) targets.set(`${v.workspace}\u0000${v.sandbox}`, { workspace: v.workspace, sandbox: v.sandbox });
    }
    if (targets.size === 0) {
      log.append('gateway_read', { for_seq: commitSeq, error: 'no validate for this method and principal inside the read window' });
      options.onReadDone?.(commitSeq);
      return;
    }
    const work = (async () => {
      for (const { workspace, sandbox } of targets.values()) {
        let fields: Obj = { for_seq: commitSeq, workspace, sandbox };
        for (let attempt = 1; attempt <= 3; attempt += 1) {
          fields = { for_seq: commitSeq, workspace, sandbox };
          try {
            fields.sandbox_id = await reader.getSandboxId(workspace, sandbox);
            fields.chunks = await reader.getDraftChunks(workspace, sandbox);
            fields.revisions = (await reader.listPolicyRevisions(workspace, sandbox)).map((r) => ({ version: r.version, policy_hash: r.policy_hash, status: r.status }));
            break;
          } catch (error) {
            fields.error = error instanceof Error ? error.message : String(error);
            fields.attempts = attempt;
            if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
          }
        }
        if (Array.isArray(fields.chunks)) {
          // A validate whose chunks the gateway now shows as approved cannot
          // commit again; stop reading its sandbox on its behalf.
          const approved = new Set((fields.chunks as { chunk_id: string; status: string }[]).filter((c) => c.status === 'approved').map((c) => c.chunk_id));
          for (let i = pending.length - 1; i >= 0; i -= 1) {
            const v = pending[i];
            if (v.workspace === workspace && v.sandbox === sandbox && v.chunkIds.length > 0 && v.chunkIds.every((id) => approved.has(id))) pending.splice(i, 1);
          }
        }
        try {
          log.append('gateway_read', fields);
        } catch (error) {
          process.stderr.write(`observer: failed to log gateway read for seq ${commitSeq}: ${String(error)}\n`);
        }
      }
      options.onReadDone?.(commitSeq);
    })();
    inFlight.add(work);
    void work.finally(() => inFlight.delete(work));
  }

  const implementation = {
    Describe(call: grpc.ServerUnaryCall<Obj, Obj>, callback: grpc.sendUnaryData<Obj>): void {
      const auth = authOf(call);
      const gateway = (call.request?.gateway ?? {}) as Obj;
      try {
        log.append('describe', { gateway_auth: auth, gateway_peer: gateway });
      } catch (error) {
        process.stderr.write(`observer: failed to log describe: ${String(error)}\n`);
      }
      if (auth.mode === 'failed') {
        callback({ code: grpc.status.UNAUTHENTICATED, details: `gateway JWT refused: ${auth.reason}` });
        return;
      }
      const version = (gateway.protocol_version ?? {}) as Obj;
      if (version.major !== undefined && version.major !== 1) {
        callback({ code: grpc.status.FAILED_PRECONDITION, details: `unsupported extension protocol major ${String(version.major)}` });
        return;
      }
      const required = Array.isArray(gateway.required_capabilities) ? gateway.required_capabilities : [];
      const unmet = required.filter((cap) => cap !== CONTRACT_CAPABILITY);
      if (unmet.length > 0) {
        callback({ code: grpc.status.FAILED_PRECONDITION, details: `gateway requires unsupported capabilities: ${unmet.join(', ')}` });
        return;
      }
      callback(null, {
        name,
        bindings: OBSERVED_METHODS.map((method) => ({
          id: `observe-${method}`,
          selector: { rpc: `openshell.v1.OpenShell/${method}` },
          phases: ['GATEWAY_INTERCEPTOR_PHASE_VALIDATE', 'GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT'],
          failure_policy: 'fail_open',
        })),
        failure_policy: 'fail_open',
        provider_profiles: false,
        expected_audience: jwtPolicy ? audience : '',
        extension: {
          protocol_version: { major: 1, minor: 0 },
          implementation_name: IMPLEMENTATION_NAME,
          implementation_version: IMPLEMENTATION_VERSION,
          supported_capabilities: [CONTRACT_CAPABILITY],
          required_capabilities: [CONTRACT_CAPABILITY],
        },
      });
    },

    SnapshotProviderProfiles(_call: grpc.ServerUnaryCall<Obj, Obj>, callback: grpc.sendUnaryData<Obj>): void {
      callback({ code: grpc.status.UNIMPLEMENTED, details: 'this interceptor is not a provider profile source' });
    },

    Evaluate(call: grpc.ServerUnaryCall<Obj, Obj>, callback: grpc.sendUnaryData<Obj>): void {
      // Every path below answers allowed=true with no patches. Errors are
      // logged, never turned into a denial.
      let annotations: Record<string, string> = {};
      try {
        const evaluation = (call.request ?? {}) as Obj;
        const auth = authOf(call);
        const phase = str(evaluation.phase) || 'unknown';
        const method = str(evaluation.method);
        const phaseBody = (evaluation[phase] ?? {}) as Obj;
        const struct = phase === 'post_commit' ? phaseBody.committed_response : phaseBody.proposed_operation;
        const converted = structToJson(struct);
        const principal = (evaluation.principal ?? {}) as Obj;
        const fields: Obj = {
          phase,
          service: str(evaluation.service),
          method,
          binding_id: str(evaluation.binding_id),
          interceptor_name: str(evaluation.interceptor_name),
          principal: principal as Json,
          gateway_auth: auth,
          // Names only, never values: shows which metadata the gateway sends.
          metadata_keys: Object.keys(call.metadata.getMap()).sort(),
        };
        if (converted.ok) fields.payload = converted.value;
        else fields.payload_error = converted.reason;
        const record = log.append('evaluation', fields);
        annotations = { emilia_observer_seq: String(record.seq), emilia_observer_phase: phase };
        if (auth.mode !== 'failed' && converted.ok && (OBSERVED_METHODS as readonly string[]).includes(method)) {
          const key = principalKey(principal);
          if (phase === 'validate') {
            const payload = converted.value as Obj;
            const scope = (payload.workspaceScope ?? {}) as Obj;
            const named = method === 'ApproveDraftChunk'
              ? [str(payload.chunkId)]
              : (Array.isArray(payload.approvals) ? payload.approvals : []).map((a) => str((a as Obj | null)?.chunkId));
            pending.push({ seq: record.seq, at: Date.now(), method, principalKey: key, workspace: str(scope.workspace), sandbox: str(payload.sandbox), chunkIds: named.filter(Boolean) });
            if (pending.length > 10_000) pending.shift();
          } else if (phase === 'post_commit') {
            setImmediate(() => scheduleReads(record.seq, method, key));
          }
        }
      } catch (error) {
        process.stderr.write(`observer: evaluation not logged: ${error instanceof Error ? error.message : String(error)}\n`);
      }
      callback(null, { allowed: true, reason: '', status_code: '', patches: [], log_annotations: annotations });
    },
  };

  const server = new grpc.Server();
  server.addService(serviceDefinition(INTERCEPTOR_SERVICE), implementation as unknown as grpc.UntypedServiceImplementation);
  const address = await new Promise<string>((resolve, reject) => {
    const credentials = options.tls
      ? grpc.ServerCredentials.createSsl(null, [{ cert_chain: options.tls.certPem, private_key: options.tls.keyPem }], false)
      : grpc.ServerCredentials.createInsecure();
    server.bindAsync(options.listen, credentials, (error, port) => {
      if (error) reject(error);
      else resolve(options.listen.startsWith('unix:') ? options.listen : options.listen.replace(/:\d+$/, `:${port}`));
    });
  });

  return {
    address,
    log,
    audience,
    idle: async () => {
      await new Promise((resolve) => setImmediate(resolve));
      while (inFlight.size > 0) await Promise.allSettled([...inFlight]);
    },
    close: async () => {
      await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
      while (inFlight.size > 0) await Promise.allSettled([...inFlight]);
      log.close();
    },
  };
}
