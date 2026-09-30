// SPDX-License-Identifier: Apache-2.0
// Generated from gateway-client.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Minimal OpenShell gateway client: the reads the observer, the approver CLI
// and the policy-chain export need, plus the two approval calls the end-to-end
// test drives. It uses the caller's own credential; nothing here is privileged.
import fs from 'node:fs';
import grpc from '@grpc/grpc-js';
import protobuf from 'protobufjs';
import { canonicalRule, jcs, sha256Hex } from './canonical.ts';
import { OPENSHELL_SERVICE, TO_OBJECT, lookupType, serviceDefinition } from './protos.ts';
function parseEndpoint(endpoint, caPem) {
    if (endpoint.startsWith('unix:'))
        return { target: endpoint, credentials: grpc.credentials.createInsecure() };
    if (endpoint.startsWith('https://')) {
        return { target: endpoint.slice('https://'.length).replace(/\/$/, ''), credentials: grpc.credentials.createSsl(caPem ?? null) };
    }
    const target = endpoint.startsWith('http://') ? endpoint.slice('http://'.length).replace(/\/$/, '') : endpoint;
    return { target, credentials: grpc.credentials.createInsecure() };
}
function timestampToIso(value) {
    if (!value || typeof value !== 'object')
        return null;
    const { seconds, nanos } = value;
    const s = typeof seconds === 'string' ? Number(seconds) : typeof seconds === 'number' ? seconds : 0;
    const n = typeof nanos === 'number' ? nanos : 0;
    if (!Number.isFinite(s))
        return null;
    return new Date(s * 1000 + Math.floor(n / 1e6)).toISOString();
}
/**
 * Split a length-delimited protobuf message into the raw bytes of every
 * occurrence of one field number. Used to hold the exact proposed_rule bytes
 * the gateway sent next to what this build decodes from them.
 */
function rawFieldOccurrences(bytes, fieldNumber) {
    const reader = protobuf.Reader.create(bytes);
    const found = [];
    while (reader.pos < reader.len) {
        const tag = reader.uint32();
        const wireType = tag & 7;
        if ((tag >>> 3) === fieldNumber && wireType === 2) {
            found.push(reader.bytes());
        }
        else {
            reader.skipType(wireType);
        }
    }
    return found;
}
const policyChunkType = () => lookupType('openshell.v1.PolicyChunk');
const ruleType = () => lookupType('openshell.sandbox.v1.NetworkPolicyRule');
/** Inspect every message and map entry before decoding can discard unknown fields. */
function requireModeledFields(type, bytes, depth = 0) {
    if (depth > 32)
        throw new Error('rule nesting is deeper than 32');
    const reader = protobuf.Reader.create(bytes);
    while (reader.pos < reader.len) {
        const tag = reader.uint32();
        const field = type.fieldsById[tag >>> 3];
        const wireType = tag & 7;
        if (!field)
            throw new Error(`unknown field ${tag >>> 3} in ${type.fullName}`);
        field.resolve();
        if (field.map) {
            if (wireType !== 2)
                throw new Error(`invalid wire type for map ${field.fullName}`);
            const entry = protobuf.Reader.create(reader.bytes());
            while (entry.pos < entry.len) {
                const entryTag = entry.uint32();
                const entryField = entryTag >>> 3;
                const entryWireType = entryTag & 7;
                if (entryField !== 1 && entryField !== 2)
                    throw new Error(`unknown map-entry field ${entryField} in ${field.fullName}`);
                if (entryField === 2 && field.resolvedType instanceof protobuf.Type) {
                    if (entryWireType !== 2)
                        throw new Error(`invalid wire type for map value ${field.fullName}`);
                    requireModeledFields(field.resolvedType, entry.bytes(), depth + 1);
                }
                else
                    entry.skipType(entryWireType);
            }
        }
        else if (field.resolvedType instanceof protobuf.Type) {
            if (wireType !== 2)
                throw new Error(`invalid wire type for message ${field.fullName}`);
            requireModeledFields(field.resolvedType, reader.bytes(), depth + 1);
        }
        else
            reader.skipType(wireType);
    }
}
/**
 * Decode one PolicyChunk from its wire bytes. The rule digest is computed only
 * when every wire field is modeled by this build, including nested messages
 * and map entries. Re-encoding must also preserve the wire size. Equal sizes
 * alone are not enough: omitted map defaults can expand and mask the bytes
 * lost when an unknown field is discarded.
 */
export function chunkViewFromBytes(chunkBytes) {
    const chunk = policyChunkType().toObject(policyChunkType().decode(chunkBytes), TO_OBJECT);
    const view = {
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
    try {
        requireModeledFields(ruleType(), ruleBytes);
    }
    catch (error) {
        view.rule_error = `proposed_rule cannot be fully modeled by the pinned protos (the gateway schema may be newer than the pinned protos): ${error instanceof Error ? error.message : String(error)}`;
        return view;
    }
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
    client;
    opts;
    definition = serviceDefinition(OPENSHELL_SERVICE);
    constructor(opts) {
        this.opts = opts;
        const { target, credentials } = parseEndpoint(opts.endpoint, opts.caPem);
        this.client = new grpc.Client(target, credentials);
    }
    static fromCli(endpoint, tokenFile, caFile) {
        return new GatewayClient({
            endpoint,
            bearerToken: tokenFile ? fs.readFileSync(tokenFile, 'utf8').trim() : undefined,
            caPem: caFile ? fs.readFileSync(caFile) : undefined,
        });
    }
    close() {
        this.client.close();
    }
    metadata() {
        const md = new grpc.Metadata();
        if (this.opts.bearerToken)
            md.set('authorization', `Bearer ${this.opts.bearerToken}`);
        return md;
    }
    unary(method, request, raw = false) {
        const def = this.definition[method];
        const deserialize = raw ? (bytes) => bytes : def.responseDeserialize;
        return new Promise((resolve, reject) => {
            this.client.makeUnaryRequest(def.path, def.requestSerialize, deserialize, request, this.metadata(), { deadline: Date.now() + (this.opts.deadlineMs ?? 5000) }, (error, value) => (error ? reject(error) : resolve(value)));
        });
    }
    /** The sandbox's id and the provider names its spec attaches. */
    async getSandbox(workspace, name) {
        const response = await this.unary('GetSandbox', { name, workspace_scope: { workspace } });
        const sandbox = response.sandbox;
        const metadata = sandbox?.metadata;
        const id = metadata?.id;
        if (typeof id !== 'string' || id.length === 0)
            throw new Error(`GetSandbox returned no id for ${workspace}/${name}`);
        const spec = sandbox?.spec;
        const providers = Array.isArray(spec?.providers) ? spec.providers.filter((p) => typeof p === 'string') : [];
        return { id, providers };
    }
    async getSandboxId(workspace, name) {
        return (await this.getSandbox(workspace, name)).id;
    }
    /** Every sandbox in one workspace, as { sandbox: name, sandbox_id }. */
    async listSandboxes(workspace, maxPages = 50) {
        const out = [];
        let pageToken = '';
        for (let page = 0; page < maxPages; page += 1) {
            const response = await this.unary('ListSandboxes', { page_size: 1000, page_token: pageToken, workspace_scope: { workspace } });
            for (const sandbox of response.sandboxes ?? []) {
                const metadata = sandbox.metadata;
                const name = metadata?.name;
                const id = metadata?.id;
                if (typeof name !== 'string' || name.length === 0 || typeof id !== 'string' || id.length === 0)
                    throw new Error('ListSandboxes returned a sandbox without a name or id');
                out.push({ sandbox: name, sandbox_id: id });
            }
            pageToken = typeof response.next_page_token === 'string' ? response.next_page_token : '';
            if (!pageToken)
                return out.sort((a, b) => a.sandbox.localeCompare(b.sandbox));
        }
        throw new Error(`ListSandboxes did not finish within ${maxPages} pages`);
    }
    async getDraftChunks(workspace, sandbox, statusFilter = '') {
        const bytes = await this.unary('GetDraftPolicy', { sandbox, status_filter: statusFilter, workspace_scope: { workspace } }, true);
        return rawFieldOccurrences(bytes, 1).map((chunkBytes) => chunkViewFromBytes(chunkBytes));
    }
    async listPolicyRevisions(workspace, sandbox, maxPages = 50) {
        const revisions = [];
        let pageToken = '';
        for (let page = 0; page < maxPages; page += 1) {
            const response = await this.unary('ListSandboxPolicies', {
                sandbox, page_size: 1000, page_token: pageToken, workspace_scope: { workspace },
            });
            for (const revision of response.revisions ?? []) {
                revisions.push({
                    version: typeof revision.version === 'number' ? revision.version : 0,
                    policy_hash: typeof revision.policy_hash === 'string' ? revision.policy_hash : '',
                    status: typeof revision.status === 'string' ? revision.status : 'POLICY_STATUS_UNSPECIFIED',
                });
            }
            pageToken = typeof response.next_page_token === 'string' ? response.next_page_token : '';
            if (!pageToken)
                return revisions.sort((a, b) => a.version - b.version);
        }
        throw new Error(`ListSandboxPolicies did not finish within ${maxPages} pages`);
    }
    async approveDraftChunk(workspace, sandbox, chunkId, reviewToken, requestId = '') {
        const response = await this.unary('ApproveDraftChunk', {
            sandbox, chunk_id: chunkId, review_token: reviewToken, request_id: requestId, workspace_scope: { workspace },
        });
        return {
            policy_version: typeof response.policy_version === 'number' ? response.policy_version : 0,
            policy_hash: typeof response.policy_hash === 'string' ? response.policy_hash : '',
        };
    }
    async approveAllDraftChunks(workspace, sandbox, approvals) {
        return this.unary('ApproveAllDraftChunks', { sandbox, approvals, workspace_scope: { workspace } });
    }
}
