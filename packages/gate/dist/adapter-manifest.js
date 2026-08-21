// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
// Signed, source-locked adapter inventory. This identifies the external
// revision, implementation build, and conformance receipt a relying party
// chose. It does not prove the external system's behavior or deployment.
import { RISK_DIGEST, riskClone, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
export const ADAPTER_MANIFEST_VERSION = 'EP-ADAPTER-MANIFEST-v1';
export const ADAPTER_MANIFEST_CLAIM_BOUNDARY = 'signed_adapter_revision_and_receipt_references_not_external_system_behavior_deployment_or_conformance_truth';
const BODY_KEYS = [
    '@version', 'adapter_id', 'system', 'version', 'status', 'issued_at',
    'valid_from', 'expires_at', 'external_spec', 'implementation',
    'build_receipt_digest', 'conformance', 'supported_operations',
    'claim_boundary',
];
const EXTERNAL_KEYS = ['name', 'revision', 'digest', 'uri'];
const IMPLEMENTATION_KEYS = ['artifact_digest', 'source_commit'];
const CONFORMANCE_KEYS = ['profile_id', 'profile_revision', 'receipt_digest', 'passed_at'];
const STATUS = new Set(['active', 'withdrawn', 'test_only']);
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
function canonicalOperations(value) {
    return Array.isArray(value) && value.length > 0 && value.length <= 256
        && value.every((entry) => riskIdentifier(entry))
        && new Set(value).size === value.length
        && value.every((entry, index) => index === 0 || value[index - 1] < entry);
}
function validHttpsUri(value) {
    try {
        return typeof value === 'string' && value.length <= 2048 && new URL(value).protocol === 'https:';
    }
    catch {
        return false;
    }
}
function validateBody(value) {
    if (!riskRecord(value))
        throw new TypeError('adapter_manifest_shape_invalid');
    const { issuer, proof: _proof, ...body } = value;
    if (issuer !== undefined && (!riskExact(issuer, ['id', 'key_id'])
        || !riskIdentifier(issuer.id) || !riskIdentifier(issuer.key_id))) {
        throw new TypeError('adapter_manifest_issuer_invalid');
    }
    if (!riskExact(body, BODY_KEYS)
        || body['@version'] !== ADAPTER_MANIFEST_VERSION
        || !riskIdentifier(body.adapter_id) || !riskIdentifier(body.system)
        || !Number.isSafeInteger(body.version) || body.version < 1
        || !STATUS.has(body.status)
        || !riskExact(body.external_spec, EXTERNAL_KEYS)
        || !riskIdentifier(body.external_spec.name)
        || !riskIdentifier(body.external_spec.revision)
        || typeof body.external_spec.digest !== 'string'
        || !RISK_DIGEST.test(body.external_spec.digest)
        || !validHttpsUri(body.external_spec.uri)
        || !riskExact(body.implementation, IMPLEMENTATION_KEYS)
        || typeof body.implementation.artifact_digest !== 'string'
        || !RISK_DIGEST.test(body.implementation.artifact_digest)
        || typeof body.implementation.source_commit !== 'string'
        || !COMMIT.test(body.implementation.source_commit)
        || typeof body.build_receipt_digest !== 'string'
        || !RISK_DIGEST.test(body.build_receipt_digest)
        || !riskExact(body.conformance, CONFORMANCE_KEYS)
        || !riskIdentifier(body.conformance.profile_id)
        || !riskIdentifier(body.conformance.profile_revision)
        || typeof body.conformance.receipt_digest !== 'string'
        || !RISK_DIGEST.test(body.conformance.receipt_digest)
        || !canonicalOperations(body.supported_operations)
        || body.claim_boundary !== ADAPTER_MANIFEST_CLAIM_BOUNDARY) {
        throw new TypeError('adapter_manifest_shape_invalid');
    }
    const issued = riskInstant(body.issued_at);
    const validFrom = riskInstant(body.valid_from);
    const expires = riskInstant(body.expires_at);
    const passed = riskInstant(body.conformance.passed_at);
    if (!Number.isFinite(issued) || !Number.isFinite(validFrom)
        || !Number.isFinite(expires) || !Number.isFinite(passed)
        || passed > issued || validFrom < issued || expires <= validFrom) {
        throw new TypeError('adapter_manifest_window_invalid');
    }
}
export function signAdapterManifest(input, signer) {
    if (!riskRecord(input) || !Array.isArray(input.supported_operations)) {
        throw new TypeError('adapter_manifest_input_invalid');
    }
    const body = {
        '@version': ADAPTER_MANIFEST_VERSION,
        adapter_id: input.adapter_id,
        system: input.system,
        version: input.version,
        status: input.status,
        issued_at: input.issued_at,
        valid_from: input.valid_from,
        expires_at: input.expires_at,
        external_spec: input.external_spec,
        implementation: input.implementation,
        build_receipt_digest: input.build_receipt_digest,
        conformance: input.conformance,
        supported_operations: [...input.supported_operations].sort(),
        claim_boundary: ADAPTER_MANIFEST_CLAIM_BOUNDARY,
    };
    validateBody(body);
    return signRiskBody(ADAPTER_MANIFEST_VERSION, body, signer);
}
export function loadAdapterManifestRegistry({ manifests, trusted_keys, now = Date.now(), }) {
    if (!Array.isArray(manifests) || manifests.length < 1 || manifests.length > 1024) {
        throw new TypeError('adapter registry requires a bounded manifest set');
    }
    const rawNow = typeof now === 'function' ? now() : now;
    const at = typeof rawNow === 'string' ? riskInstant(rawNow) : rawNow;
    if (!Number.isFinite(at))
        throw new TypeError('adapter registry time is invalid');
    const byId = new Map();
    for (const artifact of manifests) {
        validateBody(artifact);
        const verified = verifyRiskBody(artifact, ADAPTER_MANIFEST_VERSION, trusted_keys);
        if (!verified.valid || !verified.body) {
            throw new TypeError(`adapter registry verification failed: ${verified.reason}`);
        }
        const body = verified.body;
        validateBody(body);
        if (at < riskInstant(body.valid_from)) {
            throw new TypeError(`adapter registry manifest not yet valid: ${body.adapter_id}`);
        }
        if (at >= riskInstant(body.expires_at)) {
            throw new TypeError(`adapter registry manifest expired: ${body.adapter_id}`);
        }
        if (byId.has(body.adapter_id)) {
            throw new TypeError(`adapter registry duplicate identity: ${body.adapter_id}`);
        }
        byId.set(body.adapter_id, riskFreeze(riskClone(body)));
    }
    const resolve = (request = {}) => {
        const manifest = byId.get(request.adapter_id);
        if (!manifest)
            return riskFreeze({ ok: false, reason: 'adapter_not_registered', manifest: null });
        if (manifest.status !== 'active') {
            return riskFreeze({ ok: false, reason: 'adapter_not_active', manifest: null });
        }
        if (request.external_spec_digest !== manifest.external_spec.digest) {
            return riskFreeze({ ok: false, reason: 'adapter_external_revision_drift', manifest: null });
        }
        if (request.implementation_digest !== manifest.implementation.artifact_digest) {
            return riskFreeze({ ok: false, reason: 'adapter_implementation_drift', manifest: null });
        }
        if (!manifest.supported_operations.includes(request.operation)) {
            return riskFreeze({ ok: false, reason: 'adapter_operation_unsupported', manifest: null });
        }
        return riskFreeze({ ok: true, reason: null, manifest: riskClone(manifest) });
    };
    return riskFreeze({
        '@version': 'EP-ADAPTER-MANIFEST-REGISTRY-v1',
        claim_boundary: ADAPTER_MANIFEST_CLAIM_BOUNDARY,
        size: byId.size,
        adapter_ids: [...byId.keys()].sort(),
        resolve,
    });
}
export default {
    ADAPTER_MANIFEST_VERSION,
    ADAPTER_MANIFEST_CLAIM_BOUNDARY,
    signAdapterManifest,
    loadAdapterManifestRegistry,
};
//# sourceMappingURL=adapter-manifest.js.map