// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Declared-surface coverage for EMILIA Gate.
 *
 * `gated` is intentionally hard to earn: a fresh workload attestation proves
 * the expected Gate is running, and a separately pinned active probe proves the
 * named surface refuses a canary action without a receipt. A passive witness by
 * itself is reported as `witness_only`, never as enforcement.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { verifyDeploymentAttestation, deploymentProfileDigest } from './deployment-attestation.js';
import { NETWORK_WITNESS_EVENTS, acceptNetworkWitnessStatement, networkWitnessDigest, validateTrustedNetworkWitnessAcceptance, } from './network-witness.js';
import { strictJsonGate } from './strict-json.js';
import { signAgileSet, verifyAgileSignatureSet, } from '@emilia-protocol/verify/pq-signature-agility';
export const COVERAGE_INVENTORY_VERSION = 'EP-GATE-COVERAGE-INVENTORY-v1';
export const COVERAGE_REPORT_VERSION = 'EP-GATE-COVERAGE-REPORT-v1';
export const ENFORCEMENT_PROBE_VERSION = 'EP-GATE-ENFORCEMENT-PROBE-v1';
export const COVERAGE_STATES = Object.freeze(['gated', 'witness_only', 'ungated', 'stale', 'unknown']);
export const PROBE_RESULTS = Object.freeze(['blocked_without_receipt', 'executed_without_receipt', 'indeterminate']);
const PROBE_DOMAIN = `${ENFORCEMENT_PROBE_VERSION}\0`;
const MAX_EVIDENCE_ITEMS = 50_000;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function string(value, max = 512) {
    return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}
function digest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function exactKeys(value, allowed) {
    return isPlainObject(value) && Object.keys(value).every((key) => allowed.has(key));
}
function strictInstantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339);
    if (!match)
        return NaN;
    const [, y, m, d, h, min, s] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(y), Number(m) - 1, Number(d));
    calendar.setUTCHours(Number(h), Number(min), Number(s), 0);
    if (calendar.toISOString().slice(0, 19) !== `${y}-${m}-${d}T${h}:${min}:${s}`)
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
function decodeBase64Url(value, maxBytes) {
    if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value))
        return null;
    try {
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== value)
            return null;
        return bytes;
    }
    catch {
        return null;
    }
}
function keyIdFor(key) {
    const der = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
    return `ep:probe-key:sha256:${sha256(der).slice(0, 16)}`;
}
function probeBytes(body) {
    return Buffer.from(PROBE_DOMAIN + canonicalize(body), 'utf8');
}
function probeDigest(statement) {
    const { signature: _signature, ...body } = statement;
    return `sha256:${sha256(probeBytes(body))}`;
}
function validateSurface(surface) {
    if (!exactKeys(surface, new Set([
        'surface_id', 'action_family', 'gate_id', 'environment_id', 'deployment_profile_hash',
        'probe_action_digest', 'required', 'witness',
    ])))
        return 'surface_shape_invalid';
    for (const field of ['surface_id', 'action_family', 'gate_id', 'environment_id']) {
        if (!string(surface[field]))
            return `surface_${field}_invalid`;
    }
    if (!digest(surface.deployment_profile_hash) || !digest(surface.probe_action_digest)) {
        return 'surface_digest_invalid';
    }
    if (surface.required !== true && surface.required !== false)
        return 'surface_required_invalid';
    if (surface.witness !== undefined) {
        if (!exactKeys(surface.witness, new Set(['witness_id', 'capture_point_id', 'event', 'required']))) {
            return 'surface_witness_shape_invalid';
        }
        if (!string(surface.witness.witness_id) || !string(surface.witness.capture_point_id)
            || !NETWORK_WITNESS_EVENTS.includes(surface.witness.event)
            || (surface.witness.required !== true && surface.witness.required !== false)) {
            return 'surface_witness_invalid';
        }
    }
    return null;
}
function validateInventory(inventory) {
    if (!exactKeys(inventory, new Set(['@version', 'inventory_id', 'surfaces'])))
        return 'inventory_shape_invalid';
    if (inventory['@version'] !== COVERAGE_INVENTORY_VERSION)
        return 'inventory_version_invalid';
    if (!string(inventory.inventory_id) || !Array.isArray(inventory.surfaces)
        || inventory.surfaces.length === 0 || inventory.surfaces.length > 10_000)
        return 'inventory_invalid';
    const ids = new Set();
    for (const surface of inventory.surfaces) {
        const invalid = validateSurface(surface);
        if (invalid)
            return invalid;
        if (ids.has(surface.surface_id))
            return 'surface_id_duplicate';
        ids.add(surface.surface_id);
    }
    try {
        canonicalize(inventory);
    }
    catch {
        return 'inventory_canonicalization_invalid';
    }
    return null;
}
export function coverageInventoryDigest(inventory) {
    const invalid = validateInventory(inventory);
    if (invalid)
        throw new TypeError(invalid);
    return `sha256:${hashCanonical(inventory)}`;
}
function validateProbeBody(body, expectedVersion = ENFORCEMENT_PROBE_VERSION) {
    if (!exactKeys(body, new Set(['@version', 'probe', 'test'])))
        return 'probe_shape_invalid';
    if (body['@version'] !== expectedVersion)
        return 'probe_version_invalid';
    if (!exactKeys(body.probe, new Set(['id', 'key_id'])))
        return 'probe_identity_shape_invalid';
    if (!string(body.probe.id) || !string(body.probe.key_id))
        return 'probe_identity_invalid';
    if (!exactKeys(body.test, new Set([
        'surface_id', 'gate_id', 'environment_id', 'action_family', 'action_digest',
        'tested_at', 'nonce', 'result', 'response_status',
    ])))
        return 'probe_test_shape_invalid';
    for (const field of ['surface_id', 'gate_id', 'environment_id', 'action_family', 'nonce']) {
        if (!string(body.test[field], 1024))
            return `probe_${field}_invalid`;
    }
    if (!digest(body.test.action_digest) || !Number.isFinite(strictInstantMs(body.test.tested_at))) {
        return 'probe_binding_invalid';
    }
    if (!PROBE_RESULTS.includes(body.test.result))
        return 'probe_result_invalid';
    if (!Number.isSafeInteger(body.test.response_status)
        || body.test.response_status < 100 || body.test.response_status > 599)
        return 'probe_status_invalid';
    if (body.test.result === 'blocked_without_receipt' && body.test.response_status !== 428) {
        return 'probe_block_status_invalid';
    }
    try {
        canonicalize(body);
    }
    catch {
        return 'probe_canonicalization_invalid';
    }
    return null;
}
export function signEnforcementProbe(input, privateKey) {
    if (!privateKey)
        throw new TypeError('privateKey is required');
    const keyId = input?.key_id ?? keyIdFor(privateKey);
    const body = {
        '@version': ENFORCEMENT_PROBE_VERSION,
        probe: { id: input?.probe_id, key_id: keyId },
        test: {
            surface_id: input?.surface_id,
            gate_id: input?.gate_id,
            environment_id: input?.environment_id,
            action_family: input?.action_family,
            action_digest: input?.action_digest,
            tested_at: input?.tested_at,
            nonce: input?.nonce,
            result: input?.result,
            response_status: input?.response_status,
        },
    };
    const invalid = validateProbeBody(body);
    if (invalid)
        throw new TypeError(invalid);
    const statementDigest = probeDigest(body);
    return Object.freeze({
        ...body,
        signature: Object.freeze({
            algorithm: 'Ed25519',
            key_id: keyId,
            statement_digest: statementDigest,
            signature_b64u: crypto.sign(null, probeBytes(body), privateKey).toString('base64url'),
        }),
    });
}
/** Duplicate-key-safe parser for an untrusted serialized probe artifact. */
export function parseEnforcementProbeStatement(raw, { maxBytes = 64 * 1024 } = {}) {
    if (typeof raw !== 'string' || !Number.isSafeInteger(maxBytes) || maxBytes < 1
        || Buffer.byteLength(raw, 'utf8') > maxBytes)
        return null;
    if (!strictJsonGate(raw).ok)
        return null;
    try {
        const parsed = JSON.parse(raw);
        return isPlainObject(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
}
function findProbePin(pins, probeId, keyId) {
    if (!Array.isArray(pins))
        return null;
    return pins.find((pin) => isPlainObject(pin) && pin.probe_id === probeId && pin.key_id === keyId) ?? null;
}
export function verifyEnforcementProbe(statement, options = {}) {
    const refuse = (reason) => ({ accepted: false, verified: false, reason });
    try {
        if (!exactKeys(statement, new Set(['@version', 'probe', 'test', 'signature'])))
            return refuse('probe_shape_invalid');
        const { signature, ...body } = statement;
        const invalid = validateProbeBody(body);
        if (invalid)
            return refuse(invalid);
        if (!exactKeys(signature, new Set(['algorithm', 'key_id', 'statement_digest', 'signature_b64u']))
            || signature.algorithm !== 'Ed25519' || signature.key_id !== body.probe.key_id
            || !digest(signature.statement_digest) || !string(signature.signature_b64u, 512)) {
            return refuse('probe_signature_envelope_invalid');
        }
        const pin = findProbePin(options.pinnedProbes, body.probe.id, body.probe.key_id);
        if (!pin || !string(pin.public_key, 4096))
            return refuse('probe_key_unpinned');
        if (!Array.isArray(pin.surface_ids) || !pin.surface_ids.includes(body.test.surface_id)) {
            return refuse('probe_surface_unpinned');
        }
        const expected = options.expectedSurface;
        if (isPlainObject(expected)) {
            if (body.test.surface_id !== expected.surface_id || body.test.gate_id !== expected.gate_id
                || body.test.environment_id !== expected.environment_id
                || body.test.action_family !== expected.action_family
                || body.test.action_digest !== expected.probe_action_digest)
                return refuse('probe_context_mismatch');
        }
        const now = options.now === undefined ? Date.now() : Number(options.now);
        const maxAgeSec = options.maxAgeSec === undefined ? 300 : options.maxAgeSec;
        const maxFutureSkewSec = options.maxFutureSkewSec === undefined ? 30 : options.maxFutureSkewSec;
        if (!Number.isFinite(now) || !Number.isSafeInteger(maxAgeSec) || maxAgeSec < 0
            || !Number.isSafeInteger(maxFutureSkewSec) || maxFutureSkewSec < 0)
            return refuse('probe_profile_invalid');
        const testedAt = strictInstantMs(body.test.tested_at);
        if (testedAt > now + maxFutureSkewSec * 1000)
            return refuse('probe_from_future');
        if (now - testedAt > maxAgeSec * 1000)
            return refuse('probe_stale');
        const computed = probeDigest(body);
        if (computed !== signature.statement_digest)
            return refuse('probe_digest_mismatch');
        let key;
        try {
            const keyBytes = decodeBase64Url(pin.public_key, 4096);
            if (!keyBytes)
                throw new TypeError('invalid base64url key');
            key = crypto.createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
            if (key.asymmetricKeyType !== 'ed25519')
                throw new TypeError('probe key must be Ed25519');
        }
        catch {
            return refuse('probe_pinned_key_invalid');
        }
        const signatureBytes = decodeBase64Url(signature.signature_b64u, 64);
        if (!signatureBytes || signatureBytes.length !== 64
            || !crypto.verify(null, probeBytes(body), key, signatureBytes)) {
            return refuse('probe_signature_invalid');
        }
        return {
            accepted: true,
            verified: true,
            reason: null,
            statement_digest: computed,
            tested_at: body.test.tested_at,
            result: body.test.result,
            response_status: body.test.response_status,
            nonce: body.test.nonce,
            surface_id: body.test.surface_id,
            action_digest: body.test.action_digest,
            gate_id: body.test.gate_id,
            environment_id: body.test.environment_id,
            action_family: body.test.action_family,
            probe_id: body.probe.id,
        };
    }
    catch {
        return refuse('hostile_probe_refused');
    }
}
// ===========================================================================
// EP-GATE-ENFORCEMENT-PROBE-v2 -- hybrid (Ed25519 + ML-DSA-65) probe statement
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the probe:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the proof, a wire-format change, so the probe takes a new `@version`
 *    (EP-GATE-ENFORCEMENT-PROBE-v1 -> -v2). verifyEnforcementProbe() above is
 *    untouched: validateProbeBody(body) still defaults to the v1 version, so
 *    it refuses a v2 body's `@version` with `probe_version_invalid` before any
 *    signature inspection, and never throws.
 * 2. SET SHAPE. `signature` is replaced by `proof`, carrying
 *    `required_algorithms` plus a `signatures` array shaped exactly like
 *    EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (probeV2Bytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 probes keep verifying, unchanged, through
 *    verifyEnforcementProbe. v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point; verifyEnforcementProbeAny()
 *    routes on `@version`. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named reason; nothing
 *    throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable', never a skipped check and never a pass on the
 *    classical leg alone.
 *
 * The pinned-probe catalog entry (found via probe_id + key_id, exactly as v1)
 * carries BOTH `public_key` and `pq_public_key` for a v2 probe; a pin missing
 * either half confers nothing. Coverage evaluation (evaluateGateCoverage)
 * remains v1-only here; a v2 probe must be verified through
 * verifyEnforcementProbeV2 (or the Any router) before its acceptance result is
 * folded into a coverage report by the caller.
 */
export const ENFORCEMENT_PROBE_V2_VERSION = 'EP-GATE-ENFORCEMENT-PROBE-v2';
const PROBE_V2_DOMAIN = `${ENFORCEMENT_PROBE_V2_VERSION}\0`;
/** The registered required algorithm set, in canonical order. */
export const ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
function probeV2AlgorithmSetRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * The bytes BOTH legs sign: the same body v1 signs (`@version`, `probe`,
 * `test`) plus the committed `required_algorithms` set, under the v2 domain
 * tag. Recomputed independently by the verifier from the PRESENTED body and
 * the REGISTERED set.
 */
export function probeV2Bytes(body, requiredAlgorithms = ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS) {
    if (!probeV2AlgorithmSetRegistered(requiredAlgorithms)) {
        throw new TypeError('probeV2Bytes: algorithm set is not the registered EP-GATE-ENFORCEMENT-PROBE-v2 set');
    }
    return Buffer.from(`${PROBE_V2_DOMAIN}${canonicalize({ ...body, required_algorithms: [...requiredAlgorithms] })}`, 'utf8');
}
/** Mint a real hybrid probe statement. Throws on issuer misuse (never on caller input; there is none). */
export async function signEnforcementProbeV2(input, signers, options = {}) {
    const keyId = input?.key_id;
    if (!string(keyId))
        throw new TypeError('signEnforcementProbeV2: key_id is required');
    const body = {
        '@version': ENFORCEMENT_PROBE_V2_VERSION,
        probe: { id: input?.probe_id, key_id: keyId },
        test: {
            surface_id: input?.surface_id,
            gate_id: input?.gate_id,
            environment_id: input?.environment_id,
            action_family: input?.action_family,
            action_digest: input?.action_digest,
            tested_at: input?.tested_at,
            nonce: input?.nonce,
            result: input?.result,
            response_status: input?.response_status,
        },
    };
    const invalid = validateProbeBody(body, ENFORCEMENT_PROBE_V2_VERSION);
    if (invalid)
        throw new TypeError(invalid);
    const bytes = probeV2Bytes(body, ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS);
    const signatures = await signAgileSet(new Uint8Array(bytes), signers, options);
    return Object.freeze({
        ...body,
        proof: Object.freeze({
            profile: ENFORCEMENT_PROBE_V2_VERSION,
            required_algorithms: [...ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS],
            key_id: keyId,
            signatures,
        }),
    });
}
/**
 * FAIL-CLOSED hybrid verifier for one EP-GATE-ENFORCEMENT-PROBE-v2. Never
 * throws on caller input; a v2 probe NEVER verifies on one leg alone.
 */
export async function verifyEnforcementProbeV2(statement, options = {}) {
    const refuse = (reason) => ({ accepted: false, verified: false, reason });
    try {
        if (!exactKeys(statement, new Set(['@version', 'probe', 'test', 'proof'])))
            return refuse('probe_shape_invalid');
        const { proof, ...body } = statement;
        const invalid = validateProbeBody(body, ENFORCEMENT_PROBE_V2_VERSION);
        if (invalid)
            return refuse(invalid);
        if (!exactKeys(proof, new Set(['profile', 'required_algorithms', 'key_id', 'signatures']))
            || proof.profile !== ENFORCEMENT_PROBE_V2_VERSION || proof.key_id !== body.probe.key_id) {
            return refuse('probe_signature_envelope_invalid');
        }
        if (!probeV2AlgorithmSetRegistered(proof.required_algorithms))
            return refuse('probe_algorithm_set_invalid');
        const signatures = Array.isArray(proof.signatures) ? proof.signatures : null;
        if (!signatures || signatures.length === 0)
            return refuse('probe_signature_legs_missing');
        const presented = new Set();
        for (const s of signatures) {
            if (!isPlainObject(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string')
                return refuse('probe_signature_leg_malformed');
            if (presented.has(s.alg))
                return refuse('probe_signature_leg_duplicate');
            presented.add(s.alg);
        }
        for (const alg of presented) {
            if (!ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS.includes(alg))
                return refuse('probe_signature_leg_unexpected');
        }
        for (const alg of ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS) {
            if (!presented.has(alg))
                return refuse('probe_signature_leg_stripped');
        }
        const pin = findProbePin(options.pinnedProbes, body.probe.id, body.probe.key_id);
        if (!pin || !string(pin.public_key, 4096) || !string(pin.pq_public_key, 8192))
            return refuse('probe_key_unpinned');
        if (!Array.isArray(pin.surface_ids) || !pin.surface_ids.includes(body.test.surface_id)) {
            return refuse('probe_surface_unpinned');
        }
        const expected = options.expectedSurface;
        if (isPlainObject(expected)) {
            if (body.test.surface_id !== expected.surface_id || body.test.gate_id !== expected.gate_id
                || body.test.environment_id !== expected.environment_id
                || body.test.action_family !== expected.action_family
                || body.test.action_digest !== expected.probe_action_digest)
                return refuse('probe_context_mismatch');
        }
        const now = options.now === undefined ? Date.now() : Number(options.now);
        const maxAgeSec = options.maxAgeSec === undefined ? 300 : options.maxAgeSec;
        const maxFutureSkewSec = options.maxFutureSkewSec === undefined ? 30 : options.maxFutureSkewSec;
        if (!Number.isFinite(now) || !Number.isSafeInteger(maxAgeSec) || maxAgeSec < 0
            || !Number.isSafeInteger(maxFutureSkewSec) || maxFutureSkewSec < 0)
            return refuse('probe_profile_invalid');
        const testedAt = strictInstantMs(body.test.tested_at);
        if (testedAt > now + maxFutureSkewSec * 1000)
            return refuse('probe_from_future');
        if (now - testedAt > maxAgeSec * 1000)
            return refuse('probe_stale');
        const bytes = probeV2Bytes(body, ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS);
        const verificationKeys = [
            { alg: 'Ed25519', public_key: pin.public_key },
            { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ];
        let setResult = null;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, verificationKeys, {
                mldsaBackend: options.mldsaBackend,
                mldsaBackendLoader: options.mldsaBackendLoader,
                policy: 'hybrid_all',
                requiredAlgorithms: [...ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS],
            });
        }
        catch {
            setResult = null;
        }
        if (setResult?.verified !== true) {
            const reason = String(setResult?.reason ?? 'signature_set_unverified');
            return refuse(`probe_signature_invalid (${reason})`);
        }
        return {
            accepted: true,
            verified: true,
            reason: null,
            statement_digest: `sha256:${sha256(bytes)}`,
            tested_at: body.test.tested_at,
            result: body.test.result,
            response_status: body.test.response_status,
            nonce: body.test.nonce,
            surface_id: body.test.surface_id,
            action_digest: body.test.action_digest,
            gate_id: body.test.gate_id,
            environment_id: body.test.environment_id,
            action_family: body.test.action_family,
            probe_id: body.probe.id,
        };
    }
    catch {
        return refuse('hostile_probe_refused');
    }
}
/** Route a probe statement of EITHER version to its own verifier. */
export async function verifyEnforcementProbeAny(statement, options = {}) {
    if (isPlainObject(statement) && statement['@version'] === ENFORCEMENT_PROBE_V2_VERSION) {
        return verifyEnforcementProbeV2(statement, options);
    }
    return Promise.resolve(verifyEnforcementProbe(statement, options));
}
function deploymentKey(gateId, environmentId, profileHash) {
    return `${gateId}\0${environmentId}\0${profileHash}`;
}
function probeMatchesSurface(probe, surface) {
    return probe?.surface_id === surface.surface_id
        && probe?.gate_id === surface.gate_id
        && probe?.environment_id === surface.environment_id
        && probe?.action_family === surface.action_family
        && probe?.action_digest === surface.probe_action_digest;
}
function reportHash(report) {
    return `sha256:${hashCanonical(report)}`;
}
function canonicalSnapshot(value) {
    return JSON.parse(canonicalize(value));
}
function immutableCanonicalSnapshot(value) {
    const snapshot = canonicalSnapshot(value);
    const stack = [snapshot];
    while (stack.length) {
        const current = stack.pop();
        if (current && typeof current === 'object') {
            for (const child of Object.values(current))
                stack.push(child);
            Object.freeze(current);
        }
    }
    return snapshot;
}
function snapshotExpectedProbeNonces(value, inventory) {
    if (value === undefined || value === null)
        return null;
    if (value instanceof Map) {
        const selected = Object.create(null);
        for (const surface of inventory.surfaces) {
            if (value.has(surface.surface_id))
                selected[surface.surface_id] = value.get(surface.surface_id);
        }
        return immutableCanonicalSnapshot(selected);
    }
    return immutableCanonicalSnapshot(value);
}
function snapshotEvidenceList(items) {
    const snapshots = [];
    for (const item of items) {
        try {
            snapshots.push(canonicalSnapshot(item));
        }
        catch { /* invalid evidence is ignored */ }
    }
    return snapshots;
}
function witnessCoverageKey(result) {
    if (!string(result?.witness_id) || !string(result?.capture_point_id)
        || !NETWORK_WITNESS_EVENTS.includes(result?.event) || !digest(result?.action_digest))
        return null;
    return `${result.witness_id}\0${result.capture_point_id}\0${result.event}\0${result.action_digest}`;
}
function witnessEvidenceKey(result) {
    if (!string(result?.witness_id) || !string(result?.capture_point_id)
        || !Number.isSafeInteger(result?.sequence) || result.sequence < 0)
        return null;
    return `${result.witness_id}\0${result.capture_point_id}\0${result.sequence}`;
}
function verifiedWitnessPositionKey(result) {
    if (result?.verified !== true || !digest(result?.statement_digest)
        || !string(result?.witness_id) || !string(result?.capture_point_id)
        || !Number.isSafeInteger(result?.sequence) || result.sequence < 0
        || result.stream_id !== `${result.witness_id}\0${result.capture_point_id}`)
        return null;
    return `${result.stream_id}\0${result.sequence}`;
}
/**
 * Evaluate coverage of a relying-party-declared inventory. Inventory
 * completeness remains an explicit external assumption and is never inferred.
 */
export async function evaluateGateCoverage(input = {}, options = {}) {
    let inventory;
    let invalid;
    try {
        invalid = validateInventory(input.inventory);
        inventory = invalid ? input.inventory : immutableCanonicalSnapshot(input.inventory);
    }
    catch {
        invalid = 'inventory_hostile_input';
        inventory = null;
    }
    if (invalid) {
        return {
            '@version': COVERAGE_REPORT_VERSION,
            complete: false,
            reason: invalid,
            inventory_hash: null,
            surfaces: [],
            counts: Object.fromEntries(COVERAGE_STATES.map((state) => [state, 0])),
        };
    }
    let now;
    let attestationVerifiers;
    let pinnedProbes;
    let pinnedWitnesses;
    let expectedProbeNonces;
    let probeMaxAgeSec;
    let witnessMaxAgeSec;
    let maxFutureSkewSec;
    let witnessSequenceStore;
    let allowEphemeralWitnessStore;
    let trustedWitnessAcceptances;
    try {
        now = options.now === undefined ? Date.now() : Number(options.now);
        attestationVerifiers = options.attestationVerifiers;
        pinnedProbes = options.pinnedProbes === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.pinnedProbes);
        pinnedWitnesses = options.pinnedWitnesses === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.pinnedWitnesses);
        expectedProbeNonces = snapshotExpectedProbeNonces(options.expectedProbeNonces, inventory);
        probeMaxAgeSec = options.probeMaxAgeSec;
        witnessMaxAgeSec = options.witnessMaxAgeSec;
        maxFutureSkewSec = options.maxFutureSkewSec;
        witnessSequenceStore = options.witnessSequenceStore;
        allowEphemeralWitnessStore = options.allowEphemeralWitnessStore === true;
        const trustedWitnessInput = options.trustedWitnessAcceptances;
        if (trustedWitnessInput !== undefined
            && (!Array.isArray(trustedWitnessInput) || trustedWitnessInput.length > MAX_EVIDENCE_ITEMS)) {
            throw new TypeError('trusted witness acceptance collection is invalid');
        }
        trustedWitnessAcceptances = [];
        for (const acceptance of Array.isArray(trustedWitnessInput) ? trustedWitnessInput : []) {
            trustedWitnessAcceptances.push(immutableCanonicalSnapshot(acceptance));
        }
        Object.freeze(trustedWitnessAcceptances);
    }
    catch {
        return {
            '@version': COVERAGE_REPORT_VERSION,
            complete: false,
            reason: 'coverage_rp_configuration_invalid',
            inventory_hash: coverageInventoryDigest(inventory),
            surfaces: [],
            counts: Object.fromEntries(COVERAGE_STATES.map((state) => [state, 0])),
        };
    }
    if (!Number.isFinite(now))
        throw new TypeError('coverage now must be finite');
    const lists = {};
    for (const field of ['deployments', 'probes', 'witnesses']) {
        let value;
        try {
            value = input[field];
        }
        catch {
            value = null;
        }
        if (value !== undefined && (!Array.isArray(value) || value.length > MAX_EVIDENCE_ITEMS)) {
            return {
                '@version': COVERAGE_REPORT_VERSION,
                complete: false,
                reason: `coverage_${field}_limit_exceeded`,
                inventory_hash: coverageInventoryDigest(inventory),
                surfaces: [],
                counts: Object.fromEntries(COVERAGE_STATES.map((state) => [state, 0])),
            };
        }
        lists[field] = Array.isArray(value) ? value.slice() : [];
    }
    if (lists.witnesses.length + trustedWitnessAcceptances.length > MAX_EVIDENCE_ITEMS) {
        return {
            '@version': COVERAGE_REPORT_VERSION,
            complete: false,
            reason: 'coverage_witness_evidence_limit_exceeded',
            inventory_hash: coverageInventoryDigest(inventory),
            surfaces: [],
            counts: Object.fromEntries(COVERAGE_STATES.map((state) => [state, 0])),
        };
    }
    // Signed JSON artifacts are copied before the first async verifier call so
    // a shared caller cannot rewrite the evidence set mid-evaluation.
    const probes = snapshotEvidenceList(lists.probes);
    const witnesses = snapshotEvidenceList(lists.witnesses);
    const deployments = [];
    for (const candidate of lists.deployments) {
        try {
            if (!isPlainObject(candidate))
                continue;
            deployments.push({ profile: canonicalSnapshot(candidate.profile), evidence: candidate.evidence });
        }
        catch { /* invalid candidate is ignored */ }
    }
    const deploymentResults = new Map();
    for (const candidate of deployments) {
        let candidateHash;
        try {
            candidateHash = deploymentProfileDigest(candidate.profile);
        }
        catch {
            continue;
        }
        if (!inventory.surfaces.some((surface) => surface.deployment_profile_hash === candidateHash))
            continue;
        const result = await verifyDeploymentAttestation(candidate.evidence, {
            profile: candidate.profile,
            verifiers: attestationVerifiers,
            now,
        });
        const wrapped = {
            ...result,
            gate_id: result.gate_id,
            environment_id: result.environment_id,
            profile_hash: candidateHash,
        };
        const key = deploymentKey(wrapped.gate_id, wrapped.environment_id, wrapped.profile_hash);
        const previous = deploymentResults.get(key);
        if (!previous || wrapped.accepted === true
            || strictInstantMs(wrapped.issued_at) > strictInstantMs(previous.issued_at)) {
            deploymentResults.set(key, wrapped);
        }
    }
    const freshProbes = new Map();
    const historicalProbes = new Map();
    for (const statement of probes) {
        const fresh = verifyEnforcementProbe(statement, {
            pinnedProbes,
            maxAgeSec: probeMaxAgeSec,
            maxFutureSkewSec,
            now,
        });
        if (fresh.accepted) {
            if (!freshProbes.has(fresh.surface_id))
                freshProbes.set(fresh.surface_id, []);
            freshProbes.get(fresh.surface_id).push(fresh);
        }
        const historical = verifyEnforcementProbe(statement, {
            pinnedProbes,
            maxAgeSec: Number.MAX_SAFE_INTEGER,
            maxFutureSkewSec,
            now,
        });
        if (historical.accepted) {
            if (!historicalProbes.has(historical.surface_id))
                historicalProbes.set(historical.surface_id, []);
            historicalProbes.get(historical.surface_id).push(historical);
        }
    }
    const witnessResults = new Map();
    const witnessRefusals = new Map();
    const acceptedWitnessEvidence = new Map();
    const equivocatedWitnessEvidence = new Map();
    const verifiedWitnessEvidence = new Map();
    const trustedByDigest = new Map();
    const indexWitnessAcceptance = (coverageKey, evidenceKey, result) => {
        let bucket = witnessResults.get(coverageKey);
        if (!bucket) {
            bucket = new Map();
            witnessResults.set(coverageKey, bucket);
        }
        bucket.set(evidenceKey, result);
    };
    const recordWitnessRefusal = (coverageKey, result) => {
        const previous = witnessRefusals.get(coverageKey);
        if (!previous || result.reason === 'sequence_equivocation') {
            witnessRefusals.set(coverageKey, result);
        }
    };
    const removeWitnessAcceptance = (evidenceKey) => {
        const previous = acceptedWitnessEvidence.get(evidenceKey) ?? null;
        if (!previous)
            return null;
        acceptedWitnessEvidence.delete(evidenceKey);
        const coverageKey = witnessCoverageKey(previous);
        const bucket = witnessResults.get(coverageKey);
        bucket?.delete(evidenceKey);
        if (bucket?.size === 0)
            witnessResults.delete(coverageKey);
        return previous;
    };
    const recordWitnessEquivocation = (result, evidenceKey, coverageKey, conflictingResult = null) => {
        const previous = removeWitnessAcceptance(evidenceKey);
        equivocatedWitnessEvidence.set(evidenceKey, result);
        recordWitnessRefusal(coverageKey, result);
        for (const candidate of [previous, conflictingResult]) {
            const candidateCoverageKey = witnessCoverageKey(candidate);
            if (candidateCoverageKey) {
                recordWitnessRefusal(candidateCoverageKey, result);
            }
        }
    };
    const recordWitnessResult = (result) => {
        const coverageKey = witnessCoverageKey(result);
        const evidenceKey = witnessEvidenceKey(result);
        if (!coverageKey || !evidenceKey)
            return;
        const verifiedPositionKey = verifiedWitnessPositionKey(result);
        if (verifiedPositionKey) {
            const previousVerified = verifiedWitnessEvidence.get(verifiedPositionKey);
            if (previousVerified?.statement_digest !== undefined
                && previousVerified.statement_digest !== result.statement_digest) {
                recordWitnessEquivocation({ ...result, accepted: false, consumed: false, reason: 'sequence_equivocation' }, evidenceKey, coverageKey, previousVerified);
                return;
            }
            if (!previousVerified)
                verifiedWitnessEvidence.set(verifiedPositionKey, result);
        }
        if (result.reason === 'sequence_equivocation') {
            recordWitnessEquivocation(result, evidenceKey, coverageKey);
            return;
        }
        if (result.accepted === true) {
            const equivocation = equivocatedWitnessEvidence.get(evidenceKey);
            if (equivocation) {
                recordWitnessRefusal(coverageKey, equivocation);
                return;
            }
            const previous = acceptedWitnessEvidence.get(evidenceKey);
            if (previous && previous.statement_digest !== result.statement_digest) {
                recordWitnessEquivocation({ ...result, accepted: false, reason: 'sequence_equivocation' }, evidenceKey, coverageKey);
                return;
            }
            acceptedWitnessEvidence.set(evidenceKey, result);
            indexWitnessAcceptance(coverageKey, evidenceKey, result);
        }
        else if (string(result.reason)) {
            recordWitnessRefusal(coverageKey, result);
        }
    };
    for (const acceptance of trustedWitnessAcceptances) {
        const trusted = validateTrustedNetworkWitnessAcceptance(acceptance, {
            maxAgeSec: witnessMaxAgeSec,
            maxFutureSkewSec,
            now,
            allowEphemeralStore: allowEphemeralWitnessStore,
        });
        recordWitnessResult(trusted);
        if (trusted.accepted === true)
            trustedByDigest.set(trusted.statement_digest, trusted);
    }
    for (const statement of witnesses) {
        let previouslyAccepted = null;
        try {
            previouslyAccepted = trustedByDigest.get(networkWitnessDigest(statement)) ?? null;
        }
        catch { /* ingest below */ }
        if (previouslyAccepted) {
            recordWitnessResult(previouslyAccepted);
            continue;
        }
        const accepted = await acceptNetworkWitnessStatement(statement, {
            pinnedWitnesses,
            maxAgeSec: witnessMaxAgeSec,
            maxFutureSkewSec,
            now,
            sequenceStore: witnessSequenceStore,
            allowEphemeralStore: allowEphemeralWitnessStore,
        });
        recordWitnessResult(accepted);
    }
    const rows = [];
    for (const surface of inventory.surfaces) {
        const deployment = deploymentResults.get(deploymentKey(surface.gate_id, surface.environment_id, surface.deployment_profile_hash)) ?? null;
        const matchingProbes = (freshProbes.get(surface.surface_id) ?? []).filter((probe) => probeMatchesSurface(probe, surface));
        const bypass = matchingProbes.find((probe) => probe.result === 'executed_without_receipt');
        const expectedProbeNonce = isPlainObject(expectedProbeNonces)
            && Object.hasOwn(expectedProbeNonces, surface.surface_id)
            ? expectedProbeNonces[surface.surface_id]
            : null;
        const block = string(expectedProbeNonce, 1024)
            ? matchingProbes.find((probe) => probe.result === 'blocked_without_receipt'
                && probe.nonce === expectedProbeNonce)
            : null;
        let witness = null;
        let witnessRefusal = null;
        if (surface.witness) {
            const key = `${surface.witness.witness_id}\0${surface.witness.capture_point_id}\0${surface.witness.event}\0${surface.probe_action_digest}`;
            const accepted = witnessResults.get(key);
            witness = accepted?.values().next().value ?? null;
            witnessRefusal = witnessRefusals.get(key) ?? null;
        }
        let state = 'unknown';
        let reason = 'active_enforcement_not_proven';
        if (bypass) {
            state = 'ungated';
            reason = 'probe_executed_without_receipt';
        }
        else if (deployment?.accepted === true && block) {
            state = 'gated';
            reason = 'attested_gate_and_refusal_probe';
        }
        else if (witness) {
            state = 'witness_only';
            reason = 'traffic_observed_without_active_enforcement_proof';
        }
        else {
            const staleInput = (historicalProbes.get(surface.surface_id) ?? [])
                .some((probe) => probeMatchesSurface(probe, surface));
            if (staleInput || (deployment && deployment.verdict === 'refuse_stale')) {
                state = 'stale';
                reason = 'coverage_evidence_stale';
            }
        }
        const witnessOk = !surface.witness?.required || Boolean(witness);
        rows.push({
            surface_id: surface.surface_id,
            action_family: surface.action_family,
            required: surface.required,
            state,
            reason,
            deployment_attested: deployment?.accepted === true,
            refusal_probe_verified: Boolean(block),
            bypass_probe_verified: Boolean(bypass),
            probe_nonce_verified: Boolean(block),
            witness_required: surface.witness?.required === true,
            witness_verified: Boolean(witness),
            witness_acceptance_reason: witness
                ? null
                : (witnessRefusal?.reason ?? (surface.witness?.required === true ? 'witness_not_accepted' : null)),
            complete: state === 'gated' && witnessOk,
        });
    }
    const counts = Object.fromEntries(COVERAGE_STATES.map((state) => [state, rows.filter((row) => row.state === state).length]));
    const requiredRows = rows.filter((row) => row.required);
    const completeRequired = requiredRows.filter((row) => row.complete).length;
    const body = {
        '@version': COVERAGE_REPORT_VERSION,
        generated_at: new Date(now).toISOString(),
        inventory_id: inventory.inventory_id,
        inventory_hash: coverageInventoryDigest(inventory),
        complete: requiredRows.length > 0 && completeRequired === requiredRows.length,
        declared_required_surfaces: requiredRows.length,
        complete_required_surfaces: completeRequired,
        // Canonical EP JSON permits safe integers only. Basis points keep the
        // report deterministic and signable without binary-float ambiguity.
        declared_coverage_bps: requiredRows.length === 0
            ? 0
            : Math.floor((completeRequired * 10_000) / requiredRows.length),
        counts,
        surfaces: rows,
        limitations: [
            'Coverage is measured only over the relying-party-declared inventory; omitted routes remain an external inventory risk.',
            'Attestation proves expected workload measurements and the active probe proves one tested refusal path; neither proves all physical bypasses are impossible.',
            'A gated row requires the exact relying-party challenge nonce for that evaluation; a replayed signed block result cannot establish current coverage.',
            'A network witness counts only after durable sequence acceptance, or from a relying-party-trusted acceptance result; it never establishes enforcement by itself.',
        ],
    };
    return Object.freeze({ ...body, report_hash: reportHash(body) });
}
export default {
    COVERAGE_INVENTORY_VERSION,
    COVERAGE_REPORT_VERSION,
    ENFORCEMENT_PROBE_VERSION,
    COVERAGE_STATES,
    PROBE_RESULTS,
    coverageInventoryDigest,
    parseEnforcementProbeStatement,
    signEnforcementProbe,
    verifyEnforcementProbe,
    evaluateGateCoverage,
};
//# sourceMappingURL=coverage.js.map