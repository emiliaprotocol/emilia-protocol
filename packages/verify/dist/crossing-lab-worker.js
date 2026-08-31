// SPDX-License-Identifier: Apache-2.0
/**
 * Isolated process entrypoint for Crossing Lab adapters.
 *
 * The parent starts this file with Node's permission model enabled, no network
 * permission, no child-process permission, and read access limited to this
 * worker. The already-verified adapter bytes travel over bounded stdio JSON,
 * are digest-checked again here, and are imported from an in-memory data URL.
 * The mutable workspace path is never imported.
 */
import crypto from 'node:crypto';
const MAX_INPUT_BYTES = 1_048_576;
const MAX_ADAPTER_BYTES = 262_144;
const MAX_STDIN_BYTES = MAX_INPUT_BYTES + (Math.ceil(MAX_ADAPTER_BYTES / 3) * 4) + 4_096;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_STDIN_BYTES) {
        process.stderr.write('crossing-lab adapter input exceeds limit\n');
        process.exit(1);
    }
});
process.stdin.on('end', async () => {
    try {
        const request = JSON.parse(raw);
        if (request === null || typeof request !== 'object' || Array.isArray(request)
            || !['verifyNative', 'mapAction'].includes(request.method)
            || !Object.hasOwn(request, 'input')
            || typeof request.adapter_source_base64 !== 'string'
            || typeof request.adapter_digest !== 'string'
            || !DIGEST_RE.test(request.adapter_digest)
            || Object.keys(request).some((key) => ![
                'method', 'input', 'adapter_source_base64', 'adapter_digest',
            ].includes(key))) {
            throw new TypeError('invalid worker request');
        }
        if (Buffer.byteLength(JSON.stringify({ method: request.method, input: request.input }), 'utf8') > MAX_INPUT_BYTES) {
            throw new TypeError('crossing-lab adapter input exceeds limit');
        }
        const adapterBytes = Buffer.from(request.adapter_source_base64, 'base64');
        if (adapterBytes.length > MAX_ADAPTER_BYTES
            || adapterBytes.toString('base64') !== request.adapter_source_base64) {
            throw new TypeError('invalid or oversized adapter source');
        }
        const actualDigest = `sha256:${crypto.createHash('sha256').update(adapterBytes).digest('hex')}`;
        if (actualDigest !== request.adapter_digest)
            throw new TypeError('adapter source digest mismatch');
        const adapterUrl = `data:text/javascript;base64,${request.adapter_source_base64}`;
        const imported = await import(adapterUrl);
        const adapter = imported.default;
        if (adapter === null || typeof adapter !== 'object' || Array.isArray(adapter)
            || typeof adapter.id !== 'string' || typeof adapter.version !== 'string'
            || typeof adapter.verifyNative !== 'function' || typeof adapter.mapAction !== 'function'
            || Object.keys(adapter).some((key) => !['id', 'version', 'verifyNative', 'mapAction'].includes(key))) {
            throw new TypeError('adapter must be one closed default export');
        }
        // Invoke twice on the same imported adapter instance. Spawning two fresh
        // workers would reset module-local state and let a counter- or cache-based
        // adapter appear deterministic even when consecutive calls disagree.
        const input = deepFreeze(request.input);
        const invoke = () => request.method === 'verifyNative'
            ? adapter.verifyNative(input)
            : adapter.mapAction(input);
        const first = await invoke();
        const second = await invoke();
        const output = JSON.stringify({ adapter_id: adapter.id, adapter_version: adapter.version, results: [first, second] });
        if (Buffer.byteLength(output, 'utf8') > 262_144)
            throw new TypeError('adapter output exceeds limit');
        process.stdout.write(`${output}\n`);
    }
    catch (error) {
        process.stderr.write(`${error?.name ?? 'Error'}: ${error?.message ?? 'adapter failed'}\n`);
        process.exit(1);
    }
});
//# sourceMappingURL=crossing-lab-worker.js.map