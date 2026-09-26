// SPDX-License-Identifier: Apache-2.0
// Generated from verify-sources.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/** Check actual archive bytes, separately from the offline receipt suite. */
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const HERE = dirname(fileURLToPath(import.meta.url));
const MAX_BYTES = 512 * 1024;
export const SOURCE_LOCK = JSON.parse(await readFile(resolve(HERE, 'source-lock.json'), 'utf8'));
const PINS = [SOURCE_LOCK.previous_draft, SOURCE_LOCK.draft];
export function verifyDocumentBytes(pin, bytes) {
    const actualSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
        name: pin.name,
        url: pin.url,
        expected_bytes: pin.bytes,
        actual_bytes: bytes.byteLength,
        expected_sha256: pin.sha256,
        actual_sha256: actualSha256,
        passed: bytes.byteLength === pin.bytes && actualSha256 === pin.sha256,
    };
}
export async function verifyPinnedSources(load) {
    const checks = await Promise.all(PINS.map(async (pin) => {
        try {
            return verifyDocumentBytes(pin, await load(pin));
        }
        catch (error) {
            return { name: pin.name, url: pin.url, passed: false,
                error: error instanceof Error ? error.message : String(error) };
        }
    }));
    return {
        '@version': 'CCS-09-ARCHIVE-BYTES-CHECK-v1',
        passed: checks.every((check) => check.passed),
        checks,
        scope: 'Exact source bytes only; this does not establish receipt or runtime conformance.',
    };
}
async function fetchArchive(pin) {
    const response = await fetch(pin.url, {
        signal: AbortSignal.timeout(10_000), redirect: 'error',
    });
    if (!response.ok || !response.body)
        throw new Error(`archive HTTP ${response.status}`);
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            total += value.byteLength;
            if (total > MAX_BYTES)
                throw new Error('archive exceeds 512 KiB limit');
            chunks.push(value);
        }
    }
    finally {
        await reader.cancel();
        reader.releaseLock();
    }
    return Buffer.concat(chunks);
}
export function parseArguments(args) {
    if (args.length === 1 && args[0] === '--online')
        return { mode: 'online' };
    if (args.length === 2 && args[0] === '--directory' && args[1] && !args[1].startsWith('--')) {
        return { mode: 'directory', directory: resolve(args[1]) };
    }
    throw new Error('Use --online or --directory <path containing both pinned draft .txt files>');
}
async function main() {
    const args = parseArguments(process.argv.slice(2));
    const report = await verifyPinnedSources(args.mode === 'online' ? fetchArchive : async (pin) => {
        const path = resolve(args.directory, `${pin.name}.txt`);
        if ((await stat(path)).size > MAX_BYTES)
            throw new Error('archive exceeds 512 KiB limit');
        return readFile(path);
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
