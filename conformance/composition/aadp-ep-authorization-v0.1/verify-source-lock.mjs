// SPDX-License-Identifier: Apache-2.0
// Generated from verify-source-lock.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const SOURCE_LOCK = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
export async function verifySourceLock(fetchBytes = async (url) => {
    const response = await fetch(url, {
        headers: { accept: 'application/octet-stream, text/plain;q=0.9, */*;q=0.1' },
        redirect: 'follow',
    });
    if (!response.ok)
        throw new Error(`source fetch failed: ${response.status} ${url}`);
    return new Uint8Array(await response.arrayBuffer());
}) {
    const upstream = [
        {
            name: SOURCE_LOCK.aadp.draft,
            url: SOURCE_LOCK.aadp.text.url,
            expected_sha256: SOURCE_LOCK.aadp.text.sha256,
        },
        ...SOURCE_LOCK.onedoor.inspected_files.map((entry) => ({
            name: entry.path,
            url: entry.url,
            expected_sha256: entry.sha256,
        })),
    ];
    const upstreamResults = [];
    for (const source of upstream) {
        const bytes = await fetchBytes(source.url);
        const actual = sha256(bytes);
        if (actual !== source.expected_sha256) {
            throw new Error(`source lock mismatch for ${source.name}: expected ${source.expected_sha256}, got ${actual}`);
        }
        upstreamResults.push({
            name: source.name,
            url: source.url,
            sha256: actual,
            bytes: bytes.byteLength,
            verified: true,
        });
    }
    const localResults = SOURCE_LOCK.emilia.runtime_files.map((entry) => {
        const bytes = readFileSync(new URL(`../../../${entry.path}`, import.meta.url));
        const actual = sha256(bytes);
        if (actual !== entry.sha256) {
            throw new Error(`local source lock mismatch for ${entry.path}: expected ${entry.sha256}, got ${actual}`);
        }
        return {
            path: entry.path,
            sha256: actual,
            bytes: bytes.byteLength,
            verified: true,
        };
    });
    return {
        profile: 'AADP-EP-SOURCE-LOCK-VERIFICATION-v1',
        source_lock_file_sha256: `sha256:${sha256(readFileSync(new URL('./source-lock.json', import.meta.url)))}`,
        upstream: upstreamResults,
        repository_source: {
            repository: SOURCE_LOCK.emilia.repository,
            binding: SOURCE_LOCK.emilia.binding,
        },
        local: localResults,
        passed: true,
    };
}
async function main() {
    process.stdout.write(`${JSON.stringify(await verifySourceLock(), null, 2)}\n`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    await main();
}
