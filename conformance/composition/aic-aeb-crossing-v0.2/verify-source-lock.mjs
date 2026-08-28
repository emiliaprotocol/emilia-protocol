// SPDX-License-Identifier: Apache-2.0
// Generated from verify-source-lock.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const SOURCE_LOCK_BYTES = readFileSync(new URL('./source-lock.json', import.meta.url));
const SOURCE_LOCK = JSON.parse(SOURCE_LOCK_BYTES.toString('utf8'));
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
export async function verifyAicSourceLock(fetchBytes = async (url) => {
    const response = await fetch(url, {
        headers: { accept: 'application/octet-stream, text/plain;q=0.9, */*;q=0.1' },
        redirect: 'follow',
    });
    if (!response.ok)
        throw new Error(`source fetch failed: ${response.status} ${url}`);
    return new Uint8Array(await response.arrayBuffer());
}) {
    const sources = [
        ...SOURCE_LOCK.drafts.map((entry) => ({
            name: entry.name,
            url: entry.url,
            expected_sha256: entry.sha256,
        })),
        ...SOURCE_LOCK.varwof.repositories.flatMap((repository) => (repository.inspected_files.map((entry) => ({
            name: `${repository.repository}@${repository.revision}:${entry.path}`,
            url: entry.url,
            expected_sha256: entry.sha256,
        })))),
    ];
    const verified = [];
    for (const source of sources) {
        const bytes = await fetchBytes(source.url);
        const actual = sha256(bytes);
        if (actual !== source.expected_sha256) {
            throw new Error(`source lock mismatch for ${source.name}: expected ${source.expected_sha256}, got ${actual}`);
        }
        verified.push({
            name: source.name,
            url: source.url,
            sha256: actual,
            bytes: bytes.byteLength,
            verified: true,
        });
    }
    return {
        profile: 'AIC-AEB-CROSSING-SOURCE-LOCK-VERIFICATION-v1',
        source_lock_file_sha256: `sha256:${sha256(SOURCE_LOCK_BYTES)}`,
        sources: verified,
        passed: true,
    };
}
async function main() {
    process.stdout.write(`${JSON.stringify(await verifyAicSourceLock(), null, 2)}\n`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    await main();
}
