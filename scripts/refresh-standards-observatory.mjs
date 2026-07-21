#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from refresh-standards-observatory.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeStandardsText } from './lib/standards-text.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CATALOG_PATH = path.join(ROOT, 'standards/observatory/catalog.source.v1.json');
const OUTPUT_PATH = path.join(ROOT, 'standards/observatory/source-lock.v1.json');
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
async function fetchSource(source) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    let response;
    try {
        response = await fetch(source.source_url, {
            redirect: 'follow',
            signal: controller.signal,
            headers: {
                'user-agent': 'EMILIA-Standards-Observatory/1.0 (+https://www.emiliaprotocol.ai/observatory)',
                accept: 'text/plain,text/html,application/json;q=0.9,*/*;q=0.8',
            },
        });
    }
    finally {
        clearTimeout(timer);
    }
    if (!response.ok)
        throw new Error(`${source.id}: HTTP ${response.status} from ${source.source_url}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    const normalizedBody = normalizeStandardsText(bytes.toString('utf8'));
    const normalizedQuote = normalizeStandardsText(source.quote.text);
    const quoteVerified = normalizedBody.includes(normalizedQuote);
    if (!quoteVerified) {
        throw new Error(`${source.id}: locked quote not found in fetched source: ${JSON.stringify(source.quote.text)}`);
    }
    return {
        id: source.id,
        revision: source.revision,
        source_url: source.source_url,
        final_url: response.url,
        http_status: response.status,
        content_type: response.headers.get('content-type'),
        etag: response.headers.get('etag'),
        last_modified: response.headers.get('last-modified'),
        bytes: bytes.length,
        sha256: sha256(bytes),
        quote: source.quote,
        quote_sha256: sha256(Buffer.from(normalizedQuote, 'utf8')),
        quote_verified: true,
    };
}
async function main() {
    const catalog = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));
    const locks = [];
    for (const source of catalog.sources) {
        process.stdout.write(`LOCK ${source.id} ... `);
        const lock = await fetchSource(source);
        locks.push(lock);
        console.log(`OK sha256:${lock.sha256.slice(0, 12)}`);
    }
    const body = {
        '@version': 'EMILIA-STANDARDS-SOURCE-LOCK-v1',
        retrieved_at: catalog.as_of,
        source_count: locks.length,
        sources: locks,
    };
    body.lock_sha256 = sha256(Buffer.from(JSON.stringify(body.sources), 'utf8'));
    fs.writeFileSync(OUTPUT_PATH, `${JSON.stringify(body, null, 2)}\n`);
    console.log(`STANDARDS SOURCES: WROTE ${locks.length} verified locks (sha256:${body.lock_sha256})`);
}
main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`STANDARDS SOURCES: FAIL - ${message}`);
    process.exit(1);
});
