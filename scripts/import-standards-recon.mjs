#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from import-standards-recon.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// The raw per-artifact recon index is PRIVATE and gitignored. It must never be written
// under a tracked public path; the published surface carries aggregate counts only
// (see standards/observatory/recon-summary.v1.json and build-standards-observatory.mjs).
const DEFAULT_OUTPUT = path.join(ROOT, 'docs/strategy-private/observatory/recon-index.v1.json');
const CATALOG = path.join(ROOT, 'standards/observatory/catalog.source.v1.json');
function parseArgs(argv) {
    const parsed = { inputs: [], output: DEFAULT_OUTPUT, declared: null, asOf: null };
    for (let index = 0; index < argv.length; index += 1) {
        const value = argv[index];
        if (value === '--input')
            parsed.inputs.push(argv[++index]);
        else if (value === '--emit')
            parsed.output = path.resolve(argv[++index]);
        else if (value === '--declared')
            parsed.declared = Number(argv[++index]);
        else if (value === '--as-of')
            parsed.asOf = argv[++index];
        else
            throw new Error(`unknown argument: ${value}`);
    }
    return parsed;
}
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
function listJsonl(input) {
    const resolved = path.resolve(input);
    if (!fs.existsSync(resolved))
        throw new Error(`input does not exist: ${resolved}`);
    if (fs.statSync(resolved).isFile())
        return [resolved];
    return fs.readdirSync(resolved, { withFileTypes: true })
        .flatMap((entry) => listJsonl(path.join(resolved, entry.name)))
        .filter((file) => file.endsWith('.jsonl'));
}
function toolUses(record) {
    const content = record?.message?.content;
    if (!Array.isArray(content))
        return [];
    return content.filter((item) => item?.type === 'tool_use');
}
function normalizeSourceUrl(value) {
    if (typeof value !== 'string' || !/^https?:\/\//.test(value))
        return null;
    try {
        const url = new URL(value);
        url.hash = '';
        return url.toString();
    }
    catch {
        return null;
    }
}
function parseFile(file) {
    let lastSourceUrl = null;
    const reports = [];
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
    for (let lineNumber = 0; lineNumber < lines.length; lineNumber += 1) {
        let record;
        try {
            record = JSON.parse(lines[lineNumber]);
        }
        catch (error) {
            throw new Error(`${file}:${lineNumber + 1}: invalid JSON: ${error.message}`);
        }
        for (const tool of toolUses(record)) {
            if (tool.name === 'WebFetch') {
                lastSourceUrl = normalizeSourceUrl(tool.input?.url) || lastSourceUrl;
                continue;
            }
            if (tool.name !== 'StructuredOutput')
                continue;
            const input = tool.input;
            if (!input || typeof input !== 'object' || !input.name || !input.title || !input.layer)
                continue;
            const reportBytes = Buffer.from(JSON.stringify(input), 'utf8');
            reports.push({
                id: String(input.name),
                title: String(input.title),
                layer: String(input.layer),
                venue: typeof input.venue === 'string' ? input.venue : null,
                tier: typeof input.tier === 'string' ? input.tier : null,
                source_url: lastSourceUrl,
                fetch_failed: input.fetch_failed === true,
                review_state: 'agent_analyzed_unverified',
                report_sha256: sha256(reportBytes),
            });
        }
    }
    return reports;
}
function stableJson(value) {
    return `${JSON.stringify(value, null, 2)}\n`;
}
function main() {
    const args = parseArgs(process.argv.slice(2));
    if (!args.inputs.length && process.env.EMILIA_RECON_INPUTS) {
        args.inputs.push(...process.env.EMILIA_RECON_INPUTS.split(path.delimiter).filter(Boolean));
    }
    if (!args.inputs.length) {
        throw new Error('usage: import-standards-recon.mjs --input <workflow-dir> [--input <workflow-dir>] [--declared N] [--emit path]; EMILIA_RECON_INPUTS may supply a path-delimited input list');
    }
    const catalog = JSON.parse(fs.readFileSync(CATALOG, 'utf8'));
    const files = [...new Set(args.inputs.flatMap(listJsonl))].sort();
    const reports = files.flatMap(parseFile).sort((left, right) => left.id.localeCompare(right.id));
    const duplicateIds = reports.filter((report, index) => index > 0 && report.id === reports[index - 1].id).map((report) => report.id);
    if (duplicateIds.length)
        throw new Error(`duplicate report id(s): ${[...new Set(duplicateIds)].join(', ')}`);
    const declared = args.declared ?? catalog.methodology.declared_agent_reads;
    if (!Number.isInteger(declared) || declared < reports.length) {
        throw new Error(`declared read count must be an integer >= recovered reports (${reports.length})`);
    }
    const reportDigest = sha256(Buffer.from(JSON.stringify(reports), 'utf8'));
    const output = {
        '@version': 'EMILIA-STANDARDS-RECON-INDEX-v1',
        as_of: args.asOf ?? catalog.as_of,
        review_model: 'correlated_agent_assisted_discovery',
        claim_boundary: 'Entries identify material inspected by the recon. They are not publication-grade claims and do not drive the guarantee matrix.',
        metrics: {
            declared_agent_reads: declared,
            recovered_structured_reports: reports.length,
            unrecovered_reports: declared - reports.length,
            fetch_failures_in_recovered_reports: reports.filter((report) => report.fetch_failed).length,
            workflow_files_scanned: files.length,
        },
        corpus_sha256: reportDigest,
        reports,
    };
    fs.mkdirSync(path.dirname(args.output), { recursive: true });
    fs.writeFileSync(args.output, stableJson(output));
    console.log(`STANDARDS RECON: WROTE ${reports.length}/${declared} reports (${files.length} workflow files; sha256:${reportDigest})`);
}
try {
    main();
}
catch (error) {
    console.error(`STANDARDS RECON: FAIL - ${error.message}`);
    process.exit(1);
}
