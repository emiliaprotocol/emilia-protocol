#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-repository-boundary.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const FORBIDDEN_PREFIXES = [
    'docs/ip/',
    'docs/grace-raise/',
    'docs/strategy-private/',
    'docs/marketing/',
    'docs/outreach/',
    'docs/positioning/',
    'docs/pilots/',
    'docs/seo/',
    'docs/legal/',
    'docs/launch/',
    'docs/distribution/',
    'outreach/',
];
const FORBIDDEN_EXACT = new Set([
    'docs/TARGET-LIST-AND-OUTREACH.md',
    'docs/INVESTOR-NARRATIVE.md',
    'docs/ECONOMIC-MOAT.md',
    'docs/CEO-ROLE-SPEC.md',
    'docs/FOCUS-RECOMMENDATION.md',
    'docs/WHAT-THE-WINNER-HAS.md',
    'docs/NIST-ENGAGEMENT-PLAN.md',
    'docs/OUTREACH-EMAILS.md',
    'docs/PILOT-OUTREACH-EMAILS.md',
    'docs/SEND_TOMORROW_INDEX.md',
    'docs/FINANCIAL-INSTITUTIONS-PILOT-PROPOSAL.md',
    'docs/GOVERNMENT-PILOT-PROPOSAL.md',
    'docs/MN-FRAUD-OVERSIGHT-ONE-PAGER.md',
    'docs/TRUST-DESK-AUTOMATION-SPEC.md',
    'docs/TRUST-DESK-LAUNCH-RUNBOOK.md',
    'docs/briefs/INVESTOR_ONE_PAGER.md',
    'docs/briefs/CALIFORNIA-VERIFIABLE-AI-OVERSIGHT-BRIEFING.md',
]);
// This catches confidential docs force-added outside the canonical private
// directories. It is deliberately scoped to document files under docs/ so
// public application routes such as app/investors remain unaffected.
const CONFIDENTIAL_DOC_NAME = /(?:^|[-_.])(private|confidential|target-list|buyer-map|fundraising|investor-deck|pitch-deck|outreach-list)(?:[-_.]|$)/i;
const DOCUMENT_EXTENSIONS = new Set(['.md', '.mdx', '.txt', '.pdf', '.pptx', '.key']);
const PUBLIC_KERNEL_PREFIXES = [
    'packages/verify/src/claim-assurance',
    'packages/verify/dist/claim-assurance',
    'packages/verify/claim-assurance.js',
    'packages/gate/src/claim-assurance',
    'packages/gate/dist/claim-assurance',
    'packages/gate/claim-assurance.js',
    'examples/claim-assurance-reference/',
    'public/assurance/records/',
    'public/schemas/ep-assurance-record.schema.json',
    'public/schemas/ep-claim-assurance',
    'public/schemas/ep-claim-case.schema.json',
];
const PUBLIC_KERNEL_COMMERCIAL_CONCEPTS = [
    { id: 'competitor_material', pattern: /\b(?:certisyn|hillier)\b/i },
    {
        id: 'private_capital_strategy',
        pattern: /\b(?:private equity|portfolio compan(?:y|ies)|portfolio authority|investment thesis|investor)\b/i,
    },
    {
        id: 'commercial_terms',
        pattern: /\b(?:pricing|price sheet|paid pilot|sales pipeline|target account|buyer map|procurement)\b/i,
    },
    {
        id: 'operated_product_family',
        pattern: /\b(?:commercial product|product family|trust center|assurance cloud|assurance network|hosted (?:service|registry|resolver|workspace)|managed service)\b/i,
    },
    {
        id: 'certification_ownership',
        pattern: /\b(?:certification mark|badge licensing|mark ownership|certificate programme|certificate program)\b/i,
    },
    { id: 'catalogue_merchandising', pattern: /\b(?:catalogue|catalog)\b/i },
];
function normalizedPath(rawFile) {
    return rawFile.replaceAll('\\', '/').replace(/^\.\//, '');
}
function isPublicKernelPath(file) {
    return PUBLIC_KERNEL_PREFIXES.some((prefix) => file.startsWith(prefix));
}
/**
 * Keep the open Claim Assurance kernel technical and neutral. The kernel may
 * define formats, verification, fixtures, and the non-authorizing Gate bridge;
 * company positioning and operated-product merchandising stay outside it.
 */
export function findPublicKernelSemanticViolations(entries) {
    const violations = [];
    for (const entry of entries) {
        const file = normalizedPath(entry.path);
        if (!isPublicKernelPath(file))
            continue;
        for (const concept of PUBLIC_KERNEL_COMMERCIAL_CONCEPTS) {
            if (concept.pattern.test(entry.content)) {
                violations.push(`${file}:commercial_concept:${concept.id}`);
            }
        }
    }
    return [...new Set(violations)].sort();
}
export function findRepositoryBoundaryViolations(files) {
    const violations = [];
    for (const rawFile of files) {
        const file = normalizedPath(rawFile);
        if (FORBIDDEN_EXACT.has(file) || FORBIDDEN_PREFIXES.some((prefix) => file.startsWith(prefix))) {
            violations.push(file);
            continue;
        }
        if (file.startsWith('docs/') && DOCUMENT_EXTENSIONS.has(path.posix.extname(file))) {
            const base = path.posix.basename(file, path.posix.extname(file));
            if (CONFIDENTIAL_DOC_NAME.test(base))
                violations.push(file);
        }
    }
    return [...new Set(violations)].sort();
}
function trackedFiles() {
    const output = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
    return output.split('\0').filter(Boolean);
}
function trackedPublicKernelText(files) {
    return files
        .map(normalizedPath)
        .filter(isPublicKernelPath)
        .map((file) => ({ path: file, content: readFileSync(file, 'utf8') }));
}
function main() {
    const files = trackedFiles();
    const pathViolations = findRepositoryBoundaryViolations(files);
    const semanticViolations = findPublicKernelSemanticViolations(trackedPublicKernelText(files));
    if (pathViolations.length > 0 || semanticViolations.length > 0) {
        console.error('Public/private repository boundary violated by tracked files:');
        for (const file of [...pathViolations, ...semanticViolations].sort())
            console.error(`- ${file}`);
        console.error('Move confidential company material to the private emilia-company repository.');
        process.exit(1);
    }
    console.log('Repository boundary: public tracked tree contains no prohibited private paths or Claim Assurance commercial concepts.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
    main();
