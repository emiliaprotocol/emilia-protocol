#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-repository-boundary.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { execFileSync } from 'node:child_process';
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
export function findRepositoryBoundaryViolations(files) {
    const violations = [];
    for (const rawFile of files) {
        const file = rawFile.replaceAll('\\', '/').replace(/^\.\//, '');
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
function main() {
    const violations = findRepositoryBoundaryViolations(trackedFiles());
    if (violations.length > 0) {
        console.error('Public/private repository boundary violated by tracked files:');
        for (const file of violations)
            console.error(`- ${file}`);
        console.error('Move confidential company material to the private emilia-company repository.');
        process.exit(1);
    }
    console.log('Repository boundary: public tracked tree contains no prohibited private-document paths.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
    main();
