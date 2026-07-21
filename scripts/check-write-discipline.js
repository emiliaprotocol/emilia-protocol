#!/usr/bin/env node
// Generated from check-write-discipline.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP Write Discipline Guard
 *
 * Fails CI if any route file under app/api/ imports forbidden
 * mutating functions directly instead of using protocolWrite().
 *
 * Usage: node scripts/check-write-discipline.js
 *
 * @license Apache-2.0
 */
import { readFileSync, readdirSync, statSync } from 'fs';
import { sep, relative, resolve } from 'path';
const FORBIDDEN_IMPORTS = [
    'canonicalSubmitReceipt',
    'canonicalSubmitAutoReceipt',
    'canonicalBilateralConfirm',
    'canonicalFileDispute',
    'canonicalResolveDispute',
    'canonicalRespondDispute',
    'canonicalAppealDispute',
    'canonicalResolveAppeal',
    'canonicalWithdrawDispute',
    'canonicalFileReport',
    'issueCommit',
    'verifyCommit',
    'revokeCommit',
];
const ALLOWED_IMPORTS = [
    '@/lib/protocol-write',
    // Read-only query services are OK
];
const projectRoot = process.cwd();
const apiDir = resolve(projectRoot, 'app', 'api');
/**
 * Validate a directory entry name is safe (no traversal).
 * Returns the concatenated path using the platform separator,
 * or null if the name is suspicious.
 */
function safePath(base, name) {
    // Reject traversal components and names containing separators
    if (name.includes('/') || name.includes('\\') || name === '..' || name === '.') {
        return null;
    }
    // Only allow alphanumeric, hyphens, underscores, dots, brackets
    if (!/^[\w.\-\[\]()]+$/.test(name)) {
        return null;
    }
    const candidate = base + sep + name;
    if (!candidate.startsWith(base + sep)) {
        return null;
    }
    return candidate;
}
function walkDir(dir, results = []) {
    for (const entry of readdirSync(dir)) {
        const fullPath = safePath(dir, entry);
        if (!fullPath)
            continue;
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
            walkDir(fullPath, results);
        }
        else if (entry === 'route.js' || entry === 'route.ts') {
            results.push(fullPath);
        }
    }
    return results;
}
let violations = [];
try {
    const routeFiles = walkDir(apiDir);
    for (const file of routeFiles) {
        const content = readFileSync(file, 'utf-8');
        const relPath = relative(projectRoot, file);
        // Check 1: Forbidden canonical function imports
        for (const forbidden of FORBIDDEN_IMPORTS) {
            // Check for direct imports of forbidden functions
            const importPattern = new RegExp(`\\b${forbidden}\\b`);
            if (importPattern.test(content)) {
                // Make sure it's not just in a comment
                const lines = content.split('\n');
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (line.startsWith('//') || line.startsWith('*'))
                        continue;
                    if (importPattern.test(line)) {
                        violations.push({
                            file: relPath,
                            line: i + 1,
                            function: forbidden,
                            text: line.substring(0, 120),
                        });
                    }
                }
            }
        }
        // Check 2: Route files must use getGuardedClient, not getServiceClient.
        // getServiceClient bypasses runtime write-path enforcement on trust tables.
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.startsWith('//') || line.startsWith('*'))
                continue;
            if (/\bgetServiceClient\b/.test(line)) {
                violations.push({
                    file: relPath,
                    line: i + 1,
                    function: 'getServiceClient',
                    text: line.substring(0, 120),
                });
            }
        }
        // Check 3: route handlers must not forward or inspect the raw auth row.
        // The row can contain api_key_hash and other sensitive fields. Use the
        // narrow helpers from lib/supabase.js for identity, operator, and actor
        // projections so a future auth-shape change cannot reintroduce the leak.
        const withoutComments = content
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/(^|\s)\/\/.*$/gm, '$1');
        const rawAuthEntity = /\bauth\s*\.\s*entity\b/;
        if (rawAuthEntity.test(withoutComments)) {
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const lineWithoutComment = lines[i].replace(/\/\/.*$/, '');
                if (rawAuthEntity.test(lineWithoutComment)) {
                    violations.push({
                        file: relPath,
                        line: i + 1,
                        function: 'auth.entity',
                        text: lines[i].trim().substring(0, 120),
                    });
                }
            }
        }
    }
}
catch (e) {
    if (e.code === 'ENOENT') {
        console.log('✓ No app/api directory found — nothing to check');
        process.exit(0);
    }
    throw e;
}
if (violations.length > 0) {
    console.error('✗ Write discipline violations found:\n');
    for (const v of violations) {
        console.error(`  ${v.file}:${v.line}`);
        console.error(`    Forbidden: ${v.function}`);
        console.error(`    Line: ${v.text}\n`);
    }
    console.error(`\n${violations.length} violation(s) found.`);
    console.error('Routes must use protocolWrite() for trust-bearing writes and getGuardedClient() for database access.');
    console.error('getServiceClient() is only permitted in the canonical write layer and non-route library code.');
    console.error('Routes must use authEntityId()/authEntityActor() projections instead of the raw auth.entity row.');
    process.exit(1);
}
else {
    console.log(`✓ All route files pass write discipline check`);
    process.exit(0);
}
