// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import { sanitizeForReport } from './redact.js';
import { severityRank } from './detect.js';
export const AUTHORITY_CLAIM_BOUNDARY = 'config_derived_reachability_only_not_behavioral_not_exploitability_not_an_authorization_guarantee';
export const AUTHORITY_SCOPE = Object.freeze({
    reports: [
        'What supported agent runtimes are configured to reach from configuration files visible to this process.',
        'Which configured paths carry credential-shaped fields. Descriptors may include key name, class, exact length, prefix class, detection evidence, and scheme, but never the value.',
        'Whether a declared operation surface was visible to this configuration-only scan.',
    ],
    does_not_report: [
        'What any agent actually did.',
        'The real tool surface of a configured server.',
        'Whether any credential is valid, scoped, sufficient for an operation, or already rotated.',
    ],
    does_not_prove: [
        'Exploitability. Configuration-derived reachability is not a vulnerability.',
        'Safety or completeness. Absence of a finding means nothing was detected on supported surfaces.',
        'That an unknown or unseen operation is harmless.',
    ],
});
const BAR = '='.repeat(72);
function severityTag(severity) {
    return severity.toUpperCase();
}
export function renderAuthorityText(input) {
    const result = sanitizeForReport(input, 'report');
    const { inventory, signals, summary } = result;
    const lines = [
        BAR,
        'EMILIA AUTHORITY SCAN - alpha diagnostic',
        'This is not a security product and makes no authorization guarantee.',
        BAR,
        '',
    ];
    const read = inventory.sources.filter((source) => source.status === 'read');
    const unsupported = inventory.sources.filter((source) => source.status === 'unsupported_format');
    const unreadable = inventory.sources.filter((source) => source.status === 'unreadable');
    const malformed = inventory.sources.filter((source) => source.status === 'malformed');
    const tooLarge = inventory.sources.filter((source) => source.status === 'too_large');
    const symlinks = inventory.sources.filter((source) => source.status === 'symlink');
    lines.push(`Configuration sources read: ${read.length} of ${inventory.sources.length} checked.`);
    if (unsupported.length) {
        lines.push(`Unsupported formats excluded: ${unsupported.length}.`);
        for (const source of unsupported)
            lines.push(`  ${source.file} - not covered by this report.`);
    }
    if (unreadable.length)
        lines.push(`Unreadable configuration sources excluded: ${unreadable.length}.`);
    if (malformed.length)
        lines.push(`Malformed JSON sources excluded: ${malformed.length}.`);
    if (tooLarge.length)
        lines.push(`Oversized sources excluded: ${tooLarge.length}.`);
    if (symlinks.length)
        lines.push(`Symlinked configuration sources excluded: ${symlinks.length}.`);
    if (inventory.limitations.length) {
        lines.push('Discovery limits:');
        for (const limitation of inventory.limitations)
            lines.push(`  - ${limitation}`);
    }
    const active = inventory.servers.filter((server) => !server.disabled);
    const credentialServers = active.filter((server) => (server.env.some((entry) => entry.secret)
        || server.header_secrets.some((entry) => entry.secret)));
    lines.push(`MCP servers declared: ${inventory.servers.length} (${active.length} enabled).`);
    lines.push(`Servers with credential-shaped config fields: ${credentialServers.length}.`);
    lines.push('');
    lines.push('OPERATION SURFACE');
    lines.push(`  Coverage is not computable: ${summary.coverage.reason}.`);
    lines.push('  To classify a static tool list or OpenAPI surface, run:');
    lines.push('  emilia-scan <tools.json|openapi.json>');
    lines.push('');
    lines.push(BAR);
    lines.push(`FINDINGS (${signals.length})`);
    lines.push(BAR);
    if (!signals.length) {
        lines.push('');
        lines.push('No signals matched. This is not a clean bill of health; see scope below.');
    }
    for (const finding of [...signals].sort((left, right) => severityRank(left.severity) - severityRank(right.severity))) {
        lines.push('');
        lines.push(`[${severityTag(finding.severity)}] ${finding.id}  ${finding.title}`);
        lines.push('');
        const observations = Array.isArray(finding.observed)
            ? finding.observed
            : [finding.observed];
        for (const observation of observations.slice(0, 12)) {
            lines.push(`    ${typeof observation === 'string' ? observation : JSON.stringify(observation)}`);
        }
        if (observations.length > 12)
            lines.push(`    ... and ${observations.length - 12} more`);
        lines.push('');
        lines.push(`    Why it matters: ${finding.why}`);
        lines.push(`    Does not prove: ${finding.does_not_prove}`);
    }
    lines.push('', BAR, 'SCOPE OF THIS REPORT', BAR, '', 'What it reports:');
    for (const item of AUTHORITY_SCOPE.reports)
        lines.push(`  - ${item}`);
    lines.push('', 'What it does not report:');
    for (const item of AUTHORITY_SCOPE.does_not_report)
        lines.push(`  - ${item}`);
    lines.push('', 'What it does not prove:');
    for (const item of AUTHORITY_SCOPE.does_not_prove)
        lines.push(`  - ${item}`);
    lines.push('', `claim_boundary: ${AUTHORITY_CLAIM_BOUNDARY}`, '');
    lines.push('Configuration values were parsed locally in memory. Credential descriptors');
    lines.push('may include key name, class, exact length, prefix class, detection evidence,');
    lines.push('and scheme, but never the credential value. After scanner startup, scanner code');
    lines.push('launched no configured server or child process and performed no network I/O.');
    lines.push('When invoked through npx, npm may download the package before startup.');
    lines.push('');
    return lines.join('\n');
}
export function renderAuthorityJson(input) {
    return JSON.stringify(sanitizeForReport({
        tool: 'emilia-authority-scan',
        version: input.version,
        generated_from: 'local configuration only',
        claim_boundary: AUTHORITY_CLAIM_BOUNDARY,
        scope: AUTHORITY_SCOPE,
        summary: input.summary,
        signals: input.signals,
        inventory: input.inventory,
    }, 'report'), null, 2);
}
export function authorityExitCode(result) {
    if (result.inventory.sources.some((source) => source.status === 'malformed'))
        return 2;
    if (result.signals.length)
        return 1;
    if (!result.summary.coverage.computable)
        return 3;
    return 0;
}
export function writePrivateReport(file, output) {
    try {
        fs.writeFileSync(file, output, {
            encoding: 'utf8',
            flag: 'wx',
            mode: 0o600,
        });
    }
    catch (error) {
        if (error?.code === 'EEXIST') {
            throw new Error(`refusing to overwrite existing or symlinked report path: ${file}`);
        }
        throw error;
    }
}
//# sourceMappingURL=report.js.map