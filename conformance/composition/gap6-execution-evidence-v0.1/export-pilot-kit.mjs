// SPDX-License-Identifier: Apache-2.0
// Generated from export-pilot-kit.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildAuditWorkpaper, renderMarkdown as renderAuditWorkpaper, } from '../../../packages/gate/reports/auditor-workpaper.js';
import { buildUnderwriterAttestation, renderMarkdown as renderUnderwriterAttestation, } from '../../../packages/gate/reports/underwriter.js';
import { runProfile } from './run.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUTPUT = resolve(HERE, 'pilot-kit-output');
function json(value) {
    return `${JSON.stringify(value, null, 2)}\n`;
}
function sha256(bytes) {
    return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function availableOutput(requested) {
    if (!existsSync(requested) || readdirSync(requested).length === 0)
        return requested;
    for (let suffix = 2; suffix < 10_000; suffix += 1) {
        const candidate = `${requested}-${suffix}`;
        if (!existsSync(candidate) || readdirSync(candidate).length === 0)
            return candidate;
    }
    throw new Error('pilot kit export: no unused output path available');
}
function pilotReport(result) {
    const cases = result.cases.filter((item) => item.id.startsWith('m01-'));
    const refused = cases.filter((item) => item.claims.admission.verdict === 'refused');
    const admitted = cases.filter((item) => item.claims.admission.verdict === 'admitted');
    return [
        '# M01 Field-Origin Paid-Pilot Report',
        '',
        '## Result',
        '',
        `The Gate refused ${refused.length} hostile control-field cases before execution and admitted ${admitted.length} bounded-data case.`,
        '',
        '| Case | Gate result | Mechanism |',
        '|---|---|---|',
        ...cases.map((item) => `| \`${item.id}\` | ${item.claims.admission.verdict} | \`${item.boundary_reason ?? 'allow'}\` |`),
        '',
        '## What the evidence establishes',
        '',
        '- A pinned issuer signed an exact per-field origin map for the executor-observed action.',
        '- A customer-signed Bounded Execution Program pinned the exact field-origin profile digest for this action node.',
        '- The relying party pinned which origin classes and versioned transforms each field may use.',
        '- Gate evaluated that evidence before receipt reservation and effect entry.',
        '- The positive memo case shows that untrusted bytes may fill a bounded data field without gaining control authority.',
        '',
        '## Claim boundary',
        '',
        `\`${result.deterministic.claim_model.field_origin.claim_boundary}\``,
        '',
        'This does not prove the issuer described the source truthfully, solve prompt injection, authorize the action, or prove the external effect. The signed map makes the assertion attributable and the Gate decision reproducible under the relying party\'s pinned profile.',
        '',
        '## Reproduce',
        '',
        'From a checkout of the source revision named in `bundle-manifest.json`:',
        '',
        '```bash',
        'node conformance/composition/gap6-execution-evidence-v0.1/verify-pilot-kit.mjs --bundle /path/to/this/bundle',
        '```',
        '',
        `Gap 6 deterministic result: \`${result.results_digest}\``,
        '',
    ].join('\n');
}
export async function exportPilotKit(requestedOutput = DEFAULT_OUTPUT) {
    const output = availableOutput(resolve(requestedOutput));
    mkdirSync(output, { recursive: true });
    const result = await runProfile();
    if (!result.pilot.observed_action || !result.pilot.field_origin_evidence) {
        throw new Error('pilot kit export: positive M01 fixture was not produced');
    }
    const log = result.pilot.gate_evidence_log;
    const instants = log
        .map((entry) => Date.parse(entry.at))
        .filter((value) => Number.isFinite(value));
    if (instants.length === 0)
        throw new Error('pilot kit export: Gate emitted no dated evidence');
    const periodStart = new Date(Math.min(...instants) - 1).toISOString();
    const periodEnd = new Date(Math.max(...instants) + 1).toISOString();
    const generatedAt = Math.max(...instants) + 1;
    const audit = buildAuditWorkpaper(log, {
        client: 'Design Partner (pilot fixture)',
        engagement: 'M01 field-origin control evaluation',
        controlRef: 'M01-FIELD-ORIGIN',
        periodStart,
        periodEnd,
        sampleSize: 100,
        sampleSeed: 'm01-field-origin-reference-v0.1',
        now: generatedAt,
    });
    const underwriter = buildUnderwriterAttestation(log, {
        insured: 'Design Partner (pilot fixture)',
        policyRef: null,
        periodStart,
        periodEnd,
        now: generatedAt,
    });
    const gap6Report = {
        ...result.deterministic,
        results_digest: result.results_digest,
    };
    const files = new Map([
        ['README.md', [
                '# EMILIA M01 Paid-Pilot Evidence Bundle',
                '',
                'This directory was generated from the runnable Gap 6 and M01 field-origin profile.',
                'It contains the exact observed action, the pinned field-origin profile and trust keys,',
                'the customer-signed Bounded Execution Program and approval receipt trust configuration,',
                'the signed field-origin evidence, the Gate hash chain, the deterministic case report,',
                'and human-readable audit and underwriter support documents.',
                '',
                'Verify it offline from the matching source checkout:',
                '',
                '```bash',
                'node conformance/composition/gap6-execution-evidence-v0.1/verify-pilot-kit.mjs --bundle /path/to/this/bundle',
                '```',
                '',
                'The trust key must be pinned out of band. A key carried inside its own bundle is not a trust decision.',
                '',
            ].join('\n')],
        ['PILOT-REPORT.md', pilotReport(result)],
        ['observed-action.json', json(result.pilot.observed_action)],
        ['field-origin-profile.json', json(result.pilot.field_origin_profile)],
        ['field-origin-trusted-keys.json', json(result.pilot.field_origin_trusted_keys)],
        ['field-origin-evidence.json', json(result.pilot.field_origin_evidence)],
        ['approval-receipt.json', json(result.pilot.approval_receipt)],
        ['receipt-trust-config.json', json(result.pilot.receipt_trust_config)],
        ['action-risk-manifest.json', json(result.pilot.manifest)],
        ['selector.json', json(result.pilot.selector)],
        ['bounded-execution-program.json', json(result.pilot.execution_program_artifact)],
        ['bounded-execution-program-verification.json', json({
                verification_options: result.pilot.execution_program_verification,
                node_id: result.pilot.execution_program_node_id,
            })],
        ['gate-evidence-log.json', json(log)],
        ['gap6-report.json', json(gap6Report)],
        ['audit-workpaper.json', json(audit)],
        ['audit-workpaper.md', renderAuditWorkpaper(audit)],
        ['underwriter-attestation.json', json(underwriter)],
        ['underwriter-attestation.md', renderUnderwriterAttestation(underwriter)],
    ]);
    for (const [name, content] of files)
        writeFileSync(resolve(output, name), content);
    const manifestFiles = [...files.keys()].sort().map((name) => {
        const bytes = readFileSync(resolve(output, name));
        return { name, bytes: bytes.length, sha256: sha256(bytes) };
    });
    const manifest = {
        '@version': 'EP-M01-PAID-PILOT-BUNDLE-v0.1',
        source_commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: HERE, encoding: 'utf8' }).trim(),
        source_tree_clean: execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: HERE, encoding: 'utf8' }).trim().length === 0,
        source_profile: result.deterministic['@profile'],
        source_results_digest: result.results_digest,
        field_origin_profile_digest: result.deterministic.claim_model.field_origin.profile_digest,
        trust_note: 'Pin field-origin-trusted-keys.json out of band. Bundle carriage alone does not establish trust.',
        files: manifestFiles,
    };
    writeFileSync(resolve(output, 'bundle-manifest.json'), json(manifest));
    return { output, manifest, file_count: manifestFiles.length + 1 };
}
function cliOutput() {
    const flag = process.argv.indexOf('--output');
    if (flag === -1)
        return null;
    const value = process.argv[flag + 1];
    if (!value)
        throw new Error('pilot kit export: --output requires a directory');
    return value;
}
const isMain = process.argv[1]
    && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
    const exported = await exportPilotKit(cliOutput() ?? DEFAULT_OUTPUT);
    process.stdout.write(`M01 paid-pilot kit: ${exported.output}\n`);
    process.stdout.write(`Files: ${exported.file_count}\n`);
    process.stdout.write(`Gap 6 digest: ${exported.manifest.source_results_digest}\n`);
}
