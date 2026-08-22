// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stateHandoffDigest } from '../../../packages/verify/src/portable-state-handoff.js';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const referencePath = resolve(here, 'report.reference.json');
const CASES = [
    ['independent-producer-roundtrip', 'ACCEPTED', 'positive'],
    ['source-release-plus-atomic-import', 'ACCEPTED', 'positive'],
    ['authority-shaped-payload', 'REFUSED', 'hostile'],
    ['object-tamper', 'REFUSED', 'hostile'],
    ['required-object-omission', 'REFUSED', 'hostile'],
    ['unlisted-object-insertion', 'REFUSED', 'hostile'],
    ['bounded-canonical-input', 'REFUSED', 'hostile'],
    ['future-created-manifest', 'REFUSED', 'hostile'],
    ['object-snapshot-after-set-cut', 'REFUSED', 'hostile'],
    ['observation-after-snapshot', 'REFUSED', 'hostile'],
    ['origin-assertion-after-snapshot', 'REFUSED', 'hostile'],
    ['optional-object-omission', 'PARTIAL', 'edge'],
    ['source-release-not-consumed', 'REFUSED', 'hostile'],
    ['recipient-refusal-no-authority-burn', 'REFUSED', 'hostile'],
    ['recipient-boundary-signer-substitution', 'REFUSED', 'hostile'],
    ['recipient-commit-action-substitution', 'REFUSED', 'hostile'],
    ['head-change-during-commit', 'INDETERMINATE', 'hostile'],
    ['commit-acknowledgement-lost', 'INDETERMINATE', 'edge'],
    ['repeated-bundle-requires-explicit-reconciliation', 'INDETERMINATE', 'hostile'],
    ['reconciliation-without-retry', 'ACCEPTED', 'positive'],
    ['lineage-rollback', 'REFUSED', 'hostile'],
    ['lineage-fork', 'REFUSED', 'hostile'],
    ['lineage-gap', 'INDETERMINATE', 'edge'],
    ['vault-plaintext', 'REFUSED', 'hostile'],
    ['vault-ciphertext-with-release', 'ACCEPTED', 'positive'],
    ['unknown-required-payload-profile', 'INDETERMINATE', 'edge'],
    ['hybrid-manifest', 'ACCEPTED', 'positive'],
    ['hybrid-leg-stripping', 'REFUSED', 'hostile'],
    ['hybrid-import-receipt', 'ACCEPTED', 'positive'],
    ['hybrid-import-receipt-stripping', 'REFUSED', 'hostile'],
    ['post-import-source-retirement-binding', 'ACCEPTED', 'positive'],
    ['partial-retirement-excludes-unavailable', 'ACCEPTED', 'positive'],
    ['action-substitution-caid-change', 'REFUSED', 'hostile'],
    ['recipient-substitution-caid-change', 'REFUSED', 'hostile'],
    ['tombstone-with-erasure-nonclaim', 'ACCEPTED', 'edge'],
    ['accepted-receipt-without-admission-record', 'REFUSED', 'hostile'],
    ['accepted-receipt-with-failure-reason', 'REFUSED', 'hostile'],
    ['accepted-receipt-with-unavailable-state', 'REFUSED', 'hostile'],
    ['partial-receipt-without-unavailable-state', 'REFUSED', 'hostile'],
    ['failed-receipt-without-reason', 'REFUSED', 'hostile'],
    ['receipt-issued-before-completion', 'REFUSED', 'hostile'],
    ['failed-reconciliation-receipt', 'REFUSED', 'hostile'],
    ['receipt-boundary-substitution', 'REFUSED', 'hostile'],
    ['receipt-state-set-substitution', 'REFUSED', 'hostile'],
    ['receipt-authority-caid-substitution', 'REFUSED', 'hostile'],
    ['ambiguous-payload-adapter', 'INDETERMINATE', 'hostile'],
    ['runtime-caid-registry-drift', 'REFUSED', 'hostile'],
    ['trusted-time-not-established', 'NOT_ESTABLISHED', 'edge'],
    ['malformed-payload-fails-closed', 'REFUSED', 'hostile'],
    ['source-verifier-exception', 'INDETERMINATE', 'hostile'],
    ['payload-adapter-exception', 'INDETERMINATE', 'hostile'],
    ['recipient-admission-lookup-exception', 'INDETERMINATE', 'hostile'],
    ['recipient-head-read-exception', 'INDETERMINATE', 'hostile'],
    ['recipient-commit-response-unknown', 'INDETERMINATE', 'hostile'],
    ['vault-availability-exception', 'INDETERMINATE', 'hostile'],
    ['independent-producer-unicode-parity', 'REFUSED', 'hostile'],
    ['hostile-receipt-canonical-input', 'REFUSED', 'hostile'],
    ['hostile-manifest-relationship-input', 'REFUSED', 'hostile'],
];
export function runPortableStateHandoffReport() {
    const tsx = resolve(root, 'node_modules/tsx/dist/cli.mjs');
    const tests = [
        resolve(root, 'packages/verify/portable-state-handoff.test.ts'),
        resolve(root, 'examples/portable-state-handoff/roundtrip.test.mts'),
        resolve(root, 'conformance/composition/portable-state-handoff-v0.1/schemas.test.mts'),
    ];
    const result = spawnSync(process.execPath, [tsx, '--test', ...tests], {
        cwd: root,
        encoding: 'utf8',
    });
    if (result.status !== 0) {
        throw new Error(`portable-state handoff tests failed\n${result.stdout}\n${result.stderr}`);
    }
    const report = {
        '@version': 'EP-STATE-HANDOFF-CONFORMANCE-REPORT-v0.1',
        profile: 'EP-PORTABLE-STATE-HANDOFF-v0.1',
        payload_profile: 'EP-STATE-PAYLOAD-SOMA-COGOBJ-v0.1',
        authority_profile: 'EP-STATE-HANDOFF-AUTHORITY-v0.1',
        implementations: [
            {
                name: 'Continuum independent producer',
                path: 'examples/portable-state-handoff/continuum-exporter.mjs',
                role: 'source',
            },
            {
                name: 'EMILIA portable-state recipient',
                path: 'packages/verify/src/portable-state-handoff.ts',
                role: 'recipient',
            },
        ],
        implementation_independence: {
            status: 'SEPARATE_MODULES_AND_CANONICALIZERS',
            boundary: 'same_repository_and_team_not_external_independence',
        },
        cases: CASES.map(([id, expected_result, className]) => ({
            id,
            expected_result,
            class: className,
            status: 'PASS',
        })),
        summary: {
            total: CASES.length,
            passed: CASES.length,
            positive: CASES.filter((entry) => entry[2] === 'positive').length,
            hostile: CASES.filter((entry) => entry[2] === 'hostile').length,
            edge: CASES.filter((entry) => entry[2] === 'edge').length,
        },
        normative_ep_actions: [
            'agent.state.export.1',
            'agent.state.import.1',
            'agent.state.key-release.1',
            'agent.state.retire-source.1',
        ],
        optional_noncore_profiles: [
            'WEXP execution-evidence appraisal',
            'CAP-1 examined-set coverage',
            'WIMSE workload identity',
            'SCITT registration and timestamping',
            'SAIHM encrypted cell carriage',
        ],
        nonclaims: [
            'does_not_prove_source_state_truth',
            'does_not_prove_source_population_completeness',
            'does_not_transfer_reusable_authority',
            'does_not_prove_physical_erasure',
            'does_not_establish_trusted_time',
            'does_not_establish_external_implementation_independence',
            'is_not_an_ietf_submission_adoption_or_deployment',
        ],
    };
    return { ...report, report_digest: stateHandoffDigest(report) };
}
async function main() {
    const report = runPortableStateHandoffReport();
    if (process.argv.includes('--check')) {
        const reference = JSON.parse(await readFile(referencePath, 'utf8'));
        if (JSON.stringify(reference) !== JSON.stringify(report)) {
            throw new Error('portable-state handoff reference report is stale');
        }
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    await main();
