// SPDX-License-Identifier: Apache-2.0
import { discoverAuthority } from './discover.js';
import { detectAuthoritySignals } from './detect.js';
export const AUTHORITY_SCAN_VERSION = '0.3.1';
export function runAuthorityScan(options = {}) {
    const inventory = discoverAuthority(options);
    const summary = {
        total: 0,
        mutating: 0,
        read_only: 0,
        unknown: 0,
        coverage: {
            computable: false,
            reason: 'no tool surface is visible from configuration alone',
        },
    };
    return {
        version: AUTHORITY_SCAN_VERSION,
        inventory,
        signals: detectAuthoritySignals(inventory),
        summary,
    };
}
export * from './types.js';
export { describeSecret, safeValue, describeEnv, redactText, sanitizeForReport, sanitizeArgs, } from './redact.js';
export { discoverAuthority, configCandidates, credentialFiles, envFiles } from './discover.js';
export { detectAuthoritySignals, severityRank } from './detect.js';
export { AUTHORITY_CLAIM_BOUNDARY, AUTHORITY_SCOPE, renderAuthorityText, renderAuthorityJson, authorityExitCode, writePrivateReport, } from './report.js';
//# sourceMappingURL=index.js.map