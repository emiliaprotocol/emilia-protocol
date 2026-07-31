import type { AuthorityScanResult, DiscoveryOptions } from './types.js';
export declare const AUTHORITY_SCAN_VERSION = "0.3.1";
export declare function runAuthorityScan(options?: DiscoveryOptions): AuthorityScanResult;
export * from './types.js';
export { describeSecret, safeValue, describeEnv, redactText, sanitizeForReport, sanitizeArgs, } from './redact.js';
export { discoverAuthority, configCandidates, credentialFiles, envFiles } from './discover.js';
export { detectAuthoritySignals, severityRank } from './detect.js';
export { AUTHORITY_CLAIM_BOUNDARY, AUTHORITY_SCOPE, renderAuthorityText, renderAuthorityJson, authorityExitCode, writePrivateReport, } from './report.js';
//# sourceMappingURL=index.d.ts.map