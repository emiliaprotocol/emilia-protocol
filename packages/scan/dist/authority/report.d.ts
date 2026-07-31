import type { AuthorityScanResult } from './types.js';
export declare const AUTHORITY_CLAIM_BOUNDARY = "config_derived_reachability_only_not_behavioral_not_exploitability_not_an_authorization_guarantee";
export declare const AUTHORITY_SCOPE: Readonly<{
    reports: string[];
    does_not_report: string[];
    does_not_prove: string[];
}>;
export declare function renderAuthorityText(input: AuthorityScanResult): string;
export declare function renderAuthorityJson(input: AuthorityScanResult): string;
export declare function authorityExitCode(result: AuthorityScanResult): number;
export declare function writePrivateReport(file: string, output: string): void;
//# sourceMappingURL=report.d.ts.map