import type { SourceDiscoveryDiff, SourceDiscoveryOptions, SourceDiscoveryReport } from './types.js';
export declare const SOURCE_DISCOVERY_VERSION: "EP-SOURCE-DISCOVERY-v1";
export declare const SOURCE_PARSER_VERSION = "emilia-source-patterns-v1";
export declare const SOURCE_CLAIM_BOUNDARY = "Pattern-based static discovery proposes review inputs. It does not prove runtime reachability, complete mediation, source truth, or authorization.";
export declare function scanSourceDirectory(rootInput: string, options?: SourceDiscoveryOptions): SourceDiscoveryReport;
export declare function diffSourceDiscovery(current: SourceDiscoveryReport, baseline: unknown): SourceDiscoveryDiff;
export declare function sourceDiscoveryExitCode(value: SourceDiscoveryReport | SourceDiscoveryDiff): number;
export * from './types.js';
//# sourceMappingURL=index.d.ts.map