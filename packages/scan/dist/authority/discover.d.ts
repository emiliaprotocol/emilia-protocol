import type { AuthorityInventory, ConfigCandidate, CredentialFile, DiscoveryOptions, EnvFile } from './types.js';
export declare function configCandidates(options?: DiscoveryOptions): ConfigCandidate[];
export declare function credentialFiles(home?: string): CredentialFile[];
export declare function envFiles(cwd: string, home: string, maxDepth?: number): EnvFile[];
export declare function discoverAuthority(options?: DiscoveryOptions): AuthorityInventory;
//# sourceMappingURL=discover.d.ts.map