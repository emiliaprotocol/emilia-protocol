// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
const packageMetadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
if (typeof packageMetadata.version !== 'string' || packageMetadata.version.length === 0) {
    throw new Error('@emilia-protocol/scan package metadata has no valid version');
}
// package.json is the single release-version source for every scan surface.
export const SCAN_VERSION = packageMetadata.version;
//# sourceMappingURL=version.js.map