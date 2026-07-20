/**
 * EP Policy Authoring SDK
 *
 * Pre-deployment tooling for EP handshake policies. The SDK sits above the
 * handshake-layer validator (lib/handshake/policy.js) and provides three
 * authoring-grade capabilities:
 *
 *   - lintPolicy:    catches semantic smells before a policy ships.
 *   - simulateOne:   evaluates a scenario against a policy using production invariants.
 *   - diffPolicy:    classifies version-to-version changes as loosening / tightening / neutral.
 *
 * Designed for:
 *   - CI gates on policy repos
 *   - Pre-commit hooks on policy authoring tooling
 *   - Policy editor IDE integration
 *   - Review gates: block policy PRs that loosen production without an ADR
 *
 * @license Apache-2.0
 */

export { lintPolicy, filterBySeverity, formatReport } from './linter.js';
export { simulateOne, simulateBatch, scenarioFromPolicy } from './simulator.js';
export { diffPolicy, formatDiff } from './diff.js';
