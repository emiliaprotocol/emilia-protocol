# Dependency repair, October 26, 2026

This records the repair of replacement PR #929 after Dependabot closed #922.
It is a tested partial repair, not an audit pass or release approval.

Restored changes remove expired source-map-js and DTC http-cache-semantics
acceptances, pin the existing patched versions, and retain fail-closed audit
regressions. Expo 57.0.30 and expo-asset 57.0.20 have cleared the seven-day
quarantine, so their expired holds are removed. The stale braces acceptance is
removed because the registry audit no longer reports it. The existing node-forge
acceptance still expires October 30; no acceptance date is extended.

Additional eligible fixes: Next and eslint-config-next 16.4.2, MCP server 2.3.0,
Hono 4.13.11, ip-address 10.7.4, and DTC undici 6.29.1. Lifecycle scripts were
disabled while resolving and materializing dependencies. Next 16.4.3 was not
selected because it had not cleared quarantine.

## Verification

- Node 24.22.1: 118 audit/MCP tests passed, one skipped, across five Vitest files.
- Mobile audit/quarantine tests: 24 passed; the real-audit test correctly remains
  failed on the new uncovered Zod advisory below.
- Expo quarantine validation and DTC source artifact manifest verification passed.
- Repository boundary and diff whitespace checks passed.
- No full suite, application build, production test, merge, or deployment ran.

## Remaining gates

The root lockfile audit reports no critical findings, one high and twelve
moderate package findings. These are propagated package counts, not distinct
advisory counts. The blocking direct advisories are:

| Package and path | Advisory | Required next step |
| --- | --- | --- |
| root body-parser 2.3.0 | GHSA-27r3-jxmh-p828 | 2.4.0 was published October 22 at 11:39:38.614 UTC and becomes eligible October 29 at that time. |
| root fast-uri 3.1.8 | GHSA-w74x-v6f9-j3xg, GHSA-wjr9-j795-jxcr | 3.1.9 was published October 19 at 23:05:26.357 UTC and becomes eligible October 26 at that time. |
| Expo CLI and Hardhat development tooling, Zod 3.25.76 | GHSA-mrhx-c7xc-m3w5 | Upstream consumers still require Zod 3. Do not force Zod 4 across their declared major boundary. An upstream-compatible fix or separately reviewed acceptance is needed. |

The fast-uri release also fixes low-severity GHSA-xhq7-xmqj-769h and
GHSA-333x-w4r6-6crp. DTC's low-severity serialize-javascript finding
GHSA-m5mm-p8h7-m29v remains below its existing high-severity toolchain gate.
DTC production dependencies are a separate low-threshold audit.

The policy is `.npmrc`: "refuse to resolve dependency versions published less
than 7 days ago", implemented by `min-release-age=7`; independent package roots
repeat it in their own `.npmrc`. No quarantine exemption or new risk acceptance
was added. `scripts/audit-with-exceptions.mjs` continues to reject uncovered,
expired, stale, or widened acceptances.
