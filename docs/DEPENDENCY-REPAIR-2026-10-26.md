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

## Compatible-remedy follow-up, October 26 at 17:01 UTC

The upstream advisory ranges and current npm metadata were checked again. An
older release does not provide a compatible way around either quarantine:

- [GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828)
  affects body-parser `>=2.0.0 <2.4.0` and `<1.20.9`. The installed Express
  5.2.1 requires `^2.2.1`, so every older compatible version is affected; the
  patched 1.20.9 line does not satisfy that dependency. The advisory's
  `inflate: false` workaround rejects compressed bodies, but does not remove
  the vulnerable dependency or constitute an audit acceptance.
- [GHSA-w74x-v6f9-j3xg](https://github.com/advisories/GHSA-w74x-v6f9-j3xg)
  affects every fast-uri 3.x release before 3.1.9. Root and DTC AJV require
  `^3.0.1`, so no older compatible version clears it. The narrower host
  confusion range in
  [GHSA-wjr9-j795-jxcr](https://github.com/advisories/GHSA-wjr9-j795-jxcr)
  (`>=3.1.3 <3.1.9`) does not make a downgrade safe against both advisories.
  Patched 2.4.8 and 4.2.3 belong to incompatible major lines.

The eligible times above are calculated from the npm publication timestamps,
not from when the advisory was published. Root `.npmrc` has no emergency
third-party exemption: its only exclusion is the separately governed
`@emilia-protocol/verify` release path. The mobile Expo patch holds and dated
audit-risk acceptances are different controls, neither authorizing early
third-party package resolution. No exclusion, acceptance, or expiry was added.

### Zod: current published fixes and affected behavior

The [Zod advisory](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) still lists
`<4.6.6` as affected. Registry metadata shows 3.25.76 remains the latest stable
3.x release; no patched 3.x release is published. Root Zod is already 4.6.7.
The current consumer versions still require Zod 3:

| Consumer checked in the registry | Declared Zod dependency or peer |
| --- | --- |
| Expo CLI 57.0.32 and 58.1.15 | `^3.25.76` |
| Hardhat 3.21.0 | `^3.23.8` |
| hardhat-ethers 4.2.1 and hardhat-mocha 4.0.1 | `^3.23.8` |
| hardhat-zod-utils 3.0.8 | `^3.23.8` |

Upstream [Zod PR 6652](https://github.com/colinhacks/zod/pull/6652) repairs the
v4 array, set, and map parsers by rejecting oversized inputs before parsing
their elements when an applicable upper bound is present. Unbounded containers
are unchanged. A bounded local reproduction against the v3 compatibility
implementation bundled in the existing Zod 4.6.7 installation showed that
`.max(2)` still parsed all 20 supplied valid elements; 20 invalid elements
produced 21 issues. This was a small behavior check, not an out-of-memory test
or a fresh installation of Zod 3.25.76.

The relevant upstream consumers include Expo's unbounded plugin command/output
array schemas and Hardhat's JSON-RPC access-list arrays. Their presence in
development tooling alone is not a reachability proof or a basis for accepting
the advisory. Forcing Zod 4 across the declared major boundary, or using its
still-v3 compatibility entry point, is not an established fix. A reviewed
compatible backport, upstream consumer migration, or separately justified
containment decision remains necessary.

This follow-up changed only this report. It did not reinstall dependencies,
rerun the audit/full suite, waive a gate, or duplicate the MCP/Vitest/Vite
updates already present in this PR.
