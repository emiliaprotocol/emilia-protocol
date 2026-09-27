# Issue #250: current Rust verifier intake (prepared, not submitted)

This is a reproducible request for an updated externally authored Rust
implementation. It is **not** an acceptance record or a claim that the
historical Rust result applies to the current corpus. No request has been sent
from this document.

## Exact public input

- EMILIA source commit: `1fb0f3e56ae20d2ed53439d90f27b64660c49a50`
- EMILIA source tree: `e626dbc7408d1dc2cafe67fc1e5a2745984cdbc0`
- Live manifest: 21 suites, 340 vectors, three same-team ports
- Manifest file SHA-256: `819e5206f0e8ee7cf5f215f04279a1debacfd48e9bc167443c9c2780762e7817`
- Manifest claim SHA-256: `2c5fdafd9f5a4045bd7533c2f312ec8dd7e90ebf0072c7d699ef57e896dcda9f`
- Vector catalog SHA-256: `ee1021eb36de8e50448d9f12f00d16f3e24561276c9a42241e88178d5daa0d3e`
- Authority-document execution companion SHA-256: `121a358459ffed223a41a79570cc5307693eaa89a59b3ad330710c5e2f286959`
- Source-free v3 kit tarball SHA-256: `6933db6ea5b648ded8bdb7d82587aed825ce83caf30f830b5cd9db80037ccf26`

The kit was built from that exact commit with:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/build-clean-room-kit-v3.mts \
  --ref 1fb0f3e56ae20d2ed53439d90f27b64660c49a50 \
  --out /tmp/emilia-clean-room-kit-v3.tar.gz
```

The kit has the public vectors and expectations for development. During
evaluation, the v3 runner receives execution inputs only, under fresh random
handles. The evaluator keeps expectations and catalogue IDs to itself, then
adds 80 post-build canonicalization challenges. The public vector set remains
testable; the fresh challenge is not a proof against every possible lookup
strategy.

## What to ask the implementer to supply

1. An updated immutable source commit and tree, with locked dependencies,
   build instructions, and an executable implementing
   `EP-CONFORMANCE-FILE-RUNNER-v3`. The external author, not EMILIA, should own
   any compatibility adapter that is part of the submitted runner. See
   [`../clean-room/v3/submission.schema.json`](../clean-room/v3/submission.schema.json)
   and [`../../docs/conformance/CLEAN-ROOM-V3.md`](../../docs/conformance/CLEAN-ROOM-V3.md).
2. A v3 submission binding that source, runner SHA-256, all four kit digests
   above, and a factual list of specification inputs used. The construction
   statement must accurately describe reference-source access; do not copy
   the historical statement to a changed tree.
3. An implementer-signed construction statement binding the same source
   commit/tree, runner digest, submission digest, and specification inputs.
4. A separate Ed25519 attestation from an organization independent of both
   EMILIA and the implementer, using
   [`../clean-room/v2/independent-attestation.schema.json`](../clean-room/v2/independent-attestation.schema.json).
   The attestor's key and independent organization identity must be pinned by
   the evaluator. EMILIA cannot sign this on the third party's behalf.

We should rebuild the exact submitted source and locked dependencies, verify
the artifact hash, then evaluate the 340 published vectors and 80 fresh cases
under a digest-pinned, evaluator-controlled isolated runtime. The current
manifest-derived hostility campaign must be run against the **same** binary.
Record every divergence; do not turn an updated partial result into a pass.

## Current status and claim boundary

The historical external pin remains 16 suites/164 vectors and 359 hostility
cases. Its source tree and statement are not retroactively upgraded. Our
separate [340-vector diagnostic](DIAGNOSTIC-RUST-CURRENT-340-2026-09-12.md)
reused the older binary and found 36 divergences among 402 structured
hostility cases. It is not an implementer submission or clean-room acceptance.

On 2026-09-26, the public `jdieselny/ecr-wg` main branch was
`5528222569673ef39c8c0146ff188a0abafef361`, but its Rust verifier README
still described a historical 193-vector run. The latest branch has a different
source tree from the pinned July tree; a branch moving is not itself evidence
of current v3 conformance or construction. No updated v3 submission, current
implementer-signed construction claim, or independent-organization attestation
was identified in this intake. Strict clean-room acceptance remains zero.

The issue should stay open until all artifacts are received, verified against
one immutable set of bytes, and the claim ledger is updated without altering
the historical result.
