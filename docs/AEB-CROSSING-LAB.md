# AEB Crossing Lab

The AEB Crossing Lab is an offline workbench for a native authorization,
delegation, payment, or oversight protocol. It answers a narrow question:

> Can this native artifact be verified under its own pinned rules, mapped to
> the exact action at an AEB consequence crossing, and satisfy a named evidence
> role without losing its native identity?

It is tooling over the existing AEB adapter contract and CAID mapping profile.
Its versioned workspace and report are local tool metadata, not a new EP wire
format, evidence envelope, authorization object, or conformance certificate.

## Start a workspace

```sh
npx @emilia-protocol/verify crossing-lab init ./my-native-protocol
# edit and review the three local files
npx @emilia-protocol/verify crossing-lab seal ./my-native-protocol
npx @emilia-protocol/verify crossing-lab run ./my-native-protocol \
  --out ./crossing-lab-report.json
```

`seal` recomputes local development pins after a deliberate edit. It does not
validate the native protocol, decide whether a field is material, trust an
issuer, or execute adapter code. Review the workspace diff before running it.

The scaffold contains three required files:

- `workspace.json` carries one real `AEB-ADAPTER-v1` pinned configuration and
  evaluation input. It pins the adapter identity and bytes, native trust roots,
  adapter configuration, a status snapshot whose native authentication remains
  the adapter/integrator's responsibility, CAID mapping profile, exact expected
  action, an explicit reviewed material-action substitution fixture, evidence
  requirement, role registry, and fixture digest.
- `adapter.mjs` exposes pure, deterministic `verifyNative` and `mapAction`
  hooks. The example verifies a real Ed25519 signature and recomputes its CAID;
  its published key material remains example-only.
- `artifact.json` is one local native fixture.

The adapter runs in a bounded child on Node 26 or another Node permission
runtime that exposes `--allow-net` in `process.allowedNodeEnvironmentFlags`.
Other package APIs retain the package's broader Node support; this subcommand
refuses older runtimes operationally rather than claiming to isolate network
access that they do not govern. The child has read access only to the Lab
worker and the exact pinned adapter module, no filesystem write access, no
ambient network permission, and no child-process permission. Inputs and
outputs are bounded and closed. Workspace paths must be direct, non-symlink
files and every input is digest-pinned before adapter code runs.

Adapters with SDK or sibling-module dependencies must be bundled into the one
pinned ESM file before sealing. For example, use a Node-targeted ESM bundle:

```sh
esbuild adapter-src.ts --bundle --platform=node --format=esm \
  --external:node:* --outfile=adapter.mjs
```

Inspect the bundle, then run `seal`. Dynamic assets and runtime network calls
are intentionally unavailable.

## Adapter contract and conversion checklist

The bundle must default-export one closed object with `id`, `version`, pure
`verifyNative(input)`, and pure `mapAction(input)` members. The authoritative
TypeScript contract is
[`AebAdapter`](../packages/verify/src/aeb-adapter-contract.ts). In summary:

- `verifyNative` receives the artifact, artifact reference, status snapshot,
  relying-party-pinned trust roots and adapter configuration, and the pinned
  evaluation time. It returns `native_verification`, `acceptance`, exact native
  evidence and status digests, one evidence role and subject, a stable native
  replay unit, and bounded reasons.
- `mapAction` additionally receives the pinned mapping profile, exact expected
  action, and the native verification result. It validates the profile and
  resolver, then returns `MATCH`, `MISMATCH`, or `INDETERMINATE` with a CAID and
  normalized action digest only when its native rules support doing so.
- The artifact must never choose its own trust roots, profile, mapper, resolver,
  role, requirement, or evaluation time. `mapAction` must not run as though
  native verification succeeded when it did not.
- Derive the replay unit from the native authority instance, not the Lab
  artifact reference, AEB operation ID, or wrapper nonce.

Minimum conversion sequence:

1. Wrap the native verifier or factory in the closed default export.
2. Replace the example artifact, trust roots, adapter config, role, profile,
   resolver, requirement, exact action, and explicit material-action
   substitution.
3. Bundle all dependencies into `adapter.mjs` and inspect it.
4. Run `seal` and review every changed pin.
5. Run the Lab. If a changed action or profile leaves
   `workspace.evaluation.caid` stale, the failure summary prints the adapter's
   candidate CAID. Review that candidate against the mapping profile, update
   the workspace deliberately, seal again, and rerun. `seal` never invents or
   adopts a CAID.

The current workspace is strict JSON. For a CBOR, COSE, protobuf, or other
binary native artifact, use a closed JSON wrapper containing canonical
base64url native bytes, media type, and the SHA-256 of the decoded bytes. The
adapter must reject non-canonical base64url, verify the decoded native bytes,
and require the wrapper's native-byte digest to match those bytes. AEB's
`artifact_digest` and adapter `evidence_digest` both bind the closed JSON
wrapper, as required by the evaluator; the separately named native-byte digest
inside that wrapper binds the decoded artifact. Neither digest may be silently
substituted for the other.

## What the report keeps separate

Each adapter row is a real invocation of the target adapter through the stable
`AebAdapter` interface and the canonical `evaluateAebEvidence` evaluator. The
complete signed `AEB-EVALUATION-v1` is retained beside five independent axes:

1. `native_verification`: did the native verifier validate the artifact?
2. `acceptance`: does the relying party accept it under current pins and the
   status result supplied to the adapter?
3. `mapping`: does the native artifact denote the exact expected action under
   the pinned mapping profile?
4. `freshness`: is the pinned status fresh, stale, unavailable, revoked,
   consumed, or otherwise indeterminate?
5. `satisfaction`: does the accepted, matched artifact fill the named evidence
   role?

The standard adapter rows add an explicit reviewed exact-action substitution,
trust-root substitution, stale and unavailable status, and an independently
rewrapped evaluation that must retain the same native replay unit. Hostile rows
test safe outcome predicates instead of forcing every native protocol to detect
a problem in the same layer; the report always retains the actual axes.
Identical adapter calls are repeated and byte-canonically compared before any
passing report is produced. Malformed or unknown output, duplicate JSON, and
pin-drift checks are labeled separately as `harness_self_tests`; they are not
represented as target-adapter behavior.

`lab_passed: true` means only that every local self-test passed and the positive
fixture reached `VERIFIED / ACCEPTED / MATCH / FRESH / SATISFIED`. It does not
authorize an action, establish native-specification correctness, or prove that
Gate is deployed.

Each evaluation is signed with a fixed public test key whose private material is
published in the source. That gives deterministic harness integrity only. It
must never be trusted for evaluator identity, operator attribution, production
attestation, or authorization.

## Claim boundary

Every report is labeled
`SELF_ATTESTED_ADAPTER_COMPATIBILITY_TEST_NOT_CERTIFICATION`. A report is not:

- certification or an audit opinion;
- authorization to execute;
- evidence of deployment or complete mediation;
- evidence that an action executed or had the intended effect;
- independent interoperability evidence or proof that an adapter correctly
  implements its native specification; or
- a claim that two native protocols have equivalent semantics.

Native issuers, constraints, evidence roles, signatures, status sources, and
replay units remain attributable to their native systems.
