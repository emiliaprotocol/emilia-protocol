# AEB Crossing Lab local example

This example uses the published `emilia-verify` CLI to scaffold and evaluate a
local native adapter without a server:

```sh
npm --prefix packages/verify run build
node packages/verify/cli.js crossing-lab init /tmp/aeb-crossing-lab-example
# edit adapter.mjs, artifact.json, and workspace.json, then review them
node packages/verify/cli.js crossing-lab seal /tmp/aeb-crossing-lab-example
node packages/verify/cli.js crossing-lab run /tmp/aeb-crossing-lab-example
```

The generated module implements the stable `AebAdapter` interface. Every
adapter row is produced by the canonical `evaluateAebEvidence` evaluator under
a real `AEB-ADAPTER-v1` pinned configuration, and retains its complete signed
`AEB-EVALUATION-v1`. Hostile adapter rows cover an explicit reviewed action
substitution, trust substitution, stale or unavailable status, and wrapper-
independent replay identity. Malformed output, strict JSON, and pin drift are
separate harness self-tests.

The result is a deterministic, local, self-attested adapter compatibility test.
It is not a governed conformance pack, certification, authorization, native-
specification validation, independent interoperability evidence, deployment
proof, execution proof, or a claim that the native system and EMILIA have the
same semantics.

See [the full workbench documentation](../../docs/AEB-CROSSING-LAB.md).
