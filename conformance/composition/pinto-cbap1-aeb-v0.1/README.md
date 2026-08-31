# Pinto CBAP-1 × EMILIA AEB Crossing Profile v0.1

This directory is a runnable, source-pinned interoperability profile for the
direct-binding positive path of CBAP-1 in
`draft-pinto-agent-authz-contestability-00`. It asks one deliberately narrow
question:

> Can a strictly verified CBAP-1 record become historical contestability
> evidence for one exact action in an AEB evaluation without becoming authority
> to perform that action?

For the deterministic fixture in this directory, the answer is yes. The native
result is preserved as a 17-axis CBAP-1 result, then admitted as the AEB evidence
role `contestability-binding` for a `system` subject. The role has
`authorization_semantics: false`.

## What runs

The fixture contains real Core Deterministic CBOR and five real tagged
`COSE_Sign1` objects signed with Ed25519 test keys:

1. Contestability Profile Object (CPO)
2. exact forum acceptance
3. authorization object
4. executor pre-execution verification
5. execution record

The self-contained adapter validates deterministic CBOR, exact COSE protected
headers, the three role-specific trust roots, all five signatures, by-value
policy digests, the direct action-binding chain, acceptance binding, executor
ordering, filing horizon, and the CBAP-1 profile restrictions used here. Its
decoder rejects indefinite lengths, non-shortest encodings, duplicate or
unordered map keys, invalid UTF-8, unsupported tags and floating-point values,
more than 32 levels, and more than 65,536 decoded nodes.

The mapped action is a JCS-encoded `account.suspend.1` object. All three fields
are material. A changed field produces a different CAID and the Crossing Lab
requires the substitution row to fail closed.

## Claim boundary

This is a historical contestability-evidence crossing. It is not:

- pre-execution authority or permission to execute the action;
- execution evidence merely because the CBAP record contains an execution
  record;
- a certificate, independent audit, production deployment, or security proof;
- an independent Pinto implementation or a vector published by the Pinto
  authors;
- a claim that CBAP-1 is equivalent to AEB as a whole;
- an implementation of class manifests, companion bindings, notices, external
  or multiparty selection, active effects, or FAM;
- a claim that an inner CBAP `COSE_Sign1` is the same object as a SCITT Signed
  Statement. Inner and outer evidence digests remain separate.

The positive fixture uses direct binding, exact acceptance, unilateral
selection, by-value policies, executor-attested pre-execution evidence, an
execution-time filing clock, and declared effect `none`. Unknown native
surfaces are not silently discarded; they are outside this profile.

## Reproduce

From the repository root with the supported Node permission runtime:

```sh
node conformance/composition/pinto-cbap1-aeb-v0.1/generate-fixture.mjs --check
node --test conformance/composition/pinto-cbap1-aeb-v0.1/run.test.mjs
node packages/verify/cli.js crossing-lab run \
  conformance/composition/pinto-cbap1-aeb-v0.1/workspace
node conformance/composition/pinto-cbap1-aeb-v0.1/run.mjs --check
```

The checked-in reference report is reproducible byte for byte. The Crossing Lab
runs six adapter rows and four harness self-tests: positive admission, exact
action substitution, trust-root substitution, stale status, unavailable status,
wrapper-independent replay identity, and strict-output/harness checks.

## Files

- `source-lock.json` pins the exact Internet-Draft TXT and XML bytes.
- `mapping-profile.json` records the field mapping, native result, exclusions,
  and non-claims.
- `generate-fixture.mjs` deterministically creates and seals the workspace.
- `workspace/adapter.mjs` is the captured self-contained verifier and mapper.
- `workspace/artifact.json` is the deterministic CBOR/COSE fixture envelope.
- `workspace/workspace.json` contains the Crossing Lab configuration and pins.
- `run.mjs` produces or checks the integrated native and Crossing Lab report.
- `run.test.mjs` contains positive, hostile, boundary, and reproducibility tests.
- `report.reference.json` is the checked deterministic reference result.

## Before an external adoption claim

This profile still needs all of the following:

1. confirmation from the Pinto authors that the mapping preserves their CBAP-1
   semantics;
2. a stable, redistributable native vector set or explicit approval of these
   same-team fixture bytes;
3. reproduction by a second independently written runner; and
4. installation beside one real system with governed, current status evidence.

Until then, the report supports a local compatibility result only.
