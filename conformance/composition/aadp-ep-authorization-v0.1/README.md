<!-- SPDX-License-Identifier: Apache-2.0 -->
# AADP and EP authorization-artifact composition v0.1

This package implements and tests an EMILIA-authored composition profile for
the Agent Action Decision Protocol (AADP). The profile records a digest-bound
projection of native EP Authorization Bundle verification beside AADP's own
approval evidence. It does not revise AADP, issue an AADP permit, or make
either protocol depend on the other.

## What remains separate

The implementation preserves four distinct facts:

1. The native verifier was reached and returned `VERIFIED`, `REFUSED`, or
   `UNAVAILABLE`.
2. The EP evidence evaluation returned `SATISFIED`, `REFUSE`, or
   `INDETERMINATE`.
3. The helper's `authorization_decision` remains `false`.
4. The bounded AADP lifecycle separately returns a wire verdict from the
   `permit`, `deny`, `propose`, `dry_run`, `observe`, and `replay` vocabulary.

AADP -01 defines no `indeterminate` wire verdict. If a required verifier,
status source, policy source, or mapping is unavailable, the bounded model
returns no AADP response and the PEP follows AADP failure semantics. It does
not invent a seventh verdict.

## Closed mapping

[`mapping-profile.json`](./mapping-profile.json) is a closed, locally selected
mapping configuration. It binds:

- the mapping profile;
- the source and mapped action types;
- the mapping implementation identity, version, and source digest;
- the resolver identity, version, source digest, and complete configuration
  digest;
- the exact source-action and mapped-action digests; and
- a `no_material_field_loss: true` rule.

Every AADP material parameter must be declared exactly once and must appear at
its declared mapped path with identical canonical bytes. The closed resolver
constructs only the declared output paths and rejects reserved or ambiguous
paths. Missing fields, unknown fields, an unknown action type, or a dropped
value refuse before EP verification. The `debit_account` regression
demonstrates the former lossy mapping: the old callback ignored that
consequential field and still returned success; the current profile refuses
it by name.

## Verification record

The neutral hook binds a complete verification-record digest. That record
includes:

- artifact digest and artifact profile;
- native verification and EP evidence-satisfaction outcomes;
- verifier implementation identity, version, and digest;
- a digest of the complete serializable trust configuration;
- a separate digest of evaluation time, status inputs, and current policy;
- source and mapped action digests; and
- a digest of the full native verifier result.

Unidentified verifier callbacks are not silently omitted from the record. This
version refuses them as unbound extensions.

## Executed cases

The deterministic runner executes 22 cases covering:

- positive exact-action composition and the four-layer separation above;
- action substitution, artifact tampering, missing trust pins, and audience
  substitution;
- unavailable mapping and stale current policy;
- presenter substitution of mapping profile, implementation, and resolver;
- missing hook, single-use approval, provider-key separation, and timeout
  reporting;
- AADP's informational `source` field;
- the `debit_account` material-field-loss regression;
- three compound negatives proving that the AADP kill switch wins before
  malformed, unavailable, or stale EP input is observed;
- malformed AADP input returning the draft-defined `deny` without observing
  EP input;
- no invented AADP `indeterminate` wire verdict; and
- report binding of every source-lock hash.

The AADP request fixtures contain the required AADP -01 fields and use the
draft's wire vocabulary. The lifecycle remains an internal, bounded
draft-derived projection, not onedoor.

## Source verification

[`source-lock.json`](./source-lock.json) pins:

- the exact `draft-saha-aadp-01` text bytes;
- the exact inspected onedoor files at one commit; and
- the declared local EP artifact, verifier-version, verifier-source, and
  mapping inputs.

The source verifier fetches the AADP and onedoor URLs and hashes the actual
returned bytes. The deterministic report embeds the complete source lock and
therefore binds every declared hash.

## Run

```bash
npm run conformance:composition:aadp-ep
```

The command rebuilds the verify package, verifies the actual upstream bytes,
runs the package and composition tests, and compares the runner output with
the checked-in deterministic report.

Regenerate companions and the report only after a deliberate source change:

```bash
npm run build:standalone-runtimes
npm --prefix packages/verify run build
node conformance/composition/aadp-ep-authorization-v0.1/run.mjs --emit
```

## Claim boundary

This is same-team composition evidence. It is not an independent AADP
implementation, execution of onedoor, interoperability result, AADP adoption,
IETF working-group result, joint publication, or proof of exactly-once
physical execution.
