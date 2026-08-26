# EMILIA Release Process

This repository has four release identities. They are related by exact source
and digests, but they are not interchangeable.

## Release identities

| Identity | Canonical identifier | What it means |
| --- | --- | --- |
| Repository snapshot | Full Git commit SHA | Exact public source at one point in history. `main` is moving, and the root `package.json` is marked `private`, so its version is not an umbrella release number. |
| Protocol artifact | In-artifact version string plus exact bytes or digest | Semantics of a named wire format, profile, mapping, or conformance contract, for example `EP-RECEIPT-v1`. Changed semantics require a new version string. An Internet-Draft revision is a separate publication identity. |
| Registry package | Registry name, package version, and package-specific Git tag | One independently versioned npm, PyPI, or Go module release. Packages do not inherit the root repository version. |
| Evidence snapshot | Artifact version, input digest or bundle hash, and source commit | Exact security-case, conformance, proof-stat, reproducibility, or generated-context bytes evaluated for a source snapshot. New evidence does not retroactively update an older package or protocol release. |

The registered publishable packages, directories, workflows, ecosystems, and
tag prefixes are defined in
[`release/release-packages.v1.json`](release/release-packages.v1.json). That
registry, not a prose table in this file, is authoritative.

Protocol change control is defined in [`GOVERNANCE.md`](GOVERNANCE.md). Anyone
may propose a change. Normative behavior changes must update the specification,
reference verifiers, and conformance vectors together and preserve the meaning
of released version strings. There is no fictional working-group vote in this
repository. The current Internet-Drafts are individual submissions unless the
live IETF Datatracker states otherwise.

## Release invariants

1. **Exact protected source.** A registry release is bound to the dispatched
   commit, the protected `main` ref, the package metadata, and the exact
   package-specific tag.
2. **Write-once tags.** A release tag is immutable. Never move, reuse, or delete
   it. A correction receives a new package version and a new tag. Repository
   rules should block update and deletion for every registered release prefix;
   the Go publisher also verifies its protected tag namespace before creation.
3. **Independent package versions.** A package release changes only that
   package's version and package-specific changelog or release notes. A generic
   repository tag does not publish every package.
4. **Reviewed bytes only.** Generated runtimes and evidence must match their
   checked-in sources. Release automation refuses a dirty checkout, a tag or
   package mismatch, mutable source selection, and non-reproducible package
   bytes.
5. **No static registry credential.** npm publication uses trusted publishing
   with provenance; PyPI uses OIDC Trusted Publishing. The OIDC token is issued
   only inside the protected `registry-publishing-approval` environment.
6. **Evidence remains scoped.** Passing tests, attestations, or conformance
   vectors establishes only the property and inputs those artifacts name. It
   is not certification, deployment, independent implementation, or a claim
   that a provider effect occurred.

## Governed checks

Start from a clean checkout of the proposed protected-main commit and install
the committed lockfile:

```bash
npm ci --ignore-scripts
```

Run the narrow package or profile tests first. The current repository-level
commands are discoverable in `package.json`; the applicable release baseline is:

```bash
npm run lint
npm run typecheck
npm run test:run
node scripts/run-package-suites.mjs
npm run conformance
npm run check:protocol
npm run check:repository-boundary
node scripts/check-language-governance.js
npm run check:public-conformance-claims
npm run conformance:manifest:check
npm run check:security-case
npm run check:proof-stats
npm run check:llm-context
npm run check:standalone-runtimes
npm run check:packed-package-exports
npm run check:release-chain
npm run build
```

CI supplies pinned versions of external formal, language, and packaging
toolchains where required. The package-specific publisher workflow named in the
release registry remains authoritative for the final tests, build, and evidence
set. Do not replace its checks with an ad hoc local publish.

When governed inputs intentionally change, use their emit or sync command and
review the complete diff. The final `check` commands must pass without rewriting
the checkout:

```bash
npm run security-case:emit
npm run conformance:manifest
npm run sync:proof-stats
npm run sync:llm-context
```

These commands update distinct evidence surfaces. Their timestamps, counts, or
hashes must not be copied across source commits.

## Package release sequence

1. Update the selected package's version and package-specific changelog. If a
   new public package is added, register its exact path, ecosystem, workflow,
   and unique tag prefix in `release/release-packages.v1.json`.
2. Run the package tests and the applicable governed checks above.
3. Merge through the protected branch. Re-fetch and identify the exact
   protected-main commit; a local commit or green branch is not a release.
4. Create the package-specific tag at that exact commit when the workflow
   expects an existing tag. The Go verifier workflow instead validates an
   unpublished tag and creates it only after preflight and protected approval.
5. Dispatch the exact workflow named by the release registry from protected
   `main`. Supply the exact tag and the required
   `PUBLISH <registry-name>@<version>` confirmation.
6. Approve the `registry-publishing-approval` environment only after reviewing
   the selected commit, tag, package metadata, test results, and evidence.
7. Verify the resulting registry version, provenance or attestations, and byte
   comparison. Record the workflow run, commit SHA, release tag, registry
   identity, and artifact digests in the release record.

## Publisher controls

### npm

The reusable npm workflow executes repository code in an unprivileged build
job. It tests the package and governed evidence, packs twice, validates the
reviewed `package.json` and release registry bytes, and uploads the exact inert
tarball by immutable artifact ID. A separate protected publisher job receives
OIDC permission, downloads only that artifact, revalidates its inventory and
hash, publishes with `npm publish --provenance`, and compares the registry
tarball with the tested bytes.

### PyPI

PyPI workflows test the selected project, generate security and conformance
evidence, build the wheel and source distribution twice, run distribution
checks, and attest the exact outputs. Publication uses PyPI Trusted Publishing
from the protected environment. The workflow then downloads the registry wheel
and source distribution and compares them byte for byte with the tested
artifacts.

### Go

The Go verifier workflow validates the declared module identity and unpublished
module tag, runs `go vet` and `go test`, generates and attests exact-source
evidence, obtains protected approval, atomically creates the tag, and verifies
the fresh public module-proxy copy. Repository code never receives the tag-write
credential.

## Evidence carried with releases

Package workflows bind publication to the relevant checked-in or generated
evidence, including:

- `security/security-case.json` for named executable security claims and their
  hashed evidence inputs;
- `conformance/conformance-manifest.json` for the current registered suites and
  vectors;
- a package reproducibility manifest and hashes for the exact wheel, source
  distribution, tarball, or source archive; and
- the exact Git commit and package-specific release tag.

GitHub artifact attestations and registry provenance identify exact bytes and
workflow context. They do not change the scope of the underlying tests.

## Failure and correction policy

- If any source, tag, version, generated artifact, hash, protected-ref, or
  confirmation check disagrees, stop. Do not bypass the governed workflow.
- If publication has not occurred, fix through a new reviewed commit and repeat
  the preflight.
- If a registry version or tag already exists, never overwrite it. Publish a
  new version and document the correction in the relevant changelog.
- A successful upload is not complete until the public registry bytes and
  provenance or attestations have been verified.
