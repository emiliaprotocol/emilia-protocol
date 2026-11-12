# Gargoyle receipt interoperability pack

Gargoyle contributed a public, redacted receipt exported from its approval
workflow. EMILIA's unchanged JavaScript and Python runners accept that fixture
and reject four targeted mutations. This pack makes that result reproducible.

The recorded run used EMILIA commit
`3f712d28b2cf624342bd98c4172e1a574b39644b`. It covers one Class B
Trust Receipt, not the full EMILIA conformance corpus or a live Gate integration.

## Source and attribution

- Contribution: [Gargoyle issue #924](https://github.com/emiliaprotocol/emilia-protocol/issues/924).
- [Original fixture at the inspected upstream commit](https://github.com/Elyon-Sol/Gargoyle/blob/f2335aa5951dd878b99b9c983ed6396c83bfa42f/docs/interop-emilia/gargoyle-emilia-live-redacted.v1.json).
- Upstream commit: `f2335aa5951dd878b99b9c983ed6396c83bfa42f`.
- Fixture SHA-256: `a24bb7ec01a2a6523066d3c5a04c3108b333b142223eb3f0f89f78ebc763ab79`.
- Copyright 2026 Justin LaPorte; Apache-2.0. The upstream license and notice
  are preserved in [upstream/](upstream/).

`gargoyle-emilia-live-redacted.v1.json` is an exact, unmodified copy of the
public upstream file, including its original suite description. The description
of a live workstation run is Gargoyle's report. We did not obtain or verify the
original private export.

## Reproduce

Use an existing repository development environment: Node.js 20.19 or later,
the repository's installed JavaScript dependencies, and Python with the
dependencies declared in `packages/python-verify/pyproject.toml`. No service,
credentials, network request, generated verifier build, or dependency download
is performed by this command:

```sh
node interop/gargoyle-emilia/run.mjs
```

Set `PYTHON=/absolute/path/to/python` if your Python environment is not the
default `python3`. The recorded run used Node.js 26.12.1 and Python 3.14.5.

The runner checks the original bytes against the pinned SHA-256, makes four
copies in a temporary directory, and changes one receipt field in each copy.
It keeps the existing signatures and hashes unchanged. It invokes the ordinary
`conformance/runners/run-js.mjs` and `conformance/runners/run_py.py` entry
points, then checks every returned ID and boolean against the expected result.
Both processes have a 30-second timeout. Temporary files are removed on exit.

The command fails on fixture drift, a dirty verification source tree, a failed
runner, or an unexpected verdict. Its JSON output identifies the checkout and
runtime versions actually used. [recorded-result.json](recorded-result.json)
preserves the observed result at the pinned EMILIA commit; a later run reports
its own checkout rather than rewriting that historical result.

| Receipt | JavaScript | Python |
| --- | --- | --- |
| Original public fixture | Accept | Accept |
| Different requester in `action.initiator` | Reject | Reject |
| One changed hex digit in `action.parameters.args_sha256` | Reject | Reject |
| One changed hex digit in the signed checkpoint's root hash | Reject | Reject |
| One changed base64url character in the signoff signature | Reject | Reject |

Hash mutations retain their original encoding and length. The signature
mutation retains its encoding and length. These are binding checks, not tests
that merely replace a well-formed value with invalid syntax.

## What the result establishes

The two EMILIA implementations agree on this public receipt and these four
mutations. The fixture contains an MCP `write_file` action, separate requester
and approver identifiers, a Class B signoff, a consumption record, and a
one-leaf EP-MERKLE-v2 proof. Its context requests one approval.

Gargoyle states that it redacted the account names and path and re-signed the
public fixture using throwaway approver and log keys. The public keys supplied
with the fixture are test trust inputs, not independently enrolled identities.
No private keys are included in this pack.

This run does not establish:

- The original identity enrollment, what the human saw, or non-extractable
  storage of the workstation key.
- Class A presence, quorum-policy conformance, or verification by an outside
  organization.
- Successful file creation, exactly-once execution, consumption freshness, or
  truth of the producer's `COMMITTED` claim.
- An independent witnessed log, complete conformance, reverse interoperability
  with Gargoyle's verifier, or results for Go or Rust.

This is a local interoperability check of a redacted, re-signed fixture.
It does not change the registered suite manifest, external-implementation
acceptance count, global proof statistics, or generated public claims.

## Producer's sequence and mapping

[Gargoyle's account of the exchange](https://github.com/Elyon-Sol/Gargoyle/blob/f2335aa5951dd878b99b9c983ed6396c83bfa42f/docs/interop-emilia.md)
reports a held `write_file` call, approval through its browser console, file
execution, and receipt export on the author's workstation. The console signs
the EP Authorization Context hash separately from the Gargoyle grant. A grant
signature alone is not an EP signoff.

| Gargoyle input | Field in this public receipt |
| --- | --- |
| MCP target and tool | `action.target.system`, `action.target.resource` |
| Tool arguments and resource pre-state digests | `action.parameters.args_sha256`, `state_sha256` |
| Requester and rules pin | `action.initiator`, context `policy_id` and `policy_hash` |
| Decision UUID | Context `authorization_instance`, consumption `nonce` |
| Execution receipt timestamp | `consumption.committed_at` |

The arguments and pre-state themselves are absent, so this pack cannot
recompute those two digests or bind them to a real executor input. Using an
execution timestamp as `committed_at` records the producer's assertion; it
does not demonstrate an atomic consume-before-effect fence. Those are separate
integration questions, beyond the portable verification result preserved here.

## Reverse direction: EMILIA vectors under Gargoyle's verifier

The forward result above runs a Gargoyle receipt through EMILIA's verifiers.
`reverse.mjs` runs EMILIA's published vectors through Gargoyle's own verifier,
`python -m gargoyle.emilia_runner` in the upstream repository, and compares
every result row with this repository's `conformance/result-contract.mjs`.
Gargoyle implements two of the 21 live suites:

| Suite | Vectors | Gargoyle (Python) |
| --- | --- | --- |
| EP-RECEIPT-v1 (`receipts.v1.json`) | 14 | All match the published expectations |
| EP-CANONICALIZATION-v1 (`canonicalization.v1.json`) | 35 | All match the published expectations |
| `signoffs.v1.json` (not implemented) | 13 | Refused with exit status 2 and no rows |

The runner is Gargoyle's code on Gargoyle's RFC 8785 serializer, not an
`@emilia-protocol` or `emilia-verify` package re-run. It was written with
EMILIA's public vectors and reference source available, so this is external
interoperability evidence for two suites, not a clean-room construction result.
It does not change the registered implementation count, the clean-room
manifest, or any generated public claim.

`reverse-source.json` pins the Gargoyle commit, the SHA-256 of the three
upstream modules that produce the verdicts, and the SHA-256 of the two suite
files as recorded. The command refuses a checkout at another commit, a dirty
package tree, changed module bytes, or changed vectors; a later vector revision
is a new run, not an upgrade of this one. It also requires the uncovered suite
to be refused outright, so a missing capability cannot read as rejections.

```sh
git clone https://github.com/Elyon-Sol/Gargoyle /tmp/gargoyle
git -C /tmp/gargoyle checkout <upstream_commit from reverse-source.json>
python3 -m pip install -e /tmp/gargoyle   # installs cryptography
GARGOYLE_CHECKOUT=/tmp/gargoyle node interop/gargoyle-emilia/reverse.mjs
```

[recorded-reverse-result.json](recorded-reverse-result.json) preserves the
observed result at the pinned commits.
