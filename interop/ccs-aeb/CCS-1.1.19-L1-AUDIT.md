<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS 1.1.19 L1 verification receipt

Verified on 2026-08-25 against the public PyPI release and the upstream
annotated tag:

| Coordinate | Pinned value |
| --- | --- |
| Repository | `https://github.com/DSHCorrectover/ccs-verifier` |
| Tag | `v1.1.19` |
| Tag object | `bdd79fa8257b764cffa5bceb458330ce01bc41ce` |
| Commit | `4c5e6c7a9670be0a417414f8b8f41ff4d5df0aa6` |
| `ccs_verifier-1.1.19.tar.gz` | `b540635098ccea4b9e5ccdfc016ad144a4efe4a7d21a0f351fca5b48c00b08c7` |
| `ccs_verifier-1.1.19-py3-none-any.whl` | `762b99b3968be8c138da037ef6db15473cf6911616088d42d7b9997f16a2c3e4` |

The tag is annotated but unsigned. The tag object, commit, wheel, and source
distribution are therefore pinned independently. The installed package,
server, and server L1 rule version report `1.1.19`.

## Reference-vector correction

The 1.1.19 source distribution still bundles
`tests/conformance-vectors/reference-signed-001.json` with
`package_version` and signed `rule_version` set to `1.1.14`. Its upstream
reproduction test also hard-codes `1.1.14`, so that test does not detect the
stale vector.

EMILIA does not relabel those stale bytes. Both provenance layers are preserved
and independently locked:

| Fixture | Provenance | SHA-256 |
| --- | --- | --- |
| `fixtures/ccs-verifier-pypi-1.1.19-upstream-stale-1.1.14-reference-signed-001.json` | Exact bytes bundled in the 1.1.19 source distribution; both version fields remain `1.1.14` | `5260e619c010d36729c57c5e8814613215e65e09abfba8a6a1d93f07e919762f` |
| `fixtures/ccs-verifier-pypi-1.1.19-emilia-derived-reference-signed-001.json` | EMILIA-derived from the exact 1.1.19 source lock and public deterministic seed | `ce2594c18b6ccbfed0fb09b64fd0fb1d2534b13ae7ccd024367f3d86ff0f6a12` |

The derived fixture keeps the package's fixed reference fields and changes the
release-bound `rule_version` to `1.1.19`. The resulting receipt verifies under
the bundled reference public key. Its wrapper pins the repository, tag object,
commit, both PyPI artifact hashes, the exact upstream-stale vector, and the
checked-in generator.

Reproduce the provenance boundary offline from checked-in files:

```sh
node interop/ccs-aeb/reproduce_l1_119_fixtures.mjs
```

To additionally verify the downloaded wheel before regenerating and comparing
the derived bytes:

```sh
CCS_VERIFIER_1_1_19_WHEEL=/path/to/ccs_verifier-1.1.19-py3-none-any.whl \
  node interop/ccs-aeb/reproduce_l1_119_fixtures.mjs
```

The source-locked adapter requires the receipt's Ed25519 signature,
embedded-key fingerprint, and raw key to agree with one relying-party-pinned
issuer key. It separately enforces audience, expiry, maximum clock skew, rule
version, action, and tool.

For action mapping, the executor supplies the action it is about to perform.
The adapter verifies that the signed CCS `action` and `tool` match and that the
full signed `args_digest` equals the canonical SHA-256 digest of the executor's
arguments. Only then does it derive the CAID. The receipt's `params_hash` is
not used for this join because the reference value is profile-specific and is
not the full argument digest.

The reference key is deterministic public test material. A passing result is
not production trust, an independent CCS implementation, deployment evidence,
or evidence of provider entry or effect.
