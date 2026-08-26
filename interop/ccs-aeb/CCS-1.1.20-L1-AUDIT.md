<!-- SPDX-License-Identifier: Apache-2.0 -->

# CCS 1.1.20 L1 verification receipt

## Exact source lock

| Item | Pin |
| --- | --- |
| Repository | `https://github.com/DSHCorrectover/ccs-verifier` |
| Tag | `v1.1.20` |
| Tag object | `c6a35839a26c228cab9c1b827aab814fa4d14945` |
| Tag type | Annotated, not GPG-signed |
| Target commit | `8c95600f661028acc74056d5829e0a0f7db0ab0b` |
| `ccs_verifier-1.1.20.tar.gz` | `551c60eb416dac34567009b3b75fd1f501d4874bebeed68de21ceab1a7e0463f` |
| `ccs_verifier-1.1.20-py3-none-any.whl` | `fd718d885a04383a0a520f9bf06de258d6ff9b4f049cddc358b58c3b2a33db9d` |
| Upstream reference vector | `f4ba98ba9eb8f2a74a7b9065ed7919541ae7a58e2b4811dd0f1967408c4cd975` |

The tag object is an immutable Git object pin, but its lack of a GPG signature
means it is not cryptographic publisher authentication. EMILIA records both
facts rather than silently treating an annotated tag as a signed release.

## Corrected upstream vector

The exact vector at
`tests/conformance-vectors/reference-signed-001.json` is checked in as
`fixtures/ccs-verifier-pypi-1.1.20-upstream-reference-signed-001.json`.
Its whole-file SHA-256 matches the pin above. Its top-level `package_version`
and signed `receipt.rule_version` both equal `1.1.20`; its top-level issuer,
public key, fingerprint, and specification version agree with the signed
receipt fields.

The current adapter consumes these upstream bytes directly. The two 1.1.19
fixtures and `CCS-1.1.19-L1-AUDIT.md` remain checked in as historical evidence;
they are no longer the current-profile input.

## Non-finite-number boundary

The 1.1.20 source explicitly rejects `NaN`, positive infinity, and negative
infinity before RFC 8785 canonicalization. EMILIA's adapter independently
rejects the same three values in both signed receipt fields and executor-owned
action arguments before signature or CAID mapping. Finite JSON numbers retain
the existing receipt-version, rule-version, signature, action-digest, and CAID
semantics.

The exact upstream tag completed its source suite with `167 passed`. The ten
new cases cover each non-finite value at the top level and nested in lists and
objects, plus finite edge values.

## Reproduction

```bash
node interop/ccs-aeb/reproduce_l1_120_fixture.mjs
npm run conformance:composition:ccs-l1-aeb
```

Optional wheel and source-archive byte checks can be added to the first command:

```bash
CCS_VERIFIER_1_1_20_WHEEL=/path/to/ccs_verifier-1.1.20-py3-none-any.whl \
CCS_VERIFIER_1_1_20_SDIST=/path/to/ccs_verifier-1.1.20.tar.gz \
node interop/ccs-aeb/reproduce_l1_120_fixture.mjs
```

This is an EMILIA source-lock and adapter reproduction. It is not a production
trust anchor, independent deployment, certification, IETF adoption, or
endorsement.
