# Cedulon Decision Token × AEB Crossing Lab v0.1

This launch profile verifies one Cedulon Decision Token as pre-settlement
machine-policy evidence, maps the exact six fields evaluated by Cedulon's PDP
to `cedulon.payment.attempt.1`, and exercises the mapping in the offline AEB
Crossing Lab.

The profile is source-locked to:

- `draft-dogru-cedulon-04`, SHA-256
  `661755c600aede25451ce3a67df4a45d0d964c7b9196dc725dd310723eb8a49f`;
- the annotated Cedulon `v0.7.0` tag at commit
  `4a5eab26dde9edbd71db01f6253cc0a7aff72a37`; and
- the published `@cedulon/core@0.7.0` and `@cedulon/cose@0.7.0`
  package integrities recorded in `source-lock.json`.

The current repository head is not silently treated as v0.7.0. The adapter is
independently written and intentionally closes two gaps in the pinned v0.7.0
helper code: it never accepts a token-carried public key as a trust root, and it
checks the actual decoded COSE_Sign1 unprotected map is empty.

## Exact crossing

| Cedulon request member | CAID action member | Transform |
| --- | --- | --- |
| `amount` | `amount` | exact string copy |
| `currency` | `currency` | exact string copy |
| `payee` | `payee` | exact string copy |
| `tool` | `tool` | exact string copy |
| `nonce` | `nonce` | exact string copy |
| `manifestHash` | `manifest_hash` | exact string copy |

The adapter verifies the pinned Ed25519 key and COSE `kid`, algorithm, content
type, deterministic CBOR, closed five-claim map, empty unprotected header,
signature, expiry, detached claim equality, `requestHash`, `policyHash`, and
nonce equality. Only then can the six-field request map under the pinned
profile. Every field is material; substitution of any one produces
`MISMATCH`.

This v0.1 profile deliberately supports only the unambiguous subset where
`tool` and `manifestHash` are non-null strings. Cedulon permits null for both.
CAID's closed v1 field types have no nullable scalar, and inventing a sentinel
would change native semantics, so the adapter returns `INDETERMINATE` instead.

## Authority and settlement boundary

A Decision Token is a machine-policy allow issued before a settlement attempt.
It is not human approval and does not by itself authorize provider entry. AEB
`SATISFIED` means only that the relying party's named evidence requirement was
filled for the exact action. Gate still makes the separate local authorization
decision at a completely mediated executor boundary.

A Cedulon Spend Receipt or Rail Extract is post-attempt evidence. Neither may
occupy this profile's `machine-policy-decision` role or be used to authorize
entry. This profile makes no claim that a payment settled, that a rail extract
is complete, or that a manifest's underlying terms are true.

The status input is separately pinned into the AEB record. Revoked or consumed
status is rejected. Stale or unavailable status is `INDETERMINATE`. The profile
does not define or authenticate a network status service; a deployment must
name that source outside this bundle.

Cedulon has two native replay identities: `singleUseId` and `nonce`. The AEB
replay unit is a stable digest over both, so wrapper changes cannot create a
new identity and a change to either signed value changes the unit. At the real
consumer, both identities still require independent atomic fences. Provider
entry consumes the terminal attempt, including a fail-closed abort or an
indeterminate result. An indeterminate provider entry is not refundable and
must not be blindly retried; reconciliation requires authenticated evidence
bound to the same provider, native identities, and exact action.

The generic AEB adapter contract currently exports one composite `replay_unit`,
not two independently addressable native replay keys. This bundle therefore
tests the composite and states the two-key runtime obligation explicitly. A
future common-contract extension would be needed to make both independent keys
portable through generic AEB consumption without a Cedulon-aware Gate profile.

## Relying-party scope

The Decision Token does not carry a relying-party audience. This v0.1 bundle is
therefore a single-deployment profile: the consumer and PDP key owner are one
configured trust domain. The AEB workspace's relying-party identifier does not
retroactively add an audience to the native token. Cross-domain use needs a
separate, signed native-verification attestation or a future Cedulon token
revision with explicit audience binding.

## Reproduce

Use a Node runtime whose permission model governs network access:

```sh
npm --prefix packages/verify run build
node --test conformance/composition/cedulon-aeb-crossing-v0.1/run.test.mjs
node conformance/composition/cedulon-aeb-crossing-v0.1/run.mjs
node packages/verify/cli.js crossing-lab run \
  conformance/composition/cedulon-aeb-crossing-v0.1/workspace
```

The checked-in report is deterministic and self-attested. It is not Cedulon or
EMILIA certification, independent interoperability evidence, a production
deployment, authorization, human approval, settlement evidence, payment
finality, rail completeness, legal compliance, or proof of native-specification
correctness. Native-author confirmation and a genuinely independent runner are
still required before making an external adoption claim.
