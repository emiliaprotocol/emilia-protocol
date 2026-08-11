# OASNT-CAID and AEB composition

Status: experimental implementation note and executable vectors. This is not a
new wire format, an interoperability claim, or a claim of adoption by either
draft.

Source lock:

- `draft-thallapelly-oasnt-01`
- `draft-thallapelly-oasnt-caid-01`, Sections 4.1 and 6.4

## Single-use boundary

The OASNT token is verified and matched to the executor's material action
before its native replay identity is reserved. A refusal, including a
near-miss action, does not reserve or consume that identity. Once admitted,
the AEB store holds the native replay identity with the operation reservation:

- `NOT_COMMITTED` releases the reservation and allows the same legitimate
  authority to be presented again.
- `COMMITTED` permanently consumes the reservation.
- A subsequent presentation of the committed authority is refused.

These are AEB execution-state properties. The OASNT adapter output remains one
native human-authorization evidence leg and is not itself an execution verdict.

## Section 6.4 dual-profile join

The executor derives both identifiers independently from its own material
action:

1. `oasnt:caid:1:<digest>` is derived from the OASNT native action type and
   parameters under the OASNT canonical action rules.
2. `caid:1:...` is derived from the complete local action under the
   relying-party-pinned EMILIA mapping profile.

The identifiers are profile-specific and intentionally do not compare equal.
They MUST NOT be used as direct cross-profile join keys. The executable mapping
joins the two evidence profiles only after each expected identifier has been
rederived from the same executor-owned action representation. Namespace
substitution, a changed identifier, or a changed material action returns no
join.

The mapping is local executor policy. It adds no field to OASNT, CAID, or AEB
artifacts and does not allow a presenter to choose either derivation.

## Executable cases

The manifest is `conformance/vectors/oasnt-caid-aeb.v1.json`. Its handlers are
in the existing OASNT adapter and acceptance-profile test surfaces:

- `packages/verify/aeb-oasnt-adapter.test.ts`
- `packages/verify/aeb-acceptance-profile.test.ts`

Run:

```sh
npm --prefix packages/verify run build
npm run build:standalone-runtimes
node --test packages/verify/aeb-oasnt-adapter.test.js \
  packages/verify/aeb-acceptance-profile.test.js
```
