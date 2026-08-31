# AEB native compiler

This example treats `ACME-DELEGATION/v7` as an external protocol. Its JSON
artifact keeps its native fields and native Ed25519 signature. A relying party
pins a verifier, a mapping profile, and an evidence role, then passes the
unchanged artifact to the AEB native compiler. It also supplies the exact
action to compare and a local-policy input. Both are reported as
`RELYING_PARTY_INPUT`; the compiler does not claim independent provenance or
execution for either input. The compiler-local descriptor pins the native
protocol revision, media type, schema, verifier implementation identifier and
digest, adapter, and mapping profile.

The result is a deterministic compilation report. It is not an EMILIA
credential, does not reserve or consume authority, and does not claim provider
entry, execution, outcome, retry safety, reconciliation, or local
authorization.

From the repository root:

```sh
npm --prefix packages/verify run build
node examples/aeb-native-compiler-v1/demo.mjs
```

The example exits non-zero unless native verification, relying-party
acceptance, exact-action matching, and evidence satisfaction succeed and the
policy input says `ALLOW`. Its local-authorization axis must still be
`NOT_EVALUATED`.
