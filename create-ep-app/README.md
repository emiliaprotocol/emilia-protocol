<!-- SPDX-License-Identifier: Apache-2.0 -->
# `@emilia-protocol/create-ep-app`

Creates a minimal, local issuer-to-verifier demonstration using the published
`@emilia-protocol/issue` and `@emilia-protocol/verify` packages.

```bash
npx @emilia-protocol/create-ep-app my-ep-demo
cd my-ep-demo
npm install
npm run demo
```

The generated verifier requires a separately loaded relying-party trust
profile. It does not trust a key merely because a receipt names it, and it does
not contain a custom verifier.

This is a development scaffold, not a production authorization service. The
demo establishes cryptographic binding under locally pinned development keys;
it does not establish real-world identity, authority, human perception,
execution, effects, safety, or legal reliance.

Apache-2.0.

Always use the scoped command shown above. The unscoped `create-ep-app` name is
owned by an unrelated third party and is not an EMILIA package.
