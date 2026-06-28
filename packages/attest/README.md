# @emilia-protocol/attest

**Verify an agent identity, then sign its work as an offline-verifiable receipt.**

This is the standardized, drop-in version of the "Identity Manager" pattern that
keeps showing up when people build serious AI tooling: hash an agent's identity
file, compare it to a known-good hash (e.g. from a Keeper vault), and sign the
work product. The difference: the thing it signs here is an **EP‑RECEIPT‑v1** that
**anyone can re-derive offline** — re-hash the identity, re-hash the work, check
the Ed25519 signature and the EP‑MERKLE‑v2 anchor with
[`@emilia-protocol/verify`](../verify). No server. No trust in the issuer.

It's the "one wire" that turns a terminal/IDE/agent console into a
purpose‑bound‑compute surface: every action carries a verifiable proof of *who
was authorized* and *what actually ran*.

## Two calls

```js
import { verifyIdentity, signWorkReceipt } from '@emilia-protocol/attest';
import { verifyReceipt } from '@emilia-protocol/verify';

// 1. Verify the agent identity against the hash you stored in your vault.
const { verified, computedHash } = verifyIdentity({
  identity: fs.readFileSync('c-dawg-identity.txt'),
  knownGoodHash: '<sha256-from-keeper>',
});

// 2. Sign the work product, bound to that verified identity. Fail-closed:
//    throws if the identity does not match the known-good hash.
const { document, public_key } = signWorkReceipt({
  identity:        fs.readFileSync('c-dawg-identity.txt'),
  knownGoodHash:   '<sha256-from-keeper>',
  work:            fs.readFileSync('sprint-plan.md'),
  workName:        'sprint-plan.md',
  subject:         'ep:approver:c-dawg',
  signerPrivateKey: ed25519PrivateKey,        // KeyObject or b64u PKCS#8
  issuedAt:        new Date().toISOString(),
  anchor:          true,                       // optional EP-MERKLE-v2 anchor
});

// 3. Anyone, anywhere, offline:
verifyReceipt(document, public_key);           // { valid: true, checks: {...} }
```

## What the receipt binds

```
payload.identity.hash  = SHA-256(identity file)   ← who (re-derivable)
payload.work.hash      = SHA-256(work product)    ← what ran (re-derivable)
signature              = Ed25519 over JCS(payload)
anchor (optional)      = EP-MERKLE-v2 (domain-separated, payload-bound leaf)
```

A tampered work product breaks the signature; a tampered identity fails
`verifyIdentity`; a missing/incorrect known-good hash makes `signWorkReceipt`
refuse to sign. Fail-closed by construction.

> In-repo this imports its siblings by relative path (`../issue`, `../verify`);
> the published build imports them by package name (declared in `dependencies`).
