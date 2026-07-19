# @emilia-protocol/attest

**Bind relying-party-pinned identity bytes to a work-product hash and signature.**

This is the standardized, drop-in version of the "Identity Manager" pattern that
keeps showing up when people build serious AI tooling: hash an agent's identity
file, compare it to a known-good hash, bind the separately pinned subject, and
sign the work product. The result is an **EP‑RECEIPT‑v1** whose hashes and
signature can be recomputed offline with [`@emilia-protocol/verify`](../verify).
Acceptance still requires the relying party to authenticate and pin the identity
mapping and signer public key outside the presented receipt.

It's the "one wire" that turns a terminal/IDE/agent console into a
purpose-bound-compute evidence surface: every receipt binds a pinned subject
identifier and identity-file hash to a work-product hash. It does not prove who
was authorized, what actually executed, or whether the work was correct.

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
  knownGoodSubject:'ep:agent:c-dawg',       // pinned alongside the hash
  work:            fs.readFileSync('sprint-plan.md'),
  workName:        'sprint-plan.md',
  subject:         'ep:agent:c-dawg',
  signerPrivateKey: ed25519PrivateKey,        // KeyObject or b64u PKCS#8
  issuedAt:        new Date().toISOString(),
  anchor:          true,                       // optional EP-MERKLE-v2 anchor
});

// 3. A relying party verifies under its own pinned signer key:
verifyReceipt(document, PINNED_SIGNER_SPKI);    // { valid: true, checks: {...} }
```

## What the receipt binds

```
payload.identity.hash  = SHA-256(identity file)   ← pinned bytes (re-derivable)
payload.subject        = pinned subject id        ← exact mapping (not self-asserted)
payload.work.hash      = SHA-256(work product)    ← artifact bytes (not execution)
signature              = Ed25519 over JCS(payload)
anchor (optional)      = EP-MERKLE-v2 (domain-separated, payload-bound leaf)
```

A tampered signed payload breaks the signature; mismatched identity bytes or a
relabeled subject make `signWorkReceipt` refuse. The optional Merkle structure
proves local inclusion only; without an independently trusted log checkpoint or
witness it is not a timestamp, publication proof, or transparency guarantee.

## Boundary

This package proves a cryptographic binding under caller-supplied trust material.
It does not establish real-world identity, authority, human presence, execution,
effects, trusted time, revocation, or issuer trust. Never verify with the
`public_key` returned beside an untrusted receipt; compare or replace it with the
relying party's independently pinned signer key.

> In-repo this imports its siblings by relative path (`../issue`, `../verify`);
> the published build imports them by package name (declared in `dependencies`).
