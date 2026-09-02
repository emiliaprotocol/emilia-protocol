# resolve-before-approve

Reference-typed action arguments are resolved and frozen **before** the Action
Object is formed, and re-resolved **at dispatch**.

## The hole

A CAID commits an identifier to canonical typed content. If a material argument
is a *reference* rather than an identity, the digest commits to the reference,
not to the thing it names:

| argument | what the human reads | what the executor acts on |
| --- | --- | --- |
| `"/srv/export/current.csv"` | a file name | whatever the symlink points at now |
| `"https://pay.example/hook"` | an endpoint | the origin at the end of the redirect chain |
| `"Acme Supplies"` | a payee | the account id the directory maps that label to now |

The reference can re-resolve between approval and dispatch. The argument bytes
never change, so the CAID never changes, and the approval silently covers a
different target.

The public statements of this attack class, cited here as the rule and nothing
further: Wiz **GhostApproval**, Adversa **SymJack**, and the **OWASP AI Agent
Security cheat sheet**. Citing them is not a claim that any of them reviewed,
tested, or endorsed this code.

## The rule

1. Every declared reference-typed argument is resolved twice at capture. The
   resolved identity is written into the observed action as a domain-separated
   digest under `resolved_references`, so the Action Object the human approves
   commits to the resolved target.
2. At dispatch the executor re-resolves the same references from the same
   supplied values and compares digests. Divergence is a refusal with a stated
   reason. Dispatch never repairs a binding, never writes one, and never treats
   a failed resolution as agreement.

`identity_digest` is `sha256` over the UTF-8 preimage
`EP-RESOLVE-BEFORE-APPROVE-v1\n<kind>\n<identity>`. The kind is inside the
preimage, so a beneficiary directory can never speak for a filesystem target.

## Scope

This profile establishes only that a named reference resolved to the same
identity at two moments, under the resolvers the relying party supplied. It
establishes nothing about identity, authority, authorization, safety, or
execution. A divergence refusal says the resolved target changed; it does not
say who changed it. Agreement says two resolutions matched; it does not say the
target is the one the human meant. Verification is not acceptance.

## Files

| file | what it is |
| --- | --- |
| `resolve-before-approve.mjs` | the profile. `node:crypto` only, no I/O, never throws |
| `resolvers.mjs` | filesystem-path, url-origin and beneficiary-label resolvers |
| `caid-join.mjs` | forms the Action Object and runs CAID plus the dispatch check |
| `vectors.json` | 30 frozen hostile vectors, hermetic (no filesystem, no network) |
| `run-vectors.mjs` | vector runner (`--json` for machine-readable outcomes) |
| `resolve-before-approve.test.mjs` | node:test suite driving the real resolvers |
| `mutation-check.mjs` | disables one guard at a time and requires the outcome to change |

## Run

```sh
npm run caid:resolution
```

Resolver identity forms are stated in `resolvers.mjs`; a deployment with a
different notion of sameness supplies its own resolver. The core does not care
where the identity string came from, only that it is stable.
