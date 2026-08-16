<!-- SPDX-License-Identifier: Apache-2.0 -->
# Jesske AI enablement authorization-evidence composition v0.1

This package is a runnable, relying-party-side composition for
`draft-jesske-ai-enablement-interface-00`. It uses the draft's extensible
request metadata to carry one additional member:

```text
authorization_evidence = opaque
```

The generic enablement interface carries that value unchanged. It does not
define the evidence schema, select a verifier from presenter input, or inspect
evidence fields. A relying party selects and pins a verifier out of band. The
member can therefore be represented by any serialization supported by the
interface; this package's compact Ed25519 value is only an executable fixture.

The added member remains format-neutral, and Roland Jesske and Michael Kreipl's
draft has no dependency on EMILIA. This directory is an EMILIA-side composition
test, not proposed replacement text, an implementation by the draft authors,
or an endorsement. The runner pins the June 26, 2026 `-00` text by URL, byte
length, and SHA-256 in `vectors.json`.

## Relying-party profile

For the fixture's `call.recording.start` task, the relying party projects this
exact material action:

- call identifier;
- exact participant set, normalized as a sorted unique array;
- purpose;
- recording destination; and
- start-inclusive, end-exclusive recording window.

The authorization evidence signs that action, its CAID, issuer, audience,
subject, evidence identifier, and validity interval. The runner verifies the
native signature under a relying-party-pinned Ed25519 key, recomputes the CAID,
uses AEB/AEC to keep verification, acceptance, matching, satisfaction, and
local authorization separate, then asks the one-time admission store to reserve
the accepted native evidence before any provider entry.

The private keys in `vectors.json` are deterministic conformance fixtures only.
They are public test material and must never be used for a deployment.

Run the focused package:

```bash
npm run conformance:composition:jesske-ai-enablement
```

Or emit the full report:

```bash
node conformance/composition/jesske-ai-enablement-v0.1/run.mjs
```

The eight cases are one valid request; participant, purpose, destination, and
time-window substitutions; invocation outside the signed action window;
missing evidence; and replay of the same native evidence in a second request.

## Deliberate limits

A passing result verifies only the bounded fixture under the pinned relying-
party profile. It does not establish participant identity or consent, legal
permission to record, actual media capture or storage, control or deletion at
the named destination, independent implementation, or author/IETF endorsement.
No recording service is invoked by this runner.

Replay prevention here is process-local because the executable fixture uses
`InMemoryAebConsumptionStore`. Cross-process or multi-executor prevention needs
a shared durable atomic consumption domain, and prevention applies only to
action paths under complete mediation.
