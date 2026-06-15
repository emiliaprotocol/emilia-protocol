# PIP-012: Statement Envelope + Profile Registry — the narrow waist

**Status:** Draft
**Type:** Extension (additive)
**Created:** 2026-06-15
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP defines **`EP-ENVELOPE-v1`** — one wire object that every EP profile
inhabits — and a **content-addressed profile/action registry**, turning the family
of additive profiles (revocation, WYSIWYS, execution-integrity, eye-set
continuous-eval, provenance chain) from a set of bespoke `verifyX()` functions into
a single, extensible family. A single `verifyEnvelope(env, opts)` runs a shared,
profile-agnostic pipeline (version, registered-profile, payload, algorithm gate)
and then dispatches to the profile's `validateBody`, composing the two so a plugin
can **only add rejections, never approvals** (the `PluginCannotWeaken` invariant).
Profiles and the consequential action types they cover become **data**: a third
party registers a profile in the reserved `urn:ep:profile:x-<vendor>:*` namespace
with no core change.

## Motivation

The mechanical reason EMILIA reads as a toolbox rather than an ecosystem is that
adding the (N+1)th capability requires being EMILIA — each profile ships its own
top-level shape, its own verifier signature, and its own hardcoded place in the
conformance runner. A narrow waist (one envelope + a registry) is the move that
made COSE/JOSE "a core plus registered algorithms," MIME an open content-type
vocabulary, and Sigstore a trust rail others build on. Without it, there is no
two-sided surface: no one outside EMILIA can mint a profile, so network effects
cannot start. This PIP supplies the missing keystone.

## Specification (summary)

Normative detail: `docs/EP-ENVELOPE-SPEC.md`. Registry:
`public/.well-known/ep-profiles.json` + `ep-actions.json` (regenerated from
`lib/envelope/descriptors.js` by `scripts/build-ep-registry.mjs`).

- **Envelope:** `{ ep, profile (URN), typ?, payload, binding?, proofs?, anchor?, meta? }`.
- **`verifyEnvelope`:** shared pipeline checks `envelope_version`, `profile_known`
  (well-formed **and** registered — unknown fails closed), `payload_present`,
  `proof_alg_allowed` (no `none`/unlisted). Then `validateBody` runs; verdict is
  `sharedOk && body.valid`. A throwing plugin is a rejection.
- **`PluginCannotWeaken`:** a plugin can never rescue a shared rejection or affect
  another profile. (Enforced in code; covered by `tests/envelope.test.js`.)
- **`migrate(obj, urn)`:** lossless wrap — `canonicalize(payload) === canonicalize(obj)`;
  no re-signing; previously-issued objects and the posted I-D stay valid.
- **Registry:** content-addressed (per-profile `content_hash`, manifest
  `registry_hash`); EMILIA hosts a mirror, not the root of trust; vendor profiles
  self-publish in `urn:ep:profile:x-<vendor>:*`.
- **Scaffolder:** `scripts/create-ep-profile.mjs` emits a <50-line plugin + a
  conformance-vectors stub.

## Backwards compatibility

Fully backward compatible. No change to `EP-RECEIPT-v1`, its canonicalization, its
signature, or any existing verifier — every shipped `verifyX()` keeps working, and
the envelope wraps them. `migrate()` is byte-stable. Consumers that do not
implement the envelope are unaffected.

## Reference implementation + conformance

`lib/envelope/{envelope,profiles,descriptors,index}.js`;
`scripts/build-ep-registry.mjs`; `scripts/create-ep-profile.mjs`;
`tests/envelope.test.js` (adversarial: fail-closed, PluginCannotWeaken, lossless
migration, wrapped-profile parity) + `tests/ep-registry.test.js` (no-drift +
profiles-are-registered + vectors-exist).

## Security implications

The envelope's value is the composition guarantee: registering an untrusted
third-party profile cannot weaken the core, cannot make a structurally-invalid
envelope verify, and cannot affect other profiles, because the verdict is the
AND of the shared pipeline and the plugin. Plugins are still expected to fail
closed internally (verify signatures only under verifier-pinned keys); the
built-in wrapped profiles already do. The registry's content addressing lets a
verifier detect a tampered manifest offline. Out of scope: binding a self-published
vendor profile's content hash to a real-world identity (a transparency/PKI layer
above this spec).
