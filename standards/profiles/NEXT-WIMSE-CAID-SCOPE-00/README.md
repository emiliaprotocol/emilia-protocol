# WIMSE delegation scope to CAID companion profile

Status: experimental review draft, 2026-09-23. This directory has been shared
for review, but it has not been adopted by WIMSE or published as an
Internet-Draft.

Superseded by `../NEXT-WIMSE-CAID-SCOPE-01/` on 2026-09-26. This packet pins
CAID registry version 3 by digest, and its PROFILE.md section 3 makes any
change to those bytes a new profile version. Registry version 4 changed them,
so on a checkout that carries registry version 4, `validate.mjs` reports the
digest and version mismatch and exits nonzero instead of evaluating. That is
the fail-closed behavior section 3 requires. To replay this packet as shared,
run it from commit `f46328afc`, the last `main` commit before registry version
4, where it passes all 22 vectors.

This packet tests one narrow answer to the operation-vocabulary gap Rafael
Asor identified on the public WIMSE list: bind two delegation scope families
to two immutable CAID action-type definitions, then refuse ambiguity rather
than guessing.

The two mappings are:

| Delegation scope family | Pinned CAID action type |
| --- | --- |
| `payment.release` | `payment.release.1` |
| `tool.call` | `tool.call.1` |

The scope family says which kind of operation a delegation may cover. The
CAID type says which material fields identify one concrete action. Neither
one proves authorization, execution, safety, or success. The local enforcement
point makes the separate admission decision after it has verified the native
delegation chain and any other required evidence.

## Packet

- `PROFILE.md` defines the boundary and deterministic evaluation rules.
- `profile.json` pins the source revisions, registry bytes, and two mappings.
- `vectors.json` contains accepted cases and hostile refusals, including
  malformed details, segment-bounded wildcards, and tool-call retries.
- `validate.mjs` validates the pins and executes every vector using the
  repository's current CAID implementation.

Run from the repository root:

```sh
node standards/profiles/NEXT-WIMSE-CAID-SCOPE-00/validate.mjs
```

When the packet is sent outside the repository, `validate.mjs` MUST be
included. It imports the pinned repository CAID implementation and registry;
the packet is not a standalone replacement for those source files.

## Claim boundary

This is an interoperability experiment, not evidence that Rafael,
WIMSE, the IETF, or another implementation adopted CAID or this profile. It
does not define a neutral global registry, and it does not review the other
50 entries in the current 52-type EMILIA-maintained seed registry.
