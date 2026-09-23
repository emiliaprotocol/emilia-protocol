# WIMSE delegation scope to CAID companion profile

Status: private review draft, 2026-09-23. This directory has not been
submitted to the IETF, reviewed by WIMSE, or published as an Internet-Draft.

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
- `vectors.json` contains accepted cases and hostile refusals.
- `validate.mjs` validates the pins and executes every vector using the
  repository's current CAID implementation.

Run from the repository root:

```sh
node standards/profiles/NEXT-WIMSE-CAID-SCOPE-00/validate.mjs
```

## Claim boundary

This is a private interoperability experiment, not evidence that Rafael,
WIMSE, the IETF, or another implementation adopted CAID or this profile. It
does not define a neutral global registry, and it does not review the other
50 entries in the current 52-type EMILIA-maintained seed registry.
