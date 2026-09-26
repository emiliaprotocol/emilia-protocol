# WIMSE delegation scope to CAID companion profile, version 01

Status: experimental review draft, 2026-09-26. It supersedes
`NEXT-WIMSE-CAID-SCOPE-00`, which has been shared for review. Neither version
has been adopted by WIMSE or published as an Internet-Draft.

This packet tests one narrow answer to the operation-vocabulary gap Rafael
Asor identified on the public WIMSE list: bind two delegation scope families
to two immutable CAID action-type definitions, then refuse ambiguity rather
than guessing. Version 01 moves the registry pin from version 3 to version 4;
PROFILE.md section 8 lists the changes.

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
- `profile.json` pins the source revisions, registry bytes, the ISO 4217
  snapshot behind the currency subset, and two mappings.
- `vectors.json` contains accepted cases and hostile refusals, including
  malformed details, segment-bounded wildcards, and tool-call retries.
- `validate.mjs` validates the pins and executes every vector using the
  repository's current CAID implementation.

Run from the repository root:

```sh
node standards/profiles/NEXT-WIMSE-CAID-SCOPE-01/validate.mjs
```

When the packet is sent outside the repository, `validate.mjs` MUST be
included. It imports the pinned repository CAID implementation, registry, and
value-set snapshot loader; the packet is not a standalone replacement for
those source files.

## Claim boundary

This is an interoperability experiment, not evidence that Rafael,
WIMSE, the IETF, or another implementation adopted CAID or this profile. It
does not define a neutral global registry, and it does not review the other
50 entries in the current 52-type EMILIA-maintained seed registry.
