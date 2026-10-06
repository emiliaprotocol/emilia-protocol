# WIMSE delegation scope to CAID companion profile, version 02

Status: experimental review draft, 2026-10-06. It supersedes this repository's
`NEXT-WIMSE-CAID-SCOPE-01` review packet. No version of this companion profile
has been adopted by WIMSE or published as an Internet-Draft.

This packet keeps the same narrow interoperability question as version 01:
can a verifier bind a covered delegation scope family to one exact material
action without treating either artifact as authorization? Version 02 updates
the pinned inputs to registry version 5 and
`draft-schrock-canonical-action-identifier-05`, whose identifier scheme is
`canactid:`. A presented legacy `caid:` identifier is refused explicitly; it
is never rewritten into the current scheme.

The two mappings remain:

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
- `profile.json` pins the published delegation input, the exact CAID-05 text,
  registry version 5 bytes, the provisional IANA URI-scheme record, the ISO
  4217 snapshot behind the currency subset, and the two mappings.
- `generate-vectors.mjs` deterministically derives this version's corpus from
  the reviewed version 01 corpus, migrates current identifiers to `canactid:`,
  and adds the legacy-scheme refusal.
- `vectors.json` contains accepted cases and hostile refusals, including
  malformed details, segment-bounded wildcards, tool-call retries, and an
  obsolete-scheme input.
- `validate.mjs` validates every pin, checks that `vectors.json` exactly equals
  generator output, and executes every vector using the repository's current
  CAID implementation.

Run from the repository root:

```sh
node standards/profiles/NEXT-WIMSE-CAID-SCOPE-02/generate-vectors.mjs --check
node standards/profiles/NEXT-WIMSE-CAID-SCOPE-02/validate.mjs
```

When the packet is sent outside the repository, `validate.mjs`,
`generate-vectors.mjs`, and `vectors.json` MUST be included. The scripts import
the pinned repository CAID implementation, registry, value-set snapshot
loader, CAID-05 text, and version 01 vector corpus; the packet is not a
standalone replacement for those source files.

## Standards-status boundary

Rafael Asor's published input remains
`draft-asor-wimse-agent-delegation-chain-01`. His 2026-09-23 list message
describes possible changes for a future `-02`; this packet records those only
as author-stated revision intentions, not as published specification text.

The `canactid` URI scheme has an IANA **provisional** registration. That record
does not make CAID an RFC, make the registration permanent, establish working
group adoption, or express IETF or IANA endorsement. This companion profile is
an interoperability experiment, not evidence that Rafael, WIMSE, the IETF, or
another implementation adopted CAID or this profile. It does not define a
neutral global action-type registry and does not review the other 60 entries
of the 62-type registry version 5 it pins.
