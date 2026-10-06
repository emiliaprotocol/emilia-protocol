# Moving from `caid:` to `canactid:`

CAID-05 changes the URI scheme used by a Canonical Action Identifier. New
identifiers begin with `canactid:`. IANA provisionally registered that scheme
on October 5, 2026.

The action object, canonicalization rules, digest bytes, mapping algorithm, and
registry version did not change. The complete identifier did. These two values
are different identifiers, even when everything after the scheme is identical:

```text
caid:1:payment.release.1:jcs-sha256:...
canactid:1:payment.release.1:jcs-sha256:...
```

## New issuance

Use the CAID-05 reference implementation and emit only `canactid:` identifiers.
Recompute the identifier from the complete typed action. Do not accept an
identifier supplied by an agent, browser, or other presenter without checking
it against the authoritative action material.

For MCP results, EMILIA uses this optional metadata member:

```json
{
  "_meta": {
    "ai.emiliaprotocol/canactid": "canactid:1:payment.release.1:jcs-sha256:..."
  }
}
```

The server computes that value. Client-supplied metadata is not evidence of
the action and must not be promoted into the result.

## Existing signed records

Do not edit an existing receipt, permit, signature, checkpoint, or other
committed record merely to replace `caid:` with `canactid:`. The complete
identifier is part of the signed material. Rewriting it invalidates the old
signature and does not create a new authorization.

If an application must verify an immutable CAID-04 record, it must select the
legacy CAID-04 verification profile explicitly. The current parser and verifier
refuse `caid:` by default. A new record needs a newly computed `canactid:` value
and a new signature or authorization ceremony.

## Storage rollout

Treat this as a wire-format migration, not a display change.

1. Apply the Phase A expand migration
   `20261005090000_canactid_scheme_transition.sql`. It preserves old signed
   rows and temporarily admits both spellings in storage and database
   validators.
2. Deploy readers that distinguish the current profile from the explicit
   legacy profile. Current readers may render a CAID-04 history row as
   read-only evidence, but they must not silently turn it into a current
   passport or executable action.
3. Stop legacy issuance and drain, expire, cancel, or explicitly route every
   outstanding CAID-04 action to the old deployment before the current
   deployment becomes the sole action processor. Then deploy every issuer that
   writes `canactid:`.
4. Verify production issuance and every write path before enforcement. During
   this compatibility window, application code still refuses legacy values on
   current APIs even though the database can accept a write from an older
   instance.
5. Only then ship a separate protected-main Phase B migration that makes new
   and changed values current-only. Do not put both phases in one migration
   batch: database-first would break old instances and application-first would
   fail against the old constraints.
6. Keep old signed rows byte-for-byte unchanged. Reissue an action only when
   the authority holder approves the newly bound record.

Store the profile or artifact version with the identifier when a table contains
both historical and current records. A bare column that silently accepts both
schemes hides which verification rules were applied.

Phase A is a compatibility window, not the final enforcement state. It may be
applied before the application release because it is backward compatible.
Phase B must follow observed production issuance; a planned write freeze across
the database change and application promotion is the only safe substitute.

## What registration does not add

The IANA record gives the identifier a provisionally registered URI-scheme
name. It does not make CAID an RFC or an adopted IETF work item. It does not
authorize an action, prevent replay, prove execution, certify an implementation,
or turn the identifier into a URL that can be fetched.

The current draft is
[draft-schrock-canonical-action-identifier-05](https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/).
The provisional IANA record is
[the `canactid` URI-scheme registration](https://www.iana.org/assignments/uri-schemes/prov/canactid).
