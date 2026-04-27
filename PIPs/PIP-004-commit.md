# PIP-004: EP Commit Extension

**Status:** Accepted  
**Type:** Extension  
**Created:** 2026-04-07  
**Author(s):** Iman Schrock  
**Requires:** PIP-001  

## Abstract

The Commit extension adds atomic, immutable action closing to EP. A Commit seals an action: hash-linked, blockchain-anchored, irrevocable. Once committed, the record cannot be partially reversed through protocol means. There are no partial states.

## Lifecycle

```
issued → verified → fulfilled | revoked
```

## Key Properties

- **Pre-action authorization:** Commit tokens are evaluated under policy before the action proceeds
- **Revocation with reason:** Revocation always requires a stated reason (audit trail)
- **Verification:** Any relying system can verify a commit's validity via POST /api/commit/verify

## Reference Implementation

`app/api/commit/` — issue/route.js, verify/route.js, [commitId]/route.js, [commitId]/revoke/route.js
