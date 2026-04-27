# PIP-005: Emilia Eye Extension

**Status:** Accepted  
**Type:** Extension  
**Created:** 2026-04-07  
**Author(s):** Iman Schrock  
**Requires:** PIP-001  

## Abstract

The Eye extension adds contextual observation to EP. Eye moves through an OBSERVE → SHADOW → ENFORCE lifecycle, producing advisories that inform downstream policy decisions. Eye does not make trust decisions and does not block actions in OBSERVE mode.

## Lifecycle

```
OBSERVE:  Advisory-only. Flags patterns. No enforcement.
SHADOW:   Logs what enforcement would have done. No blocking.
ENFORCE:  Active enforcement gate. Policy-driven.
```

## Key Properties

- **Subordinate to Handshake:** Eye advisories inform policy; they never substitute for Handshake verification
- **Short-lived signals:** Observations are scoped to the action that triggered them
- **No persistent labels:** Eye does not produce reputation scores or persistent entity ratings
- **Explainable:** Every advisory includes the reason and signal class

## Signal Classes

Financial, Government, Enterprise, AI/Agent — each with domain-specific pattern libraries.

## Reference Implementation

`app/api/eye/` — observe/route.js, advisory/route.js  
`lib/eye/` — observation engine, advisory logic
