# Incident Response

Government pilots must run at least one tabletop before production use.

Required drills:

- key compromise
- replay attack
- forged receipt
- tenant-boundary violation
- SIEM export outage
- database migration rollback

Runnable drill:

```bash
npm run gov:drill:key-compromise
```

Key compromise success criteria:

- old authorization is accepted before a revocation is known
- signed revocation statement verifies under a pinned revoker key
- old authorization is rejected after the revocation statement is present
- event trail records the sequence

Incident packet:

- timeline
- affected tenants
- affected receipts/actions
- containment actions
- key rotation or revocation actions
- evidence preservation steps
- customer notification decision
- post-incident corrective actions
