# Supply-chain authority demonstration v1

A digital twin proposes an exact warehouse robot move. EMILIA Gate treats the proposal as a consequential machine action under a finite capability and one local control domain.

The executable cases show:

- the exact command is reserved, admitted to provider entry, and committed;
- a changed route and speed produce a different action digest and are refused before provider entry;
- retrying the committed operation cannot obtain another admitted provider attempt;
- a freeze after reservation establishes non-entry and releases the reservation; and
- restore advances the control epoch and does not revive the old reservation.

Run:

```bash
npm run test:supply-chain-authority
npm run demo:supply-chain-authority
```

This is a synthetic, in-memory reference demonstration. It does not control a live robot, prove durable production deployment, extend the local guarantee across independent state domains, or prove physical effect. Software provenance can establish what build is present. This example establishes whether one exact command was admitted under the demonstrated authority state. Neither claim replaces the other.
