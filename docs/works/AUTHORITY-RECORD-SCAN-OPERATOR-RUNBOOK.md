# Authority Record scan operator runbook

This workflow prepares owner-private evidence. It does not create a public
listing, send an invitation, certify a project, or authorize publication.

Repository scanning is the beta collector, not the permanent evidence limit.
Use the source-agnostic private observation envelope described in
`AUTHORITY-RECORD-EVIDENCE-SOURCES-v1.md` for signed releases, build
provenance, tool schemas, deployment manifests, runtime attestations, and
observed action interfaces. Do not project those observations into a public
v1 record until the public schema and owner-proof path support the source.

## Prepare an immutable private package

Clone the owner repository over canonical GitHub HTTPS, check out the exact
watched branch or tag, and ensure the worktree is clean. Write the package
outside the repository:

```bash
npm run works:prepare-private-scan -- \
  --workspace /absolute/path/to/owner-repository \
  --repository https://github.com/OWNER/REPOSITORY \
  --watched-ref refs/heads/main \
  --output /absolute/private/path/authority-scan.json
```

The command refuses:

- a non-canonical or substituted origin;
- a missing or substituted watched ref;
- a watched ref that does not resolve to checked-out `HEAD`;
- a dirty worktree; and
- overwriting an existing package.

The output is mode `0600` and carries the immutable commit, observation time,
scanner-profile digest, report digest, static-analysis limits, and raw report.
Raw findings remain private.

## Human review before a draft

The operator must review official documentation and the private report, then
construct only the closed public projection defined by
`EMILIA-AUTHORITY-RECORD-v1`. Each surface is labeled `OBSERVED`,
`SELLER_ASSERTED`, `UNVERIFIED`, or `INDETERMINATE`. A clean static report does
not establish complete mediation or safety.

Only an authenticated EMILIA administrator may create the private draft. The
owner then proves repository control at the immutable revision, receives an
owner credential, corrects the record, and explicitly approves the exact
current digest. Until that final approval, public reads and listings return
nothing.

## Prohibited shortcuts

- Never email or attach the raw scan package.
- Never publish an unclaimed record or bypass detail.
- Never describe a static observation as a vulnerability, certification, trust
  score, complete mapping, or buyer demand.
- Never replace an unavailable ref lookup with `STALE`.
- Never treat payment as evidence for a favorable label.
