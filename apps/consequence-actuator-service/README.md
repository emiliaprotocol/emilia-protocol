# EMILIA consequence actuator service

This service is the credential-owning half of the complete-mediation boundary.
The decision service can authorize and sign a short-lived execution envelope,
but only this separately deployed process owns provider credentials or can call
the configured provider.

`POST /v1/execute` accepts one strict action body plus its closed, signed
execution envelope. The service verifies every bound field, atomically reserves
the envelope through the Gate consequence-actuator store before provider entry,
and permanently consumes it as `COMMITTED` or `INDETERMINATE`. Its response
contains a separately signed observation that the decision service can verify
offline during reconciliation.

The PostgreSQL login must be a tenant-mapped member of
`consequence_actuator_executor` provisioned by migration
`20260725010000_consequence_actuator_store.sql`. Provider and observation
private keys belong only in this service's secret manager.
