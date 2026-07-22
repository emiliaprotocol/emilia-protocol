# Evidence readiness workspace

`/evidence-readiness` is a bounded tenant-facing review surface for EMILIA
Cloud Guard trust-receipt lifecycle records. It does not ship sample data or
persist credentials in the browser.

The page sends a tenant-scoped `ept_...` Cloud API key in memory to
`GET /api/cloud/evidence-readiness/runs`. The route authenticates the key with
the existing Cloud control plane, requires `read`, and currently requires a
production-scoped key because the underlying legacy audit rows do not carry a
separate Cloud-environment binding. It establishes tenant-owned receipt IDs in
the database before loading their bounded timelines, then returns an allowlist
projection rather than raw `after_state`, metadata, or event details. A source
failure returns no partial response. The browser can export the selected
normalized snapshot; the export is not a new source of truth.

For deployment:

1. Issue a tenant key with `read` permission through the existing Cloud tenant
   API-key flow.
2. Configure the Cloud/Supabase environment used by the control plane.
3. Confirm that `audit_events` contains the tenant's Guard trust-receipt
   lifecycle. The surface intentionally does not read the older unscoped
   protocol, handshake, or signoff event tables.

The UI deliberately reports missing fields as `not recorded`; it does not infer
compliance, claim that an external effect occurred, or turn an absent CAID into
a positive result. Customer-created records may include tests.
