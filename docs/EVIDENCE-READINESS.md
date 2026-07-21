# Evidence readiness workspace

`/evidence-readiness` is the tenant-facing review surface for EMILIA Cloud
events. It does not ship sample data or browser-persisted credentials.

The page sends a tenant-scoped `ept_...` Cloud API key in memory to
`GET /api/evidence-readiness/runs`. The route authenticates the key with the
existing Cloud control plane, requires `read`, scopes every query to the key's
tenant, and returns normalized event records plus the existing integrity check.
The browser can export the selected authenticated event as a reviewer package;
the export is not a new source of truth.

For deployment:

1. Issue a tenant key with `read` permission through the existing Cloud tenant
   API-key flow.
2. Configure the Cloud/Supabase environment used by the control plane.
3. Confirm that the tenant event tables contain action, decision, evidence, and
   outcome fields if the corresponding columns are to appear in the workspace.

The UI deliberately reports missing fields as `not recorded`; it does not infer
compliance or turn an absent CAID into a positive result.
