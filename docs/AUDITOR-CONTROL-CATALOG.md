# EMILIA Gate — Auditor Control Catalog (pre-written RCM language)

*Catalog version: `EP-GATE-CONTROL-CATALOG-v1` · 2026-07 · SPDX-License-Identifier: Apache-2.0*

> **What this document is — and is not.**
> This catalog offers **pre-written control language** for a deploying organization's
> risk-and-control matrix (RCM), so an audit senior can copy rows straight into workpapers with
> accurate citations to where each mechanism lives, how to re-perform it, and what evidence it
> emits. Every statement is written in RCM voice and matched to the module that implements it.
>
> **Adoption, tailoring, testing, and conclusions belong to management and their auditors.**
> EMILIA Protocol is not an auditor. Copying a row into an RCM does not make the control
> designed, implemented, or operating effectively at any organization — a control exists only
> where management actually routes the relevant actions through the Gate, provisions the durable
> backends, and operates the surrounding processes (identity proofing, incident response, records
> disposal) that the Gate deliberately does not own. The suggested test procedures are offered to
> support the auditor's work; the nature, timing, and extent of testing — and every conclusion
> drawn from it — are the auditor's alone. Nothing here constitutes an attestation, certification,
> or opinion. Each control carries an **honest boundary** row stating what the mechanism does
> *not* cover — copy it into the workpaper along with the statement.

## How to use this catalog

- **One subsection per control (AC-1 … AC-8).** The rows of each table map onto typical RCM
  columns: control statement, type, frequency, owner-side implementation reference, test
  procedure, evidence, and limitations. Renumber `AC-*` to your client's control-ID scheme.
- **Relationship to the SOC 2 mapping.** `docs/SOC2-CONTROL-MAPPING.md`
  (`EP-GATE-SOC2-MAPPING-v1`) maps the same mechanisms to the AICPA 2017 Trust Services
  Criteria. This catalog is the RCM-language layer above it: statements you can paste, plus
  numbered test procedures. Each control below cross-references the mapping rather than
  restating it — cite both in the workpaper.
- **Frequency.** These are automated controls that operate on every in-scope event
  ("continuous"). Where a control's effect depends on a management-scheduled event (AC-5's
  roster sync), the frequency row says so — the cadence is itself a management control parameter
  the auditor should inquire about.
- **Re-performance environment.** All commands run from a checkout of this repository, in
  `packages/gate`, with Node.js 20+ (they use the built-in `node:test` runner and
  `node:crypto`; no network and no live database — the Postgres-backend tests run against an
  injected in-memory fake that implements real `ON CONFLICT` semantics, per the
  `store-postgres.js` header). Exit code 0 = pass.
- **Validation state of this catalog.** Every command cited below was executed on 2026-07-04
  against this repository: `node eg1.mjs --json` exited 0 with 8/8 checks; `node cf1.mjs --json`
  exited 0; `node --test` across `gate.test.js`, `redteam.test.js`, `roster.test.js`,
  `breakglass.test.js`, `store-postgres.test.js`, `siem.test.js`, `custody.test.js` passed
  115/115; `reports/underwriter.test.js`, `reports/art14.test.js`, `metrics.test.js` passed
  46/46. Re-run them yourself; do not rely on this sentence.

Terminology (from `packages/gate/index.js`): a **guarded action** executes only with a receipt
that is *valid* (Ed25519 over canonical JSON, pinned issuer), *in-scope* (bound to the exact
action), *sufficiently assured* (cryptographically verified tier), *fresh*, and *unused*
(one-time consumption); otherwise it is refused with a machine-readable HTTP 428
Receipt-Required challenge, and every decision — allow or deny — is appended to a tamper-evident
evidence log.

---

## AC-1 — Receipt-gated execution of irreversible actions

| RCM field | Content |
|---|---|
| **Control statement** | Irreversible agent-initiated actions declared in the organization's action-risk manifest are executed only upon presentation of a cryptographically verified authorization receipt — Ed25519 over canonical JSON, signed by an issuer key pinned by the organization, bound to the exact action requested, within the configured freshness window, and not previously used. Requests without such a receipt are refused with a machine-readable HTTP 428 Receipt-Required challenge, and every decision (allow or deny) is recorded. |
| **Type** | Automated, preventive |
| **Frequency** | Continuous (every guarded request) |
| **Where implemented** | `packages/gate/index.js` (`check`/`guard`/middleware; deny-by-default); action families declared in `packages/gate/action-packs.js` |
| **Test procedure** | 1. Inspect the deployed action-risk manifest and agree the in-scope irreversible action families to it. 2. Re-perform enforcement: `cd packages/gate && node eg1.mjs --json` — the EG-1 harness exercises 8 refuse/allow checks (no-receipt refused, valid receipt allowed, drifted execution refused, replay refused, tampered receipt refused, …); exit code 0 and `"passed": true` required. 3. Re-perform the category checks: `cd packages/gate && node cf1.mjs --json` (adds: consequential action declared by policy, wrong-issuer key cannot authorize, evidence verifies offline). 4. Re-perform the unit suite: `cd packages/gate && node --test gate.test.js`. 5. Inspect a sample of production evidence-log entries: for each deny, agree `reason` to a named predicate (`receipt_required`, `replay_refused`, …); for each allow, agree `signer`, `have_tier`, and `receipt_id` fields are present. |
| **Evidence artifact** | EG-1 JSON report (`node eg1.mjs --json` output); CF-1 JSON report; evidence-log export (`evidence.all()`) with per-decision reasons; 428 challenge bodies captured from refused requests |
| **Honest boundary** | Covers only actions the organization actually routes through the Gate; an out-of-band execution path is invisible to this control (the Art. 14 pack's coverage ratio makes that gap measurable — see AC-7). The Gate is a policy-enforcement point, explicitly **not** authentication ("who are you") and **not** permissions ("are you allowed here"); the organization's IAM stack still owns those. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC6.1 (deny-by-default receipt gating), PI1.3 (processing is authorized) |

## AC-2 — Verified assurance tiers for high-risk actions

| RCM field | Content |
|---|---|
| **Control statement** | Actions designated high-risk in the action-risk manifest execute only when the authorizing receipt cryptographically proves the required assurance tier: `class_a` requires a valid WebAuthn device signoff by the named approver; `quorum` requires a valid EP-QUORUM-v1 document (distinct signers, distinct keys, threshold met, per-signer assertions verified). Self-asserted tier claims in receipt payload fields are never credited; a receipt that merely claims a higher tier is credited `software` and refused `assurance_too_low`. Unknown or unmodeled required tiers are refused, not defaulted down. |
| **Type** | Automated, preventive |
| **Frequency** | Continuous (every guarded request against a tiered action) |
| **Where implemented** | Tier crediting and enforcement in `packages/gate/index.js` (`receiptAssuranceTier`, `TIER_RANK` comparison); per-signer verification in `packages/verify/index.js` (WebAuthn signoff) and `packages/verify/quorum.js` (EP-QUORUM-v1); per-action required tiers in `packages/gate/action-packs.js` |
| **Test procedure** | 1. Inspect the manifest and agree each high-risk action family's `assurance_class` to management's risk designation. 2. Re-perform the adversarial suite: `cd packages/gate && node --test redteam.test.js` — includes fabricated-quorum and self-asserted-tier refusals. 3. Re-perform tier enforcement in the core suite: `cd packages/gate && node --test gate.test.js` (valid class_a allowed; bare claims refused). 4. Inspect a sample of production allow entries for tiered actions: agree `have_tier` ≥ required tier and `assurance_tier_source` = `cryptographic_verification`. 5. Inspect a sample of `assurance_too_low` denies: agree `have_tier`/`need_tier` fields show the credited-vs-required gap. |
| **Evidence artifact** | Evidence-log allow entries carrying `have_tier` + `assurance_tier_source: cryptographic_verification`; `assurance_too_low` refusal entries; tier-distribution tables in the underwriter attestation and Art. 14 pack (see AC-7) |
| **Honest boundary** | The credited tier is proven against approver keys **pinned by the organization** (or embedded evidence re-verified per-signer); which actions require which tier is a management manifest decision, not a Gate property. Per `packages/verify/quorum.js`: verified ≠ authorized-by-org — a weaker creator-supplied policy verifies just as cleanly, so the quorum policy and approver keys must be sourced org-side, out of band; the auditor should test that sourcing. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC6.3 (assurance-tier enforcement / role-based segregation) |

## AC-3 — Two-person rule (cryptographic quorum, distinct principals)

| RCM field | Content |
|---|---|
| **Control statement** | Actions designated by management as requiring dual (or M-of-N) authorization execute only upon a verified EP-QUORUM-v1 quorum in which the threshold number of **distinct** principals, each using a **distinct** key, has cryptographically bound a per-signer assertion to the same exact action within the permitted window. A partial, duplicated-signer, or fabricated quorum does not execute; it is refused. |
| **Type** | Automated, preventive |
| **Frequency** | Continuous (every guarded request against a quorum-tier action) |
| **Where implemented** | Quorum predicate and per-signer verification in `packages/verify/quorum.js` (composing `verifyWebAuthnSignoff` from `packages/verify/index.js`); tier enforcement in `packages/gate/index.js`; default quorum-tier actions (e.g. `deploy.production`, `permission.admin.change`) in `packages/gate/action-packs.js` |
| **Test procedure** | 1. Inspect the manifest and agree which action families management pinned to `quorum`. 2. Re-perform: `cd packages/gate && node --test redteam.test.js` (fabricated quorum block refused; self-asserted signers not credited). 3. Re-perform: `cd packages/gate && node --test gate.test.js` (genuine 2-of-N quorum evidence allowed at `quorum` tier). 4. Inspect a sample of production allow entries for quorum actions: agree the credited tier is `quorum` and the receipt's quorum evidence names ≥ threshold distinct signers. 5. Inquire of management how quorum policies (threshold, roster) are pinned org-side, and inspect that configuration (see AC-2 boundary). |
| **Evidence artifact** | Allow entries at verified `quorum` tier; refusal entries for under-threshold or fabricated quorums; the EP-QUORUM-v1 documents embedded in sampled receipts |
| **Honest boundary** | The quorum verifier proves M distinct **keys** with per-signer assertions over the same action; mapping keys to genuinely distinct **humans** depends on the organization's enrollment and roster discipline (AC-5). Separation-of-duties design — who is eligible to co-sign what — is management's, not the Gate's. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC6.3 (quorum as the cryptographic two-person rule), CC8.1 (production deploys pinned to quorum) |

## AC-4 — Replay prevention (one-time consumption, durable backend)

| RCM field | Content |
|---|---|
| **Control statement** | Each authorization receipt is consumed on first use and refuses every subsequent presentation (`replay_refused`). Consumption is keyed on the issuer-generated receipt ID (a receipt without one is refused) and, in multi-instance production deployments, is recorded in a shared durable store whose consume operation is a single atomic insert-if-absent (Postgres `INSERT … ON CONFLICT DO NOTHING`), so concurrent presentation across instances yields exactly one execution. Store errors refuse the action (fail closed); an expired-but-uncleaned consumption row still refuses. In production, the Gate refuses to start without a provided store unless management explicitly acknowledges a single-instance deployment. |
| **Type** | Automated, preventive |
| **Frequency** | Continuous (every guarded request presenting a receipt) |
| **Where implemented** | Consumption check in `packages/gate/index.js`; store contract in `packages/gate/store.js` (`MemoryConsumptionStore`, `createDurableConsumptionStore`); durable reference backend in `packages/gate/store-postgres.js` (`EP-GATE-PG-CONSUMPTION-v1`) |
| **Test procedure** | 1. Re-perform: `cd packages/gate && node --test gate.test.js` (same receipt allowed once, refused on second presentation). 2. Re-perform the durable backend contract: `cd packages/gate && node --test store-postgres.test.js` (atomic insert-if-absent decides consumed-vs-replay; backend error propagates rather than admitting a replay; expired-but-uncleaned row still refuses). 3. Re-perform EG-1 (replay check included): `cd packages/gate && node eg1.mjs --json`. 4. Inspect the production deployment configuration: agree that a shared durable consumption store is provisioned (connection/DSN, and the `ep_gate_consumption` table per the DDL exported in `store-postgres.js`) or that management has documented acceptance of a single-instance deployment. 5. Inspect a sample of `replay_refused` evidence entries and agree `consumption_key` to the original allow's `receipt_id`. |
| **Evidence artifact** | `replay_refused` evidence-log entries; the `ep_gate_consumption` table contents; `store-postgres.test.js` run output; EG-1 JSON report (replay check) |
| **Honest boundary** | Fleet-safe replay defense exists only where management actually provisions the shared durable backend; the in-memory default protects a single process only. Availability, backup, and recovery of the backing database are the organization's infrastructure (the Gate makes no availability claims — see the A1 section of the SOC 2 mapping). |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC6.1 / CC6.6 (protection against credential reuse) |

## AC-5 — Approver deprovisioning via IdP roster sync

| RCM field | Content |
|---|---|
| **Control statement** | The population of acceptable approvers is reconciled to the organization's identity provider on each roster sync (`EP-GATE-ROSTER-v1`): only users exported with `active === true` have keys pinned; a user absent from the import — offboarded or dropped — has every previously pinned key revoked on that sync; a key ID contested between principals pins nothing and is revoked if present; an import that would leave zero active approvers is rejected unless explicitly acknowledged, so a broken IdP export cannot silently mass-revoke. Receipts verified against a revoked key are refused. |
| **Type** | Automated, preventive (with detective output: the revocation diff) |
| **Frequency** | Recurring — operates automatically at each roster sync; the sync cadence is a management-set control parameter and determines the deprovisioning window |
| **Where implemented** | `packages/gate/roster.js` (`importRoster`, `diffRoster`, `applyRosterToRegistry`), reconciling against `packages/gate/key-registry.js` (hard revocation; keys valid only within their window); enforcement at verification time in `packages/gate/index.js` (`keysValidAt` at receipt issuance time) |
| **Test procedure** | 1. Inquire of management the roster sync source (`source` field, e.g. `scim:okta:<org>`) and cadence; agree cadence to management's deprovisioning SLA. 2. Re-perform: `cd packages/gate && node --test roster.test.js` (inactive/missing users never pin; absent user's keys revoked; contested kid pins nothing; empty import requires `allowEmpty`). 3. Re-perform key-custody enforcement: `cd packages/gate && node --test custody.test.js` (revoked issuer key signs nothing the Gate accepts). 4. For a sample of leavers from the HR/IdP termination listing, inspect the roster artifacts and `applyRosterToRegistry` output covering the termination date: agree each leaver's kid appears in the `revoked` list of the first sync after termination. 5. Inspect `integrity_warnings` on sampled roster artifacts for malformed-user/malformed-key exclusions and inquire how management dispositions them. |
| **Evidence artifact** | Versioned roster artifacts (with `integrity_warnings`); `diffRoster` output between consecutive syncs; the exact `revoked` list returned by `applyRosterToRegistry`; refusal entries for receipts signed by revoked keys |
| **Honest boundary** | "WHO may approve is an HR fact, not a crypto fact" — the roster is only as correct as the IdP export; identity proofing and the joiner-mover-leaver process belong to the IdP and the organization. Revocation takes effect **on the next sync**: between offboarding and that sync, a leaver's key remains pinned, so sync cadence is the residual-risk parameter the auditor should evaluate. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC6.2 (register/authorize before credential issuance; remove when no longer authorized) |

## AC-6 — Break-glass: evidenced, single-use, scoped quorum grant

| RCM field | Content |
|---|---|
| **Control statement** | Emergency actions outside the normal receipt path execute only under a break-glass authorization (`EP-GATE-BREAKGLASS-v1`): an M-of-N Ed25519 multi-signature by distinct pinned principals over a single grant that is scoped to enumerated action types, time-bounded, attributed (reason and incident reference are required fields — an override with no stated cause is refused), and single-use (consumed through the same one-time consumption store as receipts, committed before use so a crash burns the grant rather than leaving it replayable). No configuration flag disables the Gate; the override is itself a signed, logged artifact, and the module contract requires the break-glass evidence entry to be durably recorded before the overridden action runs. |
| **Type** | Automated, preventive (scope/window/threshold/single-use enforcement) and detective (mandatory evidence entry per use) |
| **Frequency** | Continuous (every attempted break-glass use) |
| **Where implemented** | `packages/gate/breakglass.js` (`mintBreakGlassAuthorization`, `verifyBreakGlass`, `consumeBreakGlass`, `buildBreakGlassEvidence`); consumption via `packages/gate/store.js`; evidence via `packages/gate/evidence.js` (strict mode) |
| **Test procedure** | 1. Re-perform: `cd packages/gate && node --test breakglass.test.js` (threshold unmet / duplicate signers / expired / not-yet-valid / out-of-scope / tampered / unknown-kid all refuse; a grant carrying any non-verifying signature is refused outright; single-use consumption). 2. Inspect the integration code path that executes overrides: agree it calls `verifyBreakGlass` → `consumeBreakGlass` → records the `kind: 'breakglass'` evidence entry via a strict log **before** executing, per the module contract ("no evidence entry, no override"). 3. Obtain the period's evidence log and extract all `kind: 'breakglass'` entries; for each, agree `reason` and `incident_ref` to the incident ticket, agree scope and window to the action actually taken, and agree the signer set to the pinned break-glass roster. 4. For the same period, inquire whether any emergency change was made **without** a corresponding break-glass entry (compare against incident records) — absence of the entry is a control exception, not a Gate failure. |
| **Evidence artifact** | The signed grant documents; `kind: 'breakglass'` evidence-log entries (grant ID, scope, window, reason, incident_ref, signers); consumption-store rows showing single-use burn |
| **Honest boundary** | The module makes an unevidenced override cryptographically refusable, but only for actions routed through it: direct infrastructure access (cloud console, raw CLI) bypasses the Gate entirely, and constraining that path (IAM boundaries) is the organization's. The "no evidence entry, no override" contract binds the **integration** — the auditor must inspect that the deployed code honors it (step 2), since the module cannot force a caller to consult it. |
| **SOC 2 cross-reference** | No dedicated row in `EP-GATE-SOC2-MAPPING-v1` as of that mapping's date; nearest criteria are CC6.1 (logical access) and CC7.3–CC7.4 (security-event response). Cite this catalog row directly. |

## AC-7 — Tamper-evident decision logging and SIEM export

| RCM field | Content |
|---|---|
| **Control statement** | Every Gate decision — allow or deny — is appended to a hash-chained, tamper-evident evidence log over canonical JSON; altering or removing any record breaks the chain, which `verify()` detects and localizes to the exact sequence number. In strict mode the log fails closed: if the durable sink write fails, the Gate refuses the action (`evidence_log_failed`) rather than proceeding unrecorded. Log entries are exported to the organization's SIEM in OCSF (class 6003, API Activity) or CEF via deterministic offline mappings; a malformed entry becomes a structured error event visible in the SIEM, never a silent drop. Period reports (underwriter control attestation `EP-GATE-UNDERWRITER-ATTESTATION-v1`; EU AI Act Art. 14 pack `EP-GATE-ART14-PACK-v1`) are pure functions over the log that exclude what they cannot verify and surface exclusions as `integrity_warnings`. |
| **Type** | Automated, detective (fail-closed recording is preventive with respect to unaccounted actions) |
| **Frequency** | Continuous (every decision; every export) |
| **Where implemented** | `packages/gate/evidence.js` (hash chain, strict mode, `verify()`); `packages/gate/siem.js` (`EP-GATE-SIEM-EXPORT-v1`: `toOCSF`, `toCEF`, `createSiemForwarder`); operational metrics in `packages/gate/metrics.js` (`EP-GATE-METRICS-v1`, never throws into the enforcement path); period reports in `packages/gate/reports/underwriter.js` and `packages/gate/reports/art14.js` |
| **Test procedure** | 1. Obtain the period's evidence-log export and re-perform chain verification (`verify()` over the export, or via the deployed instance): expect `{ ok: true, length, head }`; any `{ ok: false, at, reason }` localizes a break for investigation. 2. Re-perform fail-closed recording: `cd packages/gate && node --test redteam.test.js` (a failed strict sink write downgrades an allow to an `evidence_log_failed` refusal). 3. Re-perform SIEM mapping determinism: `cd packages/gate && node --test siem.test.js` (fixed entry → byte-identical OCSF/CEF event; malformed entry → structured `malformed_evidence_entry` error event). 4. Re-perform report integrity discipline: `cd packages/gate && node --test reports/underwriter.test.js reports/art14.test.js` (unverifiable entries excluded and surfaced as `integrity_warnings`; the Art. 14 renderer refuses a pack whose honesty notice was altered or removed). 5. Trace a sample of evidence entries to the corresponding SIEM events (match `metadata.uid` to the entry `hash`) and agree dispositions. 6. Inspect the deployed configuration: strict mode enabled and a durable sink provisioned. |
| **Evidence artifact** | Full log export plus `verify()` result; SIEM event stream in the organization's Splunk/Sentinel/Datadog; the two period-report JSON artifacts with their `integrity_warnings` arrays; `evidence_log_failed` refusal entries (if any) |
| **Honest boundary** | The chain proves **integrity of what was recorded**, not completeness of what management chose to route through the Gate — the Art. 14 pack's coverage ratio measures that boundary. The default sink is in-memory; durability across restarts requires an organization-supplied sink, and its backup/recovery is the organization's. SIEM export is observability, not enforcement: the evidence log, not the SIEM copy, is the enforcement record; detection rules and response run in the organization's SOC. The period reports support review; they attest control operation only, never business correctness, and carry mandatory honesty notices to that effect. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC7.2 (tamper-evident log; SIEM export; metrics), CC7.3 (machine-readable refusal predicates), CC7.4/CC7.5 (period reports), PI1.4/PI1.5 (deterministic, integrity-guarded derived outputs) |

## AC-8 — Evidence retention and legal hold

| RCM field | Content |
|---|---|
| **Control statement** | Evidence-log records are classified against management-configured retention horizons (`EP_AUDIT_HOT_DAYS` / `EP_AUDIT_COLD_DAYS`; default cold horizon six years) into HOT, COLD, and EXPIRED buckets, producing a versioned retention export (`EP-GATE-RETENTION-EXPORT-v1`) that identifies which records are eligible for archival or disposal. Records subject to legal hold — a management-maintained set of evidence hashes — are pinned and never classified as expired regardless of age. The Gate itself never deletes evidence; disposal is a separate, management-executed action operating only on records the classification marks eligible. |
| **Type** | Automated classification (decision support for the records program), detective with respect to premature-disposal risk; the legal-hold pin is preventive within the classification |
| **Frequency** | Continuous availability; executed at each retention review (management-scheduled) |
| **Where implemented** | `packages/gate/retention.js` (`classifyRetention`, `buildRetentionExport`, `RETENTION_EXPORT_VERSION`) over `packages/gate/evidence.js` entries |
| **Test procedure** | 1. Inquire of management the configured horizons and agree them to the organization's records-retention schedule and applicable regulatory minimums. 2. Re-perform classification behavior: `cd packages/gate && node --test custody.test.js` (retention bucketing and legal-hold pinning are covered in the custody suite). 3. Obtain the current legal-hold hash set and the latest retention export; agree that every held hash appears in the `legal_hold` bucket and none in `expired`. 4. Reconcile a sample of `expired`-bucket records against actual disposal actions: agree nothing outside the `expired` bucket was disposed of. 5. After any archive restore during the period, re-perform chain verification over the restored segment (`verify()`, see AC-7) to demonstrate the restored evidence is intact. |
| **Evidence artifact** | `buildRetentionExport` output (versioned, with per-bucket counts and horizons); `classifyRetention` summary; the legal-hold hash list with its change history; disposal records reconciled to the `expired` bucket |
| **Honest boundary** | The Gate classifies eligibility; it never deletes. Executing retention and disposal, defending the legal-hold list, and the storage/backup/recovery of the evidence itself are the organization's records program (the Gate makes no availability or durability claims — see the A1 section of the SOC 2 mapping). Classification depends on each record carrying a parseable timestamp; records without one land in the `unknown` bucket and are never auto-expired, but dispositioning them is management's. |
| **SOC 2 cross-reference** | `docs/SOC2-CONTROL-MAPPING.md` — CC7.x supporting (audit-record lifecycle), A1.2/A1.3 (evidence durability explicitly **not** claimed by the Gate) |

---

## Change control for this catalog

Any edit that adds or strengthens a control statement must, in the same change: (a) add or
update the honest-boundary row, (b) cite the implementing file, and (c) include a test-procedure
command that has actually been executed against the repository. A row missing any of the three
is not a valid `EP-GATE-CONTROL-CATALOG-v1` row. When `EP-GATE-SOC2-MAPPING-v1` is revised,
re-check every cross-reference here in the same pass.

## Related documents

- `docs/SOC2-CONTROL-MAPPING.md` — `EP-GATE-SOC2-MAPPING-v1`, criteria-level mapping under this catalog.
- `docs/CAPABILITY-MAP.md` — build/ship status of every mechanism cited here.
- `packages/gate/README.md` — integration guide.
