# EMILIA × Epic (FHIR) — reference integration

A minimal, runnable reference showing how EMILIA Protocol adds a **verifiable
human-authorization layer** to clinical actions in an Epic environment, built
entirely on the **free** [open.epic.com](https://open.epic.com) FHIR tier — no
Vendor Services fee and no Epic permission required to build.

## The pattern

When an agent (or clinician) takes a high-risk clinical action — a high-alert
medication override, a coverage determination, a benefit/payment change — a named
clinician's device-bound signoff (WebAuthn / Face ID in production) produces an
EMILIA receipt over the **exact** action. The receipt is then surfaced back into
the chart as a **FHIR `Provenance`** resource (or `AuditEvent`), so it is
discoverable from the Epic record and verifiable by anyone, offline, with no trust
in Epic, EMILIA, or any server.

It maps directly onto controls Epic customers already run:
- the **ISMP / Joint Commission high-alert-medication independent double-check**
- **segregation of duties** (the initiator cannot be the sole approver)

## PHI-free by construction

The receipt carries only **references and hashes** — the FHIR resource id and a
content hash of the canonical resource (which stays in Epic) — plus the action
type and the authorizing clinician identifier. **No patient data ever enters the
receipt.** That is what makes it safe to verify outside the Epic trust boundary.

## FHIR hooks

- **`Provenance`** — the natural carrier: `target` = the order/resource, `agent` =
  the clinician, `signature.data` = the portable EP receipt. (Demonstrated here.)
- **`AuditEvent`** — for the audit-trail surface; reference the receipt id.
- Read the triggering resource (e.g. `MedicationRequest`, `Task`) via the standard
  USCDIv1 FHIR APIs; write back the `Provenance`.

## Run

```bash
pip install pynacl jcs
python epic_fhir_receipt.py
```

You'll see a receipt issued and verified, the FHIR `Provenance` written back, and
two refusals — a **tampered dose** and a **forged signature** — both rejected.

## Why this exists (the go-to-market path)

Epic is customer-driven: you can list on the
[Connection Hub](https://fhir.epic.com/ConnectionHub) **once your integration is
live with at least one Epic customer.** This reference makes EMILIA
**integration-ready today**, so the moment a health system or an Epic-shop AI
vendor says yes, the path is: *land one customer → go live → list*. Build first,
so the customer's "yes" is the only thing on the critical path.
