# EMILIA × Epic on FHIR (R4) — reference integration

A minimal, runnable reference showing how an Epic customer or integrator can
carry EMILIA exact-action authorization evidence through the public
[Epic on FHIR](https://fhir.epic.com) R4 sandbox surface. This is an independent
open-source integration, not an Epic endorsement, partnership, or production
deployment.

## The pattern

When an agent or clinician proposes a high-risk clinical action, a relying
party can require evidence that an enrolled clinician approved the exact
action. The receipt can then be surfaced back into the chart. The local example
shows the natural FHIR `Provenance` shape. The exercised Epic sandbox path uses
a `DocumentReference` because Epic's public R4 surface exposes Provenance as
read-only. The receipt remains independently verifiable under the relying
party's pinned keys.

This can support controls such as an independent double-check or segregation
of duties. The receipt does not by itself establish medical correctness, legal
permission, or that the clinical effect occurred.

## Data boundary

The included demonstration receipt carries references and hashes rather than
patient content. The generic client does not decide whether caller-supplied
receipt bytes contain PHI; a deployment must enforce its own data policy before
filing or exporting evidence.

## FHIR hooks

- **`DocumentReference`** — the exercised Epic sandbox write/readback carrier.
- **`Provenance`** — the natural model when a target environment permits writes;
  Epic's public R4 sandbox exposes it read-only.
- **`AuditEvent`** — a possible audit-trail reference where the target permits
  the required operation; it is not exercised here.

## Run the local receipt demonstration

```bash
pip install pynacl jcs
python epic_fhir_receipt.py
```

The local runner issues and verifies a receipt, constructs the synthetic FHIR
`Provenance`, and rejects a changed dose and forged signature. It does not
contact Epic.

## Run the Epic sandbox client

Register a backend application through Epic on FHIR, grant the required R4
scopes, and keep the private key outside the repository. Then set:

```bash
pip install cryptography
```

Configure the non-production backend application:

```bash
export EPIC_FHIR_CLIENT_ID='your-client-id'
export EPIC_FHIR_KID='your-jwks-key-id'
export EPIC_FHIR_KEY_PATH='/absolute/path/to/nonproduction-private-key.pem'
```

Read one sandbox patient without printing the access token or key:

```bash
python epic_sandbox_client.py check-patient --patient-id YOUR_SANDBOX_PATIENT_ID
```

Create a Clinical Notes `DocumentReference` carrying an exact receipt, then read
it back. The explicit confirmation flag prevents an accidental write:

```bash
python epic_sandbox_client.py file-receipt \
  --patient-id YOUR_SANDBOX_PATIENT_ID \
  --encounter-id YOUR_SANDBOX_ENCOUNTER_ID \
  --receipt-file /absolute/path/to/receipt.json \
  --confirm-write
```

Run the secret-free unit tests:

```bash
python -m unittest test_epic_sandbox_client.py
```

## Connection Hub boundary

Epic's stated route is customer-driven: a product can request a Connection Hub
listing after its integration is live with at least one Epic customer. This
artifact establishes a tested integration path; it does not establish a live
customer deployment, Connection Hub eligibility, or Epic review.
