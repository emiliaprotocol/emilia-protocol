<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP Reference Integration: Epic on FHIR (R4)

**Status: complete against the Epic on FHIR sandbox, 2026-07-04.**
A receipt-backed authorization-evidence record was filed into a sandbox
patient chart and read back, using only public, self-service Epic developer
resources. No Epic partnership, membership, or fee was required.

The public, secret-free client that reproduces the OAuth/FHIR path is in
`examples/epic-fhir/epic_sandbox_client.py`; its write command requires an
explicit `--confirm-write`. On 2026-08-16, the client re-authenticated against
the live sandbox and read the configured test patient successfully. That
read-only check did not create or modify a FHIR resource.

## What this proves

An EMILIA authorization receipt can be carried into an Epic chart as a standard
FHIR `DocumentReference`, so the proof that a named human authorized an AI
agent's action lives *inside the EHR record* while remaining verifiable
offline under relying-party-pinned approver keys. The exercised demonstration
receipt carries no patient content; the generic client does not classify
caller-supplied receipt bytes as PHI-free. The FHIR resource anchors the
evidence to the patient and encounter, while the receipt binds exact canonical
action bytes.

## The flow

1. **Backend OAuth 2.0 (system-level).** Client-credentials grant with a
   `private_key_jwt` client assertion, RS384, `kid` resolved against a JWK Set
   URL hosted on the EMILIA domain. Scopes granted:
   `system/Patient.read`, `system/Encounter.read`,
   `system/DocumentReference.read`, `system/DocumentReference.write`,
   `system/Provenance.read`.
2. **Anchor the subject.** `Patient.Read (R4)` for the sandbox test patient,
   `Encounter.Search (R4)` for a live encounter ID (Epic's Clinical Notes
   profile requires `context/encounter` on create; see gotchas).
3. **Mint the receipt.** `@emilia-protocol/issue` mints EP-RECEIPT-v1 over the
   canonical action record (RFC 8785), with the target patient and encounter
   inside the signed action bytes. Verified offline with
   `@emilia-protocol/verify`: context commitments, signoff signatures,
   separation-of-duties, inclusion proof, checkpoint signature, validity
   windows.
4. **File the evidence.** `DocumentReference.Create (Clinical Notes) (R4)`:
   `status current`, `docStatus final`, LOINC-typed note, subject = patient,
   `context.encounter` = the live encounter, attachment = plain-text note
   containing a human-readable header plus the full receipt JSON.
   Result: `201 Created`.
5. **Read it back.** `DocumentReference.Read (R4)` returns the filed record
   (`current`/`final`), closing the loop.

## Reproduce the path

```bash
cd examples/epic-fhir
python -m unittest test_epic_sandbox_client.py

export EPIC_FHIR_CLIENT_ID='your-client-id'
export EPIC_FHIR_KID='your-jwks-key-id'
export EPIC_FHIR_KEY_PATH='/absolute/path/to/nonproduction-private-key.pem'

python epic_sandbox_client.py check-patient \
  --patient-id YOUR_SANDBOX_PATIENT_ID

python epic_sandbox_client.py file-receipt \
  --patient-id YOUR_SANDBOX_PATIENT_ID \
  --encounter-id YOUR_SANDBOX_ENCOUNTER_ID \
  --receipt-file /absolute/path/to/receipt.json \
  --confirm-write
```

The client prints only token metadata, FHIR ids, and status fields. It does not
print the bearer token or private key.

## Gotchas for implementers

- **JWK Set URL must not redirect.** Epic's fetcher refuses 30x. Serve the
  JWKS from the exact host (for us, the `www` host) with a direct 200.
- **Propagation is real.** A new client ID, and any later API-list change,
  takes roughly 30 to 60 minutes to reach the sandbox. `invalid_client` right
  after registration is normal; retry, do not re-register.
- **Clinical Notes create requires an encounter.** The profile rejects
  `DocumentReference.Create` without `context/encounter`
  (`"Valid encounter required"`). Grant `Encounter.Search` and resolve a real
  encounter first; example IDs found in Epic documentation may belong to
  non-sandbox instances and will fail with `"Invalid subject received"`.
- **Separate keys per environment.** Distinct RSA keypairs for non-production
  and production, published as separate JWK Sets; EP signing keys (Ed25519)
  are unrelated to the OAuth transport keys and never leave the issuer.

## Where this sits in EP

The Gate enforces pre-execution ("no receipt, no execution") wherever the
agent acts. This integration is the *post-execution evidence rail*: the same
receipt that gated the action is filed to the chart, so audit, inspection,
and insurance review can verify authorization years later without access to
any vendor system. Epic's R4 surface exposes no public AuditEvent write and
read-only Provenance, which makes `DocumentReference` the practical evidence
carrier today.

This artifact does not prove a live customer deployment, medical correctness,
legal permission, Epic review, Connection Hub eligibility, complete mediation,
or that the external clinical effect occurred.
