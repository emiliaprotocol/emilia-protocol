# Key Custody

Government mode requires keys to live behind a custody boundary.

Production posture:

- `EP_KEY_CUSTODY_MODE=kms` or `EP_KEY_CUSTODY_MODE=hsm`
- `EP_KMS_KEY_ID` or `EP_HSM_KEY_ID` set
- local/env private-key signing refused in government mode
- trusted issuer keys pinned with `EP_TRUSTED_ISSUER_KEYS`
- WebAuthn RP ID pinned with `EP_WEBAUTHN_RP_ID`
- key validity windows enforced by strict verification

The repository provides `lib/key-custody.js` as the abstraction. Cloud-specific KMS/HSM clients plug into `createExternalCustodySigner()`.

FIPS note: using an HSM or KMS is not itself a FIPS claim. The deployment must choose a FIPS-validated cryptographic module and document the module certificate, operating mode, and boundary.
