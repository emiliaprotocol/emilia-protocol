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

Base anchoring has a separate EVM transaction boundary in `lib/blockchain-signing.js`.
`EP_BLOCKCHAIN_SIGNING_MODE=env` is the compatibility path; `kms` and `hsm` require
an explicitly registered external signer plus `EP_BLOCKCHAIN_SIGNING_KEY_ID` and
never fall back to `EP_WALLET_PRIVATE_KEY`. A deployment must register and test
that provider before claiming hardware-backed blockchain custody.

FIPS note: using an HSM or KMS is not itself a FIPS claim. The deployment must choose a FIPS-validated cryptographic module and document the module certificate, operating mode, and boundary.
