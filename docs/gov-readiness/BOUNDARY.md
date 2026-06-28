# Authorization Boundary

The first government boundary should be customer-controlled.

Inside the customer boundary:

- receipt verification
- receipt consumption
- tenant database
- security event ledger
- KMS/HSM-backed signing
- SIEM export
- audit retention

Outside the customer boundary:

- public standards documents
- open-source SDKs
- conformance vectors
- public documentation

EMILIA-hosted services must not receive regulated or mission-sensitive data unless a separate hosted-cloud authorization boundary is defined and assessed.

Boundary rule for pilots: send hashes, receipts, and verification results whenever possible; keep raw case data, payment details, personnel records, and mission context inside the customer environment.
