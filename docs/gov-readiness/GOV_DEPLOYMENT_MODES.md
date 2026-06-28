# Government Deployment Modes

## 1. Protocol / Library

EMILIA is used as open-source verification code, conformance vectors, and receipt formats. EMILIA does not host federal data.

Use this for standards review, offline verification, and pilots inside a buyer's existing environment.

## 2. Customer-Controlled Deployment

The customer runs EMILIA components inside its own cloud or classified boundary:

- verifier
- receipt store
- security event ledger
- KMS/HSM signer adapter
- audit export

This is the preferred first government wedge because sensitive mission data does not leave the customer's environment.

## 3. EMILIA Cloud Gov

EMILIA hosts a government-facing cloud service. This requires a defined FedRAMP boundary, independent assessment, continuous monitoring, incident reporting, vulnerability management, and authorization by an agency or the FedRAMP path available at that time.

Do not represent this repository as authorized until that process is complete.
