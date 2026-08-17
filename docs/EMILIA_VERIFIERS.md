# EMILIA Protocol Independent Verifiers

The EMILIA Protocol requires robust verification of its cryptographic primitives. To ensure true decentralization and cross-implementation resilience, independent verification logic is essential.

## Our Clean-Room Implementation
We have successfully implemented a clean-room independent verifier suite in Node.js utilizing only native `node:crypto` modules. No external cryptographic dependencies are used, ensuring a pristine execution environment that relies solely on standard WebCrypto / Node.js primitives.

### Verification Capabilities
Our `@emilia-protocol/verify-independent` package provides comprehensive evaluation for all 16 conformance suites:
*   **Signatures & Signoffs** (Ed25519)
*   **Receipts & Proofs** (Merkle Trees, Timestamp Proofs, Consumption Proofs)
*   **Quorum & Consensus** (Witness requirements)
*   **Canonicalization** (RFC 8785 JCS)

### Verifier Key Identity
To ensure genuine independence from the reference implementation, this verifier uses a uniquely generated Ed25519 keypair:
*   **Verifier ID**: `ext:verifier:cleanroom:independent:v2`
*   **Key ID**: `ep:external-verifier-key:sha256:f59f4aa5eda015d9`
*   **Public Key**: `MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4`

### Usage
This verifier can process all 161 vectors in the standard EMILIA conformance suite, yielding a `statement.json` with a cryptographically verified digest.
