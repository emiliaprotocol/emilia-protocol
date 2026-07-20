# Receipt-program delegated payment

This runnable reference composes existing EMILIA primitives instead of
inventing a second ledger:

1. a signed parent capability holds a 1,000 USD budget;
2. atomic delegation commits 100 USD of the parent budget to a child;
3. CAID binds the child instruction to one material payment release;
4. Gate verifies the base human authorization, reserves 50 USD, invokes the
   simulated provider once, and commits the capability spend;
5. the receipt-program kernel signs a certificate over the exact program,
   bounded result projection, Gate evidence references, context, and state root;
6. the complete certificate is appended to the same atomic evidence log; and
7. an offline verifier re-performs CAID and verifies the signature, context,
   structure, evidence linkage, and certificate-log record against a pinned
   evidence-stream view.

Run it from the repository root:

```bash
npm run demo:receipt-program
```

The demo uses process-local stores, a local key, and explicitly enables test
mode. Production construction requires the shipped durable PostgreSQL
capability store, atomic evidence log, external KMS/HSM signer, exact
issuer/tenant/environment/audience/key context, constructor-pinned disclosure
projection, and a finite provider deadline. Provider code receives frozen
copies and an abort signal.

Signing and certificate-log failures are typed and never rewrite the terminal
Gate state. `recoverCertificates(programDigest)` explicitly scans the evidence
log for independently verified records. Deployments that require cross-store
atomic publication through every crash window still need a transactional outbox
or equivalent deployment recovery design.

The certificate key trust map binds each context `key_id` to exactly one public
key. A locally rehashed record is not persistence evidence: offline verification
requires a relying-party-owned `verifyCertificateInclusion` check against the
trusted stream, authenticated snapshot, or inclusion proof.

The certificate is not a zk-SNARK, Bulletproof, proof of provider truth, or
proof that the external effect was physically or legally correct. It is a
signed, content-addressed execution-and-binding statement whose referenced
authorization, capability, and evidence artifacts remain independently
verifiable.
