# EMILIA Government Readiness Packet

This packet is an evidence package for government pilots and prime-contractor security review. It does not claim FedRAMP authorization, FIPS validation, or agency accreditation.

It answers a narrower and useful question: can EMILIA be deployed in a serious environment with clear boundaries, pinned verification, tenant isolation, key custody controls, append-only evidence, incident response, and an independent pentest scope?

Run the static gate:

```bash
npm run gov:check
```

Run the incident drill:

```bash
npm run gov:drill:key-compromise
```

The recommended first deployment is customer-controlled: the agency, lab, or prime runs the verifier, receipt store, and keys inside its existing authorized cloud boundary. EMILIA Cloud Gov is a later authorization path.
