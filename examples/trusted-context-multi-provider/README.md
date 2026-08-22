# Trusted Context Multi-Provider Demo

This reference run applies the existing `MEMORY-PROJECTION-RECORD-v1` and
Trusted Context Pack to two EMILIA-owned source profiles:

- a repository-backed SHEESH/SOMA shape that pins repository URI, revision,
  normalized memory-object path, exact source bytes, and projected bytes; and
- a Zep shape that pins project, graph, episode, exact response bytes, and
  projected bytes.

Run it with:

```bash
npm run demo:trusted-context-multi-provider
```

The seven cases verify exact source and projection bytes, bind the resulting
projection to one exact vendor bank-detail action, refuse action and provider
substitution, preserve stale status as `INDETERMINATE`, and reject changed
source bytes.

The source bytes are synthetic. Both profiles default native trust to
`unverified`. A deployment can upgrade that classification only through a
deployment-owned native source verifier that is run once before record signing
and again during full verification. The adapter signature authenticates that
adapter assertion. It does not prove source truth, model use, action authority,
execution, or outcome.

This is not a SHEESH standard, Zep standard, native-provider conformance result,
provider endorsement, live integration, or production deployment.
