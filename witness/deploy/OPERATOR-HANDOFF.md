# EP witness independent-operator handoff

This is the shortest path from the checked-in reference witness to real
third-party operation. Completion requires an operator outside EMILIA's
administrative control. Running these steps on another EMILIA-owned account is
useful staging, but it is not independent evidence.

## Independence acceptance bar

The operator must:

1. control its own cloud account or host and witness administrator access;
2. generate the witness private key on that host and never send it to EMILIA;
3. expose the witness over TLS on a stable endpoint;
4. return only the public witness record and endpoint;
5. cosign a supplied checkpoint and allow EMILIA to verify the result offline;
6. authorize publication of the operator name only if it wants to be named.

Cloud, region, and administrator separation are operational facts, not facts a
signature proves. Record them as an operator declaration and verify them during
partner onboarding.

## Operator commands

From a pinned clone of this repository:

```sh
node witness/generate-key.mjs /etc/ep-witness
docker build -f witness/Dockerfile -t ep-witness .
docker run -d --restart unless-stopped --name ep-witness \
  -p 127.0.0.1:8787:8787 \
  -e WITNESS_PRIVATE_KEY_FILE=/keys/witness-private.pem \
  -e WITNESS_PUBLIC_FILE=/keys/witness-public.json \
  -v /etc/ep-witness:/keys:ro \
  ep-witness
```

Terminate TLS in the operator's own reverse proxy or load balancer. Do not
publish port 8787 directly.

Verify locally:

```sh
curl --fail https://WITNESS_HOST/healthz
curl --fail https://WITNESS_HOST/witness-key
```

## Public handoff package

The operator sends:

```json
{
  "endpoint": "https://WITNESS_HOST",
  "public_record": {
    "alg": "EP-WITNESS-v1",
    "witness_id": "witness:sha256:...",
    "public_key": "base64url-spki"
  },
  "operator_declaration": {
    "organization": "operator-selected name",
    "cloud_or_host": "operator-selected provider",
    "region": "operator-selected region",
    "admin_control": "not controlled by EMILIA",
    "key_generated_on_operator_host": true
  }
}
```

The declaration is onboarding evidence, not a cryptographic proof of
independence. EMILIA pins `public_record` out of band and verifies every
cosignature cryptographically.

## Acceptance test

EMILIA supplies one structurally valid checkpoint. The operator returns the
result of:

```sh
curl --fail https://WITNESS_HOST/cosign \
  -H 'content-type: application/json' \
  --data-binary @checkpoint.json
```

Acceptance requires:

- `verifyWitnessCosignature()` succeeds under the out-of-band pinned public key;
- the response echoes the same `tree_size`, `root_hash`, and `log_key_id`;
- a modified checkpoint fails verification;
- the endpoint remains reachable from a network not controlled by EMILIA.

One accepted operator closes the independent-witness milestone only for that
one witness. Equivocation resistance still requires the relying party's selected
quorum of independently operated witnesses and cross-view gossip.

## What must never be claimed early

- A local Docker Compose cluster is not independent.
- Different keys under one administrator are not independent.
- A witness signature does not prove currentness, append-only behavior, or
  physical infrastructure ownership.
- An operator being technically independent does not imply endorsement,
  certification, partnership, or IETF status.
