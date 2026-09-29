# OpenShell approver receipts

Signed evidence of who approved each network-rule change in an [OpenShell](https://github.com/NVIDIA/OpenShell) sandbox, and an offline check that every committed change has that evidence.

It is built on OpenShell's public gateway-interceptor contract (`openshell.gateway_interceptor.v1`). It is not part of OpenShell and is not affiliated with NVIDIA.

It has three parts:

1. **An observe-mode gateway interceptor.** It sees the gateway approve draft chunks, the proposed network rules a sandbox asks for. It writes each committed approval to an append-only, hash-chained local log. It always answers `allowed`. It never denies and never modifies anything.
2. **An approver receipt.** The approver signs one specific approval with an ES256 key: the workspace, the sandbox, the chunk id, the gateway's review token for that exact candidate, and a SHA-256 digest of the canonical rule text. A passkey (WebAuthn) can produce the signature. For the demo, a small CLI signs with a local key file.
3. **An offline check.** It takes the log, the receipts and the reader's pinned approver keys, and reports `verified` and `accepted` as separate fields for every committed approval. It also lists findings, and it checks completeness against the sandbox's policy version chain.

## What it proves, and what it does not

For each committed draft-chunk approval, a passing check shows:

- **`verified`**: a receipt's ES256 proof checks out, and the receipt names exactly the approval the gateway committed. That means the same workspace, sandbox, chunk id and review token, and the same rule name and rule-text digest that the observer read back from the gateway after the commit. The receipt must also be issued no later than the commit, plus a skew allowance.
- **`accepted`**: the receipt is `verified`, and the signing key is one the reader pinned as an approver key for that workspace. For a WebAuthn proof whose pin names a relying party, the assertion must also be scoped to it.
- **Completeness**: every version in the sandbox's policy chain is classified. These are reported as what they are:
  - a receipted human approval;
  - a gateway auto-approval, which is its own category and not a missing receipt;
  - a removal the gateway logged;
  - a revision that did not change the policy.

  Every other version is a finding.

So a passing check says: a holder of a pinned approver key approved this exact rule, in this exact sandbox, with a receipt dated no later than the commit (within the configured clock skew). Whether the operator can reach that key depends on where the key lives. With a passkey on the approver's device, the operator does not hold it. With the demo key file, whoever has the file does. The check cannot tell the two apart. The reader's pin list is where that decision is made.

It does not:

- **approve or block anything.** The interceptor is observe-only and every binding is `fail_open`. If it is down or slow, approvals still commit. The chain check then reports them.
- **cover individual business actions** an agent takes inside a sandbox. It covers infrastructure permission changes: draft-chunk (network rule) approvals.
- **turn operator policy writes into approvals.** `openshell policy set` and `openshell policy update` change policy without any approval. The check lists them as findings.
- **treat the gateway's caller identity as an approver.** Every evaluation carries a gateway-asserted `principal` map. It is unsigned. The report shows it as context, and it never satisfies `verified` or `accepted`.
- **recompute OpenShell's own hashes or review tokens.** The review token covers credential metadata a third party cannot see. The token is compared as an opaque value, and `candidate_effective_policy_hash` is carried for display only.
- **make the observer log tamper-proof.** The hash chain detects an edited, reordered or dropped line in the middle of the log. It does not stop whoever controls the file from rewriting all of it or cutting off its tail. The policy chain check covers missing commits, because the gateway, not the observer, holds that chain.

## How it works

### Observer

OpenShell calls an interceptor in two phases that matter here, and neither is enough alone:

- **`validate`** is the only phase that names the chunk and the review token. It carries `{chunkId, reviewToken, sandbox, workspaceScope}`, plus `requestId` when the client sets one.
- **`post_commit`** is the only phase that proves the gateway committed. It carries only `{policyVersion, policyHash}`, plus `chunksApproved` and `chunksSkipped` for bulk approval.

Nothing the interceptor receives links a `validate` call to its `post_commit`, so the observer binds both phases on `ApproveDraftChunk` and `ApproveAllDraftChunks`. After each `post_commit` it answers first. It then reads the gateway with its own credential (`GetSandbox`, `GetDraftPolicy`, `ListSandboxPolicies`) and logs what it saw.

The offline check joins a `post_commit` to the `validate` it belongs to. The candidate must come from the same caller, be inside a time window, not be a replayed request id, and agree with the read-back. The chunk must show `approved` with the same review token, and the committed `(version, hash)` must be in the sandbox's chain. When more than one different candidate fits, the check reports `ambiguous_pairing` and attributes nothing.

The observer also checks the gateway's bearer JWT on every call against a pinned Ed25519 key, and logs the result. On `Describe`, it refuses a peer that fails that check.

### Receipt

Example, with values shortened:

```json
{
  "payload": {
    "type": "emilia.openshell.draft-chunk-approval.v1",
    "decision": "approve",
    "workspace": "default",
    "sandbox": "oar-a",
    "chunk_id": "6290ac3b-d80a-425d-b867-bfedcbed788b",
    "review_token": "8f53c911...",
    "rule_name": "allow_example_com_443",
    "rule_digest": "sha256:2609103399b89bf8...",
    "candidate_effective_policy_hash": "a324c73a...",
    "approver_kid": "IAKTkwEETgEvQo2o...",
    "issued_at": "2026-09-29T07:27:04.100Z",
    "nonce": "..."
  },
  "proof": { "format": "es256", "public_key_spki": "...", "signature": "..." }
}
```

- The approval digest is `D = SHA-256(JCS(payload))`. JCS is RFC 8785, via `canonicalizeStrictJson` from `@emilia-protocol/verify`.
- **`es256`**: ECDSA P-256 over `JCS(payload)`, which is ECDSA over D. The signature is raw `r||s`, base64url encoded.
- **`webauthn`**: a WebAuthn assertion whose `clientDataJSON.challenge` is `base64url(D)`. It is checked by `verifyWebAuthnSignoff` from `@emilia-protocol/verify`, which also requires the user-present and user-verified flags. The proof carries `authenticator_data`, `client_data_json` and a DER `signature`.
- **`approver_kid`** is `base64url(SHA-256(SPKI DER))` of the signing key. It is inside the signed payload.

**Canonical rule text.** The canonical form is the proto3 JSON of `openshell.sandbox.v1.NetworkPolicyRule`:

- original proto field names (either JSON spelling is accepted on input);
- enum values as names;
- fields that carry no presence left out when they hold their default value.

Anything outside the message schema is refused, not dropped. When the observer or the signer reads a rule from the gateway, it also checks that the decoded rule re-encodes to the same number of bytes. A rule carrying fields this build does not model is refused, rather than digested without them.

**Stale review tokens.** A review token goes stale when another approval changes the sandbox's effective policy. The gateway then refuses the approval with `proposal inputs changed; evaluation refreshed, refetch and review again`, and the approver signs again over the refreshed token. A receipt over a stale token never verifies against the commit. If a fresh receipt exists, the stale one is ignored. If not, the check reports `receipt_token_mismatch`.

### Check findings

| Code | Meaning |
|---|---|
| `approval_without_receipt` | A committed approval has no receipt for its chunk. |
| `receipt_bad_signature` | The proof does not verify, or the key is not the one the payload names. |
| `receipt_token_mismatch` | The receipt signs a different review token than the one that committed (stale or another review). |
| `receipt_rule_mismatch` | The rule digest or rule name differs from the committed rule. |
| `receipt_scope_mismatch` | The workspace or sandbox differs. |
| `receipt_issued_after_commit` | `issued_at` is later than the commit plus the allowed skew. |
| `rule_not_observed` | The observer has no gateway read for this commit, so the committed rule text was never read back from the gateway. |
| `receipt_key_not_accepted` | Verified, but the key is not pinned, or not pinned for this workspace or relying party. |
| `receipt_without_committed_approval` | The receipt names a chunk that no observed commit approved. |
| `commit_without_validate`, `ambiguous_pairing`, `commit_inconsistent_with_gateway_read`, `commit_not_confirmed_by_gateway_read`, `bulk_chunks_unresolved`, `bulk_approval_without_named_chunks` | A commit could not be attributed to exactly one reviewed request. |
| `approval_not_observed` | The gateway logged a human approval at a version the observer has no commit for, for example while the observer was down. |
| `policy_change_without_approval` | A version came from an operator policy merge (`openshell policy update`). |
| `unexplained_policy_change` | A version changed the policy with no approval and no gateway log line, for example `openshell policy set`. |
| `commit_not_in_chain`, `chain_gap`, `chain_revision_invalid` | The chain does not contain a commit, skips versions, or has an invalid revision. |
| `observation_auth_failed`, `observer_without_gateway_key` | A record failed the gateway JWT check (it is ignored), or the observer ran without a pinned gateway key. |
| `log_malformed_line`, `log_chain_broken`, `malformed_observation`, `malformed_receipt`, `malformed_pins`, `malformed_chain`, `gateway_log_unparsed` | Input that does not parse. Each carries a reason, and the rest of the input is still checked. |

`result` is `pass` when there are no findings and every sandbox with an approval has a policy chain. It is `fail` when there are findings. It is `incomplete` when there are no findings but a policy chain is missing.

The check never throws on bad input. The test suite includes a 400-iteration mutation fuzz over every input.

## Run it

Requires Node.js 24 or later. From this directory:

```sh
npm ci
```

**1. Observer.** Register it in the gateway's TOML config. Registration is by config file only, and it needs a gateway restart.

```toml
[openshell.gateway.gateway_jwt]            # so every call carries a verifiable bearer JWT
signing_key_path = "/path/jwt/signing.pem"
public_key_path  = "/path/jwt/public.pem"
kid_path         = "/path/jwt/kid"
gateway_id       = "gw1"

[[openshell.gateway.interceptors]]
name = "emilia-observer"
grpc_endpoint = "unix:///run/emilia/obs.sock"
failure_policy = "fail_open"
binding_policy = "allowlist"
timeout = "500ms"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ApproveDraftChunk"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ApproveAllDraftChunks"
phases = ["validate", "post_commit"]
```

Start the observer before the gateway. The gateway refuses to start if the interceptor is unreachable, even with `fail_open`. The observer needs its own gateway credential for the post-commit reads: scopes `config:read` and `sandbox:read`, workspace role `user`.

```sh
node src/cli.ts observe --listen unix:///run/emilia/obs.sock --log observer.jsonl \
  --gateway-public-key /path/jwt/public.pem --gateway-id gw1 \
  --gateway http://127.0.0.1:8080 [--gateway-token-file token]
```

**2. Approver (demo key).**

```sh
node src/cli.ts keygen --out approver.key.pem        # prints {kid, public_key_spki}
node src/cli.ts sign --key approver.key.pem --gateway http://127.0.0.1:8080 \
  --workspace default --sandbox my-sandbox --chunk-id <id> --out receipt.json
```

`sign` prints the rule it is about to approve and asks before signing (`--yes` skips the prompt). It can also read a `GetDraftPolicy` export with `--draft-json` instead of calling the gateway. Then approve in OpenShell as usual, for example `openshell rule approve my-sandbox --chunk-id <id>`.

**3. Reader's pins.**

```json
{
  "format": "emilia.openshell.approver-pins.v1",
  "approvers": [
    { "label": "alice", "public_key_spki": "<base64url SPKI>", "workspaces": ["default"],
      "webauthn": { "rp_id": "approve.example.com", "origins": ["https://approve.example.com"] } }
  ]
}
```

**4. Check.**

```sh
node src/cli.ts chain --gateway http://127.0.0.1:8080 --workspace default --sandbox my-sandbox --out chain.json
node src/cli.ts check --log observer.jsonl --pins pins.json --receipts receipt.json \
  --chain chain.json --gateway-log gateway.log
```

The gateway log is optional. Without it, auto-approvals and operator merges show up as `unexplained_policy_change`. Only lines that carry `sandbox_id=` are used, as the gateway writes them to its own output; a line without one cannot be attributed to a sandbox and is counted instead.

Exit codes: 0 pass, 1 findings, 3 incomplete, 2 refused input.

## Tested against

**Contract.** OpenShell `main` at [`9cb72baa2e61a1b5f12407e6e82da7fdba0aa722`](https://github.com/NVIDIA/OpenShell/commit/9cb72baa2e61a1b5f12407e6e82da7fdba0aa722) (2026-09-29).

- The protos in `proto/` are unmodified copies from that commit.
- Their SHA-256 digests are pinned in `proto/UPSTREAM.json` and checked by the test suite.

**Unit and contract tests.** `npm test` runs 55 tests on Node 24 and 26. They cover:

- canonicalization and the pinned rule digest;
- the wire-size check;
- Struct decoding;
- the gateway JWT;
- the gateway log parser;
- ES256 and WebAuthn receipts;
- every finding;
- hostile input, including the fuzz;
- the observer over real gRPC on a unix socket, against a stand-in OpenShell API;
- the CLI.

**Live end to end.** `e2e/live-gateway.node-test.ts` runs against a real OpenShell gateway. Setup:

- the official `dev` release binaries, `0.1.3-dev.14+g2fe5a0e19`. That build is one commit behind the contract commit, and the one commit only changes the Docker driver's proxy CA handling;
- macOS arm64 with Docker Desktop and SQLite;
- the local-dev (unauthenticated) caller;
- the interceptor on `unix://` with the gateway JWT.

Run it with:

```sh
OPENSHELL_BIN_DIR=/path/to/openshell-binaries E2E_WORK_DIR=/tmp/oar-e2e npm run test:e2e
```

The test drives real denied connections into draft chunks and approves them with the official `openshell` CLI, then asserts the reports below. From the run recorded for this commit; the summary lines are as printed, the finding and chain lines are shortened and annotated:

```
report-a.json: result=pass summary={"committed_approvals":3,"verified":3,"accepted":3,"auto_approvals":0,"receipts_read":3,"findings":0,"policy_transitions_checked":2}
    chain oar-a v2 receipted_human_approval        (openshell rule approve)
    chain oar-a v3 receipted_human_approval        (openshell rule approve-all, two chunks)
report-full.json: result=fail summary={"committed_approvals":6,"verified":4,"accepted":3,"auto_approvals":1,"receipts_read":6,"findings":7,"policy_transitions_checked":9}
    receipt_key_not_accepted            receipt signed by an unpinned key (verified, not accepted)
    approval_without_receipt            approved with no receipt
    receipt_token_mismatch              receipt signed before an intervening approval made its token stale
    receipt_without_committed_approval  receipt for the approval made while the observer was stopped
    approval_not_observed               that approval, found through the chain and the gateway log
    policy_change_without_approval      openshell policy update --add-endpoint example.edu:443
    unexplained_policy_change           openshell policy set
    chain oar-c v2 auto_approval        sandbox created with --approval-mode auto
```

The live run also exercised these paths:

- The retry after a stale token went to the right request: two `validate` calls for the same chunk with different tokens were told apart by the read-back token.
- The only gRPC metadata the gateway sent with each evaluation was `authorization` (its bearer JWT, verified on every call) and `user-agent`.
- The observer's rule digest for `allow_www_w3_org_443`, computed from gateway wire bytes, equals the digest pinned in the unit tests.
- When the observer was stopped, the gateway logged `gateway interceptor failed open ... transport error` and committed the approval. The chain check then reported it.

**Not tested.**

- OIDC or mTLS caller principals, and the observer's own gateway reads with a bearer token (`--gateway-token-file`).
- An `https://` interceptor endpoint. `observe --tls-cert/--tls-key` exists but was not run against a gateway.
- Sandboxes with provider layers, where the committed `policy_hash` and `candidate_effective_policy_hash` can differ.
- Linux or the Kubernetes driver.
- A real passkey. The WebAuthn path is tested with assertions synthesized in the authenticator format from a software P-256 key.

## Files

| Path | What it is |
|---|---|
| `src/observer.ts` | the gateway interceptor (gRPC server) |
| `src/gateway-client.ts` | gateway reads, and the wire-size check on rules |
| `src/receipt.ts` | payload, ES256 signing, and ES256 and WebAuthn verification |
| `src/check.ts` | the offline check |
| `src/canonical.ts` | JCS and the canonical rule form |
| `src/gateway-jwt.ts` | gateway bearer JWT verification |
| `src/gateway-log.ts` | `CONFIG:*` line parser |
| `src/log.ts` | the append-only, hash-chained log |
| `src/cli.ts` | `observe`, `keygen`, `pubkey`, `drafts`, `sign`, `chain`, `check` |
| `proto/` | unmodified OpenShell protos (see `NOTICE`) |
| `test/` | unit and contract tests (`npm test`) |
| `e2e/` | the live-gateway test (`npm run test:e2e`) |

## License

Apache-2.0. The files in `proto/` are NVIDIA's, under Apache-2.0, copied without modification. See `NOTICE`.
