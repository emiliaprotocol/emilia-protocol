# OpenShell approver receipts

Signed evidence of who approved each network-rule change in an [OpenShell](https://github.com/NVIDIA/OpenShell) sandbox, and an offline check that every committed change has that evidence.

It is built on OpenShell's public gateway-interceptor contract (`openshell.gateway_interceptor.v1`). It is not part of OpenShell and is not affiliated with NVIDIA.

It has three parts:

1. **An observe-mode gateway interceptor.** It sees the gateway approve draft chunks, the proposed network rules a sandbox asks for. It writes each committed approval to an append-only, hash-chained local log. It always answers `allowed`. It never denies and never modifies anything.
2. **An approver receipt.** The approver signs one specific approval with an ES256 key: the workspace, the sandbox, the chunk id, the gateway's review token for that exact candidate, and a SHA-256 digest of the canonical rule text. A passkey (WebAuthn) can produce the signature. For the demo, a small CLI signs with a local key file.
3. **An offline check.** It takes the log, the receipts and the reader's pinned approver keys, and reports `verified` and `accepted` as separate fields for every committed approval. It also lists findings, and it checks completeness against the policy version chain of every sandbox in the workspace.

## What it proves, and what it does not

For each committed draft-chunk approval, a passing check shows:

- **`verified`**: a receipt's ES256 proof checks out, and the receipt names exactly the approval the gateway committed. That means the same workspace, sandbox, chunk id and review token, and the same rule name and rule-text digest that the observer read back from the gateway after the commit. The receipt must also be issued no later than the commit, plus a skew allowance.
- **`accepted`**: the receipt is `verified`, and the signing key is one the reader pinned as an approver key for that workspace and for the proof's format. A WebAuthn proof is accepted only under a pin that names the relying party, and the assertion must be scoped to it: its `rpIdHash`, an allowed origin, and not `crossOrigin`.
- **Completeness**: every sandbox in the workspace inventory has a policy chain, and every version in each chain is classified. These are reported as what they are:
  - a receipted human approval;
  - a gateway auto-approval, which is its own category and not a missing receipt;
  - a removal the gateway logged;
  - a revision that did not change the policy.

  Every other version is a finding. Auto-approvals and removals are known only from the gateway log (see below), so they count toward `pass` only when the reader says they trust that log.

So a passing check says: a holder of a pinned approver key approved this exact rule, in this exact sandbox, with a receipt dated no later than the commit (within the configured clock skew). Whether the operator can reach that key depends on where the key lives. With a passkey on the approver's device, the operator does not hold it. With the demo key file, whoever has the file does. The check cannot tell the two apart. The reader's pin list is where that decision is made.

It does not:

- **approve or block anything.** The interceptor is observe-only and every binding is `fail_open`. If it is down or slow, approvals still commit. The chain check then reports them.
- **cover individual business actions** an agent takes inside a sandbox. It covers infrastructure permission changes: draft-chunk (network rule) approvals.
- **turn operator policy writes into approvals.** `openshell policy set` and `openshell policy update` change policy without any approval. The check lists them as findings.
- **treat the gateway's caller identity as an approver.** Every evaluation carries a gateway-asserted `principal` map. It is unsigned. The report shows it as context, and it never satisfies `verified` or `accepted`.
- **recompute OpenShell's own hashes or review tokens.** The review token covers credential metadata a third party cannot see. The token is compared as an opaque value, and `candidate_effective_policy_hash` is carried for display only.
- **make the observer log tamper-proof.** The hash chain detects an edited, reordered or dropped line in the middle of the log. It does not stop whoever controls the file from rewriting all of it or cutting off its tail. The policy chain check covers missing commits, because the gateway, not the observer, holds that chain.
- **authenticate the gateway log.** Auto-approvals, removals and operator merges are classified from the gateway's own output, which is plain text that whoever runs the gateway can edit. One appended line can turn an `openshell policy set` into an "auto-approval" or a "removal", and deleting lines hides events. The report marks every version classified from a log line with `basis: "gateway_log"`. `auto_approval` and `removal` count toward `pass` only with `--trust-gateway-log`; without it the result is `incomplete`. A reader who does not trust the operator should read them as the operator's assertion.
- **vouch for the policy chain or inventory files.** Supply them from your own `chain --all` read of the gateway. The check finds versions missing between the ones a chain lists, but a chain cut short at the end hides later versions unless the gateway log shows them (`chain_stale`). `completeness.chain_heads` shows the newest version each chain holds and when it was read.
- **cover deleted sandboxes.** The inventory is `ListSandboxes` at read time. A sandbox deleted before that read is not in it, and neither is its policy.

## How it works

### Observer

OpenShell calls an interceptor in two phases that matter here, and neither is enough alone:

- **`validate`** carries the prepared operation after any interceptor patches, which names the chunk and the review token: `{chunkId, reviewToken, sandbox, workspaceScope}`, plus `requestId` when the client sets one. (`modify_operation` sees the operation before those patches; this observer does not bind it.)
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

**Stale review tokens.** The gateway computes a review token over, among other inputs, the hash of the sandbox's effective policy when it evaluated the chunk, and `GetDraftPolicy` returns the stored token without evaluating it again. So once another approval changes the sandbox's policy, every chunk that was already pending holds a token computed over the old policy. That is the normal case when an agent hits several denials at once. The gateway refuses an approval with a dead token (`proposal inputs changed; evaluation refreshed, refetch and review again`) and stores a fresh one. `sign` checks for this before signing (see [Run it](#run-it)). A receipt over a stale token never verifies against the commit. If a fresh receipt exists, the stale one is ignored. If not, the check reports `receipt_token_mismatch`.

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
| `receipt_key_not_accepted` | Verified, but the key is not pinned, or not pinned for this workspace or proof format, or a WebAuthn proof has no relying-party pin or does not match it. |
| `receipt_without_committed_approval` | The receipt names a chunk that no observed commit approved. |
| `commit_without_validate`, `ambiguous_pairing`, `commit_inconsistent_with_gateway_read`, `commit_not_confirmed_by_gateway_read`, `bulk_chunks_unresolved`, `bulk_approval_without_named_chunks` | A commit could not be attributed to exactly one reviewed request. |
| `approval_not_observed` | The gateway logged a human approval at a version the observer has no commit for, for example while the observer was down. |
| `policy_change_without_approval` | A version came from an operator policy merge (`openshell policy update`). |
| `unexplained_policy_change` | A version changed the policy with no approval and no gateway log line, for example `openshell policy set`. |
| `commit_not_in_chain`, `chain_gap`, `chain_revision_invalid` | The chain does not contain a commit, skips versions, or has an invalid revision. |
| `gateway_event_without_chain` | The gateway log records a human approval, merge or removal in a sandbox for which no policy chain was supplied. |
| `chain_stale`, `gateway_event_not_in_chain` | The gateway log records a version past the end of the supplied chain, or a version the chain holds with a different hash. |
| `gateway_log_unattributed` | A gateway log line records a policy version but carries no `sandbox_id`. |
| `observation_auth_failed`, `observer_without_gateway_key` | A record failed the gateway JWT check (it is ignored), or the observer ran without a pinned gateway key. |
| `log_malformed_line`, `log_chain_broken`, `malformed_observation`, `malformed_receipt`, `malformed_pins`, `malformed_chain`, `malformed_inventory`, `gateway_log_unparsed` | Input that does not parse. Each carries a reason, and the rest of the input is still checked. |

`result` is `fail` when there are findings. It is `pass` when there are none and all of these hold:

- every workspace checked has a sandbox inventory;
- every sandbox in an inventory, and every sandbox the observer log or the gateway log shows activity in, has a policy chain;
- no version is explained only by the gateway log, unless the reader passes `--trust-gateway-log`.

Otherwise it is `incomplete`, and `completeness.reason` says why.

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
openshell rule approve my-sandbox --chunk-id <id>
```

`sign` prints what the receipt will cover and asks before signing (`--yes` skips the prompt): the rule name, the canonical rule text, its digest, the review token, and its own checks of the rule text (wildcard hosts, `allow_uninspected_credentials`, `allowed_ips`, credential bindings, any-binary rules). With `--gateway` it also shows OpenShell's security notes, marked as not covered by the receipt. Every string is shown with control and bidi characters escaped.

`sign` also refuses a review token the gateway will not accept. It compares the chunk's `current_effective_policy_hash` with the hash of the sandbox's newest policy version. When they differ, another approval has made the token stale since the chunk was proposed. Then:

1. run `openshell rule approve my-sandbox --chunk-id <id>` once. The gateway refuses it and refreshes the token;
2. run `sign` again;
3. run `openshell rule approve my-sandbox --chunk-id <id>` again. It commits under the token the receipt signs.

In a sandbox with provider layers the two hashes can differ even when the token is current, and step 1 would then commit. There `sign` refuses and says so; `--allow-policy-hash-mismatch` signs anyway, with a warning.

`sign --draft-json` reads a `GetDraftPolicy` export instead of calling the gateway, for an approver with no gateway access. It cannot check token freshness, and it does not show the export's `security_notes`: the receipt does not cover them, and whoever produced the file chose them.

**3. Reader's pins.**

```json
{
  "format": "emilia.openshell.approver-pins.v1",
  "approvers": [
    { "label": "alice (passkey)", "public_key_spki": "<base64url SPKI>", "workspaces": ["default"],
      "webauthn": { "rp_id": "approve.example.com", "origins": ["https://approve.example.com"] } },
    { "label": "bob (demo key file)", "public_key_spki": "<base64url SPKI>", "workspaces": ["default"] }
  ]
}
```

A pin with a `webauthn` block accepts only WebAuthn proofs scoped to that relying party. A pin without one accepts only `es256` proofs. `"formats": ["es256", "webauthn"]` widens a pin to both; `webauthn` in `formats` needs the `webauthn` block.

**4. Check.**

```sh
node src/cli.ts chain --gateway http://127.0.0.1:8080 --workspace default --all --out-dir chains
node src/cli.ts check --log observer.jsonl --pins pins.json --receipts receipt.json \
  --chains-dir chains --gateway-log gateway.log [--trust-gateway-log]
```

`chain --all` reads the workspace's sandbox list (`ListSandboxes`) into `inventory.json`, then each sandbox's policy versions into `chain-<sandbox>.json`, and `check --chains-dir` reads both back. `chain --sandbox <name> --out chain.json` exports one sandbox, and `check` also takes `--chain` and `--inventory` files one at a time.

The gateway log is optional. Without it, auto-approvals and operator merges show up as `unexplained_policy_change`. Only lines that carry `sandbox_id=` are used, as the gateway writes them to its own output. A line that records a policy version without one cannot be attributed to a sandbox and is reported as `gateway_log_unattributed`. A line over 64 KiB is not parsed and is reported as `gateway_log_unparsed`.

Exit codes: 0 pass, 1 findings, 3 incomplete, 2 refused input.

## Tested against

**Contract.** OpenShell `main` at [`9cb72baa2e61a1b5f12407e6e82da7fdba0aa722`](https://github.com/NVIDIA/OpenShell/commit/9cb72baa2e61a1b5f12407e6e82da7fdba0aa722) (2026-09-29).

- The protos in `proto/` are unmodified copies from that commit.
- Their SHA-256 digests are pinned in `proto/UPSTREAM.json` and checked by the test suite.

**Unit and contract tests.** `npm test` runs 65 tests on Node 24 and 26. They cover:

- canonicalization and the pinned rule digest;
- the wire-size check;
- Struct decoding;
- the gateway JWT;
- the gateway log parser, including linear-time parsing of hostile lines;
- ES256 and WebAuthn receipts, and WebAuthn acceptance only under a relying-party pin;
- every finding;
- hostile input, including the fuzz;
- the observer over real gRPC on a unix socket, against a stand-in OpenShell API;
- the CLI, including `sign`'s token-freshness refusal and `chain --all` against a stand-in OpenShell API, and a prompt that shows no terminal control or bidi characters.

**Live end to end.** `e2e/live-gateway.node-test.ts` runs against a real OpenShell gateway. Setup:

- the official `dev` release binaries, `0.1.3-dev.14+g2fe5a0e19`. That build is one commit behind the contract commit, and the one commit only changes the Docker driver's proxy CA handling;
- macOS arm64 with Docker Desktop and SQLite;
- the local-dev (unauthenticated) caller;
- the interceptor on `unix://` with the gateway JWT.

Run it with:

```sh
OPENSHELL_BIN_DIR=/path/to/openshell-binaries E2E_WORK_DIR=/tmp/oar-e2e npm run test:e2e
```

The test drives real denied connections into draft chunks and approves them with the official `openshell` CLI, then asserts the reports below. The inventories and chains come from `chain --all`. From the run recorded for this commit; the summary lines are as printed, the finding and chain lines are shortened and annotated:

```
report-a.json: result=pass summary={"committed_approvals":5,"verified":5,"accepted":5,"auto_approvals":0,"receipts_read":5,"findings":0,"policy_transitions_checked":4}
    chain oar-a v2 receipted_human_approval        (openshell rule approve)
    chain oar-a v3 receipted_human_approval        (openshell rule approve-all, two chunks)
    chain oar-a v4 receipted_human_approval        (signed with `sign`, then approved)
    chain oar-a v5 receipted_human_approval        (`sign` refused the stale token; one refused approve refreshed it; signed again, approved)
report-full.json: result=fail summary={"committed_approvals":8,"verified":6,"accepted":5,"auto_approvals":1,"receipts_read":8,"findings":7,"policy_transitions_checked":11}
    receipt_key_not_accepted            receipt signed by an unpinned key (verified, not accepted)
    approval_without_receipt            approved with no receipt
    receipt_token_mismatch              receipt over a token an earlier approval had already made stale
                                        (`sign` refused it; the test signed it through the library)
    receipt_without_committed_approval  receipt for the approval made while the observer was stopped
    approval_not_observed               that approval, found through the chain and the gateway log
    policy_change_without_approval      openshell policy update --add-endpoint example.edu:443
    unexplained_policy_change           openshell policy set
    chain oar-c v2 auto_approval        sandbox created with --approval-mode auto (basis gateway_log)
```

The live run also exercised these paths:

- `sign` against the live gateway: it refused two chunks whose tokens an earlier approval had made stale (`predates policy v4`, `predates policy v2`). For the first, one `openshell rule approve` was refused with `proposal inputs changed`, `sign` then succeeded, and the approval committed under the signed token.
- `check --chains-dir` over the `chain --all` output returned exit code 0 for scenario A.
- The retry after a stale token went to the right request: two `validate` calls for the same chunk with different tokens were told apart by the read-back token.
- The only gRPC metadata the gateway sent with each evaluation was `authorization` (its bearer JWT, verified on every call) and `user-agent`.
- The observer's rule digest for `allow_www_w3_org_443`, computed from gateway wire bytes, equals the digest pinned in the unit tests.
- When the observer was stopped, the gateway logged `gateway interceptor failed open ... transport error` and committed the approval. The chain check then reported it.

**Not tested.**

- OIDC or mTLS caller principals, and the observer's own gateway reads with a bearer token (`--gateway-token-file`).
- An `https://` interceptor endpoint. `observe --tls-cert/--tls-key` exists but was not run against a gateway.
- Sandboxes with provider layers, where the committed `policy_hash` and `candidate_effective_policy_hash` can differ, and where `sign` cannot tell a stale token from a current one (`--allow-policy-hash-mismatch`).
- Linux or the Kubernetes driver.
- A real passkey. The WebAuthn path is tested with assertions synthesized in the authenticator format from a software P-256 key.

## Files

| Path | What it is |
|---|---|
| `src/observer.ts` | the gateway interceptor (gRPC server) |
| `src/gateway-client.ts` | gateway reads, and the wire-size check on rules |
| `src/receipt.ts` | payload, ES256 signing, and ES256 and WebAuthn verification |
| `src/display.ts` | what `sign` shows (escaped), its rule checks and token-freshness check |
| `src/check.ts` | the offline check |
| `src/canonical.ts` | JCS and the canonical rule form |
| `src/gateway-jwt.ts` | gateway bearer JWT verification |
| `src/gateway-log.ts` | `CONFIG:*` line parser |
| `src/log.ts` | the append-only, hash-chained log |
| `src/cli.ts` | `observe`, `keygen`, `pubkey`, `drafts`, `sign`, `chain`, `check` |
| `proto/` | unmodified OpenShell protos (see `NOTICE`) |
| `test/` | unit and contract tests (`npm test`) |
| `e2e/` | the live-gateway test (`npm run test:e2e`) |
| `*.js` next to a `.ts` | generated by the repository's `scripts/build-standalone-runtimes.mjs`; do not edit them. Edit and run the `.ts` files. |

## License

Apache-2.0. The files in `proto/` are NVIDIA's, under Apache-2.0, copied without modification. See `NOTICE`.
