# EP Witness: deploy kit

Everything needed to stand up **multiple** EP witness cosigners and to prove the
security property they exist for: making log **equivocation** (a split view)
detectable to strangers.

`witness/` ships the reference EMITTER (`server.mjs`) and the verifier-side
checks live in `@emilia-protocol/verify` (`witness.js`: `verifyWitnessCosignature`,
`requireWitnessQuorum`). What was missing, audit **GAP 3**, is (a) more than one
operator actually running, and (b) the **cross-view gossip** that turns k local
cosignatures into equivocation detection. This kit supplies both: a local 3-operator
testnet, the gossip detector, a real end-to-end test, and the config +
staging plan to stand up three *genuinely independent* operators.

## Files

| File | What it is |
|---|---|
| `equivocation-demo.mjs` | **The verifiable core.** Narrated run: 3 live witnesses, honest quorum, then a simulated split view that gossip detects. `node witness/deploy/equivocation-demo.mjs` |
| `equivocation.node-test.mjs` | Same mechanism as `node:test` assertions (CI-wireable via `node --test`). |
| `detect-equivocation.mjs` | The **gossip** half: `detectEquivocation(views, pinnedWitnessKeys, k)`, compares independently-collected views and flags one `(log_key_id, tree_size)` carrying two quorum-backed roots. Library + CLI. |
| `gen-operator-keys.mjs` | Generate N operator key sets + `pinned-witnesses.json` (the `pinnedWitnessKeys` array). |
| `docker-compose.yml` | 3 local witnesses (op1/op2/op3) on ports 8801-8803 for **testing** the wire protocol. Not a production topology. |
| `operator.env.template` | Per-operator config for a **real, independent** deployment (distinct cloud/region/admin). |
| `STAGING.md` | Cost to stand up 3 independent operators, candidate partner types, and a **DRAFT** (unsent) partner-outreach message. |

## The 60-second proof (no Docker needed)

```sh
node witness/deploy/equivocation-demo.mjs
```

Runs three real witness HTTP servers in-process and shows:

1. **honest**, one head at a tree_size, all 3 witnesses cosign, `requireWitnessQuorum(k=2)` accepts;
2. **split view**, the log commits two different roots at the SAME tree_size; each verifier accepts its own head and, alone, detects nothing;
3. **gossip**, `detectEquivocation` compares the two views and flags the conflict, naming the witness that straddled both heads;
4. **control**, two views of the same honest head raise no false positive.

## The wire protocol, over Docker (optional)

```sh
node witness/deploy/gen-operator-keys.mjs                    # -> keys/op{1,2,3} + pinned-witnesses.json
docker compose -f witness/deploy/docker-compose.yml up --build
curl -s localhost:8801/cosign -H 'content-type: application/json' \
  -d '{"tree_size":1,"root_hash":"sha256:aa","log_key_id":"ep:log:x","merkle_alg":"EP-MERKLE-v2"}'
```

Three witnesses on one host prove the emit/quorum/gossip loop end-to-end. They do
**not** deliver the security property, that needs independence. See `STAGING.md`.

## What is real here, and what is staged

- **Real, run in this kit:** the emit → quorum → gossip loop, over live HTTP witnesses, checked by the real `@emilia-protocol/verify`. `equivocation-demo.mjs` and `equivocation.node-test.mjs` pass.
- **Staged, NOT done:** standing up three *independent* operators (separate clouds/regions/orgs). That costs money and needs partners, the lead's call. `STAGING.md` has the plan, cost, and a draft ask. Nothing is deployed; nothing is sent.
