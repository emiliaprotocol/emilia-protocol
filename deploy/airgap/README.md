# EMILIA Protocol — Air-Gapped Deployment

A self-contained bundle that installs and runs EP on an **isolated host with no
internet access** — the deployment shape government and defense buyers require.
Build the bundle once on a connected machine, transfer a single tarball, install
on the isolated host. Nothing is pulled at install time, and the running stack
has no route off the host.

```
connected build machine                 isolated host (no network)
─────────────────────────               ──────────────────────────
bundle.sh                               install.sh
  docker build (app)                      docker load images.tar
  docker pull (db, rest)                  apply migrations
  docker save → images.tar                docker compose up  (internal network)
  tar → ep-airgap-<ver>.tar.gz   ──USB──▶ verify.sh  (health + offline verify + no-egress)
```

## What's in the bundle

| File | Purpose |
|---|---|
| `images.tar` | the EP app image + Postgres + PostgREST (`docker save`) |
| `docker-compose.airgap.yml` | the stack on an `internal: true` network (no egress) |
| `migrations/*.sql` | the EP schema, applied at install |
| `install.sh` | offline install + bring-up |
| `verify.sh` | post-install smoke: health, offline verification, **proves no egress** |
| `verify-offline.sh` | EP receipts verify with zero network (the core property) |
| `.env.airgap.example` | secrets template |

## Build (connected machine)

```bash
deploy/airgap/bundle.sh            # → dist/ep-airgap-<version>.tar.gz (+ .sha256)
```

This is the only step that touches the network (to fetch base + dependency
images). Verify the checksum, then transfer the tarball to the isolated host.

### Generate keys

On the connected machine, mint the self-host secrets:

```bash
SUPABASE_JWT_SECRET=$(openssl rand -hex 32)
# Service-role + anon JWTs signed with that secret (HS256), role claim set
# accordingly — see scripts/airgap-keys.mjs for a generator, or your KMS.
```

## Install (isolated host)

```bash
tar xzf ep-airgap-<version>.tar.gz && cd ep-airgap-<version>
cp .env.airgap.example .env.airgap     # fill in — install.sh refuses CHANGE_ME
./install.sh                            # load → migrate → up → verify
```

EP comes up on `http://127.0.0.1:8080` (loopback only). Put your own
reverse proxy / mTLS in front per your enclave's policy.

## The air-gap guarantee

The `epnet` network is `internal: true`: Docker gives the containers **no route
off the host**. `verify.sh` proves it by attempting an outbound connection from
inside the app container and asserting it fails. EP's value still holds with no
network — receipts, Merkle anchors, and Class-A signoffs verify with pure crypto
(`verify-offline.sh`).

## What is tested, and where

- **Statically (CI, no Docker):** `deploy/airgap/audit.sh` asserts the network
  is internal, every image is built/vendored (no surprise pulls), `install.sh`
  performs no network fetch, and the offline-verification inputs are present.
- **Offline core (anywhere):** `deploy/airgap/verify-offline.sh` proves EP
  receipt verification runs with zero network.
- **Full no-egress run (Docker host):** `verify.sh` runs on install and proves
  health + no egress on the actual stack.

> **Boundary — honest:** this artifact is built and statically validated, and its
> offline-verification core is proven anywhere. The full containerized no-egress
> run executes on a Docker-capable host (the operator's, or a CI runner via
> `workflow_dispatch`); it has not been run on a specific agency's
> certified-isolated hardware — that is the deployment step performed with the
> agency during onboarding. Everything that step needs is in this bundle.
