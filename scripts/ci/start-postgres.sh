#!/usr/bin/env bash
# Starts the Postgres container a CI job tests against.
#
# Shared GitHub runners exhaust each public registry's anonymous pull
# allowance at different times: Docker Hub's rate limit, then ECR Public's
# "Data limit exceeded". A service container names one registry, so the job
# failed whenever that registry refused. This pulls the same official image
# from three registries, in order, and fails only when all three refuse.
#
# Inputs (environment):
#   PG_PASSWORD  required
#   PG_DB        required
#   PG_USER      default postgres
#   PG_PORT      host port, default 5432
#   PG_TAG       image tag, default 17-alpine
set -euo pipefail

: "${PG_PASSWORD:?PG_PASSWORD is required}"
: "${PG_DB:?PG_DB is required}"
user="${PG_USER:-postgres}"
port="${PG_PORT:-5432}"
tag="${PG_TAG:-17-alpine}"

image=""
for candidate in \
  "public.ecr.aws/docker/library/postgres:${tag}" \
  "mirror.gcr.io/library/postgres:${tag}" \
  "docker.io/library/postgres:${tag}"; do
  for attempt in 1 2 3; do
    if docker pull --quiet "$candidate"; then
      image="$candidate"
      break 2
    fi
    echo "::warning::pull of ${candidate} failed (attempt ${attempt})"
    sleep $((attempt * 5))
  done
done
if [ -z "$image" ]; then
  echo "::error::postgres:${tag} could not be pulled from any registry"
  exit 1
fi

docker run --detach --name ci-postgres \
  -e POSTGRES_USER="$user" \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" \
  -e POSTGRES_DB="$PG_DB" \
  -p "${port}:5432" \
  "$image" >/dev/null

# The entrypoint's init server listens on the Unix socket only, so a TCP
# probe succeeds only once the final server is up.
for _ in $(seq 1 60); do
  if docker exec ci-postgres pg_isready -h 127.0.0.1 -U "$user" -d "$PG_DB" >/dev/null 2>&1; then
    echo "postgres ready on port ${port} (${image})"
    exit 0
  fi
  sleep 2
done
docker logs ci-postgres
echo "::error::postgres did not become ready"
exit 1
