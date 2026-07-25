#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

export LC_ALL=C
umask 077

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 ]] || die "exactly one operation argument is required"
operation=$1
case "$operation" in
  claim|complete|reconcile) ;;
  *) die "unsupported rollout attempt-store operation" ;;
esac

database_url=${EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL:-}
[[ -n "$database_url" ]] \
  || die "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL is required"
case "$database_url" in
  postgres://*|postgresql://*) ;;
  *) die "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL must be a PostgreSQL URL" ;;
esac
[[ ! "$database_url" =~ [[:space:]] ]] \
  || die "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL contains whitespace"

python_bin=$(command -v python3) || die "python3 is required"
psql_bin=$(command -v psql) || die "psql is required"

temporary_directory=$(mktemp -d \
  "${TMPDIR:-/tmp}/emilia-rollout-attempt-store.XXXXXX") \
  || die "unable to create private temporary directory"
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

input_file="$temporary_directory/input.json"
response_file="$temporary_directory/response.json"
connection_directory="$temporary_directory/connection"
mkdir -m 700 "$connection_directory"
"$python_bin" - "$connection_directory" <<'PY' \
  || die "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL is invalid"
import os
import pathlib
import sys
import urllib.parse

destination = pathlib.Path(sys.argv[1])
value = os.environ["EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL"]
parsed = urllib.parse.urlsplit(value)
if parsed.scheme not in {"postgres", "postgresql"}:
    raise SystemExit("unsupported PostgreSQL URL scheme")
try:
    port = parsed.port
except ValueError as error:
    raise SystemExit(f"invalid PostgreSQL port: {error}")
database = urllib.parse.unquote(parsed.path[1:]) if parsed.path.startswith("/") else ""
components = {
    "host": parsed.hostname or "",
    "port": "" if port is None else str(port),
    "database": database,
    "user": urllib.parse.unquote(parsed.username or ""),
    "password": urllib.parse.unquote(parsed.password or ""),
}
query = urllib.parse.parse_qs(
    parsed.query,
    keep_blank_values=True,
    strict_parsing=True,
)
allowed_query = {
    "sslmode",
    "sslrootcert",
    "connect_timeout",
    "channel_binding",
    "target_session_attrs",
    "application_name",
}
if set(query) - allowed_query or any(len(values) != 1 for values in query.values()):
    raise SystemExit("PostgreSQL URL has unsupported or duplicate query parameters")
components.update({key: values[0] for key, values in query.items()})
for required in ("host", "database", "user", "password"):
    if not components[required]:
        raise SystemExit(f"PostgreSQL URL is missing {required}")
for name, component in components.items():
    if "\x00" in component or any(character.isspace() for character in component):
        raise SystemExit(f"PostgreSQL URL {name} contains forbidden whitespace")
    path = destination / name
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        os.write(descriptor, component.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
tee "$input_file" >/dev/null || die "unable to read operation JSON"
input_size=$(wc -c < "$input_file")
input_size=${input_size//[[:space:]]/}
[[ "$input_size" =~ ^[1-9][0-9]*$ && "$input_size" -le 65536 ]] \
  || die "operation JSON is empty or exceeds 65536 bytes"

validation=$(
  "$python_bin" - "$operation" "$input_file" <<'PY'
import base64
import hashlib
import hmac
import json
import re
import sys

OPERATION, INPUT_PATH = sys.argv[1:]
CLAIM_SCHEMA = "emilia-deployment-attempt-claim.v1"
OPERATION_SCHEMA = "emilia-deployment-attempt-store-operation.v1"
CLAIM_DOMAIN = b"EMILIA-DEPLOYMENT-ATTEMPT-CLAIM-V1\x00"
CLAIM_KEYS = {
    "schema",
    "claim_sha256",
    "authorization_id",
    "rollout_nonce",
    "request_sha256",
    "pre_resource_version",
    "project_id",
    "region",
    "release_id",
    "transition",
    "service",
    "config_sha256",
    "deployer_principal",
    "workflow_ref",
    "workflow_sha",
    "wif_provider",
}
OPERATION_KEYS = {
    "schema",
    "operation",
    "claim",
    "outcome",
    "final_resource_version",
}
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEPLOYER_RE = re.compile(
    r"^serviceAccount:[^@\s,]+@[^@\s,]+[.]iam[.]gserviceaccount[.]com$"
)
WIF_RE = re.compile(
    r"^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/"
    r"[a-z][a-z0-9-]{3,31}/providers/[a-z][a-z0-9-]{3,31}$"
)
WORKFLOW_REF = (
    "emiliaprotocol/emilia-protocol/.github/workflows/"
    "consequence-control-deploy.yml@refs/heads/main"
)
TRANSITIONS = {
    "apply-decision-1",
    "apply-decision-10",
    "apply-decision-50",
    "apply-decision-100",
    "apply-actuator-100",
    "apply-rollback-actuator",
    "apply-rollback-decision",
}


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value):
    fail(f"non-finite JSON number is forbidden: {value}")


def exact_object(value, keys, name):
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{name} must contain exactly the required members")
    return value


def validate_claim(value):
    claim = exact_object(value, CLAIM_KEYS, "claim")
    if not all(isinstance(claim[key], str) for key in CLAIM_KEYS):
        fail("every claim member must be a string")
    if claim["schema"] != CLAIM_SCHEMA:
        fail("claim schema is unsupported")
    for key in ("project_id", "region", "release_id", "service"):
        if NAME_RE.fullmatch(claim[key]) is None:
            fail(f"claim.{key} is invalid")
    if KEY_ID_RE.fullmatch(claim["authorization_id"]) is None:
        fail("claim.authorization_id is invalid")
    if NONCE_RE.fullmatch(claim["rollout_nonce"]) is None:
        fail("claim.rollout_nonce is invalid")
    for key in ("claim_sha256", "request_sha256", "config_sha256"):
        if SHA256_RE.fullmatch(claim[key]) is None:
            fail(f"claim.{key} is invalid")
    if (
        not claim["pre_resource_version"]
        or len(claim["pre_resource_version"].encode()) > 512
        or any(character.isspace() for character in claim["pre_resource_version"])
    ):
        fail("claim.pre_resource_version is invalid")
    if claim["transition"] not in TRANSITIONS:
        fail("claim.transition is unsupported")
    if DEPLOYER_RE.fullmatch(claim["deployer_principal"]) is None:
        fail("claim.deployer_principal is invalid")
    if claim["workflow_ref"] != WORKFLOW_REF:
        fail("claim.workflow_ref is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", claim["workflow_sha"]) is None:
        fail("claim.workflow_sha is invalid")
    if WIF_RE.fullmatch(claim["wif_provider"]) is None:
        fail("claim.wif_provider is invalid")
    key_material = {
        "authorization_id": claim["authorization_id"],
        "rollout_nonce": claim["rollout_nonce"],
        "request_sha256": claim["request_sha256"],
        "pre_resource_version": claim["pre_resource_version"],
    }
    expected_digest = hashlib.sha256(
        CLAIM_DOMAIN
        + json.dumps(
            key_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    if not hmac.compare_digest(
        claim["claim_sha256"].encode(),
        expected_digest.encode(),
    ):
        fail("claim digest does not match the exact claim key")
    return claim


try:
    raw = open(INPUT_PATH, "rb").read()
    text = raw.decode("utf-8")
    value = json.loads(
        text,
        object_pairs_hook=reject_duplicate_members,
        parse_constant=reject_constant,
    )
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"operation JSON is invalid: {error}")

if OPERATION == "claim":
    claim = validate_claim(value)
    expected_status = "claimed"
    expected_final = ""
else:
    envelope = exact_object(value, OPERATION_KEYS, "terminal operation")
    if envelope["schema"] != OPERATION_SCHEMA:
        fail("terminal operation schema is unsupported")
    if envelope["operation"] != OPERATION:
        fail("terminal operation does not match argv")
    claim = validate_claim(envelope["claim"])
    outcome = envelope["outcome"]
    if OPERATION == "complete":
        if outcome != "applied":
            fail("complete outcome must be applied")
        expected_status = "completed"
    elif outcome not in {"applied", "not-applied", "indeterminate"}:
        fail("reconcile outcome is unsupported")
    else:
        expected_status = outcome
    expected_final = envelope["final_resource_version"]
    if (
        not isinstance(expected_final, str)
        or not expected_final
        or len(expected_final.encode()) > 512
        or any(character.isspace() for character in expected_final)
    ):
        fail("terminal final_resource_version is invalid")

print(
    base64.b64encode(raw).decode("ascii"),
    claim["claim_sha256"],
    expected_status,
    base64.b64encode(expected_final.encode()).decode("ascii"),
    sep="\t",
)
PY
) || die "operation JSON failed closed validation"

IFS=$'\t' read -r \
  payload_base64 expected_claim_sha256 expected_status expected_final_base64 \
  <<< "$validation"
[[ -n "$payload_base64" \
    && "$expected_claim_sha256" =~ ^[0-9a-f]{64}$ \
    && -n "$expected_status" ]] \
  || die "operation validation metadata is incomplete"

run_psql() {
  unset \
    PGHOST \
    PGPORT \
    PGDATABASE \
    PGUSER \
    PGPASSWORD \
    PGPASSFILE \
    PGSERVICE \
    PGSERVICEFILE \
    PGOPTIONS \
    PGAPPNAME \
    PSQLRC
  export PGHOST
  PGHOST=$(<"$connection_directory/host")
  export PGDATABASE
  PGDATABASE=$(<"$connection_directory/database")
  export PGUSER
  PGUSER=$(<"$connection_directory/user")
  export PGPASSWORD
  PGPASSWORD=$(<"$connection_directory/password")
  if [[ -s "$connection_directory/port" ]]; then
    export PGPORT
    PGPORT=$(<"$connection_directory/port")
  fi
  local option variable
  while IFS=$'\t' read -r option variable; do
    if [[ -s "$connection_directory/$option" ]]; then
      printf -v "$variable" '%s' "$(<"$connection_directory/$option")"
      export "${variable?}"
    fi
  done <<'EOF'
sslmode	PGSSLMODE
sslrootcert	PGSSLROOTCERT
connect_timeout	PGCONNECT_TIMEOUT
channel_binding	PGCHANNELBINDING
target_session_attrs	PGTARGETSESSIONATTRS
application_name	PGAPPNAME
EOF
  "$psql_bin" \
    -X \
    --set=ON_ERROR_STOP=1 \
    --quiet \
    --no-align \
    --tuples-only
}

if ! {
  printf "\\set payload_b64 '%s'\n" "$payload_base64"
  printf "SELECT rollout_attempt_private.apply_operation('%s', " "$operation"
  printf "pg_catalog.convert_from("
  printf "pg_catalog.decode(:'payload_b64', 'base64'), 'UTF8'));\n"
} | run_psql > "$response_file"
then
  die "PostgreSQL rollout attempt-store operation failed"
fi

"$python_bin" - \
  "$operation" \
  "$expected_claim_sha256" \
  "$expected_status" \
  "$expected_final_base64" \
  "$response_file" <<'PY'
import base64
import hmac
import json
import re
import sys

OPERATION, EXPECTED_CLAIM, EXPECTED_STATUS, FINAL_B64, RESPONSE_PATH = (
    sys.argv[1:]
)
RESPONSE_KEYS = {
    "schema",
    "operation",
    "status",
    "claim_sha256",
    "final_resource_version",
}
RESPONSE_SCHEMA = "emilia-deployment-attempt-store-response.v1"


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate PostgreSQL response member: {key}")
        result[key] = value
    return result


try:
    expected_final = base64.b64decode(FINAL_B64, validate=True).decode()
    raw = open(RESPONSE_PATH, "rb").read()
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicate_members,
        parse_constant=lambda constant: fail(
            f"non-finite PostgreSQL response number: {constant}"
        ),
    )
except (
    OSError,
    UnicodeDecodeError,
    ValueError,
    json.JSONDecodeError,
) as error:
    fail(f"PostgreSQL response is invalid: {error}")

if not isinstance(value, dict) or set(value) != RESPONSE_KEYS:
    fail("PostgreSQL response does not have the exact response shape")
if value["schema"] != RESPONSE_SCHEMA:
    fail("PostgreSQL response schema is unsupported")
if value["operation"] != OPERATION:
    fail("PostgreSQL response operation mismatch")
if value["status"] != EXPECTED_STATUS:
    fail("PostgreSQL response status mismatch")
if (
    not isinstance(value["claim_sha256"], str)
    or re.fullmatch(r"[0-9a-f]{64}", value["claim_sha256"]) is None
    or not hmac.compare_digest(
        value["claim_sha256"].encode(),
        EXPECTED_CLAIM.encode(),
    )
):
    fail("PostgreSQL response claim digest mismatch")
if OPERATION == "claim":
    if value["final_resource_version"] is not None:
        fail("claim response must not contain a final resourceVersion")
elif (
    not isinstance(value["final_resource_version"], str)
    or not hmac.compare_digest(
        value["final_resource_version"].encode(),
        expected_final.encode(),
    )
):
    fail("PostgreSQL response final resourceVersion mismatch")

print(
    json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
)
PY
