# SPDX-License-Identifier: Apache-2.0
"""Focused contract tests for the durable PostgreSQL rollout-attempt store."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
import urllib.parse


LANE = Path(__file__).resolve().parents[1]
REPOSITORY = LANE.parents[1]
ADAPTER = LANE / "postgres-rollout-attempt-store.sh"
MIGRATION = (
    REPOSITORY
    / "supabase"
    / "migrations"
    / "20260725160000_rollout_attempt_store.sql"
)
ROLES = REPOSITORY / "supabase" / "roles.sql"
DATABASE_URL = (
    "postgresql://rollout-attempt-login:secret@127.0.0.1:5432/emilia"
    "?sslmode=disable"
)
CLAIM_DOMAIN = b"EMILIA-DEPLOYMENT-ATTEMPT-CLAIM-V1\x00"


def build_claim() -> dict[str, str]:
    claim = {
        "schema": "emilia-deployment-attempt-claim.v1",
        "authorization_id": "authorization:test-rollout-001",
        "rollout_nonce": "bm9uY2Utcm9sbG91dC01MC0wMDAx",
        "request_sha256": "a" * 64,
        "pre_resource_version": "rv-decision-7",
        "project_id": "test-project",
        "region": "us-central1",
        "release_id": "release-20260725",
        "transition": "apply-decision-50",
        "service": "emilia-consequence-decision",
        "config_sha256": "b" * 64,
        "deployer_principal": (
            "serviceAccount:emilia-deployer@"
            "test-project.iam.gserviceaccount.com"
        ),
        "workflow_ref": (
            "emiliaprotocol/emilia-protocol/.github/workflows/"
            "consequence-control-deploy.yml@refs/heads/main"
        ),
        "workflow_sha": "c" * 40,
        "wif_provider": (
            "projects/123456789/locations/global/workloadIdentityPools/"
            "deploy-pool/providers/github-main"
        ),
    }
    key_material = {
        "authorization_id": claim["authorization_id"],
        "rollout_nonce": claim["rollout_nonce"],
        "request_sha256": claim["request_sha256"],
        "pre_resource_version": claim["pre_resource_version"],
    }
    claim["claim_sha256"] = hashlib.sha256(
        CLAIM_DOMAIN
        + json.dumps(
            key_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    return claim


def encode(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def response(
    operation: str,
    status: str,
    claim_sha256: str,
    final_resource_version: str | None,
) -> dict[str, object]:
    return {
        "schema": "emilia-deployment-attempt-store-response.v1",
        "operation": operation,
        "status": status,
        "claim_sha256": claim_sha256,
        "final_resource_version": final_resource_version,
    }


class FakePsql:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.args = self.root / "args"
        self.stdin = self.root / "stdin"
        self.pg_environment = self.root / "pg-environment"
        executable = self.bin / "psql"
        executable.write_text(
            """#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$FAKE_PSQL_ARGS_FILE"
command cat > "$FAKE_PSQL_STDIN_FILE"
printf '%s\\n' "${PGOPTIONS-unset}" "${PSQLRC-unset}" \
  "${PGHOST-unset}" "${PGPORT-unset}" "${PGDATABASE-unset}" \
  "${PGUSER-unset}" "${PGPASSWORD-unset}" "${PGSSLMODE-unset}" \
  "${PGSSLROOTCERT-unset}" "${PGHOSTADDR-unset}" \
  "${PGSERVICE-unset}" "${PGSERVICEFILE-unset}" \
  "${PGPASSFILE-unset}" "${PGREQUIREAUTH-unset}" \
  "${PGGSSENCMODE-unset}" \
  > "$FAKE_PSQL_ENVIRONMENT_FILE"
if [ "${FAKE_PSQL_EXIT_CODE:-0}" -ne 0 ]; then
  printf 'fake psql failure\\n' >&2
  exit "$FAKE_PSQL_EXIT_CODE"
fi
printf '%s' "$FAKE_PSQL_RESPONSE"
""",
            encoding="utf-8",
        )
        executable.chmod(0o700)

    def close(self) -> None:
        self.temporary.cleanup()

    def environment(
        self,
        fake_response: str,
        *,
        include_database_url: bool = True,
        exit_code: int = 0,
    ) -> dict[str, str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_PSQL_ARGS_FILE": str(self.args),
            "FAKE_PSQL_STDIN_FILE": str(self.stdin),
            "FAKE_PSQL_ENVIRONMENT_FILE": str(self.pg_environment),
            "FAKE_PSQL_RESPONSE": fake_response,
            "FAKE_PSQL_EXIT_CODE": str(exit_code),
            "PGOPTIONS": "-c search_path=attacker",
            "PSQLRC": "/attacker/psqlrc",
        }
        if include_database_url:
            environment["EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL"] = DATABASE_URL
        else:
            environment.pop("EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL", None)
        return environment


class PostgresRolloutAttemptAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakePsql()
        self.claim = build_claim()

    def tearDown(self) -> None:
        self.fake.close()

    def run_adapter(
        self,
        operation: str,
        payload: str,
        fake_response: str,
        *,
        include_database_url: bool = True,
        exit_code: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(ADAPTER), operation],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            cwd=LANE,
            env=self.fake.environment(
                fake_response,
                include_database_url=include_database_url,
                exit_code=exit_code,
            ),
        )

    def assert_psql_not_called(self) -> None:
        self.assertFalse(self.fake.args.exists())
        self.assertFalse(self.fake.stdin.exists())

    def test_adapter_is_executable_and_invokes_hardened_psql(self) -> None:
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertTrue(ADAPTER.stat().st_mode & stat.S_IXUSR)
        self.assertIn("set -euo pipefail", source)
        self.assertIn("EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL", source)
        self.assertIn("remote PostgreSQL requires sslmode=verify-full", source)
        self.assertRegex(source, r"(?:^|\s)-X(?:\s|$)")
        self.assertIn("ON_ERROR_STOP=1", source)
        self.assertNotIn("eval ", source)
        self.assertNotIn("source ", source)

        raw = encode(self.claim)
        expected = response(
            "claim", "claimed", self.claim["claim_sha256"], None
        )
        result = self.run_adapter("claim", raw, encode(expected))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, encode(expected) + "\n")

        arguments = self.fake.args.read_text(encoding="utf-8").splitlines()
        self.assertIn("-X", arguments)
        self.assertIn("--set=ON_ERROR_STOP=1", arguments)
        self.assertFalse(any(DATABASE_URL in argument for argument in arguments))
        self.assertFalse(any("--dbname" in argument for argument in arguments))
        self.assertNotIn(raw, arguments)
        sql = self.fake.stdin.read_text(encoding="utf-8")
        self.assertIn("rollout_attempt_private.apply_operation('claim'", sql)
        self.assertNotIn(raw, sql)
        match = re.search(r"\\set payload_b64 '([A-Za-z0-9+/=]+)'", sql)
        self.assertIsNotNone(match)
        self.assertEqual(
            __import__("base64").b64decode(match.group(1)),
            raw.encode(),
        )
        self.assertEqual(
            self.fake.pg_environment.read_text(encoding="utf-8").splitlines(),
            [
                "unset",
                "unset",
                "127.0.0.1",
                "5432",
                "emilia",
                "rollout-attempt-login",
            "secret",
            "disable",
                "unset",
                "unset",
                "unset",
                "unset",
                "unset",
                "unset",
                "disable",
            ],
        )

    def test_remote_database_requires_pinned_verified_tls_and_clears_ambient_libpq(
        self,
    ) -> None:
        expected = response(
            "claim", "claimed", self.claim["claim_sha256"], None
        )
        raw = encode(self.claim)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca = root / "database-ca.pem"
            ca.write_text(
                "-----BEGIN CERTIFICATE-----\n"
                "dGVzdC1jYS1waW4=\n"
                "-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            ca.chmod(0o600)
            digest = hashlib.sha256(ca.read_bytes()).hexdigest()
            url = (
                "postgresql://rollout-attempt-login:secret@db.test/emilia"
                "?sslmode=verify-full&sslrootcert="
                f"{urllib.parse.quote(str(ca), safe='')}"
            )
            environment = self.fake.environment(encode(expected))
            environment.update(
                {
                    "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL": url,
                    "EMILIA_ROLLOUT_ATTEMPT_DATABASE_CA_SHA256": digest,
                    "PGHOSTADDR": "203.0.113.9",
                    "PGSERVICE": "attacker",
                    "PGSERVICEFILE": "/attacker/pg_service.conf",
                    "PGPASSFILE": "/attacker/.pgpass",
                    "PGREQUIREAUTH": "none",
                    "PGGSSENCMODE": "prefer",
                    "PGSSLROOTCERT": "/attacker/ca.pem",
                }
            )
            result = subprocess.run(
                [str(ADAPTER), "claim"],
                input=raw,
                text=True,
                capture_output=True,
                check=False,
                cwd=LANE,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            values = self.fake.pg_environment.read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(values[:8], [
                "unset",
                "unset",
                "db.test",
                "unset",
                "emilia",
                "rollout-attempt-login",
                "secret",
                "verify-full",
            ])
            self.assertNotEqual(values[8], str(ca))
            self.assertRegex(
                values[8],
                r"/emilia-rollout-attempt-store\.[^/]+/database-ca\.pem$",
            )
            self.assertEqual(values[9:], ["unset"] * 5 + ["disable"])

    def test_remote_tls_downgrade_missing_or_untrusted_ca_fails_before_psql(
        self,
    ) -> None:
        raw = encode(self.claim)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca = root / "database-ca.pem"
            ca.write_text("test CA", encoding="utf-8")
            ca.chmod(0o600)
            symlink = root / "database-ca-link.pem"
            symlink.symlink_to(ca)
            digest = hashlib.sha256(ca.read_bytes()).hexdigest()
            cases = (
                (
                    "postgresql://u:p@db.test/emilia?sslmode=require",
                    digest,
                ),
                (
                    "postgresql://u:p@db.test/emilia?sslmode=verify-full",
                    digest,
                ),
                (
                    "postgresql://u:p@db.test/emilia"
                    "?sslmode=verify-full&sslrootcert="
                    f"{urllib.parse.quote(str(ca), safe='')}",
                    "0" * 64,
                ),
                (
                    "postgresql://u:p@db.test/emilia"
                    "?sslmode=verify-full&sslrootcert="
                    f"{urllib.parse.quote(str(symlink), safe='')}",
                    digest,
                ),
            )
            for url, pinned_digest in cases:
                with self.subTest(url=url, pinned_digest=pinned_digest[:8]):
                    fake = FakePsql()
                    self.fake.close()
                    self.fake = fake
                    environment = self.fake.environment("")
                    environment.update(
                        {
                            "EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL": url,
                            "EMILIA_ROLLOUT_ATTEMPT_DATABASE_CA_SHA256": (
                                pinned_digest
                            ),
                        }
                    )
                    result = subprocess.run(
                        [str(ADAPTER), "claim"],
                        input=raw,
                        text=True,
                        capture_output=True,
                        check=False,
                        cwd=LANE,
                        env=environment,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assert_psql_not_called()

    def test_complete_and_reconcile_echo_only_exact_terminal_response(
        self,
    ) -> None:
        cases = (
            ("complete", "applied", "completed", "rv-decision-8"),
            ("reconcile", "applied", "applied", "rv-decision-8"),
            (
                "reconcile",
                "not-applied",
                "not-applied",
                "rv-decision-7",
            ),
            (
                "reconcile",
                "indeterminate",
                "indeterminate",
                "rv-decision-unknown",
            ),
        )
        for operation, outcome, status_value, resource_version in cases:
            with self.subTest(operation=operation, outcome=outcome):
                fake = FakePsql()
                self.fake.close()
                self.fake = fake
                payload = {
                    "schema": (
                        "emilia-deployment-attempt-store-operation.v1"
                    ),
                    "operation": operation,
                    "claim": self.claim,
                    "outcome": outcome,
                    "final_resource_version": resource_version,
                }
                expected = response(
                    operation,
                    status_value,
                    self.claim["claim_sha256"],
                    resource_version,
                )
                result = self.run_adapter(
                    operation,
                    encode(payload),
                    encode(expected),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, encode(expected) + "\n")

    def test_invalid_operation_or_input_fails_before_psql(self) -> None:
        attacks = (
            ("delete", encode(self.claim)),
            ("claim", ""),
            ("claim", '{"schema":'),
            ("claim", encode({**self.claim, "extra": "attacker"})),
            (
                "claim",
                encode(self.claim).replace(
                    '"schema":',
                    '"schema":"shadow","schema":',
                    1,
                ),
            ),
            (
                "complete",
                encode(
                    {
                        "schema": (
                            "emilia-deployment-attempt-store-operation.v1"
                        ),
                        "operation": "reconcile",
                        "claim": self.claim,
                        "outcome": "applied",
                        "final_resource_version": "rv-decision-8",
                    }
                ),
            ),
        )
        for operation, payload in attacks:
            with self.subTest(operation=operation, payload=payload[:40]):
                fake = FakePsql()
                self.fake.close()
                self.fake = fake
                result = self.run_adapter(operation, payload, "")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assert_psql_not_called()

    def test_missing_database_url_fails_before_psql(self) -> None:
        result = self.run_adapter(
            "claim",
            encode(self.claim),
            "",
            include_database_url=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assert_psql_not_called()

    def test_psql_failure_or_non_exact_output_fails_closed(self) -> None:
        expected = response(
            "claim", "claimed", self.claim["claim_sha256"], None
        )
        cases = (
            (encode(expected), 23),
            ("NOTICE\n" + encode(expected), 0),
            (encode({**expected, "extra": "attacker"}), 0),
            (
                encode({**expected, "claim_sha256": "0" * 64}),
                0,
            ),
            (
                encode({**expected, "final_resource_version": "rv-attacker"}),
                0,
            ),
        )
        for fake_response, exit_code in cases:
            with self.subTest(
                fake_response=fake_response[:40],
                exit_code=exit_code,
            ):
                fake = FakePsql()
                self.fake.close()
                self.fake = fake
                result = self.run_adapter(
                    "claim",
                    encode(self.claim),
                    fake_response,
                    exit_code=exit_code,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


class RolloutAttemptMigrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")

    def test_is_forward_only_and_separates_owner_from_executor(self) -> None:
        self.assertGreater(int(MIGRATION.name.split("_", 1)[0]), 20260725143000)
        roles = ROLES.read_text(encoding="utf-8")
        for role in (
            "rollout_attempt_store_owner",
            "rollout_attempt_executor",
        ):
            self.assertIn(f"CREATE ROLE {role} NOLOGIN", self.sql)
            self.assertIn(f"CREATE ROLE {role} NOLOGIN", roles)
            self.assertRegex(
                self.sql,
                rf"ALTER ROLE {role} NOLOGIN[\s\S]+?NOBYPASSRLS",
            )
            self.assertRegex(
                roles,
                rf"ALTER ROLE {role} NOLOGIN[\s\S]+?NOBYPASSRLS",
            )
        self.assertIn(
            "REVOKE rollout_attempt_store_owner FROM CURRENT_USER",
            self.sql,
        )
        self.assertIn("WITH RECURSIVE", self.sql)
        self.assertIn("FROM pg_catalog.pg_auth_members", self.sql)
        self.assertIn(
            "membership.inherit_option OR membership.set_option",
            self.sql,
        )
        self.assertIn("'USAGE'", self.sql)
        self.assertIn("'SET'", self.sql)
        self.assertIn("executor_members(role_oid)", self.sql)
        self.assertIn("owner_members(role_oid)", self.sql)
        for attribute in (
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        ):
            self.assertIn(attribute, self.sql)
        self.assertIn(
            "owner and executor roles must be membership-disjoint",
            self.sql,
        )

    def test_claims_and_terminals_are_separate_append_only_relations(
        self,
    ) -> None:
        self.assertIn(
            "CREATE TABLE rollout_attempt_private.claims",
            self.sql,
        )
        self.assertIn(
            "CREATE TABLE rollout_attempt_private.terminals",
            self.sql,
        )
        self.assertIn("PRIMARY KEY (claim_sha256)", self.sql)
        self.assertIn(
            "UNIQUE (authorization_id, rollout_nonce, request_sha256, "
            "pre_resource_version)",
            self.sql,
        )
        self.assertIn("UNIQUE (authorization_id)", self.sql)
        self.assertIn("UNIQUE (rollout_nonce)", self.sql)
        self.assertIn(
            "REFERENCES rollout_attempt_private.claims (claim_sha256)",
            self.sql,
        )
        self.assertIn("reject_append_only_mutation", self.sql)
        self.assertIn("BEFORE UPDATE OR DELETE", self.sql)
        self.assertIn("BEFORE TRUNCATE", self.sql)

    def test_claim_digest_and_exact_payload_are_verified_in_database(
        self,
    ) -> None:
        self.assertIn(
            "EMILIA-DEPLOYMENT-ATTEMPT-CLAIM-V1",
            self.sql,
        )
        self.assertIn("extensions.digest(", self.sql)
        self.assertIn("pg_catalog.decode('00', 'hex')", self.sql)
        self.assertIn("claim digest does not match exact claim key", self.sql)
        self.assertIn("emilia-deployment-attempt-claim.v1", self.sql)
        self.assertIn("pg_catalog.jsonb_object_keys(p_claim)", self.sql)
        self.assertIn("claim_payload = v_claim", self.sql)

    def test_terminal_insert_is_one_atomic_cas_with_exact_resource_version(
        self,
    ) -> None:
        self.assertIn(
            "INSERT INTO rollout_attempt_private.terminals",
            self.sql,
        )
        self.assertIn("final_resource_version", self.sql)
        self.assertIn("terminal_operation", self.sql)
        self.assertIn("terminal outcome is malformed", self.sql)
        self.assertIn(
            "attempt is unclaimed, terminal conflict, or claim binding "
            "mismatched",
            self.sql,
        )
        self.assertIn("ON CONFLICT DO NOTHING", self.sql)
        self.assertIn(
            "terminals.terminal_payload = v_payload",
            self.sql,
        )
        self.assertIn(
            "claims.claim_payload = v_claim",
            self.sql,
        )

    def test_exact_response_loss_replay_is_recoverable_but_conflicts_fail(
        self,
    ) -> None:
        self.assertIn(
            "CASE WHEN v_inserted = 1 THEN 'claimed' ELSE 'recovered' END",
            self.sql,
        )
        self.assertIn(
            "v_existing_terminal.final_resource_version",
            self.sql,
        )
        self.assertIn(
            "conflicting rollout attempt claim key or digest",
            self.sql,
        )

    def test_forced_rls_and_acl_expose_only_the_dedicated_rpc(self) -> None:
        self.assertEqual(
            len(re.findall(r"ENABLE ROW LEVEL SECURITY", self.sql)),
            2,
        )
        self.assertEqual(
            len(re.findall(r"FORCE ROW LEVEL SECURITY", self.sql)),
            2,
        )
        self.assertIn(
            "FROM PUBLIC, anon, authenticated, service_role, "
            "rollout_attempt_executor",
            self.sql,
        )
        self.assertIn(
            "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rollout_attempt_private",
            self.sql,
        )
        self.assertIn(
            "GRANT EXECUTE ON FUNCTION "
            "rollout_attempt_private.apply_operation(TEXT, TEXT)",
            self.sql,
        )
        self.assertIn("TO rollout_attempt_executor", self.sql)
        self.assertNotRegex(
            self.sql,
            r"GRANT\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE|TRUNCATE)"
            r"[\s\S]+TO\s+(?:PUBLIC|anon|authenticated|service_role|"
            r"rollout_attempt_executor)",
        )

    def test_rpc_is_fail_closed_security_definer_with_session_role_check(
        self,
    ) -> None:
        self.assertIn(
            "SESSION_USER,\n"
            "        'rollout_attempt_executor',\n"
            "        'USAGE'",
            self.sql,
        )
        self.assertIn(
            "SESSION_USER,\n"
            "        'rollout_attempt_executor',\n"
            "        'SET'",
            self.sql,
        )
        self.assertIn("LANGUAGE plpgsql", self.sql)
        self.assertIn("SECURITY DEFINER", self.sql)
        self.assertIn("SET search_path = ''", self.sql)
        self.assertIn("emilia-deployment-attempt-store-response.v1", self.sql)
        self.assertIn(
            "SESSION_USER,\n"
            "      'rollout_attempt_store_owner',\n"
            "      'USAGE'",
            self.sql,
        )
        self.assertIn(
            "SESSION_USER,\n"
            "      'rollout_attempt_store_owner',\n"
            "      'SET'",
            self.sql,
        )
        for attribute in (
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        ):
            self.assertIn(attribute, self.sql)
        for denied in ("PUBLIC", "anon", "authenticated", "service_role"):
            self.assertRegex(
                self.sql,
                rf"REVOKE[\s\S]+FROM[\s\S]+{denied}",
            )


if __name__ == "__main__":
    unittest.main()
