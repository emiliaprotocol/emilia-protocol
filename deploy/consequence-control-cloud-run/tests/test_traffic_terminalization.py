from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LANE = Path(__file__).resolve().parents[1]
TRAFFIC = LANE / "traffic.sh"
sys.path.insert(0, str(LANE / "tests"))

from test_rollout_telemetry import service_document


def shell_function(name: str) -> str:
    source = TRAFFIC.read_text(encoding="utf-8")
    marker = f"{name}() {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"{marker} is missing")
    end = source.find("\n}\n", start)
    if end < 0:
        raise AssertionError(f"{name} has no closing brace")
    return source[start : end + 3]


def shell_function_before(name: str, next_name: str) -> str:
    source = TRAFFIC.read_text(encoding="utf-8")
    start_marker = f"{name}() {{"
    next_marker = f"\n{next_name}() {{"
    start = source.find(start_marker)
    end = source.find(next_marker, start)
    if start < 0 or end < 0:
        raise AssertionError(f"unable to isolate {name} before {next_name}")
    return source[start:end].rstrip() + "\n"


def run_bash(
    script: str,
    *,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, **(environment or {})},
    )


class AttemptStoreResponseRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="emilia-attempt-response-recovery-"
        )
        self.root = Path(self.directory.name)
        self.adapter = self.root / "attempt-store"
        self.count = self.root / "count"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_response_loss(
        self,
        operation: str,
        status: str,
    ) -> subprocess.CompletedProcess[str]:
        claim_sha256 = "a" * 64
        final_resource_version = "rv-terminal" if operation != "claim" else ""
        response = {
            "schema": "emilia-deployment-attempt-store-response.v1",
            "operation": operation,
            "status": status,
            "claim_sha256": claim_sha256,
            "final_resource_version": final_resource_version or None,
        }
        self.adapter.write_text(
            """#!/usr/bin/env python3
import os
import pathlib
import sys

count_path = pathlib.Path(os.environ["ATTEMPT_COUNT"])
count = int(count_path.read_text()) if count_path.exists() else 0
count_path.write_text(str(count + 1))
sys.stdin.buffer.read()
if count == 0:
    raise SystemExit(23)
print(os.environ["ATTEMPT_RESPONSE"])
""",
            encoding="utf-8",
        )
        self.adapter.chmod(0o700)
        payload = "e30="
        script = f"""
set -euo pipefail
LANE_DIR={shlex.quote(str(LANE))}
ATTEMPT_STORE_ADAPTER={shlex.quote(str(self.adapter))}
ATTEMPT_CLAIM_SHA256={claim_sha256}
lane_die() {{ printf 'error: %s\\n' "$*" >&2; exit 1; }}
{shell_function_before("attempt_store_call", "attempt_outcome_payload")}
attempt_store_call {operation} {payload} {status} {final_resource_version}
printf '%s\\t%s\\t%s\\n' \
  "$ATTEMPT_STORE_CALL_RETRIED" \
  "$ATTEMPT_STORE_RESPONSE_STATUS" \
  "$ATTEMPT_STORE_RESPONSE_FINAL"
"""
        return run_bash(
            script,
            environment={
                "ATTEMPT_COUNT": str(self.count),
                "ATTEMPT_RESPONSE": json.dumps(response, separators=(",", ":")),
            },
        )

    def test_exact_claim_response_loss_is_read_back_with_same_payload(self) -> None:
        result = self.run_response_loss("claim", "recovered")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "true\trecovered")
        self.assertEqual(self.count.read_text(encoding="utf-8"), "2")

    def test_exact_terminal_response_loss_is_read_back_with_same_payload(self) -> None:
        result = self.run_response_loss("complete", "completed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "true\tcompleted\trv-terminal")
        self.assertEqual(self.count.read_text(encoding="utf-8"), "2")


class AmbiguousUpdateReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="emilia-traffic-reconcile-"
        )
        self.root = Path(self.directory.name)
        self.pre = self.root / "pre.json"
        self.post = self.root / "post.json"
        self.other = self.root / "other.json"
        self.read_count = self.root / "read-count"
        self.outcomes = self.root / "outcomes"
        self.snapshot = self.root / "ambiguous.json"
        self.other_snapshot = self.root / "other-post.json"
        self.pre.write_text(
            json.dumps(
                service_document(
                    "decision",
                    {"decision-r2": 10, "decision-r1": 90},
                    generation=7,
                    resource_version="rv-pre",
                )
            ),
            encoding="utf-8",
        )
        self.post.write_text(
            json.dumps(
                service_document(
                    "decision",
                    {"decision-r2": 50, "decision-r1": 50},
                    generation=8,
                    resource_version="rv-ack",
                )
            ),
            encoding="utf-8",
        )
        self.other.write_text(
            json.dumps(
                service_document(
                    "actuator",
                    {"actuator-r1": 100},
                    generation=7,
                    resource_version="rv-other",
                )
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def harness(self, target_sequence: list[Path]) -> str:
        sequence = " ".join(shlex.quote(str(path)) for path in target_sequence)
        return f"""
set -euo pipefail
LANE_DIR={shlex.quote(str(LANE))}
TARGET_SERVICE=decision
OTHER_SERVICE=actuator
TARGET_PRE=decision-r2:10,decision-r1:90
TARGET_POST=decision-r2:50,decision-r1:50
TARGET_STABLE=decision-r1
TARGET_CANDIDATE=decision-r2
OTHER_EXPECTED=actuator-r1:100
OTHER_STABLE=actuator-r1
OTHER_CANDIDATE=actuator-r2
LOCK_GENERATION=7
LOCK_RESOURCE_VERSION=rv-pre
OTHER_GENERATION=7
OTHER_RESOURCE_VERSION=rv-other
AMBIGUOUS_SNAPSHOT={shlex.quote(str(self.snapshot))}
OTHER_POST_SNAPSHOT={shlex.quote(str(self.other_snapshot))}
ROLLOUT_POLL_ATTEMPTS=3
ROLLOUT_POLL_INTERVAL_SEC=0
READ_COUNT={shlex.quote(str(self.read_count))}
OUTCOMES={shlex.quote(str(self.outcomes))}
OTHER_STATE={shlex.quote(str(self.other))}
TARGET_STATES=({sequence})
lane_die() {{
  printf 'error: %s\\n' "$*" >&2
  exit 1
}}
sleep() {{
  :
}}
describe_service() {{
  local service=$1 output=$2 count
  if [[ "$service" == "$TARGET_SERVICE" ]]; then
    count=0
    [[ ! -s "$READ_COUNT" ]] || count=$(<"$READ_COUNT")
    ((count += 1))
    printf '%s' "$count" > "$READ_COUNT"
    cp "${{TARGET_STATES[count - 1]}}" "$output"
  else
    cp "$OTHER_STATE" "$output"
  fi
}}
try_describe_service() {{
  describe_service "$@"
}}
record_attempt_outcome() {{
  printf '%s\\t%s\\t%s\\n' "$1" "$2" "$3" >> "$OUTCOMES"
  ATTEMPT_TERMINALIZED=true
}}
{shell_function("verify_exact_service_state")}
{shell_function("reconcile_ambiguous_update")}
reconcile_ambiguous_update "lost provider response"
"""

    def test_pre_state_read_is_not_terminal_and_later_post_state_applies(
        self,
    ) -> None:
        result = run_bash(self.harness([self.pre, self.post, self.post]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read_count.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            self.outcomes.read_text(encoding="utf-8").splitlines(),
            ["reconcile\tapplied\trv-ack"],
        )

    def test_not_applied_requires_the_full_bounded_window(self) -> None:
        result = run_bash(self.harness([self.pre, self.pre, self.pre]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read_count.read_text(encoding="utf-8"), "3")
        self.assertEqual(
            self.outcomes.read_text(encoding="utf-8").splitlines(),
            ["reconcile\tnot-applied\trv-pre"],
        )
        self.assertIn("must not be replayed", result.stderr)


class PostClaimTerminalizationTests(unittest.TestCase):
    def run_post_claim_failure(
        self,
        *,
        send_body: str = (
            "ACK_GENERATION=8; "
            "ACK_RESOURCE_VERSION=rv-ack; "
            "ATTEMPT_FALLBACK_OUTCOME=indeterminate; "
            "ATTEMPT_FINAL_RESOURCE_VERSION=$ACK_RESOURCE_VERSION"
        ),
        poll_body: str,
        post_control_body: str,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory(
            prefix="emilia-traffic-terminal-"
        ) as directory:
            root = Path(directory)
            outcomes = root / "outcomes"
            work = root / "work"
            work.mkdir()
            script = f"""
set -euo pipefail
WORK_DIR={shlex.quote(str(work))}
OUTCOMES={shlex.quote(str(outcomes))}
LOCK_RESOURCE_VERSION=rv-pre
ACK_GENERATION=
ACK_RESOURCE_VERSION=
ATTEMPT_CLAIMED=false
ATTEMPT_TERMINALIZED=false
ATTEMPT_FALLBACK_OUTCOME=not-applied
ATTEMPT_FINAL_RESOURCE_VERSION=
lane_cleanup_pinned_config() {{
  :
}}
record_attempt_outcome() {{
  printf '%s\\t%s\\t%s\\n' "$1" "$2" "$3" >> "$OUTCOMES"
  ATTEMPT_TERMINALIZED=true
}}
{shell_function("traffic_exit_handler")}
{shell_function("apply_prepared_update")}
require_protected_traffic_identity() {{ :; }}
verify_direct_traffic_custody() {{ :; }}
revalidate_before_send() {{ :; }}
claim_deployment_attempt() {{
  ATTEMPT_CLAIMED=true
  ATTEMPT_FALLBACK_OUTCOME=not-applied
  ATTEMPT_FINAL_RESOURCE_VERSION=$LOCK_RESOURCE_VERSION
}}
send_locked_update() {{
  {send_body}
}}
poll_exact_post_state() {{
  {poll_body}
}}
verify_post_mutation_controls() {{
  {post_control_body}
}}
trap 'traffic_exit_handler "$?"' EXIT
apply_prepared_update
"""
            result = run_bash(script)
            recorded = (
                outcomes.read_text(encoding="utf-8").splitlines()
                if outcomes.exists()
                else []
            )
        return result, recorded

    def test_failure_before_request_send_terminalizes_not_applied(self) -> None:
        result, outcomes = self.run_post_claim_failure(
            send_body="return 1",
            poll_body=":",
            post_control_body=":",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outcomes, ["reconcile\tnot-applied\trv-pre"])

    def test_acknowledged_poll_failure_terminalizes_indeterminate(self) -> None:
        result, outcomes = self.run_post_claim_failure(
            poll_body="return 1",
            post_control_body=":",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outcomes, ["reconcile\tindeterminate\trv-ack"])

    def test_post_control_failure_after_exact_poll_terminalizes_applied(
        self,
    ) -> None:
        result, outcomes = self.run_post_claim_failure(
            poll_body=(
                "ATTEMPT_FALLBACK_OUTCOME=applied; "
                "ATTEMPT_FINAL_RESOURCE_VERSION=$ACK_RESOURCE_VERSION"
            ),
            post_control_body="return 1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outcomes, ["reconcile\tapplied\trv-ack"])

    def test_claim_and_successful_terminal_write_update_lifecycle_state(
        self,
    ) -> None:
        script = f"""
set -euo pipefail
LOCK_RESOURCE_VERSION=rv-pre
ATTEMPT_CLAIM_BASE64=e30=
ATTEMPT_CLAIM_SHA256={'a' * 64}
ATTEMPT_CLAIMED=false
ATTEMPT_TERMINALIZED=false
ATTEMPT_FALLBACK_OUTCOME=indeterminate
ATTEMPT_FINAL_RESOURCE_VERSION=
prepare_attempt_store_adapter() {{ :; }}
attempt_store_call() {{
  if [[ "$1" == claim ]]; then
    ATTEMPT_STORE_RESPONSE_STATUS=claimed
    ATTEMPT_STORE_RESPONSE_FINAL=
  else
    ATTEMPT_STORE_RESPONSE_STATUS=$3
    ATTEMPT_STORE_RESPONSE_FINAL=$4
  fi
}}
attempt_outcome_payload() {{ printf 'payload'; }}
{shell_function("claim_deployment_attempt")}
{shell_function("record_attempt_outcome")}
claim_deployment_attempt
printf '%s\\t%s\\t%s\\t%s\\n' \
  "$ATTEMPT_CLAIMED" "$ATTEMPT_TERMINALIZED" \
  "$ATTEMPT_FALLBACK_OUTCOME" "$ATTEMPT_FINAL_RESOURCE_VERSION"
record_attempt_outcome complete applied rv-ack
printf '%s\\n' "$ATTEMPT_TERMINALIZED"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["true\tfalse\tnot-applied\trv-pre", "true"],
        )


class EmergencyRollbackDependencyTests(unittest.TestCase):
    def test_rollback_skips_candidate_secret_gate_but_promotion_keeps_it(
        self,
    ) -> None:
        script = f"""
set -euo pipefail
SECRET_CALLS=0
verify_secret_versions() {{
  ((SECRET_CALLS += 1))
  return 23
}}
{shell_function("verify_mutation_secret_versions")}
ACTION=apply-rollback
verify_mutation_secret_versions
printf '%s\\n' "$SECRET_CALLS"
ACTION=apply-decision-10
set +e
verify_mutation_secret_versions
status=$?
set -e
printf '%s\\t%s\\n' "$status" "$SECRET_CALLS"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["0", "23\t1"])

        traffic = TRAFFIC.read_text(encoding="utf-8")
        rollback = traffic.split("apply_rollback() {", 1)[1].split(
            "\n}",
            1,
        )[0]
        self.assertIn("verify_current_signed_config", rollback)
        self.assertNotIn("verify_secret_versions", rollback)
        for function in (
            "revalidate_before_send",
            "verify_post_mutation_controls",
        ):
            body = traffic.split(f"{function}() {{", 1)[1].split(
                "\n}",
                1,
            )[0]
            self.assertIn("verify_mutation_secret_versions", body)


if __name__ == "__main__":
    unittest.main()
