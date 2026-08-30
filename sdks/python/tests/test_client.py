"""Installed-package tests for the synchronous EMILIA Python client."""

from __future__ import annotations

import io
import json
import os
import urllib.error
import unittest
from copy import deepcopy
from typing import Any, Dict, List, Mapping, Optional
from unittest.mock import MagicMock, patch

from emilia_protocol import (
    AttestExecutionParams,
    ConsumeTrustReceiptParams,
    CreateTrustReceiptParams,
    EPClient,
    EPError,
    QuorumApprover,
    QuorumPolicy,
    RequestSignoffParams,
    RequireReceiptParams,
    __version__,
)


RECEIPT_ID = "tr_" + "a" * 32
ACTION_HASH = "sha256:" + "b" * 64
CANONICAL_ACTION = {
    "action_type": "large_payment_release",
    "target_resource_id": "payment-123",
    "amount": 82000,
    "currency": "USD",
}


def receipt_payload(**overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "receipt_id": RECEIPT_ID,
        "decision": "allow",
        "observed_decision": None,
        "policy_id": "fin-high-risk-v1",
        "policy_hash": "sha256:" + "c" * 64,
        "action_hash": ACTION_HASH,
        "before_state_hash": None,
        "after_state_hash": "sha256:" + "d" * 64,
        "nonce": "nonce-1",
        "expires_at": "2999-01-01T00:00:00Z",
        "signoff_required": False,
        "required_assurance": None,
        "signoff_request_id": None,
        "risk_flags": [],
        "receipt_status": "issued",
        "enforcement_mode": "enforce",
        "evidence_status": "durable",
        "reasons": [],
        "canonical_action": deepcopy(CANONICAL_ACTION),
        "execution_binding": {"required": True, "required_fields": ["amount", "currency"]},
    }
    payload.update(overrides)
    return payload


def consumed_payload() -> Dict[str, Any]:
    return {
        "receipt_id": RECEIPT_ID,
        "status": "consumed",
        "consumed_at": "2026-08-30T00:00:00Z",
        "consumed_by_system": "payments-api",
        "execution_reference_id": "exec-ref-1",
    }


def execution_payload() -> Dict[str, Any]:
    return {
        "receipt_id": RECEIPT_ID,
        "status": "executed",
        "binding_status": "match",
        "executed_action_hash": ACTION_HASH,
        "approved_action_hash": ACTION_HASH,
        "execution_binding_check": {"ok": True},
        "execution_integrity": {"binding_status": "match"},
    }


def _mock_response(payload: Any) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__ = lambda value: value
    response.__exit__ = MagicMock(return_value=False)
    return response


def _mock_http_error(status: int, payload: Any) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://emiliaprotocol.ai/test",
        code=status,
        msg="error",
        hdrs=MagicMock(),
        fp=io.BytesIO(json.dumps(payload).encode("utf-8")),
    )


class ScriptedClient(EPClient):
    """Client whose transport consumes predetermined JSON responses."""

    def __init__(self, responses: List[Any]) -> None:
        super().__init__(api_key="ep_test_key", retries=0)
        self.responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        auth: bool = False,
    ) -> Any:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "body": deepcopy(dict(body)) if body is not None else None,
                "auth": auth,
            }
        )
        if not self.responses:
            raise AssertionError("script exhausted")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return deepcopy(response)


class TestClientConfigurationAndTransport(unittest.TestCase):
    def test_version_and_environment_defaults(self) -> None:
        with patch.dict(
            os.environ,
            {"EP_BASE_URL": "https://api.example.test/", "EP_API_KEY": "from-env"},
            clear=False,
        ):
            client = EPClient()
        self.assertEqual(__version__, "0.11.0")
        self.assertEqual(client._base_url, "https://api.example.test")
        self.assertEqual(client._api_key, "from-env")

    def test_remote_cleartext_and_embedded_credentials_are_refused(self) -> None:
        for unsafe in (
            "http://api.example.test",
            "https://user:password@api.example.test",
            "https://api.example.test?next=elsewhere",
            "https://api.example.test/#fragment",
        ):
            with self.subTest(url=unsafe), self.assertRaises(ValueError):
                EPClient(base_url=unsafe)

    def test_loopback_http_is_allowed(self) -> None:
        self.assertEqual(
            EPClient(base_url="http://127.0.0.1:3000/")._base_url,
            "http://127.0.0.1:3000",
        )

    def test_missing_api_key_fails_before_network(self) -> None:
        client = EPClient(api_key="", retries=0)
        with patch("urllib.request.urlopen") as urlopen:
            with self.assertRaises(EPError) as raised:
                client.get_handshake("hs_1")
        self.assertEqual(raised.exception.code, "missing_api_key")
        urlopen.assert_not_called()

    def test_user_agent_and_bearer_header_use_release_version(self) -> None:
        client = EPClient(api_key="secret", retries=0)
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response({"handshake_id": "hs_1"}),
        ) as urlopen:
            client.get_handshake("hs_1")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")
        self.assertEqual(
            request.get_header("User-agent"),
            "emilia-protocol-python/0.11.0",
        )

    def test_problem_details_error_uses_detail_code_and_type_tail(self) -> None:
        client = EPClient(api_key="secret", retries=0)
        error = _mock_http_error(
            409,
            {
                "type": "https://emiliaprotocol.ai/errors/action_hash_mismatch",
                "title": "Conflict",
                "detail": "The action hash differs",
            },
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(EPError) as raised:
                client.get_handshake("hs_1")
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.code, "action_hash_mismatch")
        self.assertEqual(str(raised.exception), "The action hash differs")

    def test_get_retries_but_post_does_not(self) -> None:
        client = EPClient(api_key="secret", retries=2)
        unavailable = urllib.error.URLError("offline")
        with patch("urllib.request.urlopen", side_effect=unavailable) as urlopen:
            with self.assertRaises(EPError):
                client.get_handshake("hs_1")
        self.assertEqual(urlopen.call_count, 3)

        with patch("urllib.request.urlopen", side_effect=unavailable) as urlopen:
            with self.assertRaises(EPError):
                client.gate("entity-1", "purchase")
        self.assertEqual(urlopen.call_count, 1)


class TestCoreRouteContracts(unittest.TestCase):
    def test_handshake_methods_use_runtime_paths_and_snake_case(self) -> None:
        client = ScriptedClient(
            [
                {"handshake_id": "hs_1", "policy_id": "strict", "status": "pending"},
                {"handshake_id": "hs_1", "status": "pending"},
                {
                    "presentation_id": "pr_1",
                    "handshake_id": "hs_1",
                    "party_role": "initiator",
                    "presentation_type": "attestation",
                },
                {
                    "handshake_id": "hs_1",
                    "outcome": "accepted",
                    "reason_codes": [],
                },
                {"handshake_id": "hs_1", "status": "revoked"},
            ]
        )
        created = client.initiate_handshake(
            "mutual",
            "strict",
            [
                {"entityRef": "agent-a", "role": "initiator"},
                {"entity_ref": "service-b", "role": "responder"},
            ],
            binding={"purpose": "payment"},
            action_type="payment.release",
            resource_ref="payment-123",
        )
        client.get_handshake("hs_1")
        presented = client.present(
            "hs/a b",
            "initiator",
            "attestation",
            {"subject": "agent-a"},
            issuer_ref="key-1",
            issuer_proof={"profile": "EP-HANDSHAKE-ISSUER-PROOF-v1"},
            disclosure_mode="full",
        )
        verified = client.verify("hs_1")
        revoked = client.revoke_handshake("hs_1", "no longer needed")

        self.assertEqual(created.handshake_id, "hs_1")
        self.assertEqual(presented.presentation_id, "pr_1")
        self.assertEqual(verified.outcome, "accepted")
        self.assertEqual(revoked.status, "revoked")
        self.assertEqual(
            [call["path"] for call in client.calls],
            [
                "/api/handshake",
                "/api/handshake/hs_1",
                "/api/handshake/hs%2Fa%20b/present",
                "/api/handshake/hs_1/verify",
                "/api/handshake/hs_1/revoke",
            ],
        )
        create_body = client.calls[0]["body"]
        self.assertEqual(create_body["policy_id"], "strict")
        self.assertEqual(create_body["parties"][0], {"entity_ref": "agent-a", "role": "initiator"})
        self.assertNotIn("policyId", create_body)
        self.assertEqual(create_body["action_type"], "payment.release")
        present_body = client.calls[2]["body"]
        self.assertEqual(present_body["party_role"], "initiator")
        self.assertIn("issuer_proof", present_body)
        self.assertEqual(client.calls[4]["body"], {"reason": "no longer needed"})
        self.assertTrue(all(call["auth"] for call in client.calls))

    def test_gate_uses_trust_gate_and_runtime_binding_fields(self) -> None:
        client = ScriptedClient(
            [
                {
                    "decision": "allow",
                    "entity_id": "principal-1",
                    "policy_used": "strict",
                    "confidence": "established",
                    "reasons": [],
                    "warnings": [],
                    "commit_ref": "epc_1",
                }
            ]
        )
        result = client.gate(
            "principal-1",
            "payment.release",
            policy="strict",
            value_usd=82000,
            delegation_id="dlg_1",
            handshake_id="hs_1",
            resource_ref="payment-123",
            intent_ref="intent-1",
        )
        call = client.calls[0]
        self.assertEqual(call["path"], "/api/trust/gate")
        self.assertEqual(call["body"]["handshake_id"], "hs_1")
        self.assertEqual(call["body"]["resource_ref"], "payment-123")
        self.assertEqual(result.commit_ref, "epc_1")


class TestLifecycleRouteContracts(unittest.TestCase):
    def test_six_lifecycle_methods_use_exact_paths_and_bodies(self) -> None:
        client = ScriptedClient(
            [
                receipt_payload(),
                {
                    "receipt_id": RECEIPT_ID,
                    "organization_id": "org-1",
                    "action_type": "large_payment_release",
                    "receipt_status": "issued",
                    "timeline_event_count": 1,
                },
                {
                    "signoff_id": "sig_1",
                    "receipt_id": RECEIPT_ID,
                    "action_hash": ACTION_HASH,
                    "initiator_id": "actor-1",
                    "approver_id": "controller-1",
                    "expires_at": "2999-01-01T00:00:00Z",
                    "status": "pending",
                },
                consumed_payload(),
                execution_payload(),
                {"receipt_id": RECEIPT_ID, "signed": False, "document": None},
            ]
        )
        create_params = CreateTrustReceiptParams(
            organization_id="org-1",
            action_type="large_payment_release",
            target_resource_id="payment-123",
            amount=82000,
            currency="USD",
            after_state={"status": "ready"},
        )
        client.create_trust_receipt(create_params)
        client.get_trust_receipt(RECEIPT_ID + "/unsafe")
        client.request_signoff(
            RequestSignoffParams(
                receipt_id=RECEIPT_ID,
                approver_id="controller-1",
                expires_in_minutes=30,
                comment="release payment",
            )
        )
        client.consume_trust_receipt(
            RECEIPT_ID,
            ConsumeTrustReceiptParams(
                action_hash=ACTION_HASH,
                executing_system="payments-api",
                execution_reference_id="exec-ref-1",
            ),
        )
        client.attest_execution(
            RECEIPT_ID,
            AttestExecutionParams(
                executed_action=CANONICAL_ACTION,
                observed_action={**CANONICAL_ACTION, "observed": True},
                executing_system="payments-api",
                execution_id="exec-1",
            ),
        )
        evidence = client.get_trust_receipt_evidence(RECEIPT_ID)

        self.assertEqual(
            [call["path"] for call in client.calls],
            [
                "/api/v1/trust-receipts",
                "/api/v1/trust-receipts/{0}%2Funsafe".format(RECEIPT_ID),
                "/api/v1/signoffs/request",
                "/api/v1/trust-receipts/{0}/consume".format(RECEIPT_ID),
                "/api/v1/trust-receipts/{0}/execution".format(RECEIPT_ID),
                "/api/v1/trust-receipts/{0}/evidence".format(RECEIPT_ID),
            ],
        )
        self.assertEqual(client.calls[0]["body"]["organization_id"], "org-1")
        self.assertNotIn("organizationId", client.calls[0]["body"])
        self.assertEqual(client.calls[2]["body"]["approver_id"], "controller-1")
        self.assertEqual(client.calls[3]["body"]["action_hash"], ACTION_HASH)
        self.assertEqual(client.calls[4]["body"]["executed_action"], CANONICAL_ACTION)
        self.assertTrue(client.calls[4]["body"]["observed_action"]["observed"])
        self.assertFalse(evidence["signed"])
        self.assertTrue(all(call["auth"] for call in client.calls))

    def test_create_supports_auth_derived_org_and_runtime_quorum_policy(self) -> None:
        client = ScriptedClient([receipt_payload()])
        params = CreateTrustReceiptParams(
            action_type="large_payment_release",
            target_resource_id="payment-123",
            quorum_policy=QuorumPolicy(
                required=2,
                approvers=[
                    QuorumApprover(role="controller", approver="human-1"),
                    QuorumApprover(role="treasurer", approver="human-2"),
                ],
                window_sec=600,
            ),
        )
        client.create_trust_receipt(params)

        body = client.calls[0]["body"]
        self.assertNotIn("organization_id", body)
        self.assertEqual(body["quorum_policy"]["mode"], "threshold")
        self.assertEqual(body["quorum_policy"]["required"], 2)
        self.assertEqual(
            body["quorum_policy"]["approvers"][1],
            {"role": "treasurer", "approver": "human-2"},
        )
        # action_type is intentionally a string, so the SDK does not reject
        # runtime vocabulary additions such as the current policy_rollout.
        self.assertEqual(
            CreateTrustReceiptParams(
                action_type="policy_rollout",
                target_resource_id="rollout-1",
            ).to_dict()["action_type"],
            "policy_rollout",
        )


class TestRequireReceipt(unittest.TestCase):
    def params(self, **overrides: Any) -> RequireReceiptParams:
        values: Dict[str, Any] = {
            "organization_id": "org-1",
            "action_type": "large_payment_release",
            "target_resource_id": "payment-123",
            "executing_system": "payments-api",
            "amount": 82000,
            "currency": "USD",
            "execution_reference_id": "exec-ref-1",
        }
        values.update(overrides)
        return RequireReceiptParams(**values)

    def test_consumes_before_mutation_then_attests_independent_observation(self) -> None:
        client = ScriptedClient([receipt_payload(), consumed_payload(), execution_payload()])
        mutation_calls: List[Any] = []

        def mutate(context: Any) -> Dict[str, Any]:
            self.assertEqual(len(client.calls), 2)
            self.assertEqual(context.canonical_action, CANONICAL_ACTION)
            context.canonical_action["amount"] = 1
            mutation_calls.append(context)
            return {"execution_id": "bank-exec-1", "observed_amount": 82000}

        result = client.require_receipt(
            self.params(
                observed_action=lambda context: {
                    **context.canonical_action,
                    "amount": context.result["observed_amount"],
                    "system_observation": "read-after-write",
                },
                execution_id=lambda mutation_result: mutation_result["execution_id"],
            ),
            mutate,
        )

        self.assertEqual(len(mutation_calls), 1)
        self.assertEqual(result.execution_status, "attested")
        self.assertFalse(result.do_not_retry)
        self.assertEqual(
            [call["path"] for call in client.calls],
            [
                "/api/v1/trust-receipts",
                "/api/v1/trust-receipts/{0}/consume".format(RECEIPT_ID),
                "/api/v1/trust-receipts/{0}/execution".format(RECEIPT_ID),
            ],
        )
        execution_body = client.calls[2]["body"]
        self.assertEqual(execution_body["executed_action"], CANONICAL_ACTION)
        self.assertEqual(execution_body["observed_action"]["system_observation"], "read-after-write")
        self.assertEqual(execution_body["execution_id"], "bank-exec-1")

    def test_preconsume_failures_never_run_mutation(self) -> None:
        bad_receipts = (
            receipt_payload(decision="deny", receipt_status="denied"),
            receipt_payload(receipt_id=""),
            receipt_payload(action_hash=""),
            receipt_payload(canonical_action={}),
            receipt_payload(evidence_status="degraded"),
            receipt_payload(enforcement_mode="observe", receipt_status="observed"),
            receipt_payload(receipt_status="indeterminate"),
        )
        for payload in bad_receipts:
            with self.subTest(payload=payload):
                client = ScriptedClient([payload])
                mutation_calls: List[Any] = []
                with self.assertRaises(EPError):
                    client.require_receipt(self.params(), mutation_calls.append)
                self.assertEqual(mutation_calls, [])
                self.assertEqual(len(client.calls), 1)

    def test_non_enforce_mode_is_rejected_before_create(self) -> None:
        client = ScriptedClient([])
        with self.assertRaises(EPError) as raised:
            client.require_receipt(self.params(enforcement_mode="warn"), lambda _: None)
        self.assertEqual(raised.exception.code, "enforce_mode_required")
        self.assertEqual(client.calls, [])

    def test_missing_signoff_callback_fails_before_consume(self) -> None:
        pending = receipt_payload(
            decision="allow_with_signoff",
            signoff_required=True,
            receipt_status="pending_signoff",
        )
        signoff = {
            "signoff_id": "sig_1",
            "receipt_id": RECEIPT_ID,
            "action_hash": ACTION_HASH,
            "initiator_id": "actor-1",
            "approver_id": "controller-1",
            "expires_at": "2999-01-01T00:00:00Z",
            "status": "pending",
        }
        client = ScriptedClient([pending, signoff])
        mutation_calls: List[Any] = []
        with self.assertRaises(EPError) as raised:
            client.require_receipt(
                self.params(approver_id="controller-1"),
                mutation_calls.append,
            )
        self.assertEqual(raised.exception.code, "signoff_required")
        self.assertEqual(mutation_calls, [])
        self.assertEqual(len(client.calls), 2)

    def test_callback_assertion_is_not_authority_when_consume_refuses(self) -> None:
        pending = receipt_payload(
            decision="allow_with_signoff",
            signoff_required=True,
            receipt_status="pending_signoff",
        )
        signoff = {
            "signoff_id": "sig_1",
            "receipt_id": RECEIPT_ID,
            "action_hash": ACTION_HASH,
            "initiator_id": "actor-1",
            "approver_id": "controller-1",
            "expires_at": "2999-01-01T00:00:00Z",
            "status": "pending",
        }
        refused = EPError("Signoff is not approved", status=403, code="signoff_required")
        client = ScriptedClient([pending, signoff, refused])
        mutation_calls: List[Any] = []
        with self.assertRaises(EPError) as raised:
            client.require_receipt(
                self.params(
                    approver_id="controller-1",
                    on_signoff_required=lambda _: {"approved": True},
                ),
                mutation_calls.append,
            )
        self.assertEqual(raised.exception.status, 403)
        self.assertEqual(mutation_calls, [])
        self.assertEqual(len(client.calls), 3)

    def test_callback_rejection_never_attempts_consume(self) -> None:
        pending = receipt_payload(
            decision="allow_with_signoff",
            signoff_required=True,
            receipt_status="pending_signoff",
        )
        signoff = {
            "signoff_id": "sig_1",
            "receipt_id": RECEIPT_ID,
            "action_hash": ACTION_HASH,
            "initiator_id": "actor-1",
            "approver_id": "controller-1",
            "expires_at": "2999-01-01T00:00:00Z",
            "status": "pending",
        }
        client = ScriptedClient([pending, signoff])
        mutation_calls: List[Any] = []
        with self.assertRaises(EPError) as raised:
            client.require_receipt(
                self.params(
                    approver_id="controller-1",
                    on_signoff_required=lambda _: False,
                ),
                mutation_calls.append,
            )
        self.assertEqual(raised.exception.code, "signoff_rejected")
        self.assertEqual(mutation_calls, [])
        self.assertEqual(len(client.calls), 2)

    def test_quorum_fanout_is_confirmed_then_server_consume_is_authority(self) -> None:
        quorum_policy = QuorumPolicy(
            required=2,
            approvers=[
                QuorumApprover(role="controller", approver="human-1"),
                QuorumApprover(role="treasurer", approver="human-2"),
            ],
        )
        quorum_signoff = {
            "receipt_id": RECEIPT_ID,
            "action_hash": ACTION_HASH,
            "initiator_id": "actor-1",
            "expires_at": "2999-01-01T00:00:00Z",
            "quorum": {"mode": "threshold", "required": 2, "count": 2},
            "signoffs": [
                {"signoff_id": "sig_1", "role": "controller", "approver_id": "human-1"},
                {"signoff_id": "sig_2", "role": "treasurer", "approver_id": "human-2"},
            ],
            "status": "pending",
        }
        client = ScriptedClient(
            [receipt_payload(), quorum_signoff, consumed_payload()]
        )
        callbacks: List[Any] = []
        mutations: List[Any] = []

        result = client.require_receipt(
            self.params(
                organization_id=None,
                quorum_policy=quorum_policy,
                on_signoff_required=lambda context: callbacks.append(context),
            ),
            lambda context: mutations.append(context) or {"ok": True},
        )

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(callbacks[0].signoff.signoffs), 2)
        self.assertEqual(len(mutations), 1)
        self.assertEqual(result.consume.status, "consumed")
        self.assertNotIn("organization_id", client.calls[0]["body"])
        self.assertNotIn("approver_id", client.calls[1]["body"])
        self.assertEqual(
            [call["path"] for call in client.calls],
            [
                "/api/v1/trust-receipts",
                "/api/v1/signoffs/request",
                "/api/v1/trust-receipts/{0}/consume".format(RECEIPT_ID),
            ],
        )

    def test_unconfirmed_consume_never_runs_mutation(self) -> None:
        client = ScriptedClient(
            [receipt_payload(), {**consumed_payload(), "status": "pending"}]
        )
        mutation_calls: List[Any] = []
        with self.assertRaises(EPError) as raised:
            client.require_receipt(self.params(), mutation_calls.append)
        self.assertEqual(raised.exception.code, "invalid_consume_response")
        self.assertEqual(mutation_calls, [])

    def test_mutation_exception_emits_no_execution_claim(self) -> None:
        client = ScriptedClient([receipt_payload(), consumed_payload()])

        def fail(_: Any) -> None:
            raise RuntimeError("provider response lost")

        with self.assertRaisesRegex(RuntimeError, "provider response lost"):
            client.require_receipt(
                self.params(observed_action={"amount": 82000}),
                fail,
            )
        self.assertEqual(len(client.calls), 2)

    def test_no_observation_returns_unobserved_without_attestation(self) -> None:
        client = ScriptedClient([receipt_payload(), consumed_payload()])
        result = client.require_receipt(self.params(), lambda _: {"ok": True})
        self.assertEqual(result.execution_status, "unobserved")
        self.assertIsNone(result.execution)
        self.assertTrue(result.do_not_retry)
        self.assertEqual(len(client.calls), 2)

    def test_postmutation_attestation_failure_is_indeterminate(self) -> None:
        client = ScriptedClient(
            [
                receipt_payload(),
                consumed_payload(),
                EPError(
                    "Observed fields drifted",
                    status=409,
                    code="execution_binding_mismatch",
                ),
            ]
        )
        mutation_calls: List[Any] = []
        result = client.require_receipt(
            self.params(observed_action={**CANONICAL_ACTION, "observed": True}),
            lambda context: mutation_calls.append(context) or {"ok": True},
        )
        self.assertEqual(len(mutation_calls), 1)
        self.assertEqual(result.execution_status, "indeterminate")
        self.assertIn("drifted", result.execution_error or "")
        self.assertTrue(result.do_not_retry)

    def test_optional_evidence_failure_is_reported_without_inviting_retry(self) -> None:
        client = ScriptedClient(
            [
                receipt_payload(),
                consumed_payload(),
                EPError("evidence store unavailable", status=503),
            ]
        )
        result = client.require_receipt(
            self.params(fetch_evidence=True),
            lambda _: "executed",
        )
        self.assertEqual(result.result, "executed")
        self.assertEqual(result.execution_status, "unobserved")
        self.assertIn("unavailable", result.evidence_error or "")
        self.assertTrue(result.do_not_retry)


class TestRemovedLegacySurface(unittest.TestCase):
    def test_unsupported_methods_are_absent(self) -> None:
        client = EPClient(api_key="x")
        for name in (
            "consume",
            "consume_signoff",
            "issue_challenge",
            "attest",
            "record_observation",
            "check_action",
            "get_advisory",
            "create_suppression",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(client, name))


if __name__ == "__main__":
    unittest.main()
