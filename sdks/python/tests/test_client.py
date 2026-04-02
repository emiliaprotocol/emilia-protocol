"""Tests for the ep SDK (src/ep/).

The ep package uses urllib.request (stdlib) — no httpx — so we mock
urllib.request.urlopen to control HTTP responses without making real calls.
"""

from __future__ import annotations

import io
import json
import sys
import os
import urllib.error
import unittest
from unittest.mock import MagicMock, patch, call

# Ensure src/ is on sys.path so `ep` can be imported without installation.
_SDK_ROOT = os.path.join(os.path.dirname(__file__), "..", "src")
if _SDK_ROOT not in sys.path:
    sys.path.insert(0, _SDK_ROOT)

from ep import EPClient, EPError  # noqa: E402
from ep.types import (  # noqa: E402
    GateResult,
    Handshake,
    Policy,
    Presentation,
    SignoffAttestation,
    SignoffChallenge,
    SignoffConsumption,
    VerificationResult,
    RevokeResult,
    DenyResult,
    Delegation,
    DelegationVerification,
    Commit,
    CommitVerification,
    Consumption,
    Party,
    InitiateHandshakeParams,
    PresentParams,
    GateParams,
    IssueChallengeParams,
    AttestParams,
    ConsumeSignoffParams,
    ConsumeParams,
    CreateDelegationParams,
    IssueCommitParams,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(payload: dict, status: int = 200) -> MagicMock:
    """Build a fake urllib response context-manager mock."""
    body = json.dumps(payload).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _mock_http_error(status: int, payload: dict) -> urllib.error.HTTPError:
    """Build a fake HTTPError with a JSON body."""
    body = json.dumps(payload).encode("utf-8")
    fp = io.BytesIO(body)
    err = urllib.error.HTTPError(
        url="http://example.com",
        code=status,
        msg="Error",
        hdrs=MagicMock(),
        fp=fp,
    )
    return err


# ---------------------------------------------------------------------------
# Test: Client initialisation
# ---------------------------------------------------------------------------

class TestEPClientInit(unittest.TestCase):

    def test_init_defaults(self):
        client = EPClient(base_url="https://emiliaprotocol.ai")
        self.assertEqual(client._base_url, "https://emiliaprotocol.ai")
        self.assertEqual(client._api_key, "")
        self.assertEqual(client._timeout, 10)
        self.assertEqual(client._retries, 2)

    def test_init_strips_trailing_slash(self):
        client = EPClient(base_url="https://emiliaprotocol.ai/")
        self.assertEqual(client._base_url, "https://emiliaprotocol.ai")

    def test_init_with_api_key(self):
        client = EPClient(base_url="https://emiliaprotocol.ai", api_key="ep_live_abc123")
        self.assertEqual(client._api_key, "ep_live_abc123")

    def test_init_custom_timeout_and_retries(self):
        client = EPClient(base_url="https://api.example.com", timeout=30, retries=0)
        self.assertEqual(client._timeout, 30)
        self.assertEqual(client._retries, 0)

    def test_cloud_sub_client_attached(self):
        from ep import EPCloudClient
        client = EPClient(base_url="https://emiliaprotocol.ai")
        self.assertIsInstance(client.cloud, EPCloudClient)

    def test_auth_header_sent_when_api_key_set(self):
        # Use get_handshake which calls _request(..., auth=True)
        client = EPClient(base_url="https://emiliaprotocol.ai", api_key="ep_live_tok")
        payload = {"id": "hs_1", "status": "active", "mode": "mutual", "policyId": "standard", "parties": [], "createdAt": ""}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
            client.get_handshake("hs_1")
            req_arg = mock_open.call_args[0][0]
            # urllib.request.Request stores headers with title-cased keys
            auth_val = req_arg.get_header("Authorization")
            self.assertIsNotNone(auth_val, "Authorization header was not set")
            self.assertEqual(auth_val, "Bearer ep_live_tok")

    def test_no_auth_header_when_no_api_key(self):
        client = EPClient(base_url="https://emiliaprotocol.ai")
        payload = [{"name": "standard", "family": "core", "description": ""}]
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            client.list_policies()
            # No auth needed for list_policies — just confirms it doesn't crash


# ---------------------------------------------------------------------------
# Test: list_policies
# ---------------------------------------------------------------------------

class TestListPolicies(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_list_policies_returns_list(self):
        payload = [
            {"name": "standard", "family": "core", "description": "Standard policy"},
            {"name": "strict", "family": "core", "description": "Strict policy"},
        ]
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.list_policies()
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], Policy)
        self.assertEqual(result[0].name, "standard")
        self.assertEqual(result[1].name, "strict")

    def test_list_policies_wrapped_response(self):
        payload = {"policies": [{"name": "permissive", "family": "core", "description": ""}]}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.list_policies()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "permissive")

    def test_list_policies_with_scope(self):
        payload = []
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
            self.client.list_policies(scope="payments")
            req = mock_open.call_args[0][0]
            self.assertIn("scope=payments", req.full_url)


# ---------------------------------------------------------------------------
# Test: initiate_handshake
# ---------------------------------------------------------------------------

class TestInitiateHandshake(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")
        self.handshake_payload = {
            "id": "hs_abc",
            "status": "pending",
            "mode": "mutual",
            "policyId": "standard",
            "parties": [
                {"entityRef": "agent-a", "role": "initiator"},
                {"entityRef": "merchant-b", "role": "responder"},
            ],
            "createdAt": "2026-01-01T00:00:00Z",
        }

    def test_initiate_handshake_returns_handshake(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self.handshake_payload)):
            result = self.client.initiate_handshake(
                mode="mutual",
                policy_id="standard",
                parties=[
                    {"entityRef": "agent-a", "role": "initiator"},
                    {"entityRef": "merchant-b", "role": "responder"},
                ],
            )
        self.assertIsInstance(result, Handshake)
        self.assertEqual(result.id, "hs_abc")
        self.assertEqual(result.mode, "mutual")
        self.assertEqual(result.status, "pending")
        self.assertEqual(result.policy_id, "standard")

    def test_initiate_handshake_posts_to_correct_path(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self.handshake_payload)) as mock_open:
            self.client.initiate_handshake(
                mode="mutual",
                policy_id="standard",
                parties=[{"entityRef": "a", "role": "initiator"}],
            )
            req = mock_open.call_args[0][0]
            self.assertIn("/api/handshake/initiate", req.full_url)
            self.assertEqual(req.get_method(), "POST")

    def test_initiate_handshake_with_optional_params(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self.handshake_payload)) as mock_open:
            self.client.initiate_handshake(
                mode="mutual",
                policy_id="standard",
                parties=[{"entityRef": "a", "role": "initiator"}],
                binding={"context": "checkout"},
                interaction_id="interaction-xyz",
            )
            req = mock_open.call_args[0][0]
            body = json.loads(req.data.decode())
            self.assertEqual(body["binding"], {"context": "checkout"})
            self.assertEqual(body["interactionId"], "interaction-xyz")


# ---------------------------------------------------------------------------
# Test: present
# ---------------------------------------------------------------------------

class TestPresent(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")
        self.presentation_payload = {
            "presentationId": "pres_001",
            "partyRole": "initiator",
            "status": "submitted",
            "createdAt": "2026-01-01T00:00:00Z",
        }

    def test_present_returns_presentation(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self.presentation_payload)):
            result = self.client.present(
                handshake_id="hs_abc",
                party_role="initiator",
                presentation_type="ep_trust_profile",
                claims={"score": 90},
            )
        self.assertIsInstance(result, Presentation)
        self.assertEqual(result.presentation_id, "pres_001")
        self.assertEqual(result.party_role, "initiator")

    def test_present_url_contains_handshake_id(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self.presentation_payload)) as mock_open:
            self.client.present(
                handshake_id="hs_special",
                party_role="initiator",
                presentation_type="ep_trust_profile",
                claims={},
            )
            req = mock_open.call_args[0][0]
            self.assertIn("hs_special", req.full_url)
            self.assertIn("/present", req.full_url)


# ---------------------------------------------------------------------------
# Test: verify
# ---------------------------------------------------------------------------

class TestVerify(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_verify_returns_verification_result(self):
        payload = {
            "handshakeId": "hs_abc",
            "result": "accepted",
            "reasonCodes": [],
            "evaluatedAt": "2026-01-01T00:00:00Z",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.verify("hs_abc")
        self.assertIsInstance(result, VerificationResult)
        self.assertEqual(result.result, "accepted")
        self.assertEqual(result.handshake_id, "hs_abc")

    def test_verify_posts_to_correct_path(self):
        payload = {"handshakeId": "hs_abc", "result": "rejected", "reasonCodes": ["no_profile"], "evaluatedAt": ""}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
            self.client.verify("hs_abc")
            req = mock_open.call_args[0][0]
            self.assertIn("/api/handshake/hs_abc/verify", req.full_url)
            self.assertEqual(req.get_method(), "POST")


# ---------------------------------------------------------------------------
# Test: gate
# ---------------------------------------------------------------------------

class TestGate(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_gate_returns_gate_result(self):
        payload = {"decision": "allow", "commitRef": "epc_001", "reasons": [], "appealPath": None}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.gate(entity_id="merchant-xyz", action="purchase")
        self.assertIsInstance(result, GateResult)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.commit_ref, "epc_001")

    def test_gate_deny_decision(self):
        payload = {"decision": "deny", "commitRef": None, "reasons": ["low_confidence"], "appealPath": "/appeal"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.gate(entity_id="bad-actor", action="purchase", policy="strict")
        self.assertEqual(result.decision, "deny")
        self.assertIn("low_confidence", result.reasons)


# ---------------------------------------------------------------------------
# Test: signoff (issue_challenge, attest, deny_challenge, revoke_signoff, consume_signoff)
# ---------------------------------------------------------------------------

class TestSignoff(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_issue_challenge_returns_challenge(self):
        payload = {
            "challengeId": "ch_001",
            "entityId": "entity-a",
            "scope": "payment",
            "nonce": "abc123",
            "expiresAt": "2026-01-01T01:00:00Z",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.issue_challenge(entity_id="entity-a", scope="payment")
        self.assertIsInstance(result, SignoffChallenge)
        self.assertEqual(result.challenge_id, "ch_001")
        self.assertEqual(result.scope, "payment")

    def test_attest_returns_attestation(self):
        payload = {
            "attestationId": "att_001",
            "challengeId": "ch_001",
            "status": "valid",
            "signoffId": "so_001",
            "createdAt": "2026-01-01T00:00:00Z",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.attest(
                challenge_id="ch_001",
                signature="sig_xyz",
                payload={"data": "value"},
            )
        self.assertIsInstance(result, SignoffAttestation)
        self.assertEqual(result.attestation_id, "att_001")
        self.assertEqual(result.status, "valid")

    def test_deny_challenge_returns_deny_result(self):
        payload = {"challengeId": "ch_001", "status": "denied", "deniedAt": "2026-01-01T00:00:00Z"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.deny_challenge(challenge_id="ch_001", reason="Not authorised")
        self.assertIsInstance(result, DenyResult)

    def test_revoke_signoff_returns_revoke_result(self):
        payload = {"id": "so_001", "status": "revoked", "revokedAt": "2026-01-01T00:00:00Z"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.revoke_signoff(challenge_id="ch_001", reason="Expired")
        self.assertIsInstance(result, RevokeResult)

    def test_consume_signoff_returns_consumption(self):
        payload = {
            "signoffId": "so_001",
            "action": "payment",
            "consumedAt": "2026-01-01T00:00:00Z",
            "consumptionId": "cons_001",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.consume_signoff(signoff_id="so_001", action="payment")
        self.assertIsInstance(result, SignoffConsumption)


# ---------------------------------------------------------------------------
# Test: handshake helpers (get_handshake, revoke_handshake, consume)
# ---------------------------------------------------------------------------

class TestHandshakeHelpers(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_get_handshake_returns_handshake(self):
        payload = {
            "id": "hs_abc",
            "status": "active",
            "mode": "mutual",
            "policyId": "standard",
            "parties": [],
            "createdAt": "",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.get_handshake("hs_abc")
        self.assertIsInstance(result, Handshake)
        self.assertEqual(result.id, "hs_abc")

    def test_revoke_handshake_returns_revoke_result(self):
        payload = {"id": "hs_abc", "status": "revoked", "revokedAt": "2026-01-01T00:00:00Z"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.revoke_handshake("hs_abc")
        self.assertIsInstance(result, RevokeResult)

    def test_consume_handshake_returns_consumption(self):
        payload = {
            "handshakeId": "hs_abc",
            "consumedAt": "2026-01-01T00:00:00Z",
            "consumptionId": "cons_abc",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.consume("hs_abc", receipt_data={"ref": "order-99"})
        self.assertIsInstance(result, Consumption)


# ---------------------------------------------------------------------------
# Test: delegation
# ---------------------------------------------------------------------------

class TestDelegation(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_create_delegation_returns_delegation(self):
        payload = {
            "delegationId": "del_001",
            "delegatorId": "principal-a",
            "delegateeId": "agent-b",
            "scope": "payments",
            "policyId": "standard",
            "status": "active",
            "createdAt": "2026-01-01T00:00:00Z",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.create_delegation(
                delegator_id="principal-a",
                delegatee_id="agent-b",
                scope="payments",
                policy_id="standard",
            )
        self.assertIsInstance(result, Delegation)

    def test_verify_delegation_returns_delegation_verification(self):
        payload = {"delegationId": "del_001", "valid": True, "verifiedAt": "2026-01-01T00:00:00Z"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.verify_delegation("del_001")
        self.assertIsInstance(result, DelegationVerification)


# ---------------------------------------------------------------------------
# Test: commit
# ---------------------------------------------------------------------------

class TestCommit(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key")

    def test_issue_commit_returns_commit(self):
        payload = {
            "commitId": "epc_001",
            "handshakeId": "hs_abc",
            "action": "purchase",
            "status": "active",
            "createdAt": "2026-01-01T00:00:00Z",
        }
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.issue_commit(
                handshake_id="hs_abc",
                action="purchase",
                payload={"ref": "order-1"},
            )
        self.assertIsInstance(result, Commit)

    def test_verify_commit_returns_commit_verification(self):
        payload = {"commitId": "epc_001", "valid": True, "verifiedAt": "2026-01-01T00:00:00Z"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = self.client.verify_commit("epc_001")
        self.assertIsInstance(result, CommitVerification)


# ---------------------------------------------------------------------------
# Test: error handling
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):

    def setUp(self):
        self.client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key", retries=0)

    def test_401_raises_ep_error(self):
        err = _mock_http_error(401, {"error": "Unauthorized", "code": "unauthorized"})
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(EPError) as ctx:
                self.client.list_policies()
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(ctx.exception.code, "unauthorized")

    def test_404_raises_ep_error(self):
        err = _mock_http_error(404, {"error": "Not found"})
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(EPError) as ctx:
                self.client.get_handshake("nonexistent")
        self.assertEqual(ctx.exception.status, 404)

    def test_422_raises_ep_error_with_message(self):
        err = _mock_http_error(422, {"error": "Validation failed", "code": "validation_error"})
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(EPError) as ctx:
                self.client.issue_challenge(entity_id="", scope="")
        self.assertIn("Validation failed", str(ctx.exception))

    def test_500_retries_then_raises(self):
        """With retries=0, a 500 raises immediately."""
        err = _mock_http_error(500, {"error": "Server error"})
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(EPError) as ctx:
                self.client.list_policies()
        self.assertEqual(ctx.exception.status, 500)

    def test_500_retries_with_retries_set(self):
        """With retries=2, a persistent 500 retries 3 times total."""
        client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key", retries=2)
        err = _mock_http_error(500, {"error": "Server error"})
        with patch("urllib.request.urlopen", side_effect=err) as mock_open:
            with self.assertRaises(EPError):
                client.list_policies()
            # 1 initial + 2 retries = 3 calls
            self.assertEqual(mock_open.call_count, 3)

    def test_network_error_raises_ep_error(self):
        import urllib.error
        net_err = urllib.error.URLError(reason="Connection refused")
        with patch("urllib.request.urlopen", side_effect=net_err):
            with self.assertRaises(EPError) as ctx:
                self.client.list_policies()
        self.assertEqual(ctx.exception.code, "network_error")

    def test_4xx_does_not_retry(self):
        """4xx errors should not be retried."""
        client = EPClient(base_url="https://emiliaprotocol.ai", api_key="key", retries=2)
        err = _mock_http_error(403, {"error": "Forbidden"})
        with patch("urllib.request.urlopen", side_effect=err) as mock_open:
            with self.assertRaises(EPError):
                client.list_policies()
            # Should only be called once — no retries on 4xx
            self.assertEqual(mock_open.call_count, 1)


# ---------------------------------------------------------------------------
# Test: dataclass from_dict factories
# ---------------------------------------------------------------------------

class TestFromDictFactories(unittest.TestCase):

    def test_policy_from_dict_full(self):
        d = {"name": "strict", "family": "core", "description": "High bar", "minConfidence": "established", "minScore": 80}
        p = Policy.from_dict(d)
        self.assertEqual(p.name, "strict")
        self.assertEqual(p.min_confidence, "established")
        self.assertEqual(p.min_score, 80)

    def test_policy_from_dict_minimal(self):
        p = Policy.from_dict({})
        self.assertEqual(p.name, "")
        self.assertIsNone(p.min_confidence)

    def test_handshake_from_dict_with_parties(self):
        d = {
            "id": "hs_001",
            "status": "active",
            "mode": "mutual",
            "policyId": "standard",
            "parties": [{"entityRef": "a", "role": "initiator"}],
            "createdAt": "2026-01-01T00:00:00Z",
        }
        h = Handshake.from_dict(d)
        self.assertEqual(h.id, "hs_001")
        self.assertEqual(len(h.parties), 1)
        self.assertEqual(h.parties[0].entity_ref, "a")

    def test_verification_result_from_dict(self):
        d = {"handshakeId": "hs_001", "result": "accepted", "reasonCodes": ["ok"], "evaluatedAt": "2026-01-01T00:00:00Z"}
        vr = VerificationResult.from_dict(d)
        self.assertEqual(vr.result, "accepted")
        self.assertEqual(vr.reason_codes, ["ok"])

    def test_gate_result_from_dict(self):
        d = {"decision": "review", "commitRef": None, "reasons": ["low_score"], "appealPath": "/appeal"}
        gr = GateResult.from_dict(d)
        self.assertEqual(gr.decision, "review")
        self.assertIsNone(gr.commit_ref)
        self.assertEqual(gr.appeal_path, "/appeal")

    def test_signoff_challenge_from_dict(self):
        d = {
            "challengeId": "ch_abc",
            "entityId": "ent-1",
            "scope": "checkout",
            "nonce": "nonce123",
            "expiresAt": "2026-01-01T01:00:00Z",
        }
        sc = SignoffChallenge.from_dict(d)
        self.assertEqual(sc.challenge_id, "ch_abc")
        self.assertEqual(sc.nonce, "nonce123")

    def test_presentation_from_dict(self):
        d = {"presentationId": "pres_1", "partyRole": "initiator", "status": "submitted", "createdAt": ""}
        pr = Presentation.from_dict(d)
        self.assertEqual(pr.presentation_id, "pres_1")
        self.assertEqual(pr.status, "submitted")

    def test_initiate_handshake_params_to_dict(self):
        params = InitiateHandshakeParams(
            mode="mutual",
            policy_id="standard",
            parties=[Party(entity_ref="a", role="initiator")],
            binding={"ctx": "test"},
            interaction_id="ix_001",
        )
        d = params.to_dict()
        self.assertEqual(d["mode"], "mutual")
        self.assertEqual(d["policyId"], "standard")
        self.assertEqual(d["parties"][0]["entityRef"], "a")
        self.assertEqual(d["binding"], {"ctx": "test"})
        self.assertEqual(d["interactionId"], "ix_001")

    def test_gate_params_to_dict_minimal(self):
        params = GateParams(entity_id="ent-1", action="purchase")
        d = params.to_dict()
        self.assertEqual(d["entity_id"], "ent-1")
        self.assertEqual(d["action"], "purchase")
        self.assertEqual(d["policy"], "standard")
        self.assertNotIn("handshake_id", d)

    def test_consume_params_to_dict_empty(self):
        params = ConsumeParams()
        d = params.to_dict()
        self.assertEqual(d, {})

    def test_consume_params_to_dict_with_receipt(self):
        params = ConsumeParams(receipt_data={"ref": "order-1"})
        d = params.to_dict()
        self.assertEqual(d["receiptData"], {"ref": "order-1"})

    def test_create_delegation_params_to_dict(self):
        params = CreateDelegationParams(
            delegator_id="p1",
            delegatee_id="a1",
            scope="payments",
            policy_id="standard",
            expires_at="2026-12-31T23:59:59Z",
        )
        d = params.to_dict()
        self.assertEqual(d["delegatorId"], "p1")
        self.assertEqual(d["delegateeId"], "a1")
        self.assertEqual(d["expiresAt"], "2026-12-31T23:59:59Z")

    def test_issue_commit_params_to_dict(self):
        params = IssueCommitParams(
            handshake_id="hs_1",
            action="purchase",
            payload={"amount": 100},
            binding={"ref": "ext-001"},
        )
        d = params.to_dict()
        self.assertEqual(d["handshakeId"], "hs_1")
        self.assertEqual(d["action"], "purchase")
        self.assertEqual(d["binding"], {"ref": "ext-001"})


# ---------------------------------------------------------------------------
# Test: EPError attributes
# ---------------------------------------------------------------------------

class TestEPError(unittest.TestCase):

    def test_ep_error_has_status_and_code(self):
        err = EPError("Something failed", status=422, code="validation_error")
        self.assertEqual(err.status, 422)
        self.assertEqual(err.code, "validation_error")
        self.assertIn("Something failed", str(err))

    def test_ep_error_defaults_none(self):
        err = EPError("Network failure")
        self.assertIsNone(err.status)
        self.assertIsNone(err.code)

    def test_ep_error_is_exception(self):
        with self.assertRaises(EPError):
            raise EPError("test")


if __name__ == "__main__":
    unittest.main()
