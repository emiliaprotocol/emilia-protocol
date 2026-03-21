"""EMILIA Protocol — Minimal Python SDK.

Wraps the 5 core protocol endpoints + signoff extension + consume.
Zero dependencies — uses urllib.request. Target: < 300 lines.

    from ep import EPClient

    client = EPClient(base_url="https://emiliaprotocol.ai", api_key="ep_live_...")
    policies = client.list_policies()
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

from .types import (
    AttestParams,
    Consumption,
    ConsumeParams,
    ConsumeSignoffParams,
    GateParams,
    GateResult,
    Handshake,
    InitiateHandshakeParams,
    IssueChallengeParams,
    Policy,
    Presentation,
    PresentParams,
    SignoffAttestation,
    SignoffChallenge,
    SignoffConsumption,
    VerificationResult,
)

__all__ = [
    "EPClient",
    "EPError",
    # Re-export types
    "Policy",
    "Handshake",
    "Presentation",
    "VerificationResult",
    "GateResult",
    "SignoffChallenge",
    "SignoffAttestation",
    "SignoffConsumption",
    "Consumption",
    # Param types
    "InitiateHandshakeParams",
    "PresentParams",
    "GateParams",
    "IssueChallengeParams",
    "AttestParams",
    "ConsumeSignoffParams",
    "ConsumeParams",
]

__version__ = "0.9.0"


class EPError(Exception):
    """Raised when the EP API returns a non-2xx response or a network error occurs."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code


class EPClient:
    """Minimal client for the EMILIA Protocol API.

    Covers the 5 core endpoints (listPolicies, initiateHandshake, present,
    verify, gate), the signoff extension (issueChallenge, attest,
    consumeSignoff), and consumption (consume).

    Zero dependencies -- uses urllib.request (stdlib).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 10,
        retries: int = 2,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key or ""
        self._timeout = timeout
        self._retries = retries

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        auth: bool = False,
    ) -> Any:
        url = f"{self._base_url}{path}"
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"emilia-protocol-python/{__version__}",
        }
        if auth and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None

        last_err: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                raw_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                try:
                    payload = json.loads(raw_body)
                except (json.JSONDecodeError, ValueError):
                    payload = {}
                msg = payload.get("error", f"EP API error: {e.code}")
                code = payload.get("code")
                err = EPError(msg, status=e.code, code=code)
                # Only retry on 5xx
                if e.code < 500:
                    raise err
                last_err = err
            except urllib.error.URLError as e:
                last_err = EPError(str(e.reason), code="network_error")
            except Exception as e:
                last_err = EPError(str(e), code="network_error")

        if last_err is not None:
            raise last_err
        raise EPError("Unknown error", code="network_error")

    # ------------------------------------------------------------------
    # Core 5 endpoints
    # ------------------------------------------------------------------

    def list_policies(self, scope: Optional[str] = None) -> List[Policy]:
        """List available trust policies."""
        qs = f"?scope={quote(scope)}" if scope else ""
        data = self._request("GET", f"/api/policies{qs}")
        if isinstance(data, list):
            return [Policy.from_dict(d) for d in data]
        return [Policy.from_dict(d) for d in data.get("policies", data) if isinstance(d, dict)]

    def initiate_handshake(
        self,
        mode: str,
        policy_id: str,
        parties: List[Dict[str, str]],
        binding: Optional[Dict[str, Any]] = None,
        interaction_id: Optional[str] = None,
    ) -> Handshake:
        """Initiate a trust handshake between parties."""
        params = InitiateHandshakeParams(
            mode=mode,
            policy_id=policy_id,
            parties=[
                __import__("ep.types", fromlist=["Party"]).Party(
                    entity_ref=p.get("entityRef", p.get("entity_ref", "")),
                    role=p.get("role", ""),
                )
                for p in parties
            ],
            binding=binding,
            interaction_id=interaction_id,
        )
        data = self._request("POST", "/api/handshake/initiate", params.to_dict(), auth=True)
        return Handshake.from_dict(data)

    def present(
        self,
        handshake_id: str,
        party_role: str,
        presentation_type: str,
        claims: Dict[str, Any],
        issuer_ref: Optional[str] = None,
        disclosure_mode: Optional[str] = None,
    ) -> Presentation:
        """Present credentials to a handshake."""
        params = PresentParams(
            party_role=party_role,
            presentation_type=presentation_type,
            claims=claims,
            issuer_ref=issuer_ref,
            disclosure_mode=disclosure_mode,
        )
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/present",
            params.to_dict(),
            auth=True,
        )
        return Presentation.from_dict(data)

    def verify(self, handshake_id: str) -> VerificationResult:
        """Verify a handshake -- evaluate all presentations against policy."""
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/verify",
            auth=True,
        )
        return VerificationResult.from_dict(data)

    def gate(
        self,
        entity_id: str,
        action: str,
        policy: str = "standard",
        handshake_id: Optional[str] = None,
        value_usd: Optional[float] = None,
        delegation_id: Optional[str] = None,
    ) -> GateResult:
        """Pre-action trust gate. Returns allow/deny/review."""
        params = GateParams(
            entity_id=entity_id,
            action=action,
            policy=policy,
            handshake_id=handshake_id,
            value_usd=value_usd,
            delegation_id=delegation_id,
        )
        data = self._request("POST", "/api/gate", params.to_dict(), auth=True)
        return GateResult.from_dict(data)

    # ------------------------------------------------------------------
    # Signoff extension
    # ------------------------------------------------------------------

    def issue_challenge(
        self,
        entity_id: str,
        scope: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SignoffChallenge:
        """Issue a signoff challenge for an entity."""
        params = IssueChallengeParams(entity_id=entity_id, scope=scope, context=context)
        data = self._request("POST", "/api/signoff/challenge", params.to_dict(), auth=True)
        return SignoffChallenge.from_dict(data)

    def attest(
        self,
        challenge_id: str,
        signature: str,
        payload: Dict[str, Any],
    ) -> SignoffAttestation:
        """Attest to a signoff challenge with a cryptographic signature."""
        params = AttestParams(signature=signature, payload=payload)
        data = self._request(
            "POST",
            f"/api/signoff/{quote(challenge_id, safe='')}/attest",
            params.to_dict(),
            auth=True,
        )
        return SignoffAttestation.from_dict(data)

    def consume_signoff(
        self,
        signoff_id: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SignoffConsumption:
        """Consume a signoff -- mark it as used for a specific action."""
        params = ConsumeSignoffParams(action=action, context=context)
        data = self._request(
            "POST",
            f"/api/signoff/{quote(signoff_id, safe='')}/consume",
            params.to_dict(),
            auth=True,
        )
        return SignoffConsumption.from_dict(data)

    # ------------------------------------------------------------------
    # Consumption
    # ------------------------------------------------------------------

    def consume(
        self,
        handshake_id: str,
        receipt_data: Optional[Dict[str, Any]] = None,
    ) -> Consumption:
        """Consume a handshake -- finalize and optionally bind a receipt."""
        params = ConsumeParams(receipt_data=receipt_data)
        body = params.to_dict() or None
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/consume",
            body,
            auth=True,
        )
        return Consumption.from_dict(data)
