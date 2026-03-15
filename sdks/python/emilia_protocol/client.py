"""
EMILIA Protocol Python Client

Portable trust evaluation and appeals for counterparties, software, and machine actors.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import requests


class EmiliaApiError(Exception):
    """Raised when the EP API returns a non-2xx response."""

    def __init__(self, message: str, status: int, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class EmiliaClient:
    """EP client for trust profiles, policy evaluation, install preflight, disputes, and appeals."""

    def __init__(self, base_url: str = "https://emiliaprotocol.ai", api_key: Optional[str] = None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _get(self, path: str) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}{path}", headers=self._headers(), timeout=self.timeout)
        if not response.ok:
            payload = None
            try:
                payload = response.json()
            except ValueError:
                payload = None
            message = payload.get("error") if isinstance(payload, dict) else response.text or response.reason
            raise EmiliaApiError(str(message), response.status_code, payload)
        return response.json()

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}{path}", json=body, headers=self._headers(), timeout=self.timeout)
        if not response.ok:
            payload = None
            try:
                payload = response.json()
            except ValueError:
                payload = None
            message = payload.get("error") if isinstance(payload, dict) else response.text or response.reason
            raise EmiliaApiError(str(message), response.status_code, payload)
        return response.json()

    def get_trust_profile(self, entity_id: str) -> Dict[str, Any]:
        """Full trust profile — the canonical read surface."""
        return self._get(f"/api/trust/profile/{entity_id}")

    def evaluate_trust(self, entity_id: str, policy: Any = "standard", context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate against a trust policy with optional context."""
        return self._post("/api/trust/evaluate", {
            "entity_id": entity_id,
            "policy": policy,
            "context": context,
        })

    def install_preflight(self, entity_id: str, policy: Any = "standard", context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """EP-SX: Should I install this plugin/app/package?"""
        return self._post("/api/trust/install-preflight", {
            "entity_id": entity_id,
            "policy": policy,
            "context": context,
        })

    def submit_receipt(
        self,
        entity_id: str,
        transaction_ref: str,
        transaction_type: str,
        agent_behavior: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        provenance_tier: str = "self_attested",
        request_bilateral: bool = False,
        **signals: Any,
    ) -> Dict[str, Any]:
        """Submit a transaction receipt. Idempotent on transaction_ref."""
        body: Dict[str, Any] = {
            "entity_id": entity_id,
            "transaction_ref": transaction_ref,
            "transaction_type": transaction_type,
            "agent_behavior": agent_behavior,
            "context": context,
            "provenance_tier": provenance_tier,
            "request_bilateral": request_bilateral,
        }
        body.update(signals)
        return self._post("/api/receipts/submit", body)

    def file_dispute(
        self,
        receipt_id: str,
        reason: str,
        description: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """File a formal dispute against a receipt."""
        return self._post("/api/disputes/file", {
            "receipt_id": receipt_id,
            "reason": reason,
            "description": description,
            "evidence": evidence,
        })

    def report_trust_issue(
        self,
        entity_id: str,
        report_type: str,
        description: str,
        contact_email: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Report a trust issue — no auth required. Human appeal channel."""
        return self._post("/api/disputes/report", {
            "entity_id": entity_id,
            "report_type": report_type,
            "description": description,
            "contact_email": contact_email,
            "evidence": evidence,
        })

    def get_score(self, entity_id: str) -> Dict[str, Any]:
        """Legacy: compatibility score only. Use get_trust_profile() instead."""
        return self._get(f"/api/score/{entity_id}")
