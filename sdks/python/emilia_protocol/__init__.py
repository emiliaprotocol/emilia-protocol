"""
EMILIA Protocol Python SDK

The trust layer for agentic commerce.

Usage:
    from emilia_protocol import EmiliaClient

    ep = EmiliaClient(api_key="ep_live_...")
    score = ep.get_score("rex-booking-v1")

    if score.emilia_score >= 80:
        # Trust this entity
        pass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

import httpx

__version__ = "0.1.0"
__all__ = ["EmiliaClient", "EmiliaError", "ScoreResult", "ReceiptResult", "VerifyResult"]


class EmiliaError(Exception):
    """Raised when the EP API returns an error."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


# =============================================================================
# Data classes
# =============================================================================


@dataclass
class ScoreBreakdown:
    delivery_accuracy: Optional[float] = None
    product_accuracy: Optional[float] = None
    price_integrity: Optional[float] = None
    return_processing: Optional[float] = None
    agent_satisfaction: Optional[float] = None
    consistency: Optional[float] = None


@dataclass
class ScoreResult:
    entity_id: str
    display_name: str
    entity_type: str
    emilia_score: float
    established: bool
    total_receipts: int
    verified: bool
    description: Optional[str] = None
    category: Optional[str] = None
    capabilities: Optional[List[str]] = None
    successful_receipts: int = 0
    success_rate: Optional[float] = None
    breakdown: Optional[ScoreBreakdown] = None
    a2a_endpoint: Optional[str] = None
    ucp_profile_url: Optional[str] = None
    member_since: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScoreResult":
        breakdown = None
        if d.get("breakdown"):
            breakdown = ScoreBreakdown(**d["breakdown"])
        return cls(
            entity_id=d["entity_id"],
            display_name=d["display_name"],
            entity_type=d["entity_type"],
            emilia_score=d["emilia_score"],
            established=d["established"],
            total_receipts=d["total_receipts"],
            verified=d["verified"],
            description=d.get("description"),
            category=d.get("category"),
            capabilities=d.get("capabilities"),
            successful_receipts=d.get("successful_receipts", 0),
            success_rate=d.get("success_rate"),
            breakdown=breakdown,
            a2a_endpoint=d.get("a2a_endpoint"),
            ucp_profile_url=d.get("ucp_profile_url"),
            member_since=d.get("member_since"),
        )


@dataclass
class ReceiptResult:
    receipt_id: str
    entity_id: str
    composite_score: float
    receipt_hash: str
    created_at: str
    updated_emilia_score: float
    updated_total_receipts: int

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReceiptResult":
        r = d["receipt"]
        s = d["entity_score"]
        return cls(
            receipt_id=r["receipt_id"],
            entity_id=r["entity_id"],
            composite_score=r["composite_score"],
            receipt_hash=r["receipt_hash"],
            created_at=r["created_at"],
            updated_emilia_score=s["emilia_score"],
            updated_total_receipts=s["total_receipts"],
        )


@dataclass
class VerifyResult:
    receipt_id: str
    receipt_hash: str
    anchored: bool
    verified: bool
    batch: Optional[Dict[str, Any]] = None
    proof: Optional[List[Dict[str, str]]] = None
    how_to_verify: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VerifyResult":
        return cls(
            receipt_id=d["receipt_id"],
            receipt_hash=d["receipt_hash"],
            anchored=d.get("anchored", False),
            verified=d.get("verified", False),
            batch=d.get("batch"),
            proof=d.get("proof"),
            how_to_verify=d.get("how_to_verify"),
        )


# =============================================================================
# Client
# =============================================================================


class EmiliaClient:
    """
    Python client for the EMILIA Protocol (EP).

    Args:
        base_url: EP implementation URL. Default: https://emiliaprotocol.ai
        api_key: EP API key for write operations (ep_live_...).
        timeout: Request timeout in seconds. Default: 10.
    """

    def __init__(
        self,
        base_url: str = "https://emiliaprotocol.ai",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "EmiliaClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Dict[str, Any]] = None,
        auth: bool = False,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}

        if auth:
            if not self.api_key:
                raise EmiliaError("API key required. Pass api_key to EmiliaClient.", 401)
            headers["Authorization"] = f"Bearer {self.api_key}"

        res = self._client.request(method, url, headers=headers, json=body)
        data = res.json()

        if res.status_code >= 400:
            msg = data.get("error", f"EP API error: {res.status_code}")
            raise EmiliaError(msg, res.status_code)

        return data

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_score(self, entity_id: str) -> ScoreResult:
        """Look up an entity's EMILIA Score. No auth required."""
        data = self._request("GET", f"/api/score/{quote(entity_id)}")
        return ScoreResult.from_dict(data)

    def submit_receipt(
        self,
        entity_id: str,
        transaction_type: str,
        *,
        transaction_ref: Optional[str] = None,
        delivery_accuracy: Optional[float] = None,
        product_accuracy: Optional[float] = None,
        price_integrity: Optional[float] = None,
        return_processing: Optional[float] = None,
        agent_satisfaction: Optional[float] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> ReceiptResult:
        """Submit a transaction receipt. Requires API key."""
        body: Dict[str, Any] = {
            "entity_id": entity_id,
            "transaction_type": transaction_type,
        }
        if transaction_ref is not None:
            body["transaction_ref"] = transaction_ref
        if delivery_accuracy is not None:
            body["delivery_accuracy"] = delivery_accuracy
        if product_accuracy is not None:
            body["product_accuracy"] = product_accuracy
        if price_integrity is not None:
            body["price_integrity"] = price_integrity
        if return_processing is not None:
            body["return_processing"] = return_processing
        if agent_satisfaction is not None:
            body["agent_satisfaction"] = agent_satisfaction
        if evidence is not None:
            body["evidence"] = evidence

        data = self._request("POST", "/api/receipts/submit", body=body, auth=True)
        return ReceiptResult.from_dict(data)

    def register_entity(
        self,
        entity_id: str,
        display_name: str,
        entity_type: str,
        description: str,
        *,
        capabilities: Optional[List[str]] = None,
        website_url: Optional[str] = None,
        category: Optional[str] = None,
        service_area: Optional[str] = None,
        a2a_endpoint: Optional[str] = None,
        ucp_profile_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new entity. Requires API key."""
        body: Dict[str, Any] = {
            "entity_id": entity_id,
            "display_name": display_name,
            "entity_type": entity_type,
            "description": description,
        }
        if capabilities:
            body["capabilities"] = capabilities
        if website_url:
            body["website_url"] = website_url
        if category:
            body["category"] = category
        if service_area:
            body["service_area"] = service_area
        if a2a_endpoint:
            body["a2a_endpoint"] = a2a_endpoint
        if ucp_profile_url:
            body["ucp_profile_url"] = ucp_profile_url

        return self._request("POST", "/api/entities/register", body=body, auth=True)

    def verify_receipt(self, receipt_id: str) -> VerifyResult:
        """Verify a receipt against the on-chain Merkle root. No auth required."""
        data = self._request("GET", f"/api/verify/{quote(receipt_id)}")
        return VerifyResult.from_dict(data)

    def search_entities(
        self,
        query: str,
        *,
        entity_type: Optional[str] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Search for entities. No auth required."""
        params: Dict[str, str] = {"q": query}
        if entity_type:
            params["type"] = entity_type
        if min_score is not None:
            params["min_score"] = str(min_score)
        data = self._request("GET", f"/api/entities/search?{urlencode(params)}")
        return data.get("entities", [])

    def get_leaderboard(
        self,
        *,
        limit: int = 10,
        entity_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get top-scored entities. No auth required."""
        params: Dict[str, str] = {"limit": str(min(limit, 50))}
        if entity_type:
            params["type"] = entity_type
        data = self._request("GET", f"/api/leaderboard?{urlencode(params)}")
        return data.get("entities", [])

    # -------------------------------------------------------------------------
    # Convenience
    # -------------------------------------------------------------------------

    def is_trusted(self, entity_id: str, min_score: float = 70) -> bool:
        """Check if an entity meets a minimum trust threshold."""
        try:
            score = self.get_score(entity_id)
            return score.emilia_score >= min_score and score.established
        except EmiliaError:
            return False
