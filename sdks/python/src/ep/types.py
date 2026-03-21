"""EMILIA Protocol — Python SDK type definitions (dataclasses)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Params
# ---------------------------------------------------------------------------


@dataclass
class Party:
    entity_ref: str
    role: str  # "initiator" | "responder"


@dataclass
class InitiateHandshakeParams:
    mode: str  # "mutual" | "one-way" | "delegated"
    policy_id: str
    parties: List[Party]
    binding: Optional[Dict[str, Any]] = None
    interaction_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "mode": self.mode,
            "policyId": self.policy_id,
            "parties": [{"entityRef": p.entity_ref, "role": p.role} for p in self.parties],
        }
        if self.binding is not None:
            d["binding"] = self.binding
        if self.interaction_id is not None:
            d["interactionId"] = self.interaction_id
        return d


@dataclass
class PresentParams:
    party_role: str
    presentation_type: str  # "ep_trust_profile" | "verifiable_credential" | "attestation"
    claims: Dict[str, Any]
    issuer_ref: Optional[str] = None
    disclosure_mode: Optional[str] = None  # "full" | "selective" | "zk"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "partyRole": self.party_role,
            "presentationType": self.presentation_type,
            "claims": self.claims,
        }
        if self.issuer_ref is not None:
            d["issuerRef"] = self.issuer_ref
        if self.disclosure_mode is not None:
            d["disclosureMode"] = self.disclosure_mode
        return d


@dataclass
class GateParams:
    entity_id: str
    action: str
    policy: str = "standard"
    handshake_id: Optional[str] = None
    value_usd: Optional[float] = None
    delegation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "entity_id": self.entity_id,
            "action": self.action,
            "policy": self.policy,
        }
        if self.handshake_id is not None:
            d["handshake_id"] = self.handshake_id
        if self.value_usd is not None:
            d["value_usd"] = self.value_usd
        if self.delegation_id is not None:
            d["delegation_id"] = self.delegation_id
        return d


@dataclass
class IssueChallengeParams:
    entity_id: str
    scope: str
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"entity_id": self.entity_id, "scope": self.scope}
        if self.context is not None:
            d["context"] = self.context
        return d


@dataclass
class AttestParams:
    signature: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"signature": self.signature, "payload": self.payload}


@dataclass
class ConsumeSignoffParams:
    action: str
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"action": self.action}
        if self.context is not None:
            d["context"] = self.context
        return d


@dataclass
class ConsumeParams:
    receipt_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.receipt_data is not None:
            d["receiptData"] = self.receipt_data
        return d


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    name: str = ""
    family: str = ""
    description: str = ""
    min_confidence: Optional[str] = None
    min_score: Optional[int] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Policy":
        return cls(
            name=d.get("name", ""),
            family=d.get("family", ""),
            description=d.get("description", ""),
            min_confidence=d.get("minConfidence"),
            min_score=d.get("minScore"),
        )


@dataclass
class Handshake:
    id: str = ""
    status: str = ""
    mode: str = ""
    policy_id: str = ""
    parties: List[Party] = field(default_factory=list)
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Handshake":
        parties = [Party(entity_ref=p.get("entityRef", ""), role=p.get("role", "")) for p in d.get("parties", [])]
        return cls(
            id=d.get("id", ""),
            status=d.get("status", ""),
            mode=d.get("mode", ""),
            policy_id=d.get("policyId", ""),
            parties=parties,
            created_at=d.get("createdAt", ""),
        )


@dataclass
class Presentation:
    presentation_id: str = ""
    party_role: str = ""
    status: str = ""
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Presentation":
        return cls(
            presentation_id=d.get("presentationId", ""),
            party_role=d.get("partyRole", ""),
            status=d.get("status", ""),
            created_at=d.get("createdAt", ""),
        )


@dataclass
class VerificationResult:
    handshake_id: str = ""
    result: str = ""  # "accepted" | "rejected" | "partial"
    reason_codes: List[str] = field(default_factory=list)
    evaluated_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VerificationResult":
        return cls(
            handshake_id=d.get("handshakeId", ""),
            result=d.get("result", ""),
            reason_codes=d.get("reasonCodes", []),
            evaluated_at=d.get("evaluatedAt", ""),
        )


@dataclass
class GateResult:
    decision: str = ""  # "allow" | "deny" | "review"
    commit_ref: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    appeal_path: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GateResult":
        return cls(
            decision=d.get("decision", ""),
            commit_ref=d.get("commitRef"),
            reasons=d.get("reasons", []),
            appeal_path=d.get("appealPath"),
        )


@dataclass
class SignoffChallenge:
    challenge_id: str = ""
    entity_id: str = ""
    scope: str = ""
    nonce: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffChallenge":
        return cls(
            challenge_id=d.get("challengeId", ""),
            entity_id=d.get("entityId", ""),
            scope=d.get("scope", ""),
            nonce=d.get("nonce", ""),
            expires_at=d.get("expiresAt", ""),
        )


@dataclass
class SignoffAttestation:
    attestation_id: str = ""
    challenge_id: str = ""
    status: str = ""  # "valid" | "invalid" | "expired"
    signoff_id: Optional[str] = None
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffAttestation":
        return cls(
            attestation_id=d.get("attestationId", ""),
            challenge_id=d.get("challengeId", ""),
            status=d.get("status", ""),
            signoff_id=d.get("signoffId"),
            created_at=d.get("createdAt", ""),
        )


@dataclass
class SignoffConsumption:
    signoff_id: str = ""
    consumed: bool = False
    action: str = ""
    consumed_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffConsumption":
        return cls(
            signoff_id=d.get("signoffId", ""),
            consumed=d.get("consumed", False),
            action=d.get("action", ""),
            consumed_at=d.get("consumedAt"),
        )


@dataclass
class Consumption:
    handshake_id: str = ""
    consumed: bool = False
    receipt_id: Optional[str] = None
    consumed_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Consumption":
        return cls(
            handshake_id=d.get("handshakeId", ""),
            consumed=d.get("consumed", False),
            receipt_id=d.get("receiptId"),
            consumed_at=d.get("consumedAt"),
        )
