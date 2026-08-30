"""Typed request and response objects for the synchronous EMILIA client."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generic, List, Mapping, Optional, TypeVar, Union


JsonObject = Dict[str, Any]


def _copy_object(value: Optional[Mapping[str, Any]]) -> Optional[JsonObject]:
    return deepcopy(dict(value)) if value is not None else None


def _without_none(value: Mapping[str, Any]) -> JsonObject:
    return {key: item for key, item in value.items() if item is not None}


@dataclass(frozen=True)
class Party:
    """One participant in a handshake request."""

    entity_ref: str
    role: str

    def to_dict(self) -> JsonObject:
        return {"entity_ref": self.entity_ref, "role": self.role}


@dataclass(frozen=True)
class InitiateHandshakeParams:
    """Body accepted by ``POST /api/handshake``."""

    mode: str
    policy_id: str
    parties: List[Party]
    payload: Optional[JsonObject] = None
    binding: Optional[JsonObject] = None
    interaction_id: Optional[str] = None
    binding_ttl_ms: Optional[int] = None
    idempotency_key: Optional[str] = None
    action_type: Optional[str] = None
    resource_ref: Optional[str] = None
    intent_ref: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "mode": self.mode,
                "policy_id": self.policy_id,
                "parties": [party.to_dict() for party in self.parties],
                "payload": _copy_object(self.payload),
                "binding": _copy_object(self.binding),
                "interaction_id": self.interaction_id,
                "binding_ttl_ms": self.binding_ttl_ms,
                "idempotency_key": self.idempotency_key,
                "action_type": self.action_type,
                "resource_ref": self.resource_ref,
                "intent_ref": self.intent_ref,
            }
        )


@dataclass(frozen=True)
class PresentParams:
    """Body accepted by the handshake presentation endpoint."""

    party_role: str
    presentation_type: str
    claims: JsonObject
    issuer_ref: Optional[str] = None
    issuer_proof: Optional[JsonObject] = None
    disclosure_mode: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "party_role": self.party_role,
                "presentation_type": self.presentation_type,
                "claims": _copy_object(self.claims),
                "issuer_ref": self.issuer_ref,
                "issuer_proof": _copy_object(self.issuer_proof),
                "disclosure_mode": self.disclosure_mode,
            }
        )


@dataclass(frozen=True)
class GateParams:
    """Documented body accepted by ``POST /api/trust/gate``."""

    entity_id: str
    action: str
    policy: str = "standard"
    value_usd: Optional[float] = None
    delegation_id: Optional[str] = None
    handshake_id: Optional[str] = None
    resource_ref: Optional[str] = None
    intent_ref: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "entity_id": self.entity_id,
                "action": self.action,
                "policy": self.policy,
                "value_usd": self.value_usd,
                "delegation_id": self.delegation_id,
                "handshake_id": self.handshake_id,
                "resource_ref": self.resource_ref,
                "intent_ref": self.intent_ref,
            }
        )


@dataclass(frozen=True)
class QuorumApprover:
    """One role-bound seat in an EP-QUORUM-v1 approval roster."""

    role: str
    approver: str

    def to_dict(self) -> JsonObject:
        return {"role": self.role, "approver": self.approver}


@dataclass(frozen=True)
class QuorumPolicy:
    """Runtime quorum policy accepted by trust-receipt creation."""

    required: int
    approvers: List[QuorumApprover]
    mode: str = "threshold"
    distinct_humans: bool = True
    window_sec: int = 900

    def to_dict(self) -> JsonObject:
        return {
            "mode": self.mode,
            "required": self.required,
            "approvers": [approver.to_dict() for approver in self.approvers],
            "distinct_humans": self.distinct_humans,
            "window_sec": self.window_sec,
        }


QuorumPolicyInput = Union[QuorumPolicy, Mapping[str, Any]]


def _quorum_policy_dict(value: Optional[QuorumPolicyInput]) -> Optional[JsonObject]:
    if isinstance(value, QuorumPolicy):
        return value.to_dict()
    return _copy_object(value)


@dataclass(frozen=True)
class CreateTrustReceiptParams:
    """Runtime-backed request for a v1 pre-action trust receipt."""

    action_type: str
    target_resource_id: str
    organization_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    target_changed_fields: Optional[List[str]] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    risk_flags: Optional[List[str]] = None
    before_state: Optional[JsonObject] = None
    after_state: Optional[JsonObject] = None
    policy_id: Optional[str] = None
    enforcement_mode: str = "enforce"
    quorum_policy: Optional[QuorumPolicyInput] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "organization_id": self.organization_id,
                "action_type": self.action_type,
                "target_resource_id": self.target_resource_id,
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "target_changed_fields": list(self.target_changed_fields)
                if self.target_changed_fields is not None
                else None,
                "amount": self.amount,
                "currency": self.currency,
                "risk_flags": list(self.risk_flags) if self.risk_flags is not None else None,
                "before_state": _copy_object(self.before_state),
                "after_state": _copy_object(self.after_state),
                "policy_id": self.policy_id,
                "enforcement_mode": self.enforcement_mode,
                "quorum_policy": _quorum_policy_dict(self.quorum_policy),
            }
        )


@dataclass(frozen=True)
class RequestSignoffParams:
    """Request one named-human signoff for a pending receipt."""

    receipt_id: str
    approver_id: Optional[str] = None
    expires_in_minutes: Optional[int] = None
    comment: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "receipt_id": self.receipt_id,
                "approver_id": self.approver_id,
                "expires_in_minutes": self.expires_in_minutes,
                "comment": self.comment,
            }
        )


@dataclass(frozen=True)
class ConsumeTrustReceiptParams:
    """Exact-action input for one-time receipt consumption."""

    action_hash: str
    executing_system: str
    execution_reference_id: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "action_hash": self.action_hash,
                "executing_system": self.executing_system,
                "execution_reference_id": self.execution_reference_id,
            }
        )


@dataclass(frozen=True)
class AttestExecutionParams:
    """Post-mutation evidence input.

    ``observed_action`` must come from the executor or system of record. It is
    deliberately separate from the approved ``executed_action`` snapshot.
    """

    executed_action: JsonObject
    observed_action: JsonObject
    executing_system: str
    execution_id: Optional[str] = None
    executed_at: Optional[str] = None

    def to_dict(self) -> JsonObject:
        return _without_none(
            {
                "executed_action": _copy_object(self.executed_action),
                "observed_action": _copy_object(self.observed_action),
                "executing_system": self.executing_system,
                "execution_id": self.execution_id,
                "executed_at": self.executed_at,
            }
        )


@dataclass
class Handshake:
    handshake_id: str = ""
    mode: str = ""
    policy_id: str = ""
    status: str = ""
    parties: List[JsonObject] = field(default_factory=list)
    presentations: List[JsonObject] = field(default_factory=list)
    binding: Optional[JsonObject] = None
    result: Optional[JsonObject] = None
    interaction_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Handshake":
        return cls(
            handshake_id=str(value.get("handshake_id") or value.get("id") or ""),
            mode=str(value.get("mode") or ""),
            policy_id=str(value.get("policy_id") or value.get("policyId") or ""),
            status=str(value.get("status") or ""),
            parties=deepcopy(list(value.get("parties") or [])),
            presentations=deepcopy(list(value.get("presentations") or [])),
            binding=_copy_object(value.get("binding")),
            result=_copy_object(value.get("result")),
            interaction_id=value.get("interaction_id") or value.get("interactionId"),
            created_at=value.get("created_at") or value.get("createdAt"),
            updated_at=value.get("updated_at") or value.get("updatedAt"),
        )


@dataclass
class Presentation:
    presentation_id: str = ""
    handshake_id: str = ""
    party_role: str = ""
    presentation_type: str = ""
    issuer_ref: Optional[str] = None
    issuer_status: Optional[str] = None
    verified: bool = False
    claims: JsonObject = field(default_factory=dict)
    disclosure_mode: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Presentation":
        return cls(
            presentation_id=str(value.get("presentation_id") or value.get("presentationId") or ""),
            handshake_id=str(value.get("handshake_id") or value.get("handshakeId") or ""),
            party_role=str(value.get("party_role") or value.get("partyRole") or ""),
            presentation_type=str(
                value.get("presentation_type") or value.get("presentationType") or ""
            ),
            issuer_ref=value.get("issuer_ref") or value.get("issuerRef"),
            issuer_status=value.get("issuer_status"),
            verified=value.get("verified") is True,
            claims=deepcopy(dict(value.get("claims") or {})),
            disclosure_mode=value.get("disclosure_mode") or value.get("disclosureMode"),
            created_at=value.get("created_at") or value.get("createdAt"),
        )


@dataclass
class VerificationResult:
    handshake_id: str = ""
    outcome: str = ""
    reason_codes: List[str] = field(default_factory=list)
    evaluated_at: Optional[str] = None
    assurance_achieved: Optional[str] = None
    policy_version: Optional[str] = None
    consumed_at: Optional[str] = None
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerificationResult":
        return cls(
            handshake_id=str(value.get("handshake_id") or value.get("handshakeId") or ""),
            outcome=str(value.get("outcome") or value.get("result") or ""),
            reason_codes=list(value.get("reason_codes") or value.get("reasonCodes") or []),
            evaluated_at=value.get("evaluated_at") or value.get("evaluatedAt"),
            assurance_achieved=value.get("assurance_achieved"),
            policy_version=value.get("policy_version"),
            consumed_at=value.get("consumed_at"),
            expires_at=value.get("expires_at"),
        )


@dataclass
class GateResult:
    decision: str = ""
    entity_id: str = ""
    policy_used: str = ""
    confidence: str = ""
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    appeal_path: Optional[str] = None
    action: Optional[str] = None
    commit_ref: Optional[str] = None
    profile_summary: Optional[JsonObject] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateResult":
        return cls(
            decision=str(value.get("decision") or ""),
            entity_id=str(value.get("entity_id") or ""),
            policy_used=str(value.get("policy_used") or ""),
            confidence=str(value.get("confidence") or ""),
            reasons=list(value.get("reasons") or []),
            warnings=list(value.get("warnings") or []),
            appeal_path=value.get("appeal_path"),
            action=value.get("action"),
            commit_ref=value.get("commit_ref"),
            profile_summary=_copy_object(value.get("profile_summary")),
        )


@dataclass
class RevokeResult:
    handshake_id: str = ""
    status: str = ""
    revoked_at: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RevokeResult":
        return cls(
            handshake_id=str(value.get("handshake_id") or value.get("id") or ""),
            status=str(value.get("status") or ""),
            revoked_at=value.get("revoked_at") or value.get("revokedAt"),
        )


@dataclass
class TrustReceipt:
    receipt_id: str = ""
    decision: str = ""
    observed_decision: Optional[str] = None
    policy_id: str = ""
    policy_hash: str = ""
    action_hash: str = ""
    before_state_hash: Optional[str] = None
    after_state_hash: Optional[str] = None
    nonce: str = ""
    expires_at: str = ""
    signoff_required: bool = False
    required_assurance: Optional[str] = None
    signoff_request_id: Optional[str] = None
    risk_flags: List[str] = field(default_factory=list)
    receipt_status: str = ""
    enforcement_mode: str = ""
    evidence_status: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    canonical_action: JsonObject = field(default_factory=dict)
    execution_binding: Optional[JsonObject] = None
    authority: Optional[JsonObject] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TrustReceipt":
        return cls(
            receipt_id=str(value.get("receipt_id") or ""),
            decision=str(value.get("decision") or ""),
            observed_decision=value.get("observed_decision"),
            policy_id=str(value.get("policy_id") or ""),
            policy_hash=str(value.get("policy_hash") or ""),
            action_hash=str(value.get("action_hash") or ""),
            before_state_hash=value.get("before_state_hash"),
            after_state_hash=value.get("after_state_hash"),
            nonce=str(value.get("nonce") or ""),
            expires_at=str(value.get("expires_at") or ""),
            signoff_required=value.get("signoff_required") is True,
            required_assurance=value.get("required_assurance"),
            signoff_request_id=value.get("signoff_request_id"),
            risk_flags=list(value.get("risk_flags") or []),
            receipt_status=str(value.get("receipt_status") or ""),
            enforcement_mode=str(value.get("enforcement_mode") or ""),
            evidence_status=value.get("evidence_status"),
            reasons=list(value.get("reasons") or []),
            canonical_action=deepcopy(dict(value.get("canonical_action") or {})),
            execution_binding=_copy_object(value.get("execution_binding")),
            authority=_copy_object(value.get("authority")),
        )


@dataclass
class TrustReceiptState:
    receipt_id: str = ""
    organization_id: str = ""
    action_type: str = ""
    decision: str = ""
    enforcement_mode: str = ""
    policy_id: str = ""
    policy_hash: str = ""
    action_hash: str = ""
    before_state_hash: Optional[str] = None
    after_state_hash: Optional[str] = None
    expires_at: str = ""
    signoff_required: bool = False
    receipt_status: str = ""
    signoff_key_class: Optional[str] = None
    timeline_event_count: int = 0

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TrustReceiptState":
        return cls(
            receipt_id=str(value.get("receipt_id") or ""),
            organization_id=str(value.get("organization_id") or ""),
            action_type=str(value.get("action_type") or ""),
            decision=str(value.get("decision") or ""),
            enforcement_mode=str(value.get("enforcement_mode") or ""),
            policy_id=str(value.get("policy_id") or ""),
            policy_hash=str(value.get("policy_hash") or ""),
            action_hash=str(value.get("action_hash") or ""),
            before_state_hash=value.get("before_state_hash"),
            after_state_hash=value.get("after_state_hash"),
            expires_at=str(value.get("expires_at") or ""),
            signoff_required=value.get("signoff_required") is True,
            receipt_status=str(value.get("receipt_status") or ""),
            signoff_key_class=value.get("signoff_key_class"),
            timeline_event_count=int(value.get("timeline_event_count") or 0),
        )


@dataclass
class SignoffRequest:
    signoff_id: Optional[str] = None
    receipt_id: str = ""
    action_hash: str = ""
    initiator_id: str = ""
    approver_id: Optional[str] = None
    expires_at: str = ""
    status: str = ""
    quorum: Optional[JsonObject] = None
    signoffs: List[JsonObject] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignoffRequest":
        return cls(
            signoff_id=value.get("signoff_id"),
            receipt_id=str(value.get("receipt_id") or ""),
            action_hash=str(value.get("action_hash") or ""),
            initiator_id=str(value.get("initiator_id") or ""),
            approver_id=value.get("approver_id"),
            expires_at=str(value.get("expires_at") or ""),
            status=str(value.get("status") or ""),
            quorum=_copy_object(value.get("quorum")),
            signoffs=deepcopy(list(value.get("signoffs") or [])),
        )


@dataclass
class ConsumeTrustReceiptResult:
    receipt_id: str = ""
    status: str = ""
    consumed_at: str = ""
    consumed_by_system: str = ""
    execution_reference_id: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConsumeTrustReceiptResult":
        return cls(
            receipt_id=str(value.get("receipt_id") or ""),
            status=str(value.get("status") or ""),
            consumed_at=str(value.get("consumed_at") or ""),
            consumed_by_system=str(value.get("consumed_by_system") or ""),
            execution_reference_id=value.get("execution_reference_id"),
        )


@dataclass
class ExecutionAttestation:
    receipt_id: str = ""
    status: str = ""
    binding_status: str = ""
    executed_action_hash: str = ""
    approved_action_hash: str = ""
    execution_binding_check: Optional[JsonObject] = None
    execution_integrity: JsonObject = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionAttestation":
        return cls(
            receipt_id=str(value.get("receipt_id") or ""),
            status=str(value.get("status") or ""),
            binding_status=str(value.get("binding_status") or ""),
            executed_action_hash=str(value.get("executed_action_hash") or ""),
            approved_action_hash=str(value.get("approved_action_hash") or ""),
            execution_binding_check=_copy_object(value.get("execution_binding_check")),
            execution_integrity=deepcopy(dict(value.get("execution_integrity") or {})),
        )


@dataclass(frozen=True)
class SignoffRequiredContext:
    receipt: TrustReceipt
    signoff: SignoffRequest


@dataclass(frozen=True)
class ReceiptContext:
    receipt: TrustReceipt
    consume: ConsumeTrustReceiptResult
    canonical_action: JsonObject


@dataclass(frozen=True)
class MutationObservationContext:
    receipt: TrustReceipt
    consume: ConsumeTrustReceiptResult
    canonical_action: JsonObject
    result: Any


Observation = Union[
    Mapping[str, Any], Callable[[MutationObservationContext], Mapping[str, Any]]
]


@dataclass
class RequireReceiptParams:
    """Configuration for the fail-closed ``require_receipt`` lifecycle."""

    action_type: str
    target_resource_id: str
    executing_system: str
    organization_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    target_changed_fields: Optional[List[str]] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    risk_flags: Optional[List[str]] = None
    before_state: Optional[JsonObject] = None
    after_state: Optional[JsonObject] = None
    policy_id: Optional[str] = None
    enforcement_mode: str = "enforce"
    quorum_policy: Optional[QuorumPolicyInput] = None
    execution_reference_id: Optional[str] = None
    approver_id: Optional[str] = None
    signoff_comment: Optional[str] = None
    signoff_expires_in_minutes: Optional[int] = None
    on_signoff_required: Optional[Callable[[SignoffRequiredContext], Any]] = None
    observed_action: Optional[Observation] = None
    execution_id: Optional[Union[str, Callable[[Any], Optional[str]]]] = None
    fetch_evidence: bool = False

    def to_create_params(self) -> CreateTrustReceiptParams:
        return CreateTrustReceiptParams(
            organization_id=self.organization_id,
            action_type=self.action_type,
            target_resource_id=self.target_resource_id,
            actor_id=self.actor_id,
            actor_role=self.actor_role,
            target_changed_fields=self.target_changed_fields,
            amount=self.amount,
            currency=self.currency,
            risk_flags=self.risk_flags,
            before_state=self.before_state,
            after_state=self.after_state,
            policy_id=self.policy_id,
            enforcement_mode=self.enforcement_mode,
            quorum_policy=self.quorum_policy,
        )


T = TypeVar("T")


@dataclass
class RequireReceiptResult(Generic[T]):
    result: T
    receipt: TrustReceipt
    consume: ConsumeTrustReceiptResult
    signoff: Optional[SignoffRequest] = None
    execution: Optional[ExecutionAttestation] = None
    execution_status: str = "unobserved"
    execution_error: Optional[str] = None
    evidence: Optional[JsonObject] = None
    evidence_error: Optional[str] = None
    do_not_retry: bool = False
