"""EMILIA Protocol — Python SDK type definitions (dataclasses).

Covers all protocol endpoints (handshake, signoff, delegation, commit)
and cloud endpoints (dashboards, analytics, audit, policy management).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Core Params
# ---------------------------------------------------------------------------


@dataclass
class Party:
    """A party involved in a handshake."""

    entity_ref: str
    role: str  # "initiator" | "responder"


@dataclass
class InitiateHandshakeParams:
    """Parameters for initiating a trust handshake."""

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
    """Parameters for presenting credentials to a handshake."""

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
    """Parameters for the pre-action trust gate."""

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
    """Parameters for issuing a signoff challenge."""

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
    """Parameters for attesting to a signoff challenge."""

    signature: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"signature": self.signature, "payload": self.payload}


@dataclass
class ConsumeSignoffParams:
    """Parameters for consuming a signoff."""

    action: str
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"action": self.action}
        if self.context is not None:
            d["context"] = self.context
        return d


@dataclass
class ConsumeParams:
    """Parameters for consuming a handshake."""

    receipt_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.receipt_data is not None:
            d["receiptData"] = self.receipt_data
        return d


@dataclass
class CreateDelegationParams:
    """Parameters for creating a trust delegation."""

    delegator_id: str
    delegatee_id: str
    scope: str
    policy_id: str
    constraints: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "delegatorId": self.delegator_id,
            "delegateeId": self.delegatee_id,
            "scope": self.scope,
            "policyId": self.policy_id,
        }
        if self.constraints is not None:
            d["constraints"] = self.constraints
        if self.expires_at is not None:
            d["expiresAt"] = self.expires_at
        return d


@dataclass
class IssueCommitParams:
    """Parameters for issuing a trust commit."""

    handshake_id: str
    action: str
    payload: Dict[str, Any]
    binding: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "handshakeId": self.handshake_id,
            "action": self.action,
            "payload": self.payload,
        }
        if self.binding is not None:
            d["binding"] = self.binding
        return d


@dataclass
class RecordObservationParams:
    """Parameters for recording a behavioral or contextual observation."""

    source_type: str
    source_ref: str
    subject_ref: str
    actor_ref: str
    action_type: str
    observation_type: str
    severity_hint: str
    expires_at: str
    target_ref: Optional[str] = None
    issuer_ref: Optional[str] = None
    evidence_hash: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "subject_ref": self.subject_ref,
            "actor_ref": self.actor_ref,
            "action_type": self.action_type,
            "observation_type": self.observation_type,
            "severity_hint": self.severity_hint,
            "expires_at": self.expires_at,
        }
        if self.target_ref is not None:
            d["target_ref"] = self.target_ref
        if self.issuer_ref is not None:
            d["issuer_ref"] = self.issuer_ref
        if self.evidence_hash is not None:
            d["evidence_hash"] = self.evidence_hash
        if self.metadata is not None:
            d["metadata"] = self.metadata
        return d


@dataclass
class CheckActionParams:
    """Parameters for checking an action against recorded observations."""

    subject_ref: str
    actor_ref: str
    action_type: str
    context_hash: str
    target_ref: Optional[str] = None
    issuer_ref: Optional[str] = None
    payload_hash: Optional[str] = None
    policy_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "subject_ref": self.subject_ref,
            "actor_ref": self.actor_ref,
            "action_type": self.action_type,
            "context_hash": self.context_hash,
        }
        if self.target_ref is not None:
            d["target_ref"] = self.target_ref
        if self.issuer_ref is not None:
            d["issuer_ref"] = self.issuer_ref
        if self.payload_hash is not None:
            d["payload_hash"] = self.payload_hash
        if self.policy_class is not None:
            d["policy_class"] = self.policy_class
        return d


@dataclass
class CreateSuppressionParams:
    """Parameters for creating a suppression."""

    scope_binding_hash: str
    reason_code: str
    justification: str
    expires_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope_binding_hash": self.scope_binding_hash,
            "reason_code": self.reason_code,
            "justification": self.justification,
            "expires_at": self.expires_at,
        }


@dataclass
class ExportAuditParams:
    """Parameters for exporting audit data."""

    format: str = "json"  # "json" | "csv" | "pdf"
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    entity_id: Optional[str] = None
    event_types: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"format": self.format}
        date_range: Dict[str, str] = {}
        if self.date_from is not None:
            date_range["from"] = self.date_from
        if self.date_to is not None:
            date_range["to"] = self.date_to
        if date_range:
            d["dateRange"] = date_range
        if self.entity_id is not None:
            d["entityId"] = self.entity_id
        if self.event_types is not None:
            d["eventTypes"] = self.event_types
        return d


# ---------------------------------------------------------------------------
# Core Responses
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    """A trust policy definition."""

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
    """A trust handshake between parties."""

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
    """A credential presentation within a handshake."""

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
    """Result of verifying a handshake against policy."""

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
    """Result of a pre-action trust gate evaluation."""

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
    """A signoff challenge issued to an entity."""

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
    """Result of attesting to a signoff challenge."""

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
    """Result of consuming a signoff."""

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
    """Result of consuming a handshake."""

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


@dataclass
class RevokeResult:
    """Result of revoking a handshake or signoff."""

    id: str = ""
    revoked: bool = False
    revoked_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RevokeResult":
        return cls(
            id=d.get("id", ""),
            revoked=d.get("revoked", False),
            revoked_at=d.get("revokedAt", ""),
        )


@dataclass
class DenyResult:
    """Result of denying a signoff challenge."""

    challenge_id: str = ""
    denied: bool = False
    reason: Optional[str] = None
    denied_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DenyResult":
        return cls(
            challenge_id=d.get("challengeId", ""),
            denied=d.get("denied", False),
            reason=d.get("reason"),
            denied_at=d.get("deniedAt", ""),
        )


@dataclass
class Delegation:
    """A trust delegation from one entity to another."""

    delegation_id: str = ""
    delegator_id: str = ""
    delegatee_id: str = ""
    scope: str = ""
    policy_id: str = ""
    status: str = ""
    constraints: Optional[Dict[str, Any]] = None
    created_at: str = ""
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Delegation":
        return cls(
            delegation_id=d.get("delegationId", ""),
            delegator_id=d.get("delegatorId", ""),
            delegatee_id=d.get("delegateeId", ""),
            scope=d.get("scope", ""),
            policy_id=d.get("policyId", ""),
            status=d.get("status", ""),
            constraints=d.get("constraints"),
            created_at=d.get("createdAt", ""),
            expires_at=d.get("expiresAt"),
        )


@dataclass
class DelegationVerification:
    """Result of verifying a delegation."""

    delegation_id: str = ""
    valid: bool = False
    status: str = ""
    reason_codes: List[str] = field(default_factory=list)
    verified_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DelegationVerification":
        return cls(
            delegation_id=d.get("delegationId", ""),
            valid=d.get("valid", False),
            status=d.get("status", ""),
            reason_codes=d.get("reasonCodes", []),
            verified_at=d.get("verifiedAt", ""),
        )


@dataclass
class Commit:
    """A trust commit binding a handshake to an action."""

    commit_id: str = ""
    handshake_id: str = ""
    action: str = ""
    status: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Commit":
        return cls(
            commit_id=d.get("commitId", ""),
            handshake_id=d.get("handshakeId", ""),
            action=d.get("action", ""),
            status=d.get("status", ""),
            payload=d.get("payload", {}),
            created_at=d.get("createdAt", ""),
        )


@dataclass
class CommitVerification:
    """Result of verifying a commit."""

    commit_id: str = ""
    valid: bool = False
    status: str = ""
    reason_codes: List[str] = field(default_factory=list)
    verified_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CommitVerification":
        return cls(
            commit_id=d.get("commitId", ""),
            valid=d.get("valid", False),
            status=d.get("status", ""),
            reason_codes=d.get("reasonCodes", []),
            verified_at=d.get("verifiedAt", ""),
        )


# ---------------------------------------------------------------------------
# Cloud Responses
# ---------------------------------------------------------------------------


@dataclass
class PendingSignoff:
    """A pending signoff item."""

    challenge_id: str = ""
    entity_id: str = ""
    scope: str = ""
    status: str = ""
    created_at: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PendingSignoff":
        return cls(
            challenge_id=d.get("challengeId", ""),
            entity_id=d.get("entityId", ""),
            scope=d.get("scope", ""),
            status=d.get("status", ""),
            created_at=d.get("createdAt", ""),
            expires_at=d.get("expiresAt", ""),
        )


@dataclass
class PendingSignoffsResponse:
    """Paginated response of pending signoffs."""

    items: List[PendingSignoff] = field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PendingSignoffsResponse":
        return cls(
            items=[PendingSignoff.from_dict(i) for i in d.get("items", [])],
            total=d.get("total", 0),
            offset=d.get("offset", 0),
            limit=d.get("limit", 0),
        )


@dataclass
class SignoffQueueItem:
    """An item in the signoff queue."""

    challenge_id: str = ""
    entity_id: str = ""
    scope: str = ""
    priority: str = ""
    status: str = ""
    created_at: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffQueueItem":
        return cls(
            challenge_id=d.get("challengeId", ""),
            entity_id=d.get("entityId", ""),
            scope=d.get("scope", ""),
            priority=d.get("priority", ""),
            status=d.get("status", ""),
            created_at=d.get("createdAt", ""),
            expires_at=d.get("expiresAt", ""),
        )


@dataclass
class SignoffQueueResponse:
    """Paginated response for the signoff queue."""

    items: List[SignoffQueueItem] = field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffQueueResponse":
        return cls(
            items=[SignoffQueueItem.from_dict(i) for i in d.get("items", [])],
            total=d.get("total", 0),
            offset=d.get("offset", 0),
            limit=d.get("limit", 0),
        )


@dataclass
class DashboardActivity:
    """A recent activity entry on the signoff dashboard."""

    challenge_id: str = ""
    action: str = ""
    entity_id: str = ""
    timestamp: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DashboardActivity":
        return cls(
            challenge_id=d.get("challengeId", ""),
            action=d.get("action", ""),
            entity_id=d.get("entityId", ""),
            timestamp=d.get("timestamp", ""),
        )


@dataclass
class SignoffDashboard:
    """Dashboard summary of signoff activity."""

    pending: int = 0
    approved: int = 0
    denied: int = 0
    expired: int = 0
    average_response_time: float = 0.0
    recent_activity: List[DashboardActivity] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffDashboard":
        return cls(
            pending=d.get("pending", 0),
            approved=d.get("approved", 0),
            denied=d.get("denied", 0),
            expired=d.get("expired", 0),
            average_response_time=d.get("averageResponseTime", 0.0),
            recent_activity=[DashboardActivity.from_dict(a) for a in d.get("recentActivity", [])],
        )


@dataclass
class AnalyticsDataPoint:
    """A single data point in a signoff analytics time series."""

    timestamp: str = ""
    count: int = 0
    approved: int = 0
    denied: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AnalyticsDataPoint":
        return cls(
            timestamp=d.get("timestamp", ""),
            count=d.get("count", 0),
            approved=d.get("approved", 0),
            denied=d.get("denied", 0),
        )


@dataclass
class SignoffAnalytics:
    """Analytics data for signoff activity."""

    total_challenges: int = 0
    approval_rate: float = 0.0
    average_response_time: float = 0.0
    by_scope: Dict[str, int] = field(default_factory=dict)
    timeseries: List[AnalyticsDataPoint] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignoffAnalytics":
        return cls(
            total_challenges=d.get("totalChallenges", 0),
            approval_rate=d.get("approvalRate", 0.0),
            average_response_time=d.get("averageResponseTime", 0.0),
            by_scope=d.get("byScope", {}),
            timeseries=[AnalyticsDataPoint.from_dict(p) for p in d.get("timeseries", [])],
        )


@dataclass
class EscalationResult:
    """Result of escalating a signoff challenge."""

    challenge_id: str = ""
    escalated_to: str = ""
    escalated_at: str = ""
    status: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EscalationResult":
        return cls(
            challenge_id=d.get("challengeId", ""),
            escalated_to=d.get("escalatedTo", ""),
            escalated_at=d.get("escalatedAt", ""),
            status=d.get("status", ""),
        )


@dataclass
class NotificationResult:
    """Result of sending a signoff notification."""

    challenge_id: str = ""
    channel: str = ""
    sent: bool = False
    sent_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NotificationResult":
        return cls(
            challenge_id=d.get("challengeId", ""),
            channel=d.get("channel", ""),
            sent=d.get("sent", False),
            sent_at=d.get("sentAt", ""),
        )


@dataclass
class AuditEvent:
    """An audit event record."""

    event_id: str = ""
    type: str = ""
    entity_id: str = ""
    action: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditEvent":
        return cls(
            event_id=d.get("eventId", ""),
            type=d.get("type", ""),
            entity_id=d.get("entityId", ""),
            action=d.get("action", ""),
            metadata=d.get("metadata", {}),
            timestamp=d.get("timestamp", ""),
        )


@dataclass
class SearchEventsResponse:
    """Response from searching audit events."""

    items: List[AuditEvent] = field(default_factory=list)
    total: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SearchEventsResponse":
        return cls(
            items=[AuditEvent.from_dict(e) for e in d.get("items", [])],
            total=d.get("total", 0),
        )


@dataclass
class EventTimeline:
    """Chronological timeline of events for a handshake."""

    handshake_id: str = ""
    events: List[AuditEvent] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EventTimeline":
        return cls(
            handshake_id=d.get("handshakeId", ""),
            events=[AuditEvent.from_dict(e) for e in d.get("events", [])],
        )


@dataclass
class ExportAuditResult:
    """Result of an audit data export request."""

    export_id: str = ""
    format: str = ""
    status: str = ""
    download_url: Optional[str] = None
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExportAuditResult":
        return cls(
            export_id=d.get("exportId", ""),
            format=d.get("format", ""),
            status=d.get("status", ""),
            download_url=d.get("downloadUrl"),
            created_at=d.get("createdAt", ""),
        )


@dataclass
class AuditReport:
    """A generated audit report."""

    report_type: str = ""
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    items: List[AuditEvent] = field(default_factory=list)
    generated_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditReport":
        dr = d.get("dateRange", {})
        return cls(
            report_type=d.get("reportType", ""),
            date_from=dr.get("from") if dr else None,
            date_to=dr.get("to") if dr else None,
            summary=d.get("summary", {}),
            items=[AuditEvent.from_dict(e) for e in d.get("items", [])],
            generated_at=d.get("generatedAt", ""),
        )


@dataclass
class IntegrityCheck:
    """A single integrity check result."""

    name: str = ""
    status: str = ""  # "pass" | "fail" | "warn"
    message: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IntegrityCheck":
        return cls(
            name=d.get("name", ""),
            status=d.get("status", ""),
            message=d.get("message"),
        )


@dataclass
class IntegrityCheckResult:
    """Result of running an integrity check."""

    healthy: bool = False
    checks: List[IntegrityCheck] = field(default_factory=list)
    checked_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IntegrityCheckResult":
        return cls(
            healthy=d.get("healthy", False),
            checks=[IntegrityCheck.from_dict(c) for c in d.get("checks", [])],
            checked_at=d.get("checkedAt", ""),
        )


@dataclass
class PolicySimulationResult:
    """Result of simulating a policy against a hypothetical context."""

    policy_id: str = ""
    decision: str = ""  # "allow" | "deny" | "review"
    reasons: List[str] = field(default_factory=list)
    evaluated_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicySimulationResult":
        return cls(
            policy_id=d.get("policyId", ""),
            decision=d.get("decision", ""),
            reasons=d.get("reasons", []),
            evaluated_at=d.get("evaluatedAt", ""),
        )


@dataclass
class PolicyRolloutResult:
    """Result of initiating a policy rollout."""

    policy_id: str = ""
    strategy: str = ""
    percentage: float = 0.0
    status: str = ""
    started_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyRolloutResult":
        return cls(
            policy_id=d.get("policyId", ""),
            strategy=d.get("strategy", ""),
            percentage=d.get("percentage", 0.0),
            status=d.get("status", ""),
            started_at=d.get("startedAt", ""),
        )


@dataclass
class PolicyVersion:
    """A version record for a policy."""

    version_id: str = ""
    policy_id: str = ""
    version: int = 0
    created_at: str = ""
    created_by: str = ""
    changelog: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyVersion":
        return cls(
            version_id=d.get("versionId", ""),
            policy_id=d.get("policyId", ""),
            version=d.get("version", 0),
            created_at=d.get("createdAt", ""),
            created_by=d.get("createdBy", ""),
            changelog=d.get("changelog"),
        )


@dataclass
class PolicyChange:
    """A single field change between two policy versions."""

    field: str = ""
    old_value: Any = None
    new_value: Any = None
    type: str = ""  # "added" | "removed" | "modified"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyChange":
        return cls(
            field=d.get("field", ""),
            old_value=d.get("oldValue"),
            new_value=d.get("newValue"),
            type=d.get("type", ""),
        )


@dataclass
class PolicyDiff:
    """Diff between two versions of a policy."""

    policy_id: str = ""
    version_a: str = ""
    version_b: str = ""
    changes: List[PolicyChange] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyDiff":
        return cls(
            policy_id=d.get("policyId", ""),
            version_a=d.get("versionA", ""),
            version_b=d.get("versionB", ""),
            changes=[PolicyChange.from_dict(c) for c in d.get("changes", [])],
        )


# ---------------------------------------------------------------------------
# Eye Responses
# ---------------------------------------------------------------------------


@dataclass
class ObservationResponse:
    """Response from recording an observation."""

    observation_id: str = ""
    observation_type: str = ""
    severity_hint: str = ""
    observed_at: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ObservationResponse":
        return cls(
            observation_id=d.get("observation_id", d.get("observationId", "")),
            observation_type=d.get("observation_type", d.get("observationType", "")),
            severity_hint=d.get("severity_hint", d.get("severityHint", "")),
            observed_at=d.get("observed_at", d.get("observedAt", "")),
            expires_at=d.get("expires_at", d.get("expiresAt", "")),
        )


@dataclass
class AdvisoryResponse:
    """Response from checking an action or retrieving an advisory."""

    advisory_id: str = ""
    status: str = ""
    reason_codes: List[str] = field(default_factory=list)
    recommended_policy_action: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    scope_binding_hash: str = ""
    issued_at: str = ""
    expires_at: str = ""
    version: int = 1

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AdvisoryResponse":
        return cls(
            advisory_id=d.get("advisory_id", d.get("advisoryId", "")),
            status=d.get("status", ""),
            reason_codes=d.get("reason_codes", d.get("reasonCodes", [])),
            recommended_policy_action=d.get("recommended_policy_action", d.get("recommendedPolicyAction", "")),
            evidence_refs=d.get("evidence_refs", d.get("evidenceRefs", [])),
            scope_binding_hash=d.get("scope_binding_hash", d.get("scopeBindingHash", "")),
            issued_at=d.get("issued_at", d.get("issuedAt", "")),
            expires_at=d.get("expires_at", d.get("expiresAt", "")),
            version=d.get("version", 1),
        )


@dataclass
class SuppressionResponse:
    """Response from creating a suppression."""

    suppression_id: str = ""
    status: str = ""
    created_at: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SuppressionResponse":
        return cls(
            suppression_id=d.get("suppression_id", d.get("suppressionId", "")),
            status=d.get("status", ""),
            created_at=d.get("created_at", d.get("createdAt", "")),
            expires_at=d.get("expires_at", d.get("expiresAt", "")),
        )
