"""EMILIA Protocol — Type Definitions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional, TypedDict

# ---------------------------------------------------------------------------
# Enum-style Literal types
# ---------------------------------------------------------------------------

EntityType = Literal[
    "agent",
    "merchant",
    "service_provider",
    "github_app",
    "github_action",
    "mcp_server",
    "npm_package",
    "chrome_extension",
    "shopify_app",
    "marketplace_plugin",
    "agent_tool",
]

AgentBehavior = Literal[
    "completed",
    "retried_same",
    "retried_different",
    "abandoned",
    "disputed",
]

TransactionType = Literal[
    "purchase",
    "service",
    "task_completion",
    "delivery",
    "return",
]

TrustPolicy = Literal["strict", "standard", "permissive", "discovery"]

TrustDecision = Literal["allow", "review", "deny"]

DisputeReason = Literal[
    "fraudulent_receipt",
    "inaccurate_signals",
    "identity_dispute",
    "context_mismatch",
    "duplicate_transaction",
    "coerced_receipt",
    "other",
]

ReportType = Literal[
    "wrongly_downgraded",
    "harmed_by_trusted_entity",
    "fraudulent_entity",
    "inaccurate_profile",
    "other",
]

TrustDomain = Literal[
    "financial",
    "code_execution",
    "communication",
    "delegation",
    "infrastructure",
    "content_creation",
    "data_access",
]


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class EPError(Exception):
    """Raised when an EP API call fails.

    Attributes:
        status: HTTP status code (if the error came from the API).
        code:   Machine-readable error code returned by the API (if any).
    """

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code

    def __repr__(self) -> str:
        return (
            f"EPError({str(self)!r}, status={self.status!r}, code={self.code!r})"
        )


# ---------------------------------------------------------------------------
# Context TypedDict (used for context-aware evaluation)
# ---------------------------------------------------------------------------


class TrustContext(TypedDict, total=False):
    """Contextual metadata passed to trust evaluation and receipt submission."""

    task_type: str
    category: str
    geo: str
    modality: str
    value_band: str
    risk_class: str


# ---------------------------------------------------------------------------
# Trust Profile sub-objects
# ---------------------------------------------------------------------------


@dataclass
class BehavioralProfile:
    """Observable behavioral rates derived from receipt history."""

    completion_rate: Optional[float] = None
    retry_rate: Optional[float] = None
    abandon_rate: Optional[float] = None
    dispute_rate: Optional[float] = None


@dataclass
class SignalProfile:
    """Structured signal scores (0-100 each)."""

    delivery_accuracy: Optional[float] = None
    product_accuracy: Optional[float] = None
    price_integrity: Optional[float] = None
    return_processing: Optional[float] = None
    consistency: Optional[float] = None


@dataclass
class ProvenanceProfile:
    """Breakdown of receipt provenance (bilateral vs unilateral, tier weights)."""

    breakdown: dict[str, int] = field(default_factory=dict)
    bilateral_rate: Optional[float] = None


@dataclass
class TrustProfile:
    """Composite trust profile: behavioral rates, signals, provenance."""

    behavioral: Optional[BehavioralProfile] = None
    signals: Optional[SignalProfile] = None
    consistency: Optional[float] = None
    provenance: Optional[ProvenanceProfile] = None


@dataclass
class DisputeSummary:
    """Summary of disputes filed against an entity."""

    total: int = 0
    active: int = 0
    reversed: int = 0


@dataclass
class AnomalyAlert:
    """Anomaly detection alert on an entity's trust signals."""

    type: str = ""
    delta: float = 0.0
    alert: str = ""


# ---------------------------------------------------------------------------
# Top-level entity trust profile
# ---------------------------------------------------------------------------


@dataclass
class EntityTrustProfile:
    """Full trust profile for a registered EP entity.

    This is the canonical read surface for trust decisions. Use
    ``current_confidence`` and ``trust_profile`` for routing / payment
    decisions rather than the legacy ``compat_score``.
    """

    entity_id: str
    display_name: str
    entity_type: str
    current_confidence: str
    historical_establishment: bool
    effective_evidence_current: float
    effective_evidence_historical: float
    compat_score: float
    receipt_count: Optional[int] = None
    unique_submitters: Optional[int] = None
    trust_profile: Optional[TrustProfile] = None
    disputes: Optional[DisputeSummary] = None
    anomaly: Optional[AnomalyAlert] = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EntityTrustProfile":
        """Deserialise a raw API response dict into an EntityTrustProfile."""
        tp: Optional[TrustProfile] = None
        raw_tp = d.get("trust_profile")
        if raw_tp:
            beh: Optional[BehavioralProfile] = None
            if raw_tp.get("behavioral"):
                rb = raw_tp["behavioral"]
                beh = BehavioralProfile(
                    completion_rate=rb.get("completion_rate"),
                    retry_rate=rb.get("retry_rate"),
                    abandon_rate=rb.get("abandon_rate"),
                    dispute_rate=rb.get("dispute_rate"),
                )

            sig: Optional[SignalProfile] = None
            if raw_tp.get("signals"):
                rs = raw_tp["signals"]
                sig = SignalProfile(
                    delivery_accuracy=rs.get("delivery_accuracy"),
                    product_accuracy=rs.get("product_accuracy"),
                    price_integrity=rs.get("price_integrity"),
                    return_processing=rs.get("return_processing"),
                    consistency=rs.get("consistency"),
                )

            prov: Optional[ProvenanceProfile] = None
            if raw_tp.get("provenance"):
                rp = raw_tp["provenance"]
                prov = ProvenanceProfile(
                    breakdown=rp.get("breakdown", {}),
                    bilateral_rate=rp.get("bilateral_rate"),
                )

            tp = TrustProfile(
                behavioral=beh,
                signals=sig,
                consistency=raw_tp.get("consistency"),
                provenance=prov,
            )

        disp: Optional[DisputeSummary] = None
        if d.get("disputes"):
            rd = d["disputes"]
            disp = DisputeSummary(
                total=rd.get("total", 0),
                active=rd.get("active", 0),
                reversed=rd.get("reversed", 0),
            )

        anom: Optional[AnomalyAlert] = None
        if d.get("anomaly"):
            ra = d["anomaly"]
            anom = AnomalyAlert(
                type=ra.get("type", ""),
                delta=ra.get("delta", 0.0),
                alert=ra.get("alert", ""),
            )

        return cls(
            entity_id=d["entity_id"],
            display_name=d["display_name"],
            entity_type=d["entity_type"],
            current_confidence=d["current_confidence"],
            historical_establishment=d["historical_establishment"],
            effective_evidence_current=d.get("effective_evidence_current", 0.0),
            effective_evidence_historical=d.get("effective_evidence_historical", 0.0),
            compat_score=d.get("compat_score", 0.0),
            receipt_count=d.get("receipt_count"),
            unique_submitters=d.get("unique_submitters"),
            trust_profile=tp,
            disputes=disp,
            anomaly=anom,
        )
