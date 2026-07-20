// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import java.util.Locale
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
data class EmiliaMobileActionIdentity(
    @SerialName("action_caid") val actionCaid: String? = null,
    @SerialName("action_digest") val actionDigest: String? = null,
    val fingerprint: String? = null,
) {
    /**
     * Returns a fingerprint derived from the CAID itself. A conflicting
     * server-provided fingerprint fails closed instead of changing the lock
     * shown to the approver.
     */
    fun stableFingerprint(): String? {
        val caid = actionCaid?.takeIf(CAID::matches) ?: return null
        val digest = caid.substringAfterLast(':')
        val digestBytes = try {
            digest.base64UrlBytes()
        } catch (_: EmiliaMobileException.MalformedChallenge) {
            return null
        }
        if (digestBytes.size != 32 || digestBytes.base64Url() != digest) return null
        val hex = buildString(16) {
            for (index in 0 until 8) {
                val value = digestBytes[index].toInt() and 0xff
                append(HEX[value ushr 4])
                append(HEX[value and 0x0f])
            }
        }
        val derived = hex.chunked(4).joinToString("-")
        return derived.takeIf { fingerprint == null || fingerprint == derived }
    }

    fun isValidActionLock(): Boolean =
        stableFingerprint() != null && actionDigest?.let(SHA256::matches) == true

    private companion object {
        val CAID = Regex(
            """^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$""",
        )
        const val HEX = "0123456789ABCDEF"
        val SHA256 = Regex("""^sha256:[0-9a-f]{64}$""")
    }
}

@Serializable
data class EmiliaMobileActionChange(
    val field: String = "",
    val change: String = "",
    val before: String? = null,
    val after: String? = null,
)

@Serializable
data class EmiliaMobileQuorum(
    val approved: Int = 0,
    val required: Int = 1,
    val denied: Int = 0,
    val withdrawn: Int = 0,
) {
    val safeApproved: Int get() = approved.coerceAtLeast(0)
    val safeRequired: Int get() = required.coerceAtLeast(1)
    val safeDenied: Int get() = denied.coerceAtLeast(0)
    val safeWithdrawn: Int get() = withdrawn.coerceAtLeast(0)
}

@Serializable
data class EmiliaMobileContinuity(
    val state: String = EmiliaMobileLifecycleState.AWAITING_DECISION.wireValue,
    @SerialName("retry_safe") val retrySafe: Boolean = true,
    val quorum: EmiliaMobileQuorum? = null,
)

@Serializable
data class EmiliaMobileSystemAlignment(
    val system: String = "",
    val verdict: String = "INDETERMINATE",
    @SerialName("profile_id") val profileId: String? = null,
    @SerialName("profile_hash") val profileHash: String? = null,
    @SerialName("native_verified") val nativeVerified: Boolean = false,
    @SerialName("evidence_digest") val evidenceDigest: String? = null,
    val reason: String? = null,
)

@Serializable
data class EmiliaMobileActionEvent(
    @SerialName("event_id") val eventId: String = "",
    val type: String = "",
    val details: JsonObject = JsonObject(emptyMap()),
    @SerialName("evidence_digest") val evidenceDigest: String? = null,
    @SerialName("created_at") val createdAt: String = "",
)

@Serializable
data class EmiliaMobileAction(
    @SerialName("action_reference") val actionReference: String,
    val title: String,
    val summary: String,
    val risk: String,
    @SerialName("material_fields") val materialFields: JsonObject,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("created_at") val createdAt: String,
    val status: String? = null,
    val revision: Int? = null,
    val identity: EmiliaMobileActionIdentity? = null,
    @SerialName("supersedes_action_caid") val supersedesActionCaid: String? = null,
    val changes: List<EmiliaMobileActionChange> = emptyList(),
    val continuity: EmiliaMobileContinuity? = null,
    val quorum: EmiliaMobileQuorum? = null,
    val alignments: List<EmiliaMobileSystemAlignment> = emptyList(),
    val events: List<EmiliaMobileActionEvent> = emptyList(),
    @SerialName("can_withdraw") val canWithdraw: Boolean = false,
    val passport: JsonObject? = null,
) {
    val effectiveQuorum: EmiliaMobileQuorum?
        get() = quorum ?: continuity?.quorum

    /**
     * Unknown lifecycle values are intentionally rendered as indeterminate.
     * EXECUTED additionally requires a digest attached to the server's
     * verified provider-outcome record.
     */
    val lifecycleState: EmiliaMobileLifecycleState
        get() {
            val state = continuity?.state?.let(EmiliaMobileLifecycleState::fromWire)
                ?: EmiliaMobileLifecycleState.fromLegacyStatus(status)
            return if (state == EmiliaMobileLifecycleState.EXECUTED && !hasVerifiedExecutionEvidence()) {
                EmiliaMobileLifecycleState.INDETERMINATE
            } else {
                state
            }
        }

    val canDecideSafely: Boolean
        get() {
            if (status != null && status != "pending") return false
            if (expectedChallengeIdentity() == null) return false
            val state = lifecycleState
            if (state != EmiliaMobileLifecycleState.AWAITING_DECISION
                && state != EmiliaMobileLifecycleState.QUORUM_PENDING) return false
            return continuity?.retrySafe != false
        }

    fun expectedChallengeIdentity(): EmiliaMobileExpectedActionIdentity? {
        val actionIdentity = identity?.takeIf { it.isValidActionLock() } ?: return null
        if (!ACTION_REFERENCE.matches(actionReference)) return null
        return EmiliaMobileExpectedActionIdentity(
            actionReference = actionReference,
            actionCaid = requireNotNull(actionIdentity.actionCaid),
            actionDigest = requireNotNull(actionIdentity.actionDigest),
        )
    }

    val canWithdrawSafely: Boolean
        get() = canWithdraw && lifecycleState !in setOf(
            EmiliaMobileLifecycleState.CONSUMED,
            EmiliaMobileLifecycleState.INDETERMINATE,
            EmiliaMobileLifecycleState.EXECUTED,
            EmiliaMobileLifecycleState.REFUSED,
        )

    fun withIndeterminateOutcome(): EmiliaMobileAction = copy(
        continuity = EmiliaMobileContinuity(
            state = EmiliaMobileLifecycleState.INDETERMINATE.wireValue,
            retrySafe = false,
            quorum = effectiveQuorum,
        ),
        quorum = effectiveQuorum,
        canWithdraw = false,
    )

    private fun hasVerifiedExecutionEvidence(): Boolean {
        val passportLifecycle = passport?.get("lifecycle") as? JsonObject
        val passportDigest = (passportLifecycle?.get("outcome_digest") as? JsonPrimitive)?.content
        if (passportDigest?.let(SHA256::matches) == true) return true
        return events.any { event ->
            event.type == "executed" && event.evidenceDigest?.let(SHA256::matches) == true
        }
    }

    private companion object {
        val ACTION_REFERENCE = Regex("""^[A-Za-z0-9:_.@-]{8,256}$""")
        val SHA256 = Regex("""^sha256:[0-9a-f]{64}$""")
    }
}

@Serializable
data class EmiliaMobileInboxResponse(
    @SerialName("approver_id") val approverId: String,
    val actions: List<EmiliaMobileAction> = emptyList(),
)

@Serializable
data class EmiliaMobileHistoryResponse(
    @SerialName("approver_id") val approverId: String,
    val actions: List<EmiliaMobileAction> = emptyList(),
)

@Serializable
data class EmiliaMobilePassportResponse(
    val passport: JsonObject,
)

@Serializable
data class EmiliaMobileWithdrawalResponse(
    val withdrawn: Boolean,
    val state: String,
)

enum class EmiliaMobileLifecycleState(val wireValue: String) {
    AWAITING_DECISION("AWAITING_DECISION"),
    QUORUM_PENDING("QUORUM_PENDING"),
    AUTHORIZED("AUTHORIZED"),
    CONSUMED("CONSUMED"),
    INDETERMINATE("INDETERMINATE"),
    EXECUTED("EXECUTED"),
    REFUSED("REFUSED"),
    DENIED("DENIED"),
    WITHDRAWN("WITHDRAWN"),
    EXPIRED("EXPIRED"),
    CANCELLED("CANCELLED");

    companion object {
        fun fromWire(value: String): EmiliaMobileLifecycleState =
            entries.firstOrNull { it.wireValue == value.uppercase(Locale.US) } ?: INDETERMINATE

        fun fromLegacyStatus(value: String?): EmiliaMobileLifecycleState = when (value) {
            "approved" -> AUTHORIZED
            "denied" -> DENIED
            "withdrawn" -> WITHDRAWN
            "expired" -> EXPIRED
            "cancelled" -> CANCELLED
            else -> AWAITING_DECISION
        }
    }
}
