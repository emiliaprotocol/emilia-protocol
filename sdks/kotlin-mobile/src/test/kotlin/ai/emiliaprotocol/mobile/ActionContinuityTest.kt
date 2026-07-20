// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ActionContinuityTest {
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = true }
    private val caidDigest = "XupRmBfC678AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private val caid =
        "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:$caidDigest"
    private val digest = "sha256:" + "a".repeat(64)

    @Test
    fun expandedHistoryDecodesEveryContinuitySurface() {
        val response = json.decodeFromString<EmiliaMobileHistoryResponse>(
            """
            {
              "approver_id": "ep:approver:finance",
              "actions": [{
                "action_reference": "mobact_11111111111111111111111111111111",
                "title": "Release payment",
                "summary": "Release the exact treasury payment.",
                "risk": "high",
                "material_fields": {"amount": "${'$'}250,000", "beneficiary": "Grid Works"},
                "expires_at": "2026-07-21T00:00:00.000Z",
                "created_at": "2026-07-20T20:00:00.000Z",
                "status": "approved",
                "revision": 2,
                "identity": {
                  "action_caid": "$caid",
                  "action_digest": "$digest",
                  "fingerprint": "5EEA-5198-17C2-EBBF"
                },
                "supersedes_action_caid": "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${"B".repeat(43)}",
                "continuity": {
                  "state": "EXECUTED",
                  "retry_safe": false,
                  "quorum": {"approved": 2, "required": 2, "denied": 0, "withdrawn": 0}
                },
                "quorum": {"approved": 2, "required": 2, "denied": 0, "withdrawn": 0},
                "changes": [{
                  "field": "amount",
                  "change": "changed",
                  "before": "${'$'}200,000",
                  "after": "${'$'}250,000"
                }],
                "alignments": [{
                  "system": "AgentROA",
                  "verdict": "EQUIVALENT_UNDER_PROFILE",
                  "profile_id": "ep:map:agentroa:v1",
                  "profile_hash": "sha256:${"c".repeat(64)}",
                  "native_verified": true,
                  "evidence_digest": "sha256:${"d".repeat(64)}"
                }],
                "events": [{
                  "event_id": "mae_${"1".repeat(32)}",
                  "type": "executed",
                  "details": {"executor": "provider:treasury"},
                  "evidence_digest": "sha256:${"e".repeat(64)}",
                  "created_at": "2026-07-20T20:05:00.000Z"
                }],
                "can_withdraw": false,
                "passport": {
                  "@version": "EP-MOBILE-DECISION-PASSPORT-v1",
                  "lifecycle": {"state": "EXECUTED", "outcome_digest": "sha256:${"e".repeat(64)}"}
                }
              }]
            }
            """.trimIndent(),
        )

        val action = response.actions.single()
        assertEquals("ep:approver:finance", response.approverId)
        assertEquals("5EEA-5198-17C2-EBBF", action.identity?.stableFingerprint())
        assertTrue(requireNotNull(action.identity).isValidActionLock())
        assertEquals(caid, action.expectedChallengeIdentity()?.actionCaid)
        assertEquals(2, action.revision)
        assertEquals("changed", action.changes.single().change)
        assertEquals(2, action.effectiveQuorum?.safeApproved)
        assertEquals("AgentROA", action.alignments.single().system)
        assertEquals("executed", action.events.single().type)
        assertEquals(EmiliaMobileLifecycleState.EXECUTED, action.lifecycleState)
        assertFalse(action.canDecideSafely)
        assertFalse(action.canWithdrawSafely)
    }

    @Test
    fun executedWithoutServerEvidenceIsIndeterminateAndCannotRetry() {
        val action = action(
            status = "approved",
            continuity = EmiliaMobileContinuity("EXECUTED", retrySafe = true),
        )

        assertEquals(EmiliaMobileLifecycleState.INDETERMINATE, action.lifecycleState)
        assertFalse(action.canDecideSafely)
        assertFalse(action.canWithdrawSafely)
    }

    @Test
    fun consumedAndIndeterminateRemainDistinctNonRetryableStates() {
        val consumed = action(
            status = "approved",
            continuity = EmiliaMobileContinuity("CONSUMED", retrySafe = false),
            canWithdraw = true,
        )
        val indeterminate = action(
            status = "pending",
            continuity = EmiliaMobileContinuity("INDETERMINATE", retrySafe = false),
        )

        assertEquals(EmiliaMobileLifecycleState.CONSUMED, consumed.lifecycleState)
        assertEquals(EmiliaMobileLifecycleState.INDETERMINATE, indeterminate.lifecycleState)
        assertFalse(consumed.canWithdrawSafely)
        assertFalse(indeterminate.canDecideSafely)
        assertEquals(
            EmiliaMobileLifecycleState.INDETERMINATE,
            action(
                status = "pending",
                continuity = EmiliaMobileContinuity("FUTURE_UNKNOWN_STATE", retrySafe = true),
            ).lifecycleState,
        )
    }

    @Test
    fun fingerprintIsDerivedFromCaidAndConflictsFailClosed() {
        val missingPresentation = EmiliaMobileActionIdentity(caid, digest)
        val conflictingPresentation = EmiliaMobileActionIdentity(
            caid,
            digest,
            "BBBB-BBBB-BBBB-BBBB",
        )
        val punctuationDigest =
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:" +
                "__________________________________________8"
        val punctuationIdentity = EmiliaMobileActionIdentity(punctuationDigest, digest)
        val nonCanonicalDigest = EmiliaMobileActionIdentity(
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${"_".repeat(43)}",
            digest,
        )

        assertEquals("5EEA-5198-17C2-EBBF", missingPresentation.stableFingerprint())
        assertEquals("FFFF-FFFF-FFFF-FFFF", punctuationIdentity.stableFingerprint())
        assertNull(nonCanonicalDigest.stableFingerprint())
        assertNull(conflictingPresentation.stableFingerprint())
        assertFalse(conflictingPresentation.isValidActionLock())
    }

    @Test
    fun pendingDecisionRequiresACompleteSelectedActionIdentity() {
        val pending = action(
            status = "pending",
            continuity = EmiliaMobileContinuity("AWAITING_DECISION", retrySafe = true),
        )
        val missingIdentity = pending.copy(identity = null)

        assertTrue(pending.canDecideSafely)
        assertEquals(pending.actionReference, pending.expectedChallengeIdentity()?.actionReference)
        assertFalse(missingIdentity.canDecideSafely)
        assertNull(missingIdentity.expectedChallengeIdentity())
    }

    @Test
    fun legacyInboxStillDecodesWithSafeOptionalDefaults() {
        val response = json.decodeFromString<EmiliaMobileInboxResponse>(
            """
            {
              "approver_id": "ep:approver:legacy",
              "actions": [{
                "action_reference": "mobact_22222222222222222222222222222222",
                "title": "Legacy action",
                "summary": "Old response shape",
                "risk": "high",
                "material_fields": {"amount": "10"},
                "expires_at": "2026-07-21T00:00:00.000Z",
                "created_at": "2026-07-20T20:00:00.000Z"
              }]
            }
            """.trimIndent(),
        )

        val action = response.actions.single()
        assertTrue(action.changes.isEmpty())
        assertTrue(action.alignments.isEmpty())
        assertTrue(action.events.isEmpty())
        assertNull(action.identity)
        assertEquals(EmiliaMobileLifecycleState.AWAITING_DECISION, action.lifecycleState)
        assertFalse(action.canDecideSafely)
    }

    private fun action(
        status: String?,
        continuity: EmiliaMobileContinuity?,
        canWithdraw: Boolean = false,
    ) = EmiliaMobileAction(
        actionReference = "mobact_11111111111111111111111111111111",
        title = "Action",
        summary = "Summary",
        risk = "high",
        materialFields = kotlinx.serialization.json.buildJsonObject {},
        expiresAt = "2026-07-21T00:00:00.000Z",
        createdAt = "2026-07-20T20:00:00.000Z",
        status = status,
        identity = EmiliaMobileActionIdentity(caid, digest, "5EEA-5198-17C2-EBBF"),
        continuity = continuity,
        canWithdraw = canWithdraw,
    )
}
