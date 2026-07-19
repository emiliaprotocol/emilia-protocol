// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import java.time.Instant
import java.io.File
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MobileCeremonyTest {
    private val now = Instant.parse("2026-07-14T19:02:00.000Z")
    private val credentialId = "credential-android-1".toByteArray()
    private val androidKeyId = "android-keystore:sha256:${"A".repeat(43)}"

    private data class Fixture(
        val challenge: EmiliaMobileChallenge,
        val data: ByteArray,
    )

    private fun fixture(transform: (EmiliaMobileChallenge) -> EmiliaMobileChallenge = { it }): Fixture {
        val action = buildJsonObject {
            put("action_type", "benefit.payment_destination_change")
            put("case_id", "case-9482")
            put("destination_last4", "4401")
        }
        val presentation = buildJsonObject {
            put("@version", EmiliaMobilePresentation.VERSION)
            put("title", "Payment destination change")
            put("summary", "Change benefit payment destination for case 9482")
            put("risk", "high")
            put("consequence", "Future benefit payments will be sent to the new destination.")
            put("material_fields", buildJsonObject {
                put("action_type", "benefit.payment_destination_change")
                put("case_id", "case-9482")
                put("destination_last4", "4401")
            })
        }
        val actionHash = EmiliaCanonicalJson.digest(action)
        val displayHash = EmiliaCanonicalJson.digest(presentation)
        val profileHash = "sha256:" + "a".repeat(64)
        val context = buildJsonObject {
            put("ep_version", "1.0")
            put("context_type", "ep.signoff.v1")
            put("action_hash", actionHash)
            put("policy_id", JsonNull)
            put("policy_hash", JsonNull)
            put("initiator", "ep:agent:benefits-assistant")
            put("approver", "ep:approver:case-supervisor")
            put("approver_index", 1)
            put("required_approvals", 1)
            put("nonce", "sig_0123456789abcdef0123456789abcdef")
            put("issued_at", "2026-07-14T19:00:00.000Z")
            put("expires_at", "2026-07-14T19:05:00.000Z")
            put("decision", "approved")
            put("display_hash", displayHash)
            put("mobile_binding", buildJsonObject {
                put("profile", "EP-MOBILE-CHALLENGE-v1")
                put("profile_hash", profileHash)
                put("platform", "android")
                put("app_id", "gov.example.android.approvals")
                put("device_key_id", "ep:key:mobile-android-1")
                put("credential_id", credentialId.base64Url())
                put("attestation_key_id", androidKeyId)
            })
        }
        val challengeId = "mob_0123456789abcdef"
        val binding = buildJsonObject {
            put("@version", "EP-MOBILE-ATTESTATION-BINDING-v1")
            put("challenge_id", challengeId)
            put("nonce", "sig_0123456789abcdef0123456789abcdef")
            put("action_hash", actionHash)
            put("context_hash", EmiliaCanonicalJson.digest(context))
            put("profile_hash", profileHash)
            put("rp_id", "approve.example.gov")
            put("platform", "android")
            put("app_id", "gov.example.android.approvals")
            put("device_key_id", "ep:key:mobile-android-1")
            put("attestation_key_id", androidKeyId)
        }
        val challenge = transform(EmiliaMobileChallenge(
            version = "AE-CHALLENGE-v1",
            challengeProfile = "EP-MOBILE-CHALLENGE-v1",
            challengeId = challengeId,
            nonce = "sig_0123456789abcdef0123456789abcdef",
            action = action,
            actionHash = actionHash,
            profileHash = profileHash,
            authorizationContext = context,
            webauthn = EmiliaWebAuthnRequest(
                rpId = "approve.example.gov",
                challenge = EmiliaCanonicalJson.sha256(context).base64Url(),
                credentialIds = listOf(credentialId.base64Url()),
                userVerification = "required",
                timeoutMs = 300_000,
            ),
            presentation = presentation,
            attestation = EmiliaAttestationRequest(
                required = true,
                format = "play-integrity-standard",
                binding = binding,
                requestHash = EmiliaCanonicalJson.sha256(binding).base64Url(),
            ),
            issuedAt = "2026-07-14T19:00:00.000Z",
            expiresAt = "2026-07-14T19:05:00.000Z",
        ))
        return Fixture(challenge, Json.encodeToString(challenge).toByteArray())
    }

    private fun enrollmentChallenge(): ByteArray {
        val challengeBytes = "registration-challenge".toByteArray().base64Url()
        val binding = buildJsonObject {
            put("@version", "EP-MOBILE-ENROLLMENT-CHALLENGE-v1")
            put("enrollment_id", "enr_0123456789abcdef")
            put("challenge", challengeBytes)
            put("approver_id", "ep:approver:case-supervisor")
            put("platform", "android")
            put("app_id", "gov.example.approvals")
            put("rp_id", "approve.example.gov")
            put("origin", "https://approve.example.gov")
            put("enrollment_valid_to", "2027-07-14T19:00:00.000Z")
            put("issued_at", "2026-07-14T19:00:00.000Z")
            put("expires_at", "2026-07-14T19:05:00.000Z")
        }
        val challenge = EmiliaMobileEnrollmentChallenge(
            version = "AE-CHALLENGE-v1",
            challengeProfile = "EP-MOBILE-ENROLLMENT-CHALLENGE-v1",
            challengeId = "enr_0123456789abcdef",
            enrollmentId = "enr_0123456789abcdef",
            nonce = "reg_0123456789abcdef",
            challenge = challengeBytes,
            approverId = "ep:approver:case-supervisor",
            platform = "android",
            appId = "gov.example.approvals",
            rpId = "approve.example.gov",
            origin = "https://approve.example.gov",
            user = EmiliaMobileEnrollmentChallenge.User(
                id = "ep:approver:case-supervisor".toByteArray().base64Url(),
                name = "case-supervisor@example.gov",
                displayName = "Case Supervisor",
            ),
            enrollmentValidTo = "2027-07-14T19:00:00.000Z",
            webauthn = buildJsonObject {},
            platformBinding = binding,
            platformRequestHash = EmiliaCanonicalJson.sha256(binding).base64Url(),
            issuedAt = "2026-07-14T19:00:00.000Z",
            expiresAt = "2026-07-14T19:05:00.000Z",
        )
        return Json.encodeToString(challenge).toByteArray()
    }

    @Test
    fun canonicalJsonMatchesSharedSafeIntegerProfile() {
        val vectorFile = File(requireNotNull(System.getProperty("user.dir")))
            .resolve("../../mobile/conformance/mobile-core.v1.json")
            .canonicalFile
        val vectors = Json.parseToJsonElement(vectorFile.readText()).jsonObject
            .getValue("canonicalization").jsonArray
        vectors.forEach { element ->
            val vector = element.jsonObject
            val id = vector.getValue("id").jsonPrimitive.content
            val value = vector.getValue("value")
            assertEquals(id, vector.getValue("canonical").jsonPrimitive.content, EmiliaCanonicalJson.encode(value).toString(Charsets.UTF_8))
            assertEquals(id, "sha256:" + vector.getValue("sha256").jsonPrimitive.content, EmiliaCanonicalJson.digest(value))
        }
    }

    @Test
    fun controlledPresentationMatchesSharedMappingVectors() {
        val vectorFile = File(requireNotNull(System.getProperty("user.dir")))
            .resolve("../../mobile/conformance/mobile-core.v1.json")
            .canonicalFile
        val vectors = Json.parseToJsonElement(vectorFile.readText()).jsonObject
            .getValue("presentation_mapping").jsonArray
        vectors.forEach { element ->
            val vector = element.jsonObject
            val id = vector.getValue("id").jsonPrimitive.content
            val expectedAccept = vector.getValue("expect").jsonPrimitive.content == "accept"
            var action = vector.getValue("action").jsonObject
            var fields = vector.getValue("material_fields").jsonObject
            vector["repeat_scalar"]?.jsonObject?.let { repeated ->
                val field = repeated.getValue("field").jsonPrimitive.content
                val codePoint = repeated.getValue("code_point").jsonPrimitive.content.toInt()
                val count = repeated.getValue("count").jsonPrimitive.content.toInt()
                val value = String(Character.toChars(codePoint)).repeat(count)
                action = JsonObject(action + (field to JsonPrimitive(value)))
                fields = JsonObject(fields + (field to JsonPrimitive(value)))
            }
            val presentation = buildJsonObject {
                put("@version", EmiliaMobilePresentation.VERSION)
                put("title", "Controlled action")
                put("summary", "Review every exact raw field.")
                put("risk", "consequential")
                put("consequence", "The selected decision applies only to these exact values.")
                put("material_fields", fields)
            }
            val result = runCatching {
                EmiliaMobileChallengeValidator.validatePresentation(presentation, action)
            }
            assertEquals(id, expectedAccept, result.isSuccess)
            if (expectedAccept) {
                assertEquals(id, fields.mapValues { it.value.jsonPrimitive.content }, result.getOrThrow().materialFields)
            }
        }
    }

    @Test
    fun validatesAndBuildsPortableCeremonyResponse() = runTest {
        val item = fixture()
        val passkeys = EmiliaPasskeyAssertionProvider { rpId, challenge, allowed ->
            assertEquals("approve.example.gov", rpId)
            assertEquals(32, challenge.size)
            assertEquals(1, allowed.size)
            EmiliaPasskeyAssertion(
                credentialId = credentialId,
                authenticatorData = byteArrayOf(1, 2, 3),
                clientDataJson = "client-data".toByteArray(),
                signature = byteArrayOf(4, 5, 6),
            )
        }
        val integrity = object : EmiliaPlatformIntegrityProvider {
            override val format = "play-integrity-standard"
            override val attestationKeyId = androidKeyId
            override suspend fun assertion(requestHash: ByteArray): EmiliaPlatformIntegrityAssertion {
                assertEquals(32, requestHash.size)
                return EmiliaPlatformIntegrityAssertion(
                    token = "play-integrity-token".toByteArray(),
                    deviceKeySignature = "device-key-signature".toByteArray(),
                )
            }
        }
        val coordinator = EmiliaMobileCeremonyCoordinator(
            passkeys = passkeys,
            integrity = integrity,
            appId = "gov.example.android.approvals",
            deviceKeyId = "ep:key:mobile-android-1",
        )
        val response = coordinator.perform(item.data, EmiliaMobileDecision.APPROVED, now)
        assertEquals("EP-MOBILE-CEREMONY-v1", response.version)
        assertEquals("approved", response.decision)
        assertEquals(credentialId.base64Url(), response.credentialId)
        assertEquals("play-integrity-standard", response.attestation.format)
        assertEquals(androidKeyId, response.attestationKeyId)
        assertEquals("device-key-signature".toByteArray().base64Url(), response.attestation.deviceKeySignature)
    }

    @Test
    fun refusesApproveVersusDenyInversionBeforeSigning() {
        val item = fixture()
        assertThrows(EmiliaMobileException.DecisionMismatch::class.java) {
            EmiliaMobileChallengeValidator.decodeAndValidate(
                item.data,
                now,
                EmiliaMobileDecision.DENIED,
            )
        }
    }

    @Test
    fun sampleRequiresVerifiedDecisionMatchBeforeSealedStatus() {
        val source = File(requireNotNull(System.getProperty("user.dir")))
            .resolve("sample/src/main/kotlin/ai/emiliaprotocol/approver/MainActivity.kt")
            .readText()
        assertEquals(true, source.contains("result.decision != decision.wireValue"))
    }

    @Test
    fun refusesActionAndBindingMutation() {
        val badAction = fixture { original ->
            original.copy(action = buildJsonObject {
                put("action_type", "benefit.payment_destination_change")
                put("case_id", "case-9482")
                put("destination_last4", "9999")
            })
        }
        assertThrows(EmiliaMobileException.ActionMismatch::class.java) {
            EmiliaMobileChallengeValidator.decodeAndValidate(badAction.data, now)
        }

        val badBinding = fixture { original ->
            original.copy(attestation = original.attestation.copy(
                binding = buildJsonObject { put("substituted", true) }
            ))
        }
        assertThrows(EmiliaMobileException.ContextMismatch::class.java) {
            EmiliaMobileChallengeValidator.decodeAndValidate(badBinding.data, now)
        }
    }

    @Test
    fun refusesUnknownAndNestedPresentationFieldsBeforeSigning() {
        val unknown = fixture { original ->
            original.copy(presentation = JsonObject(
                original.presentation.jsonObject + ("hidden_detail" to JsonPrimitive("not rendered"))
            ))
        }
        assertThrows(EmiliaMobileException.DisplayMismatch::class.java) {
            EmiliaMobileChallengeValidator.decodeAndValidate(unknown.data, now)
        }

        val nested = fixture { original ->
            val presentation = original.presentation.jsonObject
            val fields = presentation.getValue("material_fields").jsonObject
            original.copy(presentation = JsonObject(
                presentation + ("material_fields" to JsonObject(
                    fields + ("hidden" to buildJsonObject { put("nested", true) })
                ))
            ))
        }
        assertThrows(EmiliaMobileException.DisplayMismatch::class.java) {
            EmiliaMobileChallengeValidator.decodeAndValidate(nested.data, now)
        }
    }

    @Test
    fun enrollmentBindsPasskeyAndPlayIntegrityToTheSameRequest() = runTest {
        val passkeys = EmiliaPasskeyRegistrationProvider { rpId, challenge, userId, _, _ ->
            assertEquals("approve.example.gov", rpId)
            assertEquals("registration-challenge", challenge.toString(Charsets.UTF_8))
            assertEquals("ep:approver:case-supervisor", userId.toString(Charsets.UTF_8))
            buildJsonObject {
                put("id", "registered-credential")
                put("rawId", "registered-credential")
                put("type", "public-key")
                put("response", buildJsonObject {
                    put("clientDataJSON", "client-data")
                    put("attestationObject", "attestation-object")
                })
            }
        }
        val platform = EmiliaPlatformEnrollmentProvider { requestHash ->
            assertEquals(32, requestHash.size)
            EmiliaPlatformEnrollment(
                format = "play-integrity-standard",
                attestationKeyId = androidKeyId,
                token = "integrity-token".toByteArray(),
                requestHash = requestHash,
            )
        }
        val coordinator = EmiliaMobileEnrollmentCoordinator(
            passkeys = passkeys,
            platformEnrollment = platform,
            appId = "gov.example.approvals",
        )
        val response = coordinator.perform(
            enrollmentChallenge(),
            now,
        )
        assertEquals("EP-MOBILE-ENROLLMENT-v1", response.version)
        assertEquals("2027-07-14T19:00:00.000Z", response.requestedValidTo)
        assertEquals(androidKeyId, response.attestationKeyId)
        assertEquals(response.platformRequestHash, response.platformAttestation.requestHash)
    }
}
