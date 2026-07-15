// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import java.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

@Serializable
data class EmiliaMobileEnrollmentChallenge(
    @SerialName("@version") val version: String,
    @SerialName("challenge_profile") val challengeProfile: String,
    @SerialName("challenge_id") val challengeId: String,
    @SerialName("enrollment_id") val enrollmentId: String,
    val nonce: String,
    val challenge: String,
    @SerialName("approver_id") val approverId: String,
    val platform: String,
    @SerialName("app_id") val appId: String,
    @SerialName("rp_id") val rpId: String,
    val origin: String,
    val user: User,
    @SerialName("enrollment_valid_to") val enrollmentValidTo: String,
    val webauthn: JsonElement,
    @SerialName("platform_binding") val platformBinding: JsonElement,
    @SerialName("platform_request_hash") val platformRequestHash: String,
    @SerialName("issued_at") val issuedAt: String,
    @SerialName("expires_at") val expiresAt: String,
) {
    @Serializable
    data class User(val id: String, val name: String, @SerialName("display_name") val displayName: String)
}

fun interface EmiliaPasskeyRegistrationProvider {
    suspend fun registration(
        rpId: String,
        challenge: ByteArray,
        userId: ByteArray,
        userName: String,
        displayName: String,
    ): JsonElement
}

data class EmiliaPlatformEnrollment(
    val format: String,
    val attestationKeyId: String,
    val token: ByteArray,
)

fun interface EmiliaPlatformEnrollmentProvider {
    suspend fun enrollment(requestHash: ByteArray): EmiliaPlatformEnrollment
}

@Serializable
data class EmiliaMobileEnrollmentResponse(
    @SerialName("@version") val version: String = "EP-MOBILE-ENROLLMENT-v1",
    @SerialName("enrollment_id") val enrollmentId: String,
    @SerialName("approver_id") val approverId: String,
    val platform: String,
    @SerialName("app_id") val appId: String,
    @SerialName("platform_request_hash") val platformRequestHash: String,
    @SerialName("attestation_key_id") val attestationKeyId: String,
    @SerialName("requested_valid_to") val requestedValidTo: String,
    @SerialName("passkey_registration") val passkeyRegistration: JsonElement,
    @SerialName("platform_attestation") val platformAttestation: PlatformAttestation,
) {
    @Serializable
    data class PlatformAttestation(val format: String, val token: String)
}

class EmiliaMobileEnrollmentCoordinator(
    private val passkeys: EmiliaPasskeyRegistrationProvider,
    private val platformEnrollment: EmiliaPlatformEnrollmentProvider,
    private val platform: String = "android",
    private val appId: String,
) {
    private val json = Json { ignoreUnknownKeys = false; explicitNulls = true }

    suspend fun perform(
        challengeData: ByteArray,
        now: Instant = Instant.now(),
    ): EmiliaMobileEnrollmentResponse {
        val challenge = try {
            json.decodeFromString<EmiliaMobileEnrollmentChallenge>(challengeData.toString(Charsets.UTF_8))
        } catch (_: Exception) {
            throw EmiliaMobileException.MalformedChallenge("enrollment challenge JSON could not be decoded")
        }
        val issued = try { Instant.parse(challenge.issuedAt) } catch (_: Exception) { null }
        val expires = try { Instant.parse(challenge.expiresAt) } catch (_: Exception) { null }
        val validTo = try { Instant.parse(challenge.enrollmentValidTo) } catch (_: Exception) { null }
        if (challenge.version != "AE-CHALLENGE-v1"
            || challenge.challengeProfile != "EP-MOBILE-ENROLLMENT-CHALLENGE-v1"
            || challenge.challengeId != challenge.enrollmentId
            || challenge.platform != platform || challenge.appId != appId
            || issued == null || expires == null || now < issued || now > expires
            || validTo == null || validTo <= now) throw EmiliaMobileException.MalformedChallenge("enrollment challenge is invalid or expired")

        val expectedBinding = buildJsonObject {
            put("@version", "EP-MOBILE-ENROLLMENT-CHALLENGE-v1")
            put("enrollment_id", challenge.enrollmentId)
            put("challenge", challenge.challenge)
            put("approver_id", challenge.approverId)
            put("platform", challenge.platform)
            put("app_id", challenge.appId)
            put("rp_id", challenge.rpId)
            put("origin", challenge.origin)
            put("enrollment_valid_to", challenge.enrollmentValidTo)
            put("issued_at", challenge.issuedAt)
            put("expires_at", challenge.expiresAt)
        }
        if (challenge.platformBinding != expectedBinding) throw EmiliaMobileException.ContextMismatch
        val requestHash = EmiliaCanonicalJson.sha256(expectedBinding)
        if (requestHash.base64Url() != challenge.platformRequestHash) throw EmiliaMobileException.ContextMismatch

        val registration = passkeys.registration(
            challenge.rpId,
            challenge.challenge.base64UrlBytes(),
            challenge.user.id.base64UrlBytes(),
            challenge.user.name,
            challenge.user.displayName,
        )
        val integrity = platformEnrollment.enrollment(requestHash)
        return EmiliaMobileEnrollmentResponse(
            enrollmentId = challenge.enrollmentId,
            approverId = challenge.approverId,
            platform = platform,
            appId = appId,
            platformRequestHash = challenge.platformRequestHash,
            attestationKeyId = integrity.attestationKeyId,
            requestedValidTo = challenge.enrollmentValidTo,
            passkeyRegistration = registration,
            platformAttestation = EmiliaMobileEnrollmentResponse.PlatformAttestation(
                integrity.format,
                integrity.token.base64Url(),
            ),
        )
    }

    fun encode(response: EmiliaMobileEnrollmentResponse): String = json.encodeToString(response)
}
