// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import java.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

sealed class EmiliaMobileException(message: String) : Exception(message) {
    data class MalformedChallenge(val detail: String) : EmiliaMobileException(detail)
    data object ActionMismatch : EmiliaMobileException("action mismatch")
    data object DisplayMismatch : EmiliaMobileException("display mismatch")
    data object ContextMismatch : EmiliaMobileException("context mismatch")
    data object NonCanonicalJson : EmiliaMobileException("non-canonical JSON")
    data class Unavailable(val detail: String) : EmiliaMobileException(detail)
}

@Serializable
data class EmiliaWebAuthnRequest(
    @SerialName("rp_id") val rpId: String,
    val challenge: String,
    @SerialName("credential_ids") val credentialIds: List<String>,
    @SerialName("user_verification") val userVerification: String,
    @SerialName("timeout_ms") val timeoutMs: Long,
)

@Serializable
data class EmiliaAttestationRequest(
    val required: Boolean,
    val format: String,
    val binding: JsonElement,
    @SerialName("request_hash") val requestHash: String,
)

@Serializable
data class EmiliaMobileChallenge(
    @SerialName("@version") val version: String,
    @SerialName("challenge_profile") val challengeProfile: String,
    @SerialName("challenge_id") val challengeId: String,
    val nonce: String,
    val action: JsonElement,
    @SerialName("action_hash") val actionHash: String,
    @SerialName("profile_hash") val profileHash: String,
    @SerialName("authorization_context") val authorizationContext: JsonElement,
    val webauthn: EmiliaWebAuthnRequest,
    val presentation: JsonElement,
    val attestation: EmiliaAttestationRequest,
    @SerialName("issued_at") val issuedAt: String,
    @SerialName("expires_at") val expiresAt: String,
)

data class EmiliaPasskeyAssertion(
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val clientDataJson: ByteArray,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is EmiliaPasskeyAssertion
        && credentialId.contentEquals(other.credentialId)
        && authenticatorData.contentEquals(other.authenticatorData)
        && clientDataJson.contentEquals(other.clientDataJson)
        && signature.contentEquals(other.signature)

    override fun hashCode(): Int = credentialId.contentHashCode()
}

fun interface EmiliaPasskeyAssertionProvider {
    suspend fun assertion(rpId: String, challenge: ByteArray, allowedCredentialIds: List<ByteArray>): EmiliaPasskeyAssertion
}

interface EmiliaPlatformIntegrityProvider {
    val format: String
    val attestationKeyId: String
    suspend fun assertion(requestHash: ByteArray): ByteArray
}

@Serializable
data class EmiliaMobileCeremonyResponse(
    @SerialName("@version") val version: String = "EP-MOBILE-CEREMONY-v1",
    @SerialName("challenge_id") val challengeId: String,
    val nonce: String,
    val platform: String,
    @SerialName("app_id") val appId: String,
    @SerialName("device_key_id") val deviceKeyId: String,
    @SerialName("credential_id") val credentialId: String,
    @SerialName("attestation_key_id") val attestationKeyId: String,
    val decision: String,
    @SerialName("display_hash") val displayHash: String,
    val signoff: Signoff,
    val attestation: Attestation,
) {
    @Serializable
    data class Signoff(val context: JsonElement, val webauthn: WebAuthn)

    @Serializable
    data class WebAuthn(
        @SerialName("authenticator_data") val authenticatorData: String,
        @SerialName("client_data_json") val clientDataJson: String,
        val signature: String,
    )

    @Serializable
    data class Attestation(val format: String, val token: String)
}

data class EmiliaValidatedChallenge(
    val challenge: EmiliaMobileChallenge,
    val context: JsonObject,
    val mobileBinding: JsonObject,
    val requestHash: ByteArray,
)

object EmiliaMobileChallengeValidator {
    private val json = Json { ignoreUnknownKeys = false; explicitNulls = true }

    fun decodeAndValidate(data: ByteArray, now: Instant = Instant.now()): EmiliaValidatedChallenge {
        val challenge = try { json.decodeFromString<EmiliaMobileChallenge>(data.toString(Charsets.UTF_8)) }
        catch (_: Exception) { throw EmiliaMobileException.MalformedChallenge("challenge JSON could not be decoded") }
        if (challenge.version != "AE-CHALLENGE-v1"
            || challenge.challengeProfile != "EP-MOBILE-CHALLENGE-v1"
            || challenge.webauthn.userVerification != "required"
            || challenge.webauthn.credentialIds.isEmpty()) {
            throw EmiliaMobileException.MalformedChallenge("unsupported mobile challenge profile")
        }
        challenge.webauthn.credentialIds.forEach { it.base64UrlBytes() }
        val issued = try { Instant.parse(challenge.issuedAt) } catch (_: Exception) { null }
        val expires = try { Instant.parse(challenge.expiresAt) } catch (_: Exception) { null }
        if (issued == null || expires == null || now < issued || now > expires || expires <= issued) {
            throw EmiliaMobileException.MalformedChallenge("challenge is outside its validity window")
        }
        if (EmiliaCanonicalJson.digest(challenge.action) != challenge.actionHash) throw EmiliaMobileException.ActionMismatch
        val context = challenge.authorizationContext as? JsonObject ?: throw EmiliaMobileException.ContextMismatch
        if (context.string("action_hash") != challenge.actionHash
            || context.string("display_hash") != EmiliaCanonicalJson.digest(challenge.presentation)
            || context.string("nonce") != challenge.nonce) throw EmiliaMobileException.ContextMismatch
        val mobileBinding = context["mobile_binding"] as? JsonObject ?: throw EmiliaMobileException.ContextMismatch
        if (mobileBinding.string("profile_hash") != challenge.profileHash) throw EmiliaMobileException.ContextMismatch
        if (EmiliaCanonicalJson.sha256(challenge.authorizationContext).base64Url() != challenge.webauthn.challenge) {
            throw EmiliaMobileException.ContextMismatch
        }
        val platform = mobileBinding.string("platform") ?: throw EmiliaMobileException.ContextMismatch
        val expectedFormat = when (platform) {
            "ios" -> "apple-app-attest"
            "android" -> "play-integrity-standard"
            else -> throw EmiliaMobileException.ContextMismatch
        }
        if (challenge.attestation.format != expectedFormat) throw EmiliaMobileException.ContextMismatch
        val expectedBinding = buildJsonObject {
            put("@version", "EP-MOBILE-ATTESTATION-BINDING-v1")
            put("challenge_id", challenge.challengeId)
            put("nonce", challenge.nonce)
            put("action_hash", challenge.actionHash)
            put("context_hash", EmiliaCanonicalJson.digest(challenge.authorizationContext))
            put("profile_hash", challenge.profileHash)
            put("rp_id", challenge.webauthn.rpId)
            put("platform", platform)
            put("app_id", mobileBinding.requireString("app_id"))
            put("device_key_id", mobileBinding.requireString("device_key_id"))
            put("attestation_key_id", mobileBinding.requireString("attestation_key_id"))
        }
        if (challenge.attestation.binding != expectedBinding) throw EmiliaMobileException.ContextMismatch
        val requestHash = EmiliaCanonicalJson.sha256(challenge.attestation.binding)
        if (requestHash.base64Url() != challenge.attestation.requestHash) throw EmiliaMobileException.ContextMismatch
        return EmiliaValidatedChallenge(challenge, context, mobileBinding, requestHash)
    }
}

class EmiliaMobileCeremonyCoordinator(
    private val passkeys: EmiliaPasskeyAssertionProvider,
    private val integrity: EmiliaPlatformIntegrityProvider,
    private val platform: String = "android",
    private val appId: String,
    private val deviceKeyId: String,
) {
    suspend fun perform(challengeData: ByteArray, now: Instant = Instant.now()): EmiliaMobileCeremonyResponse {
        val validated = EmiliaMobileChallengeValidator.decodeAndValidate(challengeData, now)
        val challenge = validated.challenge
        if (validated.mobileBinding.string("platform") != platform
            || validated.mobileBinding.string("app_id") != appId
            || validated.mobileBinding.string("device_key_id") != deviceKeyId
            || validated.mobileBinding.string("attestation_key_id") != integrity.attestationKeyId
            || challenge.attestation.format != integrity.format) throw EmiliaMobileException.ContextMismatch
        val decision = validated.context.requireString("decision")
        if (decision != "approved" && decision != "denied") throw EmiliaMobileException.ContextMismatch
        val credentialIds = challenge.webauthn.credentialIds.map { it.base64UrlBytes() }
        val assertion = passkeys.assertion(
            challenge.webauthn.rpId,
            challenge.webauthn.challenge.base64UrlBytes(),
            credentialIds,
        )
        if (credentialIds.none { it.contentEquals(assertion.credentialId) }) throw EmiliaMobileException.ContextMismatch
        val integrityToken = integrity.assertion(validated.requestHash)
        return EmiliaMobileCeremonyResponse(
            challengeId = challenge.challengeId,
            nonce = challenge.nonce,
            platform = platform,
            appId = appId,
            deviceKeyId = deviceKeyId,
            credentialId = assertion.credentialId.base64Url(),
            attestationKeyId = integrity.attestationKeyId,
            decision = decision,
            displayHash = validated.context.requireString("display_hash"),
            signoff = EmiliaMobileCeremonyResponse.Signoff(
                context = challenge.authorizationContext,
                webauthn = EmiliaMobileCeremonyResponse.WebAuthn(
                    authenticatorData = assertion.authenticatorData.base64Url(),
                    clientDataJson = assertion.clientDataJson.base64Url(),
                    signature = assertion.signature.base64Url(),
                ),
            ),
            attestation = EmiliaMobileCeremonyResponse.Attestation(integrity.format, integrityToken.base64Url()),
        )
    }

    fun encode(response: EmiliaMobileCeremonyResponse): String = Json.encodeToString(response)
}

private fun JsonObject.string(name: String): String? = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
private fun JsonObject.requireString(name: String): String = string(name) ?: throw EmiliaMobileException.ContextMismatch
