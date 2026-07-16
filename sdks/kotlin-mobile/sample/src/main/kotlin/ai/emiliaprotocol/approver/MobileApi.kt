// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.approver

import ai.emiliaprotocol.mobile.EmiliaMobileCeremonyResponse
import ai.emiliaprotocol.mobile.EmiliaMobileChallenge
import ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentChallenge
import ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentResponse
import java.io.ByteArrayOutputStream
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

@Serializable
data class PairingResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("approver_id") val approverId: String,
    @SerialName("profile_id") val profileId: String,
)

@Serializable
data class InboxResponse(
    @SerialName("approver_id") val approverId: String,
    val actions: List<InboxAction>,
)

@Serializable
data class InboxAction(
    @SerialName("action_reference") val actionReference: String,
    val title: String,
    val summary: String,
    val risk: String,
    @SerialName("material_fields") val materialFields: JsonObject,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("created_at") val createdAt: String,
)

@Serializable
private data class ChallengeResponse(
    val ok: Boolean,
    val verdict: String,
    val challenge: EmiliaMobileChallenge? = null,
)

@Serializable
private data class EnrollmentChallengeResponse(
    val ok: Boolean,
    val verdict: String,
    val challenge: EmiliaMobileEnrollmentChallenge? = null,
)

@Serializable
data class EnrollmentRecord(
    @SerialName("device_key_id") val deviceKeyId: String,
    @SerialName("attestation_key_id") val attestationKeyId: String,
)

@Serializable
data class EnrollmentResult(
    val ok: Boolean,
    val verdict: String,
    val enrollment: EnrollmentRecord? = null,
)

@Serializable
data class CeremonyResult(
    val valid: Boolean,
    val verdict: String,
    val decision: String? = null,
    val reason: String? = null,
    @SerialName("context_hash") val contextHash: String? = null,
)

@Serializable
private data class RevocationResult(val revoked: Boolean)

@Serializable
private data class Problem(val detail: String? = null, val reason: String? = null, val verdict: String? = null)

class MobileApi(
    rawBaseUrl: String,
    private val accessToken: String? = null,
) {
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = true }
    private val baseUrl = URL(rawBaseUrl).also {
        require(it.protocol == "https") { "The approval service must use HTTPS" }
        require(it.host.isNotBlank()) { "The approval service host is missing" }
        require(!BuildConfig.PRODUCTION_RELEASE || it.toExternalForm() == PRODUCTION_BASE_URL) {
            "The production approval API identity is not pinned"
        }
    }

    suspend fun exchangePairing(code: String, appId: String): PairingResponse = post(
        "v1/mobile/pairings/exchange",
        buildJsonObject {
            put("pairing_code", code)
            put("platform", "android")
            put("app_id", appId)
        },
        authenticated = false,
    )

    suspend fun inbox(): List<InboxAction> = get<InboxResponse>("v1/mobile/inbox").actions

    suspend fun issueEnrollment(approverId: String, appId: String): EmiliaMobileEnrollmentChallenge {
        val result = post<EnrollmentChallengeResponse>(
            "v1/mobile/enrollments/challenges",
            buildJsonObject {
                put("approver_id", approverId)
                put("platform", "android")
                put("app_id", appId)
            },
        )
        return result.challenge?.takeIf { result.ok } ?: throw MobileApiException.Refused(result.verdict)
    }

    suspend fun completeEnrollment(
        challenge: EmiliaMobileEnrollmentChallenge,
        response: EmiliaMobileEnrollmentResponse,
    ): EnrollmentResult = post(
        "v1/mobile/enrollments",
        buildJsonObject {
            put("challenge", json.encodeToJsonElement(EmiliaMobileEnrollmentChallenge.serializer(), challenge))
            put("response", json.encodeToJsonElement(EmiliaMobileEnrollmentResponse.serializer(), response))
        },
    )

    suspend fun issueChallenge(
        actionReference: String,
        approverId: String,
        decision: String,
        profileId: String,
        appId: String,
        deviceKeyId: String,
    ): EmiliaMobileChallenge {
        val result = post<ChallengeResponse>(
            "v1/mobile/challenges",
            buildJsonObject {
                put("profile_id", profileId)
                put("action_reference", actionReference)
                put("approver_id", approverId)
                put("decision", decision)
                put("platform", "android")
                put("app_id", appId)
                put("device_key_id", deviceKeyId)
            },
        )
        return result.challenge?.takeIf { result.ok } ?: throw MobileApiException.Refused(result.verdict)
    }

    suspend fun verify(
        challenge: EmiliaMobileChallenge,
        response: EmiliaMobileCeremonyResponse,
    ): CeremonyResult = post(
        "v1/mobile/ceremonies",
        buildJsonObject {
            put("challenge", json.encodeToJsonElement(EmiliaMobileChallenge.serializer(), challenge))
            put("response", json.encodeToJsonElement(EmiliaMobileCeremonyResponse.serializer(), response))
        },
    )

    suspend fun revokeSession() {
        if (!delete<RevocationResult>("v1/mobile/session").revoked) {
            throw MobileApiException.Refused("session_not_revoked")
        }
    }

    private suspend inline fun <reified T> get(path: String): T = request("GET", path, null, true)

    private suspend inline fun <reified T> post(
        path: String,
        body: JsonElement,
        authenticated: Boolean = true,
    ): T = request("POST", path, body, authenticated)

    private suspend inline fun <reified T> delete(path: String): T = request("DELETE", path, null, true)

    private suspend inline fun <reified T> request(
        method: String,
        path: String,
        body: JsonElement?,
        authenticated: Boolean,
    ): T = withContext(Dispatchers.IO) {
        val endpoint = URL(baseUrl, path)
        check(endpoint.protocol == "https" && endpoint.host == baseUrl.host) { "Unsafe approval endpoint" }
        val connection = endpoint.openConnection() as HttpsURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 20_000
            connection.setRequestProperty("Accept", "application/json")
            if (authenticated) {
                val token = accessToken?.takeIf { it.isNotBlank() } ?: throw MobileApiException.SessionExpired
                connection.setRequestProperty("Authorization", "Bearer $token")
            }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val contentType = connection.contentType?.substringBefore(';')?.trim()?.lowercase()
            if (connection.url.protocol != "https" || connection.url.host != baseUrl.host
                || contentType != "application/json") throw MobileApiException.Transport
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { input ->
                val output = ByteArrayOutputStream()
                val chunk = ByteArray(8_192)
                var total = 0
                while (true) {
                    val read = input.read(chunk)
                    if (read < 0) break
                    total += read
                    if (total > MAX_RESPONSE_BYTES) throw MobileApiException.Transport
                    output.write(chunk, 0, read)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            if (status == 401) throw MobileApiException.SessionExpired
            if (status !in 200..299) {
                val problem = runCatching { json.decodeFromString<Problem>(bytes.toString(Charsets.UTF_8)) }.getOrNull()
                throw MobileApiException.Refused(problem?.detail ?: problem?.reason ?: problem?.verdict ?: "HTTP $status")
            }
            json.decodeFromString<T>(bytes.toString(Charsets.UTF_8))
        } catch (error: MobileApiException) {
            throw error
        } catch (_: Exception) {
            throw MobileApiException.Transport
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val MAX_RESPONSE_BYTES = 1_048_576
        const val PRODUCTION_BASE_URL = "https://www.emiliaprotocol.ai/api/"
    }
}

sealed class MobileApiException(message: String) : Exception(message) {
    data object Transport : MobileApiException("The approval service is unavailable. Nothing was authorized.")
    data object SessionExpired : MobileApiException("This device connection has expired.")
    data class Refused(val detail: String) : MobileApiException("The request was refused: $detail")
}
