// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.approver

import ai.emiliaprotocol.mobile.EmiliaAttestationRequest
import ai.emiliaprotocol.mobile.EmiliaCanonicalJson
import ai.emiliaprotocol.mobile.EmiliaMobileCeremonyResponse
import ai.emiliaprotocol.mobile.EmiliaMobileChallenge
import ai.emiliaprotocol.mobile.EmiliaWebAuthnRequest
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URL
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class MobileApiRecoveryTest {
    @Test
    fun directSuccessRequiresTheFullVerifiedTuple() = runBlocking {
        val fixture = fixture()
        val connections = StubConnections(
            StubResponse(200, ceremonyResult(fixture.decision, fixture.contextHash)),
        )

        val result = api(connections).verify(fixture.challenge, fixture.response)

        assertTrue(result.valid)
        assertEquals("verified", result.verdict)
        assertEquals(fixture.decision, result.decision)
        assertEquals(fixture.contextHash, result.contextHash)
        assertEquals(1, connections.opened.size)
    }

    @Test
    fun directTwoHundredMismatchesAreIndeterminateNotRefused() = runBlocking {
        val fixture = fixture()
        val invalidResults = listOf(
            ceremonyResult(fixture.decision, fixture.contextHash, valid = false),
            ceremonyResult(fixture.decision, fixture.contextHash, verdict = "refused"),
            ceremonyResult("denied", fixture.contextHash),
            ceremonyResult(fixture.decision, fixture.contextHash, reason = "verification_failed"),
            ceremonyResult(fixture.decision, "sha256:" + "f".repeat(64)),
        )

        invalidResults.forEach { body ->
            val connections = StubConnections(StubResponse(200, body))
            try {
                api(connections).verify(fixture.challenge, fixture.response)
                fail("An unverified direct outcome must not be accepted")
            } catch (error: MobileApiException) {
                assertTrue(error is MobileApiException.OutcomeUnknown)
                assertEquals(1, connections.opened.size)
            }
        }
    }

    @Test
    fun everyServerErrorRecoversCommittedOutcomeWithAuthentication() = runBlocking {
        val fixture = fixture()
        for (status in listOf(500, 502, 503, 599)) {
            val connections = StubConnections(
                StubResponse(status, "{\"detail\":\"server_failure\"}"),
                StubResponse(200, committedRecovery(fixture.decision, fixture.contextHash)),
            )
            val result = api(connections).verify(fixture.challenge, fixture.response)

            assertEquals(fixture.decision, result.decision)
            assertEquals(fixture.contextHash, result.contextHash)
            assertEquals(listOf("POST", "GET"), connections.opened.map { it.requestMethod })
            assertEquals("/api/v1/mobile/ceremonies/${fixture.challenge.challengeId}", connections.opened.last().url.path)
            assertEquals("Bearer mobile-access-token", connections.opened.last().getRequestProperty("Authorization"))
        }
    }

    @Test
    fun recoveredOutcomeMustMatchDecisionAndCanonicalContext() = runBlocking {
        val fixture = fixture()
        val mismatches = listOf(
            "denied" to fixture.contextHash,
            fixture.decision to ("sha256:" + "f".repeat(64)),
        )

        for ((decision, contextHash) in mismatches) {
            val connections = StubConnections(
                StubResponse(500, "{\"detail\":\"server_failure\"}"),
                StubResponse(200, committedRecovery(decision, contextHash)),
            )
            try {
                api(connections).verify(fixture.challenge, fixture.response)
                fail("A mismatched recovered result must not be accepted")
            } catch (_: MobileApiException.OutcomeUnknown) {
                assertEquals(2, connections.opened.size)
            }
        }
    }

    @Test
    fun unresolvedRecoveryReturnsOutcomeUnknown() = runBlocking {
        val fixture = fixture()
        val connections = StubConnections(
            StubResponse(504, "{\"detail\":\"timeout\"}"),
            StubResponse(200, "{\"committed\":false,\"outcome\":\"unknown\",\"result\":null}"),
        )

        try {
            api(connections).verify(fixture.challenge, fixture.response)
            fail("An unresolved recovery must not permit retry")
        } catch (_: MobileApiException.OutcomeUnknown) {
            assertEquals(2, connections.opened.size)
        }
    }

    @Test
    fun fourHundredsKeepExistingHandlingWithoutRecovery() = runBlocking {
        val fixture = fixture()
        var connections = StubConnections(StubResponse(409, "{\"detail\":\"ceremony_conflict\"}"))
        try {
            api(connections).verify(fixture.challenge, fixture.response)
            fail("Expected refusal")
        } catch (error: MobileApiException.Refused) {
            assertEquals("ceremony_conflict", error.detail)
            assertEquals(1, connections.opened.size)
        }

        connections = StubConnections(StubResponse(401, "{\"detail\":\"expired\"}"))
        try {
            api(connections).verify(fixture.challenge, fixture.response)
            fail("Expected session expiry")
        } catch (error: MobileApiException) {
            assertTrue(error is MobileApiException.SessionExpired)
            assertEquals(1, connections.opened.size)
        }
    }

    @Test
    fun continuityEndpointsUseEncodedReferencesAndEmptyWithdrawalBody() = runBlocking {
        val actionReference = "mobact:finance@revision.2"
        val historyConnections = StubConnections(
            StubResponse(
                200,
                """
                {
                  "approver_id": "ep:approver:finance",
                  "actions": [{
                    "action_reference": "$actionReference",
                    "title": "Release payment",
                    "summary": "Release payment",
                    "risk": "high",
                    "material_fields": {"amount": "10"},
                    "expires_at": "2026-07-21T00:00:00.000Z",
                    "created_at": "2026-07-20T20:00:00.000Z",
                    "continuity": {"state": "CONSUMED", "retry_safe": false}
                  }]
                }
                """.trimIndent(),
            ),
        )
        assertEquals(
            "CONSUMED",
            api(historyConnections).history().single().continuity?.state,
        )
        assertEquals("/api/v1/mobile/history", historyConnections.opened.single().url.path)

        val passportConnections = StubConnections(
            StubResponse(
                200,
                """{"passport":{"@version":"EP-MOBILE-DECISION-PASSPORT-v1"}}""",
            ),
        )
        assertEquals(
            "EP-MOBILE-DECISION-PASSPORT-v1",
            api(passportConnections).passport(actionReference)["@version"]
                ?.toString()?.trim('"'),
        )
        assertEquals(
            "/api/v1/mobile/actions/mobact%3Afinance%40revision.2/passport",
            passportConnections.opened.single().url.path,
        )

        val withdrawalConnections = StubConnections(
            StubResponse(200, """{"withdrawn":true,"state":"withdrawn"}"""),
        )
        val withdrawal = api(withdrawalConnections).withdraw(actionReference)
        assertTrue(withdrawal.withdrawn)
        assertEquals("POST", withdrawalConnections.opened.single().requestMethod)
        assertEquals(
            "/api/v1/mobile/actions/mobact%3Afinance%40revision.2/withdraw",
            withdrawalConnections.opened.single().url.path,
        )
        assertEquals("{}", withdrawalConnections.opened.single().writtenBody())
    }

    @Test
    fun withdrawalConflictMeansAuthorityWasAlreadyConsumed() = runBlocking {
        val connections = StubConnections(
            StubResponse(409, """{"reason":"already_consumed"}"""),
        )

        try {
            api(connections).withdraw("mobact:finance@revision.2")
            fail("A consumed approval must not be reported as withdrawn")
        } catch (error: MobileApiException) {
            assertTrue(error is MobileApiException.AlreadyConsumed)
        }
        assertEquals(1, connections.opened.size)
    }

    private fun api(connections: StubConnections): MobileApi = MobileApi(
        rawBaseUrl = "https://www.emiliaprotocol.ai/api/",
        accessToken = "mobile-access-token",
        connectionFactory = connections,
    )

    private fun committedRecovery(decision: String, contextHash: String): String = """
        {
          "committed": true,
          "outcome": "committed",
          "result": {
            "valid": true,
            "verdict": "verified",
            "decision": "$decision",
            "context_hash": "$contextHash"
          }
        }
    """.trimIndent()

    private fun ceremonyResult(
        decision: String,
        contextHash: String,
        valid: Boolean = true,
        verdict: String = "verified",
        reason: String? = null,
    ): String = """
        {
          "valid": $valid,
          "verdict": "$verdict",
          "decision": "$decision",
          "reason": ${reason?.let { "\"$it\"" } ?: "null"},
          "context_hash": "$contextHash"
        }
    """.trimIndent()

    private fun fixture(): Fixture {
        val decision = "approved"
        val context = buildJsonObject {
            put("action_reference", "mobact_0123456789abcdef0123456789abcdef")
            put(
                "action_caid",
                "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${"A".repeat(43)}",
            )
            put("action_digest", "sha256:" + "a".repeat(64))
            put("action_hash", "sha256:" + "a".repeat(64))
            put("decision", decision)
            put("nonce", "sig_0123456789abcdef0123456789abcdef")
        }
        val challenge = EmiliaMobileChallenge(
            version = "AE-CHALLENGE-v1",
            challengeProfile = EmiliaMobileChallenge.PROFILE,
            challengeId = "mob_0123456789abcdef",
            nonce = "sig_0123456789abcdef0123456789abcdef",
            action = buildJsonObject { put("amount", 10) },
            actionHash = "sha256:" + "a".repeat(64),
            profileHash = "sha256:" + "b".repeat(64),
            authorizationContext = context,
            webauthn = EmiliaWebAuthnRequest(
                rpId = "www.emiliaprotocol.ai",
                challenge = "Y2hhbGxlbmdl",
                credentialIds = listOf("Y3JlZGVudGlhbA"),
                userVerification = "required",
                timeoutMs = 300_000,
            ),
            presentation = buildJsonObject { put("title", "Approve") },
            attestation = EmiliaAttestationRequest(
                required = true,
                format = "play-integrity-standard",
                binding = buildJsonObject { put("challenge_id", "mob_0123456789abcdef") },
                requestHash = "cmVxdWVzdA",
            ),
            issuedAt = "2026-07-16T18:00:00.000Z",
            expiresAt = "2026-07-16T18:05:00.000Z",
        )
        val response = EmiliaMobileCeremonyResponse(
            challengeId = challenge.challengeId,
            nonce = challenge.nonce,
            platform = "android",
            appId = "ai.emiliaprotocol.approver",
            deviceKeyId = "ep:key:mobile-android-1",
            credentialId = "Y3JlZGVudGlhbA",
            attestationKeyId = "attestation-key",
            decision = decision,
            displayHash = "sha256:" + "c".repeat(64),
            signoff = EmiliaMobileCeremonyResponse.Signoff(
                context = context,
                webauthn = EmiliaMobileCeremonyResponse.WebAuthn("YQ", "Yg", "Yw"),
            ),
            attestation = EmiliaMobileCeremonyResponse.Attestation("play-integrity-standard", "ZA"),
        )
        return Fixture(challenge, response, decision, EmiliaCanonicalJson.digest(context))
    }
}

private data class Fixture(
    val challenge: EmiliaMobileChallenge,
    val response: EmiliaMobileCeremonyResponse,
    val decision: String,
    val contextHash: String,
)

private data class StubResponse(val status: Int, val body: String)

private class StubConnections(vararg responses: StubResponse) : (URL) -> HttpsURLConnection {
    private val queued = ArrayDeque(responses.toList())
    val opened = mutableListOf<StubHttpsURLConnection>()

    override fun invoke(url: URL): HttpsURLConnection {
        val connection = StubHttpsURLConnection(url, queued.removeFirst())
        opened += connection
        return connection
    }
}

private class StubHttpsURLConnection(
    url: URL,
    private val stub: StubResponse,
) : HttpsURLConnection(url) {
    private val responseBytes = stub.body.toByteArray(Charsets.UTF_8)
    private val requestBody = ByteArrayOutputStream()

    override fun connect() = Unit
    override fun disconnect() = Unit
    override fun usingProxy(): Boolean = false
    override fun getCipherSuite(): String = "TLS_AES_128_GCM_SHA256"
    override fun getLocalCertificates(): Array<Certificate>? = null
    override fun getServerCertificates(): Array<Certificate> = emptyArray()
    override fun getResponseCode(): Int = stub.status
    override fun getContentType(): String = "application/json"
    override fun getInputStream(): InputStream = ByteArrayInputStream(responseBytes)
    override fun getErrorStream(): InputStream? =
        if (stub.status in 200..299) null else ByteArrayInputStream(responseBytes)
    override fun getOutputStream(): OutputStream = requestBody

    fun writtenBody(): String = requestBody.toString(Charsets.UTF_8)
}
