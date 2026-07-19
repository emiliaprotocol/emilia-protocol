// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import android.app.Activity
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.credentials.CredentialManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class EmiliaAndroidPasskeyProvider(
    private val activity: Activity,
    private val credentialManager: CredentialManager = CredentialManager.create(activity),
) : EmiliaPasskeyAssertionProvider {
    override suspend fun assertion(
        rpId: String,
        challenge: ByteArray,
        allowedCredentialIds: List<ByteArray>,
    ): EmiliaPasskeyAssertion {
        val requestJson = buildJsonObject {
            put("challenge", challenge.base64Url())
            put("rpId", rpId)
            put("userVerification", "required")
            put("allowCredentials", buildJsonArray {
                allowedCredentialIds.forEach { credentialId ->
                    add(buildJsonObject {
                        put("type", "public-key")
                        put("id", credentialId.base64Url())
                    })
                }
            })
        }.toString()
        val option = GetPublicKeyCredentialOption(requestJson = requestJson)
        val request = GetCredentialRequest(listOf(option))
        val result = credentialManager.getCredential(context = activity, request = request)
        val credential = result.credential as? PublicKeyCredential
            ?: throw EmiliaMobileException.Unavailable("Credential Manager returned a non-passkey credential")
        val response = Json.parseToJsonElement(credential.authenticationResponseJson).jsonObject
        val responseBody = response["response"]?.jsonObject ?: throw EmiliaMobileException.ContextMismatch
        val rawId = (response["rawId"] ?: response["id"])?.jsonPrimitive?.content
            ?: throw EmiliaMobileException.ContextMismatch
        return EmiliaPasskeyAssertion(
            credentialId = rawId.base64UrlBytes(),
            authenticatorData = responseBody.getValue("authenticatorData").jsonPrimitive.content.base64UrlBytes(),
            clientDataJson = responseBody.getValue("clientDataJSON").jsonPrimitive.content.base64UrlBytes(),
            signature = responseBody.getValue("signature").jsonPrimitive.content.base64UrlBytes(),
        )
    }
}

class EmiliaAndroidPasskeyRegistrationProvider(
    private val activity: Activity,
    private val credentialManager: CredentialManager = CredentialManager.create(activity),
) : EmiliaPasskeyRegistrationProvider {
    override suspend fun registration(
        rpId: String,
        challenge: ByteArray,
        userId: ByteArray,
        userName: String,
        displayName: String,
    ) = Json.parseToJsonElement(
        (credentialManager.createCredential(
            context = activity,
            request = CreatePublicKeyCredentialRequest(
                requestJson = buildJsonObject {
                    put("challenge", challenge.base64Url())
                    put("rp", buildJsonObject { put("id", rpId); put("name", "EMILIA Approver") })
                    put("user", buildJsonObject {
                        put("id", userId.base64Url())
                        put("name", userName)
                        put("displayName", displayName)
                    })
                    put("pubKeyCredParams", buildJsonArray {
                        add(buildJsonObject { put("type", "public-key"); put("alg", -7) })
                    })
                    put("authenticatorSelection", buildJsonObject {
                        put("residentKey", "preferred")
                        put("userVerification", "required")
                    })
                    put("attestation", "direct")
                }.toString(),
            ),
        ) as? CreatePublicKeyCredentialResponse
            ?: throw EmiliaMobileException.Unavailable("Credential Manager returned a non-passkey registration")
        ).registrationResponseJson
    )
}

class EmiliaPlayIntegrityProvider private constructor(
    private val tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider,
    internal val deviceKey: EmiliaAndroidDeviceKey,
) : EmiliaPlatformIntegrityProvider {
    override val format: String = "play-integrity-standard"
    override val attestationKeyId: String get() = deviceKey.keyId

    internal suspend fun integrityToken(requestHash: ByteArray): ByteArray = suspendCancellableCoroutine { continuation ->
        require(requestHash.size == 32) { "Play Integrity request hash must be SHA-256" }
        tokenProvider.request(
            StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash.base64Url())
                .build()
        ).addOnSuccessListener { token ->
            if (continuation.isActive) continuation.resume(token.token().toByteArray(Charsets.UTF_8))
        }.addOnFailureListener { error ->
            if (continuation.isActive) continuation.resumeWithException(error)
        }
    }

    override suspend fun assertion(requestHash: ByteArray) = EmiliaPlatformIntegrityAssertion(
        token = integrityToken(requestHash),
        deviceKeySignature = deviceKey.sign(requestHash),
    )

    companion object {
        suspend fun prepare(
            context: Context,
            cloudProjectNumber: Long,
            deviceKey: EmiliaAndroidDeviceKey = EmiliaAndroidDeviceKey(),
        ): EmiliaPlayIntegrityProvider = suspendCancellableCoroutine { continuation ->
            require(cloudProjectNumber > 0) { "Play Integrity cloud project number must be configured" }
            val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
            manager.prepareIntegrityToken(
                StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()
            ).addOnSuccessListener { provider ->
                if (continuation.isActive) continuation.resume(EmiliaPlayIntegrityProvider(provider, deviceKey))
            }.addOnFailureListener { error ->
                if (continuation.isActive) continuation.resumeWithException(error)
            }
        }
    }
}

class EmiliaAndroidDeviceKey(
    private val alias: String = DEFAULT_ALIAS,
) {
    private val keyPair: KeyPair by lazy { loadOrCreate() }

    val publicKeySpki: ByteArray get() = keyPair.public.encoded.copyOf()
    val keyId: String get() = "android-keystore:sha256:${MessageDigest.getInstance("SHA-256").digest(publicKeySpki).base64Url()}"

    fun sign(value: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(keyPair.private)
        update(value)
        sign()
    }

    private fun loadOrCreate(): KeyPair {
        val store = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val privateKey = store.getKey(alias, null)
        val certificate = store.getCertificate(alias)
        if (privateKey != null && certificate != null) return KeyPair(certificate.publicKey, privateKey as java.security.PrivateKey)

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKeyPair()
    }

    companion object {
        const val DEFAULT_ALIAS = "ai.emiliaprotocol.mobile.device-key.v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }
}

class EmiliaPlayIntegrityEnrollmentProvider(
    private val integrity: EmiliaPlayIntegrityProvider,
) : EmiliaPlatformEnrollmentProvider {
    override suspend fun enrollment(requestHash: ByteArray): EmiliaPlatformEnrollment {
        require(requestHash.size == 32) { "Enrollment challenge request hash must be SHA-256" }
        val key = integrity.deviceKey
        val binding = buildJsonObject {
            put("@version", "EP-MOBILE-ANDROID-KEY-BINDING-v1")
            put("challenge_request_hash", requestHash.base64Url())
            put("algorithm", "ES256")
            put("key_id", key.keyId)
            put("public_key_spki", key.publicKeySpki.base64Url())
        }
        val playRequestHash = EmiliaCanonicalJson.sha256(binding)
        return EmiliaPlatformEnrollment(
            format = "play-integrity-standard",
            attestationKeyId = key.keyId,
            token = integrity.integrityToken(playRequestHash),
            requestHash = playRequestHash,
            deviceKey = EmiliaAndroidDeviceKeyProof(
                algorithm = "ES256",
                keyId = key.keyId,
                publicKeySpki = key.publicKeySpki.base64Url(),
                signature = key.sign(EmiliaCanonicalJson.encode(binding)).base64Url(),
            ),
        )
    }
}
