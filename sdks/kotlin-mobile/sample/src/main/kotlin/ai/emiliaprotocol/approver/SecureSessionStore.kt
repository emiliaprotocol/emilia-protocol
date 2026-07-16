// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.approver

import android.annotation.SuppressLint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class MobileSession(
    val accessToken: String,
    val approverId: String,
    val profileId: String,
    val expiresAt: String,
    val deviceKeyId: String? = null,
    val attestationKeyId: String? = null,
)

class SecureSessionStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = false; explicitNulls = true }

    @Synchronized
    @SuppressLint("ApplySharedPref", "UseKtx")
    fun save(session: MobileSession) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val plaintext = json.encodeToString(session).toByteArray(Charsets.UTF_8)
        val ciphertext = cipher.doFinal(plaintext)
        check(preferences.edit()
            .putString(CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putString(IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .commit()) { "Secure session storage is unavailable" }
    }

    @Synchronized
    fun load(): MobileSession? {
        val encoded = preferences.getString(CIPHERTEXT, null) ?: return null
        val encodedIv = preferences.getString(IV, null) ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key(),
                GCMParameterSpec(128, Base64.decode(encodedIv, Base64.NO_WRAP)),
            )
            val plaintext = cipher.doFinal(Base64.decode(encoded, Base64.NO_WRAP))
            json.decodeFromString<MobileSession>(plaintext.toString(Charsets.UTF_8))
        } catch (_: Exception) {
            clear()
            null
        }
    }

    @Synchronized
    @SuppressLint("ApplySharedPref", "UseKtx")
    fun clear() {
        preferences.edit().clear().commit()
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        builder.setUnlockedDeviceRequired(true)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "ai.emiliaprotocol.approver.mobile-session.v1"
        const val PREFERENCES = "emilia-approver-secure-session"
        const val CIPHERTEXT = "session_ciphertext"
        const val IV = "session_iv"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
