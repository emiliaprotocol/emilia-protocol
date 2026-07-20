// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.mobile

import java.math.BigDecimal
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

object EmiliaCanonicalJson {
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private val json = Json { encodeDefaults = true; explicitNulls = true }

    fun encode(value: JsonElement): ByteArray = canonical(value).toByteArray(Charsets.UTF_8)

    fun sha256(value: JsonElement): ByteArray = MessageDigest.getInstance("SHA-256").digest(encode(value))

    fun digest(value: JsonElement): String = "sha256:" + sha256(value).joinToString("") { "%02x".format(it) }

    private fun canonical(value: JsonElement): String = when (value) {
        JsonNull -> "null"
        is JsonObject -> value.keys.sorted().joinToString(prefix = "{", postfix = "}", separator = ",") { key ->
            json.encodeToString(key) + ":" + canonical(requireNotNull(value[key]))
        }
        is JsonArray -> value.joinToString(prefix = "[", postfix = "]", separator = ",") { canonical(it) }
        is JsonPrimitive -> {
            if (value.isString) json.encodeToString(value.content)
            else if (value.content == "true" || value.content == "false") value.content
            else canonicalInteger(value.content)
        }
    }

    private fun canonicalInteger(text: String): String {
        val integer = try {
            BigDecimal(text).toBigIntegerExact()
        } catch (_: ArithmeticException) {
            throw EmiliaMobileException.NonCanonicalJson
        } catch (_: NumberFormatException) {
            throw EmiliaMobileException.NonCanonicalJson
        }
        if (integer < BigInteger.valueOf(-MAX_SAFE_INTEGER)
            || integer > BigInteger.valueOf(MAX_SAFE_INTEGER)) {
            throw EmiliaMobileException.NonCanonicalJson
        }
        return integer.toString()
    }
}

internal fun ByteArray.base64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

internal fun String.base64UrlBytes(): ByteArray = try {
    require(isNotEmpty() && all { it.isLetterOrDigit() || it == '-' || it == '_' })
    Base64.getUrlDecoder().decode(this)
} catch (_: IllegalArgumentException) {
    throw EmiliaMobileException.MalformedChallenge("invalid base64url")
}
