// SPDX-License-Identifier: Apache-2.0
package org.example.government.approvals

import ai.emiliaprotocol.mobile.EmiliaAndroidPasskeyProvider
import ai.emiliaprotocol.mobile.EmiliaAndroidPasskeyRegistrationProvider
import ai.emiliaprotocol.mobile.EmiliaMobileCeremonyCoordinator
import ai.emiliaprotocol.mobile.EmiliaMobileChallenge
import ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentChallenge
import ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentCoordinator
import ai.emiliaprotocol.mobile.EmiliaPlayIntegrityEnrollmentProvider
import ai.emiliaprotocol.mobile.EmiliaPlayIntegrityProvider
import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = true }
    private val preferences by lazy { getSharedPreferences("emilia-mobile", MODE_PRIVATE) }
    private val requestID by lazy { EditText(this) }
    private val status by lazy { TextView(this) }
    private val progress by lazy { ProgressBar(this) }
    private val enroll by lazy { Button(this) }
    private val approve by lazy { Button(this) }
    private val deny by lazy { Button(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(content())
        refreshEnrollment()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun content(): LinearLayout {
        val padding = (24 * resources.displayMetrics.density).toInt()
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(padding, padding, padding, padding)
            addView(TextView(context).apply {
                text = "Government Approval"
                textSize = 28f
                setTextColor(0xff17323d.toInt())
            }, matchWrap())
            addView(status, matchWrap())
            addView(enroll.apply {
                text = "Enroll this device"
                setOnClickListener { enrollDevice() }
            }, matchWrap())
            addView(requestID.apply {
                hint = "Approval request identifier"
                inputType = InputType.TYPE_CLASS_TEXT
                setSingleLine(true)
            }, matchWrap())
            addView(approve.apply {
                text = "Review for approval"
                setOnClickListener { issue("approved") }
            }, matchWrap())
            addView(deny.apply {
                text = "Review for denial"
                setOnClickListener { issue("denied") }
            }, matchWrap())
            addView(progress.apply { visibility = ProgressBar.GONE }, matchWrap())
        }
    }

    private fun matchWrap() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    ).apply { setMargins(0, 12, 0, 12) }

    private fun refreshEnrollment() {
        val enrolled = preferences.getString("device_key_id", null) != null
        status.text = if (enrolled) "Device enrolled" else "Enrollment required"
        enroll.visibility = if (enrolled) Button.GONE else Button.VISIBLE
        approve.isEnabled = enrolled
        deny.isEnabled = enrolled
    }

    private fun enrollDevice() = runBusy {
        require(BuildConfig.PLAY_CLOUD_PROJECT_NUMBER > 0) { "Configure the Play cloud project number first" }
        val approverID = "ep:approver:case-supervisor"
        val issued = apiPost("v1/mobile/enrollments/challenges", buildJsonObject {
            put("approver_id", approverID)
            put("platform", "android")
            put("app_id", packageName)
        })
        check(issued.getValue("ok").jsonPrimitive.content.toBoolean())
        val challenge = json.decodeFromJsonElement(
            EmiliaMobileEnrollmentChallenge.serializer(),
            issued.getValue("challenge"),
        )
        val integrity = EmiliaPlayIntegrityProvider.prepare(
            applicationContext,
            BuildConfig.PLAY_CLOUD_PROJECT_NUMBER,
            "play-integrity:production",
        )
        val coordinator = EmiliaMobileEnrollmentCoordinator(
            passkeys = EmiliaAndroidPasskeyRegistrationProvider(this),
            platformEnrollment = EmiliaPlayIntegrityEnrollmentProvider(integrity),
            appId = packageName,
        )
        val response = coordinator.perform(
            json.encodeToString(challenge).toByteArray(),
        )
        val completed = apiPost("v1/mobile/enrollments", buildJsonObject {
            put("challenge", json.encodeToJsonElement(EmiliaMobileEnrollmentChallenge.serializer(), challenge))
            put("response", json.encodeToJsonElement(ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentResponse.serializer(), response))
        })
        check(completed.getValue("ok").jsonPrimitive.content.toBoolean())
        val enrollment = completed.getValue("enrollment").jsonObject
        preferences.edit()
            .putString("device_key_id", enrollment.getValue("device_key_id").jsonPrimitive.content)
            .putString("attestation_key_id", enrollment.getValue("attestation_key_id").jsonPrimitive.content)
            .apply()
        withContext(Dispatchers.Main) { refreshEnrollment() }
        "Device enrolled"
    }

    private fun issue(decision: String) = runBusy {
        val reference = requestID.text.toString().trim()
        require(reference.isNotEmpty()) { "Enter the request identifier" }
        val issued = apiPost("v1/mobile/challenges", buildJsonObject {
            put("profile_id", BuildConfig.PROFILE_ID)
            put("action_reference", reference)
            put("approver_id", "ep:approver:case-supervisor")
            put("decision", decision)
            put("platform", "android")
            put("app_id", packageName)
            put("device_key_id", requireNotNull(preferences.getString("device_key_id", null)))
        })
        check(issued.getValue("ok").jsonPrimitive.content.toBoolean())
        val challenge = json.decodeFromJsonElement(
            EmiliaMobileChallenge.serializer(),
            issued.getValue("challenge"),
        )
        withContext(Dispatchers.Main) { confirm(challenge, decision) }
        "Ready for review"
    }

    private fun confirm(challenge: EmiliaMobileChallenge, decision: String) {
        AlertDialog.Builder(this)
            .setTitle(if (decision == "approved") "Approve exact action" else "Submit signed denial")
            .setMessage(challenge.presentation.toString())
            .setNegativeButton("Cancel", null)
            .setPositiveButton(if (decision == "approved") "Approve" else "Deny") { _, _ -> perform(challenge) }
            .show()
    }

    private fun perform(challenge: EmiliaMobileChallenge) = runBusy {
        val integrity = EmiliaPlayIntegrityProvider.prepare(
            applicationContext,
            BuildConfig.PLAY_CLOUD_PROJECT_NUMBER,
            requireNotNull(preferences.getString("attestation_key_id", null)),
        )
        val coordinator = EmiliaMobileCeremonyCoordinator(
            passkeys = EmiliaAndroidPasskeyProvider(this),
            integrity = integrity,
            appId = packageName,
            deviceKeyId = requireNotNull(preferences.getString("device_key_id", null)),
        )
        val response = coordinator.perform(json.encodeToString(challenge).toByteArray())
        val result = apiPost("v1/mobile/ceremonies", buildJsonObject {
            put("challenge", json.encodeToJsonElement(EmiliaMobileChallenge.serializer(), challenge))
            put("response", json.encodeToJsonElement(ai.emiliaprotocol.mobile.EmiliaMobileCeremonyResponse.serializer(), response))
        })
        check(result.getValue("valid").jsonPrimitive.content.toBoolean()) {
            result["verdict"]?.jsonPrimitive?.content ?: "refused"
        }
        if (response.decision == "approved") "Approval recorded" else "Denial recorded"
    }

    private fun runBusy(block: suspend () -> String) {
        progress.visibility = ProgressBar.VISIBLE
        approve.isEnabled = false
        deny.isEnabled = false
        scope.launch {
            status.text = try { block() } catch (error: Exception) {
                "Refused: ${error.message ?: "unknown error"}"
            }
            progress.visibility = ProgressBar.GONE
            refreshEnrollment()
        }
    }

    private suspend fun apiPost(path: String, body: JsonObject): JsonObject = withContext(Dispatchers.IO) {
        val connection = URL("${BuildConfig.API_BASE_URL.trimEnd('/')}/$path").openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
            val response = stream.bufferedReader().use { it.readText() }
            check(connection.responseCode in 200..299) { "HTTP ${connection.responseCode}" }
            json.parseToJsonElement(response).jsonObject
        } finally {
            connection.disconnect()
        }
    }
}
