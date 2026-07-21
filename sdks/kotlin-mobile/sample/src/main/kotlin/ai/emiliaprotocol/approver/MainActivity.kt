// SPDX-License-Identifier: Apache-2.0
package ai.emiliaprotocol.approver

import ai.emiliaprotocol.mobile.EmiliaAndroidPasskeyProvider
import ai.emiliaprotocol.mobile.EmiliaAndroidPasskeyRegistrationProvider
import ai.emiliaprotocol.mobile.EmiliaMobileAction
import ai.emiliaprotocol.mobile.EmiliaMobileCeremonyCoordinator
import ai.emiliaprotocol.mobile.EmiliaMobileChallenge
import ai.emiliaprotocol.mobile.EmiliaMobileChallengeValidator
import ai.emiliaprotocol.mobile.EmiliaMobileContinuity
import ai.emiliaprotocol.mobile.EmiliaMobileDecision
import ai.emiliaprotocol.mobile.EmiliaMobileEnrollmentCoordinator
import ai.emiliaprotocol.mobile.EmiliaMobileExpectedActionIdentity
import ai.emiliaprotocol.mobile.EmiliaMobileLifecycleState
import ai.emiliaprotocol.mobile.EmiliaMobileQuorum
import ai.emiliaprotocol.mobile.EmiliaPlayIntegrityEnrollmentProvider
import ai.emiliaprotocol.mobile.EmiliaPlayIntegrityProvider
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal val JsonElement.decision: String
    get() = ((this as? JsonObject)?.get("decision") as? JsonPrimitive)
        ?.takeIf { it.isString }
        ?.content
        ?: throw MobileApiException.Refused("decision_mismatch")

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = true }
    private val passportJson = Json { prettyPrint = true; explicitNulls = true }
    private val sessionStore by lazy { SecureSessionStore(applicationContext) }
    private var session: MobileSession? = null
    private var actions: List<EmiliaMobileAction> = emptyList()
    private var historyActions: List<EmiliaMobileAction> = emptyList()
    private var selectedAction: EmiliaMobileAction? = null
    private var showingHistory = false
    private var challenge: EmiliaMobileChallenge? = null
    private var pendingDecision: EmiliaMobileDecision? = null
    private var pendingActionIdentity: EmiliaMobileExpectedActionIdentity? = null
    private var busyMessage: String? = null
    private var notice: String? = null
    private var noticeKind = NoticeKind.COMPLETE
    private var pairingCode = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (BuildConfig.PRODUCTION_RELEASE) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        session = sessionStore.load()
        receivePairingIntent(intent)
        render()
        if (session != null) refreshInbox()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        receivePairingIntent(intent)
        render()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun render() {
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(PAPER)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(36))
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                val top = bars.top
                val bottom = bars.bottom
                view.setPadding(dp(22), dp(18) + top, dp(22), dp(36) + bottom)
                insets
            }
        }
        scroll.addView(root, matchWrap())
        root.addView(brandHeader(), matchWrap())
        busyMessage?.let { root.addView(progressCard(it), matchWrap(top = 18)) }
        notice?.let { root.addView(noticeCard(it, noticeKind), matchWrap(top = 18)) }

        when {
            session == null -> root.addView(pairingPanel(), matchWrap(top = 22))
            selectedAction != null -> root.addView(actionPanel(requireNotNull(selectedAction)), matchWrap(top = 18))
            session?.deviceKeyId == null || session?.attestationKeyId == null -> {
                root.addView(connectionStrip(), matchWrap(top = 18))
                root.addView(enrollmentPanel(), matchWrap(top = 18))
            }
            else -> {
                root.addView(connectionStrip(), matchWrap(top = 18))
                root.addView(inboxPanel(), matchWrap(top = 18))
            }
        }
        setContentView(scroll)
    }

    private fun brandHeader(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(label("EMILIA  /  APPROVER", 12f, BRASS, Typeface.BOLD), matchWrap())
        addView(label("Human judgment,\nbefore machine action.", 32f, INK, Typeface.BOLD).apply {
            contentDescription = "EMILIA Approver. Human judgment before machine action."
        }, matchWrap(top = 8))
        addView(label("Exact action. Named approver. One signed decision.", 16f, MUTED), matchWrap(top = 10))
    }

    private fun pairingPanel(): View = panel().apply {
        addView(label("Connect this device", 22f, INK, Typeface.BOLD), matchWrap())
        addView(label("Enter the one-time code issued by your organization.", 15f, MUTED), matchWrap(top = 8))
        val code = EditText(context).apply {
            hint = "XXXX-XXXX-XXXX"
            textSize = 20f
            setTextColor(INK)
            setHintTextColor(SOFT)
            gravity = Gravity.CENTER
            isSingleLine = true
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
            filters = arrayOf(InputFilter.LengthFilter(14))
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = shape(Color.WHITE, SOFT, 1)
            contentDescription = "One-time pairing code"
            setText(pairingCode)
        }
        addView(code, matchWrap(top = 18))
        addView(primaryButton("Connect device") {
            val value = code.text.toString().trim().uppercase(Locale.US)
            pairingCode = value
            if (value.isBlank()) showNotice("Enter the pairing code.", true) else connect(value)
        }, matchWrap(top = 14))
        addView(label("No organization secret is stored in this app.", 13f, MUTED), matchWrap(top = 12))
    }

    private fun connectionStrip(): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = shape(MIST, TEAL, 1)
        setPadding(dp(14), dp(12), dp(10), dp(12))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            addView(label("CONNECTED", 11f, TEAL, Typeface.BOLD), matchWrap())
            addView(label(session?.approverId ?: "", 13f, INK), matchWrap(top = 2))
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(quietButton("Disconnect") { disconnect() }, wrapWrap())
    }

    private fun enrollmentPanel(): View = panel().apply {
        addView(pill("DEVICE SETUP", BRASS), wrapWrap())
        addView(label("Secure this device", 24f, INK, Typeface.BOLD), matchWrap(top = 14))
        addView(label("A passkey binds your identity. Play Integrity binds the signed decision to this genuine app and device.", 15f, MUTED), matchWrap(top = 8))
        addView(primaryButton("Secure device") { enrollDevice() }, matchWrap(top = 18))
        addView(quietButton("Refresh") { refreshInbox() }, matchWrap(top = 8))
    }

    private fun inboxPanel(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val visibleActions = if (showingHistory) historyActions else actions
        val heading = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(label(
                if (showingHistory) "Decision history" else "Protected actions",
                24f,
                INK,
                Typeface.BOLD,
            ), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(quietButton("Refresh") { refreshVisibleActions() }, wrapWrap())
        }
        addView(heading, matchWrap())
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(quietButton("Inbox (${actions.size})") {
                showingHistory = false
                selectedAction = null
                notice = null
                render()
            }, wrapWrap())
            addView(quietButton("History") { openHistory() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(8) })
        }, matchWrap(top = 6))
        if (visibleActions.isEmpty() && busyMessage == null) {
            addView(panel().apply {
                addView(label(
                    if (showingHistory) "No decision records yet" else "Nothing is waiting",
                    19f,
                    INK,
                    Typeface.BOLD,
                ), matchWrap())
                addView(label(
                    if (showingHistory) {
                        "Decisions and execution lifecycle records will appear here."
                    } else {
                        "New consequential actions will appear here."
                    },
                    15f,
                    MUTED,
                ), matchWrap(top = 6))
            }, matchWrap(top = 14))
        } else {
            visibleActions.forEach { action -> addView(actionCard(action), matchWrap(top = 12)) }
        }
    }

    private fun actionCard(action: EmiliaMobileAction): View = panel().apply {
        val state = action.lifecycleState
        contentDescription =
            "${state.wireValue} ${action.risk} risk action. ${action.title}. ${action.summary}"
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(pill(action.risk.uppercase(Locale.US), riskColor(action.risk)), wrapWrap())
            addView(pill(state.wireValue, stateColor(state)), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(8) })
        }, matchWrap())
        addView(label(action.title, 20f, INK, Typeface.BOLD), matchWrap(top = 12))
        addView(label(action.summary, 15f, MUTED), matchWrap(top = 6))
        action.identity?.stableFingerprint()?.let { fingerprint ->
            addView(label("ACTION LOCK  $fingerprint", 12f, TEAL, Typeface.BOLD), matchWrap(top = 10))
        }
        action.effectiveQuorum?.let { quorum ->
            addView(label(quorumSummary(quorum), 13f, MUTED), matchWrap(top = 8))
        }
        action.materialFields.entries.take(3).forEach { (name, value) ->
            addView(fieldRow(humanize(name), display(value)), matchWrap(top = 8))
        }
        addView(primaryButton(if (showingHistory) "View lifecycle record" else "Review exact action") {
            selectedAction = action
            notice = null
            render()
        }, matchWrap(top = 16))
    }

    private fun actionPanel(action: EmiliaMobileAction): View = panel().apply {
        val state = action.lifecycleState
        addView(quietButton(if (showingHistory) "Back to history" else "Back to inbox") {
            selectedAction = null
            challenge = null
            pendingDecision = null
            pendingActionIdentity = null
            render()
        }, wrapWrap())
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(pill(action.risk.uppercase(Locale.US), riskColor(action.risk)), wrapWrap())
            addView(pill(state.wireValue, stateColor(state)), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(8) })
        }, matchWrap(top = 18))
        addView(label(action.title, 26f, INK, Typeface.BOLD), matchWrap(top = 12))
        addView(label(action.summary, 16f, MUTED), matchWrap(top = 8))
        addView(lifecycleBanner(action), matchWrap(top = 16))
        action.identity?.takeIf { it.isValidActionLock() }?.let { identity ->
            addView(divider(), matchWrap(top = 18, bottom = 10))
            addView(label("ACTION LOCK", 11f, MUTED, Typeface.BOLD), matchWrap())
            addView(label(requireNotNull(identity.stableFingerprint()), 22f, TEAL, Typeface.BOLD), matchWrap(top = 6))
            addView(label(identity.actionCaid.orEmpty(), 12f, INK), matchWrap(top = 8))
            addView(label("Action digest  ${identity.actionDigest}", 11f, MUTED), matchWrap(top = 4))
        }
        action.supersedesActionCaid?.let { prior ->
            addView(label("Supersedes $prior", 12f, BRASS, Typeface.BOLD), matchWrap(top = 12))
        }
        action.effectiveQuorum?.let { quorum ->
            addView(divider(), matchWrap(top = 18, bottom = 10))
            addView(quorumProgress(quorum), matchWrap())
        }
        addView(divider(), matchWrap(top = 18, bottom = 10))
        addView(label("MATERIAL FIELDS", 11f, MUTED, Typeface.BOLD), matchWrap())
        action.materialFields.entries.sortedBy { it.key }.forEach { (name, value) ->
            addView(fieldRow(humanize(name), display(value)), matchWrap(top = 10))
        }
        if (action.changes.isNotEmpty()) {
            addView(divider(), matchWrap(top = 18, bottom = 10))
            addView(label("MATERIAL CHANGES", 11f, MUTED, Typeface.BOLD), matchWrap())
            action.changes.forEach { change ->
                val transition = when (change.change) {
                    "added" -> "Added: ${change.after ?: "None"}"
                    "removed" -> "Removed: ${change.before ?: "None"}"
                    else -> "${change.before ?: "None"}  →  ${change.after ?: "None"}"
                }
                addView(fieldRow(humanize(change.field), transition), matchWrap(top = 10))
            }
        }
        if (action.alignments.isNotEmpty()) {
            addView(divider(), matchWrap(top = 18, bottom = 10))
            addView(label("CROSS-SYSTEM ALIGNMENT", 11f, MUTED, Typeface.BOLD), matchWrap())
            action.alignments.forEach { alignment ->
                val detail = buildString {
                    append(alignment.verdict)
                    append(if (alignment.nativeVerified) "\nNative evidence verified" else "\nNative evidence not verified")
                    alignment.profileId?.let { append("\nProfile: $it") }
                    alignment.profileHash?.let { append("\nProfile hash: $it") }
                    alignment.evidenceDigest?.let { append("\nEvidence: $it") }
                    alignment.reason?.let { append("\n$it") }
                }
                addView(fieldRow(alignment.system, detail), matchWrap(top = 10))
            }
        }
        if (action.events.isNotEmpty()) {
            addView(divider(), matchWrap(top = 18, bottom = 10))
            addView(label("EVIDENCE TIMELINE", 11f, MUTED, Typeface.BOLD), matchWrap())
            action.events.forEach { event ->
                addView(fieldRow(
                    humanize(event.type),
                    listOfNotNull(
                        event.createdAt.takeIf { it.isNotBlank() }?.let(::shortTime),
                        event.evidenceDigest,
                    ).joinToString("\n"),
                ), matchWrap(top = 10))
            }
        }
        addView(label("Expires ${shortTime(action.expiresAt)}", 13f, MUTED), matchWrap(top = 14))
        if (!showingHistory && action.canDecideSafely) {
            addView(primaryButton("Approve with passkey") {
                beginDecision(EmiliaMobileDecision.APPROVED)
            }, matchWrap(top = 20))
            addView(dangerButton("Deny and sign refusal") {
                beginDecision(EmiliaMobileDecision.DENIED)
            }, matchWrap(top = 10))
        } else if (state == EmiliaMobileLifecycleState.INDETERMINATE) {
            addView(label(
                "DO NOT RETRY. Reconcile this action with the server or operator before taking another decision.",
                14f,
                DANGER,
                Typeface.BOLD,
            ), matchWrap(top = 18))
        } else if (action.expectedChallengeIdentity() == null
            && (state == EmiliaMobileLifecycleState.AWAITING_DECISION
                || state == EmiliaMobileLifecycleState.QUORUM_PENDING)) {
            addView(label(
                "This inbox record has no valid CAID action lock. Decision controls are disabled.",
                14f,
                DANGER,
                Typeface.BOLD,
            ), matchWrap(top = 18))
        }
        if (action.canWithdrawSafely) {
            addView(dangerButton("Withdraw approval before consumption") {
                confirmWithdrawal(action)
            }, matchWrap(top = 14))
        }
        if (action.passport != null) {
            addView(quietButton("Share decision passport") {
                shareDecisionPassport(action)
            }, matchWrap(top = 10))
        }
    }

    private fun progressCard(message: String): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = shape(Color.WHITE, LINE, 1)
        setPadding(dp(14), dp(12), dp(14), dp(12))
        addView(ProgressBar(context).apply { contentDescription = message }, LinearLayout.LayoutParams(dp(24), dp(24)))
        addView(label(message, 15f, INK, Typeface.BOLD), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginStart = dp(12)
        })
    }

    private fun noticeCard(message: String, kind: NoticeKind): View = LinearLayout(this).apply {
        val color = noticeColor(kind)
        orientation = LinearLayout.VERTICAL
        background = shape(if (kind == NoticeKind.COMPLETE) SUCCESS_WASH else ERROR_WASH, color, 1)
        setPadding(dp(14), dp(12), dp(14), dp(12))
        addView(label(kind.name, 11f, color, Typeface.BOLD), matchWrap())
        addView(label(message, 14f, INK), matchWrap(top = 4))
        contentDescription = message
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
    }

    private fun connect(code: String) = runBusy("Pairing this device") {
        val response = MobileApi(BuildConfig.API_BASE_URL).exchangePairing(code, packageName)
        val connected = MobileSession(
            accessToken = response.accessToken,
            approverId = response.approverId,
            profileId = response.profileId,
            expiresAt = response.expiresAt,
        )
        sessionStore.save(connected)
        session = connected
        pairingCode = ""
        actions = protectIndeterminateActions(api().inbox())
        showNotice("Device connected. Secure it before deciding.")
    }

    private fun enrollDevice() {
        if (BuildConfig.PLAY_CLOUD_PROJECT_NUMBER <= 0) {
            showNotice("This build is not connected to a Play Integrity cloud project.", true)
            return
        }
        runBusy("Binding passkey and device integrity") {
            val current = requireNotNull(session)
            val challenge = api().issueEnrollment(current.approverId, packageName)
            val integrity = EmiliaPlayIntegrityProvider.prepare(
                applicationContext,
                BuildConfig.PLAY_CLOUD_PROJECT_NUMBER,
            )
            val coordinator = EmiliaMobileEnrollmentCoordinator(
                passkeys = EmiliaAndroidPasskeyRegistrationProvider(this@MainActivity),
                platformEnrollment = EmiliaPlayIntegrityEnrollmentProvider(integrity),
                appId = packageName,
            )
            val response = coordinator.perform(json.encodeToString(challenge).toByteArray(Charsets.UTF_8))
            val completed = api().completeEnrollment(challenge, response)
            val enrollment = completed.enrollment?.takeIf { completed.ok }
                ?: throw MobileApiException.Refused(completed.verdict)
            val updated = current.copy(
                deviceKeyId = enrollment.deviceKeyId,
                attestationKeyId = enrollment.attestationKeyId,
            )
            try {
                sessionStore.save(updated)
            } catch (_: Exception) {
                runCatching { api().revokeSession() }
                clearSession()
                throw MobileApiException.Refused("secure_storage_unavailable")
            }
            session = updated
            actions = protectIndeterminateActions(api().inbox())
            showNotice("Device secured. Passkey and platform integrity are active.")
        }
    }

    private fun refreshInbox() = runBusy("Checking protected actions") {
        actions = protectIndeterminateActions(api().inbox())
        notice = null
    }

    private fun refreshVisibleActions() {
        if (showingHistory) {
            openHistory()
        } else {
            refreshInbox()
        }
    }

    private fun openHistory() = runBusy("Loading decision history") {
        historyActions = protectIndeterminateActions(api().history())
        showingHistory = true
        selectedAction = null
        notice = null
    }

    private fun beginDecision(decision: EmiliaMobileDecision) = runBusy(
        "Binding the exact action",
        onSuccess = { challenge?.let { showChallengeConfirmation(it, decision) } },
    ) {
        val current = requireNotNull(session)
        val action = requireNotNull(selectedAction)
        val expectedActionIdentity = action.expectedChallengeIdentity()
            ?: throw MobileApiException.Refused("action_identity_missing")
        if (!action.canDecideSafely) throw MobileApiException.OutcomeUnknown
        val deviceKey = current.deviceKeyId ?: throw MobileApiException.Refused("device_not_enrolled")
        val issued = api().issueChallenge(
            action.actionReference,
            current.approverId,
            decision.wireValue,
            current.profileId,
            packageName,
            deviceKey,
        )
        EmiliaMobileChallengeValidator.decodeAndValidate(
            json.encodeToString(issued).toByteArray(Charsets.UTF_8),
            expectedActionIdentity = expectedActionIdentity,
            requestedDecision = decision,
        )
        challenge = issued
        pendingDecision = decision
        pendingActionIdentity = expectedActionIdentity
    }

    private fun showChallengeConfirmation(value: EmiliaMobileChallenge, decision: EmiliaMobileDecision) {
        val presentation = try {
            EmiliaMobileChallengeValidator.validatePresentation(value.presentation, value.action)
        } catch (_: Exception) {
            challenge = null
            pendingDecision = null
            pendingActionIdentity = null
            showNotice("The signed presentation is not supported by this app. Nothing was authorized.", true)
            render()
            return
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), 0, dp(4), 0)
            addView(label(presentation.risk.uppercase(Locale.US), 11f, DANGER, Typeface.BOLD), matchWrap())
            addView(label(presentation.summary, 15f, MUTED), matchWrap(top = 8))
            addView(label(presentation.consequence, 14f, DANGER, Typeface.BOLD), matchWrap(top = 10))
            presentation.materialFields.entries.sortedBy { it.key }.forEach { (name, field) ->
                addView(fieldRow(humanize(name), field), matchWrap(top = 10))
            }
            addView(label("EP-MOBILE-PRESENTATION-v1", 11f, MUTED), matchWrap(top = 12))
        }
        AlertDialog.Builder(this)
            .setTitle(presentation.title)
            .setView(ScrollView(this).apply { addView(content) })
            .setNegativeButton("Cancel") { _, _ ->
                challenge = null
                pendingDecision = null
                pendingActionIdentity = null
            }
            .setPositiveButton(if (decision == EmiliaMobileDecision.APPROVED) "Approve" else "Deny") { _, _ ->
                performCeremony(decision)
            }
            .show()
    }

    private fun performCeremony(decision: EmiliaMobileDecision) = runBusy(
        if (decision == EmiliaMobileDecision.APPROVED) "Waiting for passkey" else "Signing the refusal",
    ) {
        if (pendingDecision != decision) throw MobileApiException.Refused("decision_mismatch")
        val current = requireNotNull(session)
        val issued = requireNotNull(challenge)
        val expectedActionIdentity = requireNotNull(pendingActionIdentity)
        val integrity = EmiliaPlayIntegrityProvider.prepare(
            applicationContext,
            BuildConfig.PLAY_CLOUD_PROJECT_NUMBER,
        )
        if (integrity.attestationKeyId != requireNotNull(current.attestationKeyId)) {
            throw MobileApiException.Refused("device_key_mismatch")
        }
        val coordinator = EmiliaMobileCeremonyCoordinator(
            passkeys = EmiliaAndroidPasskeyProvider(this@MainActivity),
            integrity = integrity,
            appId = packageName,
            deviceKeyId = requireNotNull(current.deviceKeyId),
        )
        val response = coordinator.perform(
            json.encodeToString(issued).toByteArray(Charsets.UTF_8),
            decision,
            expectedActionIdentity,
        )
        api().verify(issued, response)
        selectedAction = null
        challenge = null
        pendingDecision = null
        pendingActionIdentity = null
        actions = protectIndeterminateActions(api().inbox())
        historyActions = emptyList()
        showingHistory = false
        showNotice(if (decision == EmiliaMobileDecision.APPROVED) "Approval sealed. The action is eligible for release." else "Denial sealed. The action remains refused.")
    }

    private fun confirmWithdrawal(action: EmiliaMobileAction) {
        AlertDialog.Builder(this)
            .setTitle("Withdraw this approval?")
            .setMessage(
                "Withdrawal is allowed only before execution authority is consumed. " +
                    "It does not reverse an action that has already crossed that boundary.",
            )
            .setNegativeButton("Keep approval", null)
            .setPositiveButton("Withdraw approval") { _, _ -> withdrawApproval(action) }
            .show()
    }

    private fun withdrawApproval(action: EmiliaMobileAction) = runBusy("Withdrawing approval") {
        try {
            api().withdraw(action.actionReference)
            actions = protectIndeterminateActions(api().inbox())
            historyActions = protectIndeterminateActions(api().history())
            selectedAction = historyActions.firstOrNull { it.actionReference == action.actionReference }
            showingHistory = true
            showNotice("Approval withdrawn before execution authority was consumed.")
        } catch (_: MobileApiException.AlreadyConsumed) {
            val consumed = action.copy(
                continuity = EmiliaMobileContinuity(
                    state = EmiliaMobileLifecycleState.CONSUMED.wireValue,
                    retrySafe = false,
                    quorum = action.effectiveQuorum,
                ),
                canWithdraw = false,
            )
            historyActions = historyActions.map {
                if (it.actionReference == action.actionReference) consumed else it
            }
            selectedAction = consumed
            val refreshed = try {
                protectIndeterminateActions(api().history())
            } catch (_: Exception) {
                null
            }
            if (refreshed != null) {
                historyActions = refreshed
                selectedAction = refreshed.firstOrNull {
                    it.actionReference == action.actionReference
                } ?: consumed
            }
            showingHistory = true
            showNotice(
                "Execution authority was already consumed. The approval cannot be withdrawn.",
                NoticeKind.CONSUMED,
            )
        }
    }

    private fun shareDecisionPassport(action: EmiliaMobileAction) = runBusy(
        "Preparing decision passport",
    ) {
        val passport = api().passport(action.actionReference)
        val encoded = passportJson.encodeToString(passport)
        if (encoded.toByteArray(Charsets.UTF_8).size > MAX_SHARE_BYTES) {
            throw MobileApiException.Refused("decision_passport_too_large")
        }
        val share = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_SUBJECT, "EMILIA decision passport")
            putExtra(Intent.EXTRA_TEXT, encoded)
        }
        startActivity(Intent.createChooser(share, "Share decision passport"))
    }

    private fun disconnect() {
        busyMessage = "Revoking this device session"
        render()
        scope.launch {
            try {
                api().revokeSession()
                clearSession()
                showNotice("Device disconnected and session revoked.")
            } catch (_: MobileApiException.SessionExpired) {
                clearSession()
                showNotice("Device disconnected. The session had already expired.")
            } catch (_: Exception) {
                showNotice("The server could not revoke this session. This device remains connected.", true)
            } finally {
                busyMessage = null
                render()
            }
        }
    }

    private fun runBusy(message: String, onSuccess: (() -> Unit)? = null, block: suspend () -> Unit) {
        if (busyMessage != null) return
        busyMessage = message
        notice = null
        render()
        scope.launch {
            var succeeded = false
            try {
                block()
                succeeded = true
            } catch (error: MobileApiException.OutcomeUnknown) {
                markSelectedActionIndeterminate()
                challenge = null
                pendingDecision = null
                pendingActionIdentity = null
                showNotice(error.message.orEmpty(), NoticeKind.INDETERMINATE)
            } catch (_: MobileApiException.SessionExpired) {
                clearSession()
                showNotice("This device connection expired. Pair it again.", true)
            } catch (error: Exception) {
                showNotice(error.message ?: "The request was refused.", true)
            } finally {
                busyMessage = null
                render()
                if (succeeded) onSuccess?.invoke()
            }
        }
    }

    private fun api(): MobileApi {
        val token = session?.accessToken ?: throw MobileApiException.SessionExpired
        return MobileApi(BuildConfig.API_BASE_URL, token)
    }

    private fun clearSession() {
        sessionStore.clear()
        session = null
        actions = emptyList()
        historyActions = emptyList()
        selectedAction = null
        showingHistory = false
        challenge = null
        pendingDecision = null
        pendingActionIdentity = null
    }

    private fun receivePairingIntent(value: Intent?) {
        val uri = value?.data ?: return
        if (uri.scheme != "https" || uri.host != "www.emiliaprotocol.ai" || uri.path != "/mobile/pair") {
            showNotice("This pairing link is not valid.", true)
            return
        }
        if (session != null) {
            showNotice("Disconnect this device before pairing it with another organization.", true)
            return
        }
        val code = uri.getQueryParameter("code")?.trim()?.uppercase(Locale.US).orEmpty()
        if (!PAIRING_CODE.matches(code)) {
            showNotice("This pairing link is malformed or incomplete.", true)
            return
        }
        pairingCode = code
        showNotice("Pairing link ready. Confirm the code to connect this device.")
    }

    private fun showNotice(message: String, error: Boolean = false) {
        notice = message
        noticeKind = if (error) NoticeKind.REFUSED else NoticeKind.COMPLETE
    }

    private fun showNotice(message: String, kind: NoticeKind) {
        notice = message
        noticeKind = kind
    }

    private fun markSelectedActionIndeterminate() {
        val current = selectedAction ?: return
        val locked = current.withIndeterminateOutcome()
        selectedAction = locked
        actions = actions.map { if (it.actionReference == current.actionReference) locked else it }
        historyActions = historyActions.map {
            if (it.actionReference == current.actionReference) locked else it
        }
        val currentSession = session ?: return
        val updated = currentSession.copy(
            indeterminateActionReferences =
                currentSession.indeterminateActionReferences + current.actionReference,
        )
        session = updated
        try {
            sessionStore.save(updated)
        } catch (_: Exception) {
            clearSession()
            showNotice(
                "The outcome is indeterminate and the local retry lock could not be stored. " +
                    "This device was disconnected; do not repeat the action.",
                NoticeKind.INDETERMINATE,
            )
        }
    }

    private fun protectIndeterminateActions(
        values: List<EmiliaMobileAction>,
    ): List<EmiliaMobileAction> {
        val lockedReferences = session?.indeterminateActionReferences.orEmpty()
        return values.map { action ->
            if (action.actionReference in lockedReferences && action.canDecideSafely) {
                action.withIndeterminateOutcome()
            } else {
                action
            }
        }
    }

    private fun panel() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(18), dp(18), dp(18), dp(18))
        background = shape(Color.WHITE, LINE, 1)
        elevation = dp(1).toFloat()
    }

    private fun label(value: String, size: Float, color: Int, style: Int = Typeface.NORMAL) = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(color)
        setLineSpacing(0f, 1.08f)
        typeface = Typeface.create("sans-serif", style)
    }

    private fun pill(value: String, color: Int) = TextView(this).apply {
        text = value
        textSize = 11f
        setTextColor(color)
        typeface = Typeface.create("sans-serif", Typeface.BOLD)
        setPadding(dp(9), dp(5), dp(9), dp(5))
        background = shape(colorWithAlpha(color, 22), color, 1)
        contentDescription = value.lowercase(Locale.US)
    }

    private fun fieldRow(name: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(label(name.uppercase(Locale.US), 11f, MUTED, Typeface.BOLD), matchWrap())
        addView(label(value, 16f, INK, Typeface.BOLD), matchWrap(top = 2))
        contentDescription = "$name: $value"
    }

    private fun lifecycleBanner(action: EmiliaMobileAction): View {
        val state = action.lifecycleState
        val description = when (state) {
            EmiliaMobileLifecycleState.AWAITING_DECISION ->
                "Waiting for this approver's signed decision."
            EmiliaMobileLifecycleState.QUORUM_PENDING ->
                "Some approvals are recorded; the required quorum is not complete."
            EmiliaMobileLifecycleState.AUTHORIZED ->
                "The approval threshold is satisfied. Execution has not been established."
            EmiliaMobileLifecycleState.CONSUMED ->
                "Execution authority has been consumed. This does not prove execution completed."
            EmiliaMobileLifecycleState.INDETERMINATE ->
                "The outcome is unknown. Do not retry or assume refusal."
            EmiliaMobileLifecycleState.EXECUTED ->
                "Execution is confirmed by a server-verified provider outcome."
            EmiliaMobileLifecycleState.REFUSED ->
                "The provider refused execution after authority was consumed."
            EmiliaMobileLifecycleState.DENIED ->
                "A signed denial prevents authorization."
            EmiliaMobileLifecycleState.WITHDRAWN ->
                "The approval was withdrawn before authority was consumed."
            EmiliaMobileLifecycleState.EXPIRED ->
                "The decision window expired."
            EmiliaMobileLifecycleState.CANCELLED ->
                "The action was cancelled."
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = shape(colorWithAlpha(stateColor(state), 18), stateColor(state), 1)
            addView(label(state.wireValue, 12f, stateColor(state), Typeface.BOLD), matchWrap())
            addView(label(description, 14f, INK), matchWrap(top = 4))
            contentDescription = "${state.wireValue}. $description"
        }
    }

    private fun quorumProgress(quorum: EmiliaMobileQuorum): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(label("QUORUM PROGRESS", 11f, MUTED, Typeface.BOLD), matchWrap())
        addView(label(quorumSummary(quorum), 16f, INK, Typeface.BOLD), matchWrap(top = 5))
        addView(ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = quorum.safeRequired
            progress = quorum.safeApproved.coerceAtMost(quorum.safeRequired)
            contentDescription = quorumSummary(quorum)
        }, matchWrap(top = 8))
        if (quorum.safeDenied > 0 || quorum.safeWithdrawn > 0) {
            addView(label(
                "${quorum.safeDenied} denied · ${quorum.safeWithdrawn} withdrawn",
                13f,
                MUTED,
            ), matchWrap(top = 5))
        }
    }

    private fun quorumSummary(quorum: EmiliaMobileQuorum): String =
        "${quorum.safeApproved} of ${quorum.safeRequired} approvals"

    private fun primaryButton(value: String, action: () -> Unit) = styledButton(value, INK, Color.WHITE, INK, action)
    private fun dangerButton(value: String, action: () -> Unit) = styledButton(value, Color.TRANSPARENT, DANGER, DANGER, action)
    private fun quietButton(value: String, action: () -> Unit) = styledButton(value, Color.TRANSPARENT, TEAL, Color.TRANSPARENT, action)

    private fun styledButton(value: String, fill: Int, textColor: Int, stroke: Int, action: () -> Unit) = Button(this).apply {
        text = value
        textSize = 14f
        isAllCaps = false
        setTextColor(textColor)
        typeface = Typeface.create("sans-serif", Typeface.BOLD)
        minHeight = dp(48)
        minimumHeight = dp(48)
        setPadding(dp(14), dp(8), dp(14), dp(8))
        background = shape(fill, stroke, if (stroke == Color.TRANSPARENT) 0 else 1)
        setOnClickListener { if (busyMessage == null) action() }
        contentDescription = value
    }

    private fun divider() = View(this).apply { setBackgroundColor(LINE) }

    private fun shape(fill: Int, stroke: Int, strokeWidth: Int) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(fill)
        cornerRadius = dp(7).toFloat()
        if (strokeWidth > 0) setStroke(dp(strokeWidth), stroke)
    }

    private fun matchWrap(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    ).apply { setMargins(0, dp(top), 0, dp(bottom)) }

    private fun wrapWrap(top: Int = 0) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    ).apply { topMargin = dp(top) }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun display(value: JsonElement): String = when (value) {
        JsonNull -> "None"
        is JsonPrimitive -> value.content
        else -> value.toString()
    }

    private fun humanize(value: String): String = value.replace('_', ' ').split(' ')
        .joinToString(" ") { word -> word.replaceFirstChar { it.uppercaseChar() } }

    private fun shortTime(value: String): String = runCatching {
        DateTimeFormatter.ISO_INSTANT.format(Instant.parse(value))
    }.getOrDefault(value)

    private fun riskColor(value: String): Int = when (value.lowercase(Locale.US)) {
        "critical" -> DANGER
        "high" -> BRASS
        else -> TEAL
    }

    private fun stateColor(value: EmiliaMobileLifecycleState): Int = when (value) {
        EmiliaMobileLifecycleState.INDETERMINATE,
        EmiliaMobileLifecycleState.REFUSED,
        EmiliaMobileLifecycleState.DENIED -> DANGER
        EmiliaMobileLifecycleState.CONSUMED,
        EmiliaMobileLifecycleState.QUORUM_PENDING,
        EmiliaMobileLifecycleState.AUTHORIZED -> BRASS
        else -> TEAL
    }

    private fun noticeColor(value: NoticeKind): Int = when (value) {
        NoticeKind.COMPLETE -> TEAL
        NoticeKind.CONSUMED -> BRASS
        NoticeKind.INDETERMINATE,
        NoticeKind.REFUSED -> DANGER
    }

    private fun colorWithAlpha(color: Int, alpha: Int): Int = Color.argb(
        alpha,
        Color.red(color),
        Color.green(color),
        Color.blue(color),
    )

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.content

    private enum class NoticeKind {
        COMPLETE,
        REFUSED,
        INDETERMINATE,
        CONSUMED,
    }

    private companion object {
        val PAIRING_CODE = Regex("^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$")
        const val MAX_SHARE_BYTES = 262_144
        val INK = Color.rgb(23, 43, 47)
        val TEAL = Color.rgb(20, 105, 99)
        val BRASS = Color.rgb(145, 90, 20)
        val DANGER = Color.rgb(158, 46, 42)
        val MUTED = Color.rgb(85, 96, 96)
        val SOFT = Color.rgb(105, 112, 110)
        val LINE = Color.rgb(216, 217, 210)
        val PAPER = Color.rgb(246, 244, 238)
        val MIST = Color.rgb(235, 244, 241)
        val SUCCESS_WASH = Color.rgb(233, 245, 239)
        val ERROR_WASH = Color.rgb(252, 238, 235)
    }
}
