# Mobile Privacy and Accessibility Review

Review date: 2026-07-15. Scope: the EMILIA Approver reference apps and the
`/api/v1/mobile` backend. This is an engineering review, not a substitute for a
deploying organization's privacy impact assessment or accessibility acceptance
test.

## Data inventory

| Data | Why it exists | Client storage | Server storage |
|---|---|---|---|
| Approver identifier | Route an organization's protected action to the named approver | Device-only encrypted session | Session, enrollment, action, and audit records |
| Session token | Authenticate the paired app | Keychain or Android Keystore protected | SHA-256 token hash only |
| Passkey credential and public key | Verify user-present, user-verified ceremonies | Platform passkey provider | Public credential material and counters |
| App/device attestation identifiers | Pin the approved app instance and reject replay or rollback | Platform attestation provider | Enrollment, integrity policy result, and counters |
| Action and presentation | Show and bind the exact consequential operation | In memory during review | Pending action, challenge, and tamper-evident audit record |
| Approval or denial | Enforce and later reproduce the decision | In memory, then discarded | Terminal decision and evidence record |

The reference apps do not include advertising, cross-app tracking, analytics,
contacts, location, photo-library access, microphone access, or a general
clipboard reader. They do not store the organization's pairing secret after a
successful exchange. Disconnect invokes an atomic server operation that revokes
both the session and its enrolled device credential; local secrets are removed
only after the server confirms revocation or confirms that the session expired.

## Store declarations

The iOS privacy manifest declares user ID, device ID, and product interaction as
linked data used for app functionality and fraud prevention/security, with
tracking disabled. App Store Connect privacy answers must match that manifest
and the production backend's actual retention policy.

The Google Play Data safety form should disclose account/identity identifiers,
device identifiers, app interactions, and security-related diagnostics used for
app functionality and fraud prevention. It should also state that transport is
encrypted and deletion is controlled by the deploying organization. Do not mark
data as optional when the high-assurance profile cannot operate without it.

Audit evidence can be subject to statutory retention and legal holds. The
deploying organization is the data controller for action content and determines
retention, access, correction, export, and deletion. EMILIA's reference schema
does not silently delete audit evidence on app disconnect.

## Accessibility findings

- iOS uses semantic Dynamic Type styles, VoiceOver labels and hints, stable UI
  identifiers, minimum 44-point controls, Reduce Motion support, native alerts,
  and a stacked material-field fallback at large text sizes.
- Android uses scale-independent text, minimum 48-dp controls, TalkBack content
  descriptions, polite live regions for results, scrollable layouts, and no
  color-only approval or denial state.
- Brass and placeholder colors were darkened to exceed 4.5:1 against their
  light surfaces. Approval and denial remain distinct by wording and iconography.
- The exact material fields remain readable as text; they are not rendered only
  into an image or canvas.

## Acceptance still required on physical devices

Before store submission, test VoiceOver and TalkBack through pairing,
enrollment, approval, denial, error recovery, and disconnect at the largest
supported text size. Test Switch Control, keyboard navigation on iPad, RTL
layout, increased contrast, Reduce Motion, grayscale, and biometric/passcode
fallback. Record screen-reader announcements and challenge-to-decision
abandonment by accessibility cohort during the pilot. A simulator compile is
not evidence that those physical-device checks passed.

## Security and privacy boundary

Android release builds set `FLAG_SECURE`. iOS refuses both before signing and
again before submitting a signed ceremony while screen capture or mirroring is
reported active, hides protected content while capture is reported, and replaces
the app-switcher snapshot with a neutral privacy shield. iOS cannot prevent an
ordinary screenshot, and there remains
an unavoidable platform race around capture-state notifications. These are
defense-in-depth controls, not proof of perception or proof that a fully
compromised operating system rendered honest pixels. The server continues to
rely on exact action binding, passkey verification, pinned app integrity, and
one-time consumption.
