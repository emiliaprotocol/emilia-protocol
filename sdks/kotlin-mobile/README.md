# EMILIA Mobile for Android

Native Android client for `EP-MOBILE-CEREMONY-v1`, using Credential Manager
passkeys and Play Integrity Standard requests.

```kotlin
val integrity = EmiliaPlayIntegrityProvider.prepare(
    context = applicationContext,
    cloudProjectNumber = cloudProjectNumber,
    attestationKeyId = enrolledAttestationKeyId,
)
val coordinator = EmiliaMobileCeremonyCoordinator(
    passkeys = EmiliaAndroidPasskeyProvider(activity),
    integrity = integrity,
    appId = packageName,
    deviceKeyId = enrolledDeviceKeyId,
)
val response = coordinator.perform(challengeBytes)
```

The server must call Google's decode endpoint and pin package name, signing
certificate digest, licensing policy, request hash, freshness, and required
device-integrity labels. The client cannot self-assert those results.

Run:

```sh
ANDROID_HOME="$HOME/Library/Android/sdk" ./gradlew testDebugUnitTest
```

The production reference app uses `ai.emiliaprotocol.approver`, Android 13 or
newer, release-only screen-capture blocking, Keystore-protected session state,
and a build gate that refuses an unsigned release or a missing Play cloud
project. A downstream distributor must change the package, Play signing
identity, asset links, server pins, and integrity policy as one trust bundle.
