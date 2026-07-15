// SPDX-License-Identifier: Apache-2.0
#if os(iOS)
import AuthenticationServices
import DeviceCheck
import Foundation
import UIKit

@MainActor
public final class EmiliaApplePasskeyProvider: NSObject, EmiliaPasskeyAssertionProvider,
    ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding, @unchecked Sendable {
    private let presentationAnchor: @MainActor () -> ASPresentationAnchor
    private var continuation: CheckedContinuation<EmiliaPasskeyAssertion, Error>?

    public init(presentationAnchor: @escaping @MainActor () -> ASPresentationAnchor) {
        self.presentationAnchor = presentationAnchor
    }

    public func assertion(rpID: String, challenge: Data, allowedCredentialIDs: [Data]) async throws -> EmiliaPasskeyAssertion {
        guard continuation == nil else { throw EmiliaMobileError.unavailable("a passkey ceremony is already active") }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        request.userVerificationPreference = .required
        request.allowedCredentials = allowedCredentialIDs.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        presentationAnchor()
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            continuation?.resume(throwing: EmiliaMobileError.unavailable("the platform returned a non-passkey credential"))
            continuation = nil
            return
        }
        continuation?.resume(returning: EmiliaPasskeyAssertion(
            credentialID: credential.credentialID,
            authenticatorData: credential.rawAuthenticatorData,
            clientDataJSON: credential.rawClientDataJSON,
            signature: credential.signature
        ))
        continuation = nil
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

public struct EmiliaAppleAppAttestProvider: EmiliaPlatformIntegrityProvider, Sendable {
    public let format = "apple-app-attest"
    public let attestationKeyID: String

    public init(attestationKeyID: String) {
        self.attestationKeyID = attestationKeyID
    }

    public func assertion(requestHash: Data) async throws -> Data {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw EmiliaMobileError.unavailable("Apple App Attest is not supported") }
        return try await service.generateAssertion(attestationKeyID, clientDataHash: requestHash)
    }
}

@MainActor
public final class EmiliaApplePasskeyRegistrationProvider: NSObject, EmiliaPasskeyRegistrationProvider,
    ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding, @unchecked Sendable {
    private let presentationAnchor: @MainActor () -> ASPresentationAnchor
    private var continuation: CheckedContinuation<EmiliaPasskeyRegistration, Error>?

    public init(presentationAnchor: @escaping @MainActor () -> ASPresentationAnchor) {
        self.presentationAnchor = presentationAnchor
    }

    public func registration(
        rpID: String,
        challenge: Data,
        userID: Data,
        userName: String,
        displayName: String
    ) async throws -> EmiliaPasskeyRegistration {
        guard continuation == nil else { throw EmiliaMobileError.unavailable("a passkey registration is already active") }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: userName,
            userID: userID
        )
        request.displayName = displayName
        request.userVerificationPreference = .required
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        presentationAnchor()
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
              let attestationObject = credential.rawAttestationObject
        else {
            continuation?.resume(throwing: EmiliaMobileError.unavailable("the platform returned no passkey attestation"))
            continuation = nil
            return
        }
        continuation?.resume(returning: EmiliaPasskeyRegistration(
            credentialID: credential.credentialID,
            clientDataJSON: credential.rawClientDataJSON,
            attestationObject: attestationObject
        ))
        continuation = nil
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

public struct EmiliaAppleAppAttestEnrollmentProvider: EmiliaPlatformEnrollmentProvider, Sendable {
    public init() {}

    public func enrollment(requestHash: Data) async throws -> EmiliaPlatformEnrollment {
        let keyID = try await EmiliaAppleAppAttestEnrollment.generateKey()
        let attestation = try await EmiliaAppleAppAttestEnrollment.attestKey(keyID, enrollmentChallengeHash: requestHash)
        return EmiliaPlatformEnrollment(
            format: "apple-app-attest-enrollment",
            attestationKeyID: keyID,
            token: attestation
        )
    }
}

public enum EmiliaAppleAppAttestEnrollment {
    public static func generateKey() async throws -> String {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw EmiliaMobileError.unavailable("Apple App Attest is not supported") }
        return try await service.generateKey()
    }

    public static func attestKey(_ keyID: String, enrollmentChallengeHash: Data) async throws -> Data {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw EmiliaMobileError.unavailable("Apple App Attest is not supported") }
        return try await service.attestKey(keyID, clientDataHash: enrollmentChallengeHash)
    }
}
#endif
