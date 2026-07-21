// SPDX-License-Identifier: Apache-2.0
import Foundation

public enum EmiliaActionContinuityError: Error, Equatable {
    case invalidActionIdentity
    case invalidQuorum
    case invalidPassport
    case invalidPassportDigest
}

private enum EmiliaContinuityFormat {
    static let caidPattern =
        #"^caid:1:emilia\.mobile\.authorized-action\.1:jcs-sha256:[A-Za-z0-9_-]{43}$"#
    static let digestPattern = #"^sha256:[0-9a-f]{64}$"#

    static func matches(_ value: String, pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }

    static func json(_ value: String?) -> EmiliaJSONValue {
        value.map(EmiliaJSONValue.string) ?? .null
    }
}

public enum EmiliaActionLifecycleState: Sendable, Equatable, Hashable, Codable {
    case awaitingDecision
    case quorumPending
    case authorized
    case consumed
    case indeterminate
    case executed
    case refused
    case denied
    case withdrawn
    case expired
    case cancelled
    case unknown(String)

    public init(rawValue: String) {
        switch rawValue.uppercased() {
        case "AWAITING_DECISION": self = .awaitingDecision
        case "QUORUM_PENDING": self = .quorumPending
        case "AUTHORIZED": self = .authorized
        case "CONSUMED": self = .consumed
        case "INDETERMINATE": self = .indeterminate
        case "EXECUTED": self = .executed
        case "REFUSED": self = .refused
        case "DENIED": self = .denied
        case "WITHDRAWN": self = .withdrawn
        case "EXPIRED": self = .expired
        case "CANCELLED": self = .cancelled
        default: self = .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .awaitingDecision: "AWAITING_DECISION"
        case .quorumPending: "QUORUM_PENDING"
        case .authorized: "AUTHORIZED"
        case .consumed: "CONSUMED"
        case .indeterminate: "INDETERMINATE"
        case .executed: "EXECUTED"
        case .refused: "REFUSED"
        case .denied: "DENIED"
        case .withdrawn: "WITHDRAWN"
        case .expired: "EXPIRED"
        case .cancelled: "CANCELLED"
        case .unknown(let value): value
        }
    }

    public init(from decoder: Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct EmiliaActionIdentity: Sendable, Equatable, Codable {
    public static let actionType = "emilia.mobile.authorized-action.1"

    public let actionCAID: String
    public let actionDigest: String
    public let fingerprint: String

    public init(
        actionCAID: String,
        actionDigest: String,
        fingerprint: String? = nil
    ) throws {
        guard EmiliaContinuityFormat.matches(actionCAID, pattern: EmiliaContinuityFormat.caidPattern),
              EmiliaContinuityFormat.matches(actionDigest, pattern: EmiliaContinuityFormat.digestPattern),
              let derived = Self.stableFingerprint(for: actionCAID),
              fingerprint == nil || fingerprint == derived
        else {
            throw EmiliaActionContinuityError.invalidActionIdentity
        }
        self.actionCAID = actionCAID
        self.actionDigest = actionDigest
        self.fingerprint = derived
    }

    public static func stableFingerprint(for actionCAID: String) -> String? {
        guard EmiliaContinuityFormat.matches(actionCAID, pattern: EmiliaContinuityFormat.caidPattern),
              let encodedDigest = actionCAID.split(separator: ":").last,
              let digest = Data(emiliaBase64URL: String(encodedDigest)),
              digest.count == 32
        else { return nil }
        let prefix = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: 16, by: 4).map { offset in
            let start = prefix.index(prefix.startIndex, offsetBy: offset)
            let end = prefix.index(start, offsetBy: 4)
            return String(prefix[start..<end])
        }.joined(separator: "-")
    }

    public static func derive(from action: EmiliaJSONValue) throws -> Self {
        guard let object = action.objectValue else {
            throw EmiliaActionContinuityError.invalidActionIdentity
        }
        let sourceActionType = ["action_type", "@type", "type"].lazy.compactMap { key -> String? in
            guard let value = object[key]?.stringValue,
                  !value.isEmpty,
                  value.unicodeScalars.count <= 256
            else { return nil }
            return value
        }.first ?? "application.action"
        let actionDigest = try EmiliaCanonicalJSON.digest(action)
        let wrapper: EmiliaJSONValue = .object([
            "action_type": .string(Self.actionType),
            "source_action_type": .string(sourceActionType),
            "source_action_digest": .string(actionDigest),
        ])
        let caidDigest = try EmiliaCanonicalJSON.sha256(wrapper)
        return try Self(
            actionCAID:
                "caid:1:\(Self.actionType):jcs-sha256:\(caidDigest.emiliaBase64URL)",
            actionDigest: actionDigest
        )
    }

    enum CodingKeys: String, CodingKey {
        case actionCAID = "action_caid"
        case actionDigest = "action_digest"
        case fingerprint
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let actionCAID = try container.decode(String.self, forKey: .actionCAID)
        let actionDigest = try container.decode(String.self, forKey: .actionDigest)
        let fingerprint = try container.decodeIfPresent(String.self, forKey: .fingerprint)
        do {
            try self.init(
                actionCAID: actionCAID,
                actionDigest: actionDigest,
                fingerprint: fingerprint
            )
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .fingerprint,
                in: container,
                debugDescription: "Action identity is malformed or its fingerprint does not match its CAID."
            )
        }
    }
}

public struct EmiliaActionQuorum: Sendable, Equatable, Codable {
    public let approved: Int
    public let required: Int
    public let denied: Int
    public let withdrawn: Int

    public init(
        approved: Int = 0,
        required: Int = 1,
        denied: Int = 0,
        withdrawn: Int = 0
    ) throws {
        guard approved >= 0, required > 0, denied >= 0, withdrawn >= 0 else {
            throw EmiliaActionContinuityError.invalidQuorum
        }
        self.approved = approved
        self.required = required
        self.denied = denied
        self.withdrawn = withdrawn
    }

    public var remaining: Int { max(required - approved, 0) }
    public var fractionComplete: Double {
        min(Double(approved) / Double(required), 1)
    }

    enum CodingKeys: CodingKey {
        case approved, required, denied, withdrawn
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        do {
            try self.init(
                approved: try container.decodeIfPresent(Int.self, forKey: .approved) ?? 0,
                required: try container.decodeIfPresent(Int.self, forKey: .required) ?? 1,
                denied: try container.decodeIfPresent(Int.self, forKey: .denied) ?? 0,
                withdrawn: try container.decodeIfPresent(Int.self, forKey: .withdrawn) ?? 0
            )
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .required,
                in: container,
                debugDescription: "Quorum counts must be non-negative and required must be positive."
            )
        }
    }
}

public struct EmiliaActionContinuity: Sendable, Equatable, Codable {
    public let state: EmiliaActionLifecycleState
    public let retrySafe: Bool
    public let quorum: EmiliaActionQuorum

    public init(
        state: EmiliaActionLifecycleState = .awaitingDecision,
        retrySafe: Bool = false,
        quorum: EmiliaActionQuorum
    ) {
        self.state = state
        self.retrySafe = retrySafe
        self.quorum = quorum
    }

    enum CodingKeys: String, CodingKey {
        case state
        case retrySafe = "retry_safe"
        case quorum
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.state = try container.decodeIfPresent(EmiliaActionLifecycleState.self, forKey: .state)
            ?? .awaitingDecision
        self.retrySafe = try container.decodeIfPresent(Bool.self, forKey: .retrySafe) ?? false
        self.quorum = try container.decodeIfPresent(EmiliaActionQuorum.self, forKey: .quorum)
            ?? EmiliaActionQuorum()
    }
}

public enum EmiliaMaterialChangeKind: Sendable, Equatable, Codable {
    case added
    case changed
    case removed
    case unknown(String)

    public init(rawValue: String) {
        switch rawValue.lowercased() {
        case "added": self = .added
        case "changed": self = .changed
        case "removed": self = .removed
        default: self = .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .added: "added"
        case .changed: "changed"
        case .removed: "removed"
        case .unknown(let value): value
        }
    }

    public init(from decoder: Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct EmiliaMaterialChange: Sendable, Equatable, Codable {
    public let field: String
    public let change: EmiliaMaterialChangeKind
    public let before: String?
    public let after: String?

    public init(
        field: String,
        change: EmiliaMaterialChangeKind,
        before: String? = nil,
        after: String? = nil
    ) {
        self.field = field
        self.change = change
        self.before = before
        self.after = after
    }
}

public enum EmiliaSystemAlignmentVerdict: Sendable, Equatable, Codable {
    case equivalentUnderProfile
    case notEquivalent
    case indeterminate
    case unknown(String)

    public init(rawValue: String) {
        switch rawValue.uppercased() {
        case "EQUIVALENT_UNDER_PROFILE": self = .equivalentUnderProfile
        case "NOT_EQUIVALENT": self = .notEquivalent
        case "INDETERMINATE": self = .indeterminate
        default: self = .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .equivalentUnderProfile: "EQUIVALENT_UNDER_PROFILE"
        case .notEquivalent: "NOT_EQUIVALENT"
        case .indeterminate: "INDETERMINATE"
        case .unknown(let value): value
        }
    }

    public init(from decoder: Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct EmiliaSystemAlignment: Sendable, Equatable, Codable {
    public let system: String
    public let verdict: EmiliaSystemAlignmentVerdict
    public let profileID: String?
    public let profileHash: String?
    public let nativeVerified: Bool
    public let evidenceDigest: String?
    public let reason: String?

    public var effectiveVerdict: EmiliaSystemAlignmentVerdict {
        guard verdict == .equivalentUnderProfile else { return verdict }
        guard nativeVerified,
              profileID?.isEmpty == false,
              profileHash.map({
                  EmiliaContinuityFormat.matches($0, pattern: EmiliaContinuityFormat.digestPattern)
              }) == true
        else { return .indeterminate }
        return .equivalentUnderProfile
    }

    enum CodingKeys: String, CodingKey {
        case system, verdict
        case profileID = "profile_id"
        case profileHash = "profile_hash"
        case nativeVerified = "native_verified"
        case evidenceDigest = "evidence_digest"
        case reason
    }

    public init(
        system: String,
        verdict: EmiliaSystemAlignmentVerdict,
        profileID: String? = nil,
        profileHash: String? = nil,
        nativeVerified: Bool = false,
        evidenceDigest: String? = nil,
        reason: String? = nil
    ) {
        self.system = system
        self.verdict = verdict
        self.profileID = profileID
        self.profileHash = profileHash
        self.nativeVerified = nativeVerified
        self.evidenceDigest = evidenceDigest
        self.reason = reason
    }
}

public struct EmiliaActionEvent: Sendable, Equatable, Codable, Identifiable {
    public let eventID: String
    public let type: String
    public let details: [String: EmiliaJSONValue]
    public let evidenceDigest: String?
    public let createdAt: String

    public var id: String { eventID }

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case type, details
        case evidenceDigest = "evidence_digest"
        case createdAt = "created_at"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decodeIfPresent(String.self, forKey: .type) ?? "unknown"
        self.details = try container.decodeIfPresent(
            [String: EmiliaJSONValue].self,
            forKey: .details
        ) ?? [:]
        self.evidenceDigest = try container.decodeIfPresent(String.self, forKey: .evidenceDigest)
        self.createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
        let fallbackPayload: EmiliaJSONValue = .object([
            "type": .string(type),
            "details": .object(details),
            "evidence_digest": EmiliaContinuityFormat.json(evidenceDigest),
            "created_at": .string(createdAt),
        ])
        let fallbackID = (try? EmiliaCanonicalJSON.digest(fallbackPayload))
            .map { "derived-event:\($0)" } ?? "derived-event:\(type):\(createdAt)"
        self.eventID = try container.decodeIfPresent(String.self, forKey: .eventID) ?? fallbackID
    }
}

public struct EmiliaDecisionPassport: Sendable, Equatable, Codable {
    public static let version = "EP-MOBILE-DECISION-PASSPORT-v1"

    public struct Action: Sendable, Equatable, Codable {
        public let actionReference: String
        public let actionCAID: String
        public let actionDigest: String

        enum CodingKeys: String, CodingKey {
            case actionReference = "action_reference"
            case actionCAID = "action_caid"
            case actionDigest = "action_digest"
        }
    }

    public struct Decision: Sendable, Equatable, Codable {
        public let challengeID: String?
        public let verdict: String?
        public let decidedAt: String?
        public let evidenceDigest: String?

        enum CodingKeys: String, CodingKey {
            case challengeID = "challenge_id"
            case verdict
            case decidedAt = "decided_at"
            case evidenceDigest = "evidence_digest"
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encodeIfPresent(challengeID, forKey: .challengeID)
            if challengeID == nil { try container.encodeNil(forKey: .challengeID) }
            try container.encodeIfPresent(verdict, forKey: .verdict)
            if verdict == nil { try container.encodeNil(forKey: .verdict) }
            try container.encodeIfPresent(decidedAt, forKey: .decidedAt)
            if decidedAt == nil { try container.encodeNil(forKey: .decidedAt) }
            try container.encodeIfPresent(evidenceDigest, forKey: .evidenceDigest)
            if evidenceDigest == nil { try container.encodeNil(forKey: .evidenceDigest) }
        }
    }

    public struct Lifecycle: Sendable, Equatable, Codable {
        public let state: EmiliaActionLifecycleState
        public let retrySafe: Bool
        public let quorum: EmiliaActionQuorum?
        public let consumptionNonce: String?
        public let outcomeDigest: String?

        enum CodingKeys: String, CodingKey {
            case state
            case retrySafe = "retry_safe"
            case quorum
            case consumptionNonce = "consumption_nonce"
            case outcomeDigest = "outcome_digest"
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(state, forKey: .state)
            try container.encode(retrySafe, forKey: .retrySafe)
            try container.encodeIfPresent(quorum, forKey: .quorum)
            if quorum == nil { try container.encodeNil(forKey: .quorum) }
            try container.encodeIfPresent(consumptionNonce, forKey: .consumptionNonce)
            if consumptionNonce == nil { try container.encodeNil(forKey: .consumptionNonce) }
            try container.encodeIfPresent(outcomeDigest, forKey: .outcomeDigest)
            if outcomeDigest == nil { try container.encodeNil(forKey: .outcomeDigest) }
        }
    }

    public let version: String
    public let action: Action
    public let decision: Decision
    public let lifecycle: Lifecycle
    public let createdAt: String?
    public let passportDigest: String?

    enum CodingKeys: String, CodingKey {
        case version = "@version"
        case action, decision, lifecycle
        case createdAt = "created_at"
        case passportDigest = "passport_digest"
    }

    public var hasValidDigest: Bool {
        guard version == Self.version,
              let passportDigest,
              EmiliaContinuityFormat.matches(
                  passportDigest,
                  pattern: EmiliaContinuityFormat.digestPattern
              ),
              EmiliaActionIdentity.stableFingerprint(for: action.actionCAID) != nil,
              EmiliaContinuityFormat.matches(
                  action.actionDigest,
                  pattern: EmiliaContinuityFormat.digestPattern
              )
        else { return false }
        return (try? EmiliaCanonicalJSON.digest(canonicalDigestPayload)) == passportDigest
    }

    public func shareableJSON() throws -> String {
        guard hasValidDigest else {
            throw EmiliaActionContinuityError.invalidPassportDigest
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard let json = String(data: data, encoding: .utf8) else {
            throw EmiliaActionContinuityError.invalidPassport
        }
        return json
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(action, forKey: .action)
        try container.encode(decision, forKey: .decision)
        try container.encode(lifecycle, forKey: .lifecycle)
        try container.encodeIfPresent(createdAt, forKey: .createdAt)
        if createdAt == nil { try container.encodeNil(forKey: .createdAt) }
        try container.encodeIfPresent(passportDigest, forKey: .passportDigest)
    }

    private var canonicalDigestPayload: EmiliaJSONValue {
        let quorum: EmiliaJSONValue
        if let value = lifecycle.quorum {
            quorum = .object([
                "approved": .integer(Int64(value.approved)),
                "required": .integer(Int64(value.required)),
                "denied": .integer(Int64(value.denied)),
                "withdrawn": .integer(Int64(value.withdrawn)),
            ])
        } else {
            quorum = .null
        }
        return .object([
            "@version": .string(version),
            "action": .object([
                "action_reference": .string(action.actionReference),
                "action_caid": .string(action.actionCAID),
                "action_digest": .string(action.actionDigest),
            ]),
            "decision": .object([
                "challenge_id": EmiliaContinuityFormat.json(decision.challengeID),
                "verdict": EmiliaContinuityFormat.json(decision.verdict),
                "decided_at": EmiliaContinuityFormat.json(decision.decidedAt),
                "evidence_digest": EmiliaContinuityFormat.json(decision.evidenceDigest),
            ]),
            "lifecycle": .object([
                "state": .string(lifecycle.state.rawValue),
                "retry_safe": .bool(lifecycle.retrySafe),
                "quorum": quorum,
                "consumption_nonce": EmiliaContinuityFormat.json(lifecycle.consumptionNonce),
                "outcome_digest": EmiliaContinuityFormat.json(lifecycle.outcomeDigest),
            ]),
            "created_at": EmiliaContinuityFormat.json(createdAt),
        ])
    }
}

public struct EmiliaMobileAction: Sendable, Equatable, Codable, Identifiable {
    public let actionReference: String
    public let title: String
    public let summary: String
    public let risk: String
    public let materialFields: [String: String]
    public let expiresAt: String
    public let createdAt: String
    public let status: String
    public let revision: Int
    public let identity: EmiliaActionIdentity?
    public let supersedesActionCAID: String?
    public let changes: [EmiliaMaterialChange]
    public let continuity: EmiliaActionContinuity?
    public let quorum: EmiliaActionQuorum?
    public let alignments: [EmiliaSystemAlignment]
    public let events: [EmiliaActionEvent]
    public let canWithdraw: Bool
    public let passport: EmiliaDecisionPassport?

    public var id: String { actionReference }
    public var quorumProgress: EmiliaActionQuorum? { quorum ?? continuity?.quorum }

    public var canDisplayExecuted: Bool {
        guard continuity?.state == .executed,
              let identity,
              let passport,
              passport.hasValidDigest,
              passport.action.actionReference == actionReference,
              passport.action.actionCAID == identity.actionCAID,
              passport.action.actionDigest == identity.actionDigest,
              passport.lifecycle.state == .executed,
              passport.lifecycle.outcomeDigest.map({
                  EmiliaContinuityFormat.matches($0, pattern: EmiliaContinuityFormat.digestPattern)
              }) == true
        else { return false }
        return true
    }

    public var lifecycleLabel: String? {
        guard let state = continuity?.state else { return nil }
        if state == .executed && !canDisplayExecuted {
            return "OUTCOME UNVERIFIED"
        }
        return state.rawValue
    }

    public init(
        actionReference: String,
        title: String,
        summary: String,
        risk: String,
        materialFields: [String: String],
        expiresAt: String,
        createdAt: String,
        status: String = "pending",
        revision: Int = 1,
        identity: EmiliaActionIdentity? = nil,
        supersedesActionCAID: String? = nil,
        changes: [EmiliaMaterialChange] = [],
        continuity: EmiliaActionContinuity? = nil,
        quorum: EmiliaActionQuorum? = nil,
        alignments: [EmiliaSystemAlignment] = [],
        events: [EmiliaActionEvent] = [],
        canWithdraw: Bool = false,
        passport: EmiliaDecisionPassport? = nil
    ) {
        self.actionReference = actionReference
        self.title = title
        self.summary = summary
        self.risk = risk
        self.materialFields = materialFields
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.status = status
        self.revision = max(revision, 1)
        self.identity = identity
        self.supersedesActionCAID = supersedesActionCAID
        self.changes = changes
        self.continuity = continuity
        self.quorum = quorum
        self.alignments = alignments
        self.events = events
        self.canWithdraw = canWithdraw
        self.passport = passport
    }

    enum CodingKeys: String, CodingKey {
        case actionReference = "action_reference"
        case title, summary, risk
        case materialFields = "material_fields"
        case expiresAt = "expires_at"
        case createdAt = "created_at"
        case status, revision, identity
        case supersedesActionCAID = "supersedes_action_caid"
        case changes, continuity, quorum, alignments, events
        case canWithdraw = "can_withdraw"
        case passport
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            actionReference: try container.decode(String.self, forKey: .actionReference),
            title: try container.decodeIfPresent(String.self, forKey: .title) ?? "Approval required",
            summary: try container.decodeIfPresent(String.self, forKey: .summary)
                ?? "Review the exact action before deciding.",
            risk: try container.decodeIfPresent(String.self, forKey: .risk) ?? "consequential",
            materialFields: try container.decodeIfPresent(
                [String: String].self,
                forKey: .materialFields
            ) ?? [:],
            expiresAt: try container.decodeIfPresent(String.self, forKey: .expiresAt) ?? "",
            createdAt: try container.decodeIfPresent(String.self, forKey: .createdAt) ?? "",
            status: try container.decodeIfPresent(String.self, forKey: .status) ?? "pending",
            revision: try container.decodeIfPresent(Int.self, forKey: .revision) ?? 1,
            identity: try container.decodeIfPresent(EmiliaActionIdentity.self, forKey: .identity),
            supersedesActionCAID: try container.decodeIfPresent(
                String.self,
                forKey: .supersedesActionCAID
            ),
            changes: try container.decodeIfPresent(
                [EmiliaMaterialChange].self,
                forKey: .changes
            ) ?? [],
            continuity: try container.decodeIfPresent(
                EmiliaActionContinuity.self,
                forKey: .continuity
            ),
            quorum: try container.decodeIfPresent(EmiliaActionQuorum.self, forKey: .quorum),
            alignments: try container.decodeIfPresent(
                [EmiliaSystemAlignment].self,
                forKey: .alignments
            ) ?? [],
            events: try container.decodeIfPresent([EmiliaActionEvent].self, forKey: .events) ?? [],
            canWithdraw: try container.decodeIfPresent(Bool.self, forKey: .canWithdraw) ?? false,
            passport: try container.decodeIfPresent(EmiliaDecisionPassport.self, forKey: .passport)
        )
        if let supersedesActionCAID,
           EmiliaActionIdentity.stableFingerprint(for: supersedesActionCAID) == nil {
            throw DecodingError.dataCorruptedError(
                forKey: .supersedesActionCAID,
                in: container,
                debugDescription: "Superseded action CAID is malformed."
            )
        }
    }
}

public struct EmiliaMobileActionListResponse: Sendable, Equatable, Decodable {
    public let approverID: String
    public let actions: [EmiliaMobileAction]

    enum CodingKeys: String, CodingKey {
        case approverID = "approver_id"
        case actions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.approverID = try container.decodeIfPresent(String.self, forKey: .approverID) ?? ""
        self.actions = try container.decodeIfPresent([EmiliaMobileAction].self, forKey: .actions) ?? []
    }
}

public struct EmiliaDecisionPassportResponse: Sendable, Equatable, Decodable {
    public let passport: EmiliaDecisionPassport
}

public struct EmiliaActionWithdrawalResponse: Sendable, Equatable, Decodable {
    public let withdrawn: Bool
    public let state: EmiliaActionLifecycleState
}
