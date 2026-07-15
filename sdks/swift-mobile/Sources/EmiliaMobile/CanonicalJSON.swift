// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Foundation

public enum EmiliaJSONValue: Sendable, Equatable, Codable {
    case object([String: EmiliaJSONValue])
    case array([EmiliaJSONValue])
    case string(String)
    case integer(Int64)
    case bool(Bool)
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null; return }
        if let value = try? container.decode(Bool.self) { self = .bool(value); return }
        if let value = try? container.decode(Int64.self) {
            guard abs(value) <= 9_007_199_254_740_991 else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "integer exceeds the EP safe-integer profile")
            }
            self = .integer(value)
            return
        }
        if let value = try? container.decode(String.self) { self = .string(value); return }
        if let value = try? container.decode([EmiliaJSONValue].self) { self = .array(value); return }
        if let value = try? container.decode([String: EmiliaJSONValue].self) { self = .object(value); return }
        throw DecodingError.dataCorruptedError(in: container, debugDescription: "non-integer numbers are outside the EP canonicalization profile")
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    public var objectValue: [String: EmiliaJSONValue]? {
        guard case .object(let value) = self else { return nil }
        return value
    }

    public var stringValue: String? {
        guard case .string(let value) = self else { return nil }
        return value
    }
}

public enum EmiliaCanonicalJSON {
    public static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    public static func encode(_ value: EmiliaJSONValue) throws -> Data {
        Data(try canonicalString(value).utf8)
    }

    public static func sha256(_ value: EmiliaJSONValue) throws -> Data {
        Data(SHA256.hash(data: try encode(value)))
    }

    public static func digest(_ value: EmiliaJSONValue) throws -> String {
        "sha256:" + (try sha256(value)).map { String(format: "%02x", $0) }.joined()
    }

    private static func canonicalString(_ value: EmiliaJSONValue) throws -> String {
        switch value {
        case .null: return "null"
        case .bool(let value): return value ? "true" : "false"
        case .integer(let value):
            guard abs(value) <= maximumSafeInteger else { throw EmiliaMobileError.nonCanonicalJSON }
            return String(value)
        case .string(let value): return quote(value)
        case .array(let values):
            return "[" + (try values.map(canonicalString).joined(separator: ",")) + "]"
        case .object(let values):
            let keys = values.keys.sorted(by: utf16LessThan)
            return "{" + (try keys.map { key in
                guard let value = values[key] else { throw EmiliaMobileError.nonCanonicalJSON }
                return quote(key) + ":" + (try canonicalString(value))
            }.joined(separator: ",")) + "}"
        }
    }

    private static func utf16LessThan(_ left: String, _ right: String) -> Bool {
        let lhs = Array(left.utf16)
        let rhs = Array(right.utf16)
        for index in 0..<min(lhs.count, rhs.count) {
            if lhs[index] != rhs[index] { return lhs[index] < rhs[index] }
        }
        return lhs.count < rhs.count
    }

    private static func quote(_ value: String) -> String {
        var output = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: output += "\\\""
            case 0x5c: output += "\\\\"
            case 0x08: output += "\\b"
            case 0x09: output += "\\t"
            case 0x0a: output += "\\n"
            case 0x0c: output += "\\f"
            case 0x0d: output += "\\r"
            case 0x00...0x1f: output += String(format: "\\u%04x", scalar.value)
            default: output.unicodeScalars.append(scalar)
            }
        }
        output += "\""
        return output
    }
}

public extension Data {
    var emiliaBase64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(emiliaBase64URL value: String) {
        guard !value.isEmpty, value.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }) else { return nil }
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        self.init(base64Encoded: padded)
    }
}
