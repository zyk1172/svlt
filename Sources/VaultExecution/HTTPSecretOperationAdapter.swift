import Foundation
import VaultCore

/// A user-owned, immutable response allowlist. It is injected by the App's
/// profile layer rather than accepted from an individual MCP request. The
/// profile contains no credential value and only permits non-sensitive JSON
/// Pointer fields for one exact origin, method set, and path. Invalid profiles
/// are discarded by the adapter before capability advertisement.
public struct HTTPResponseProjectionProfile: Codable, Equatable, Sendable {
    public let id: String
    public let origin: String
    public let allowedMethods: [HTTPMethod]
    public let path: String
    public let allowedJSONPointers: [String]

    public init(
        id: String,
        origin: String,
        allowedMethods: [HTTPMethod],
        path: String,
        allowedJSONPointers: [String]
    ) {
        self.id = id
        self.origin = origin
        self.allowedMethods = allowedMethods
        self.path = path
        self.allowedJSONPointers = allowedJSONPointers
    }
}

/// HTTP is deliberately limited to a small set of typed authentication
/// strategies. There is no arbitrary header dictionary: that prevents an
/// Agent from smuggling credentials through Host, Cookie, proxy, or forwarding
/// headers and keeps the response policy reviewable.
public struct HTTPSecretOperationAdapter: SecretOperationAdapter {
    public let kind: SecretAdapterKind = .http
    public let capability: SecretOperationCapability

    private let sessionManager: HTTPSessionManager
    private let outputSanitizer: OutputSanitizer
    private let outputLimitBytes: Int
    private let responseProjectionProfiles: [String: HTTPResponseProjectionProfile]
    private let invalidResponseProjectionProfileIDs: Set<String>

    public init(
        sessionManager: HTTPSessionManager = HTTPSessionManager(),
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        outputLimitBytes: Int = 1_048_576,
        responseProjectionProfiles: [HTTPResponseProjectionProfile] = []
    ) {
        self.sessionManager = sessionManager
        self.outputSanitizer = outputSanitizer
        self.outputLimitBytes = max(1, outputLimitBytes)
        var profiles: [String: HTTPResponseProjectionProfile] = [:]
        var invalidProfileIDs = Set<String>()
        for profile in responseProjectionProfiles {
            guard !invalidProfileIDs.contains(profile.id) else { continue }
            guard Self.isValidProjectionProfile(profile) else {
                invalidProfileIDs.insert(profile.id)
                continue
            }
            if profiles[profile.id] != nil {
                profiles.removeValue(forKey: profile.id)
                invalidProfileIDs.insert(profile.id)
            } else {
                profiles[profile.id] = profile
            }
        }
        self.responseProjectionProfiles = profiles
        self.invalidResponseProjectionProfileIDs = invalidProfileIDs
        self.capability = SecretOperationCapability(
            kind: .http,
            status: .supported,
            operations: [.httpRequest, .apiRequest],
            reason: "typed HTTP Basic/Bearer/API-key requests; redirects and transport risk stop for device-owner review",
            features: SecretOperationCapabilityFeatures(
                auth: ["basic", "bearer", "apiKeyHeader", "staticCookie"],
                body: ["none", "raw", "json", "form"],
                response: profiles.isEmpty
                    ? ["metadataOnly", "sanitizedPreview"]
                    : ["metadataOnly", "sanitizedPreview", "projectedJSON"],
                transportSessionReuse: true,
                derivedCredentialCapture: false,
                publicNetworkEgress: true,
                insecurePrivateNetworkHTTPProfileOptIn: true
            )
        )
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        do {
            _ = try makePlan(for: descriptor)
            return .supported
        } catch HTTPAdapterError.unsupportedStrategy {
            return .unavailable
        } catch {
            return .invalidParameters
        }
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        let plan: RequestPlan
        do {
            plan = try makePlan(for: descriptor)
        } catch HTTPAdapterError.unsupportedStrategy {
            throw SecretOperationExecutionError.unavailable
        } catch HTTPAdapterError.invalidParameter {
            throw SecretOperationExecutionError.invalidParameter
        }
        // The policy engine decides whether the device owner must approve the
        // request. This adapter still enforces the saved insecure-transport
        // profile as a technical boundary after approval: a profile for one
        // exact origin must never widen to another host or port.
        do {
            try validateTransport(plan.url, descriptor: descriptor, metadata: metadata)
        } catch HTTPAdapterError.insecureTransportDenied {
            throw SecretOperationExecutionError.insecureTransportDenied
        } catch {
            throw SecretOperationExecutionError.invalidParameter
        }
        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        var request = URLRequest(url: plan.url)
        request.httpMethod = plan.method.rawValue
        try applyBody(plan.body, to: &request)
        let hasSecretAuth = try await applyAuthentication(
            plan.auth,
            descriptor: descriptor,
            to: &request,
            secretBuffers: &secretBuffers,
            resolve: resolve
        )

        let scope = HTTPSessionScope(
            principal: context.principal,
            scheme: plan.url.scheme ?? "http",
            host: plan.url.host ?? "",
            port: plan.url.port ?? (plan.url.scheme?.lowercased() == "https" ? 443 : 80),
            authenticationProfile: plan.auth.auditProfile,
            secretReferenceIDs: descriptor.secretReferences.map(\.description),
            securityGeneration: context.securityGeneration
        )

        let response: HTTPTransportResponse
        do {
            response = try await sessionManager.execute(
                request: request,
                scope: scope,
                requestedSessionID: descriptor.sessionID,
                maxResponseBytes: outputLimitBytes
            )
        } catch let error as HTTPSessionManagerError {
            throw mapSessionError(error)
        } catch let error as URLError where error.code == .timedOut {
            throw SecretOperationExecutionError.timedOut
        } catch is CancellationError {
            throw SecretOperationExecutionError.timedOut
        } catch {
            throw SecretOperationExecutionError.processFailed
        }

        guard response.data.count <= outputLimitBytes else {
            throw SecretOperationExecutionError.outputLimitExceeded
        }

        let responseFingerprints = secretBuffers.flatMap(OutputSanitizer.fingerprints(for:))
        let sanitizedBody = try sanitizedResponseBody(
            response.data,
            secrets: secretBuffers,
            fingerprints: responseFingerprints
        )
        let contentType = try sanitizedResponseText(
            response.contentType,
            secrets: secretBuffers,
            fingerprints: responseFingerprints
        )
        let redirectLocation = try sanitizedResponseText(
            response.redirectLocation,
            secrets: secretBuffers,
            fingerprints: responseFingerprints
        )

        let bodyPreview = try responsePreview(
            plan.responsePolicy,
            body: sanitizedBody,
            hasSecretAuth: hasSecretAuth
        )
        // §37: every redirect stops here with the absolute Location. A
        // redirect without a valid Location is a malformed server response,
        // never a successful request.
        if (300...399).contains(response.statusCode) {
            guard let redirectLocation else {
                return SecretOperationOutput(
                    status: "MALFORMED_REDIRECT",
                    httpStatus: response.statusCode,
                    sessionID: response.sessionID,
                    redacted: true
                )
            }
            return SecretOperationOutput(
                status: "REDIRECT_REQUIRES_REVIEW",
                httpStatus: response.statusCode,
                sessionID: response.sessionID,
                redirectLocation: redirectLocation,
                redacted: true
            )
        }
        return SecretOperationOutput(
            status: response.statusCode >= 400 ? "HTTP_ERROR" : "COMPLETED",
            httpStatus: response.statusCode,
            contentType: contentType,
            bodyPreview: bodyPreview,
            sessionID: response.sessionID,
            redacted: true
        )
    }

    public func invalidateSecurityState() async {
        await sessionManager.invalidateAll()
    }

    private struct RequestPlan {
        let url: URL
        let method: HTTPMethod
        let auth: HTTPAuthStrategy
        let body: HTTPBody
        let responsePolicy: HTTPResponsePolicy
    }

    private enum HTTPAdapterError: Error {
        case unsupportedStrategy
        case invalidParameter
        case insecureTransportDenied
    }

    /// An insecure HTTP profile is an explicit owner-saved transport opt-in,
    /// not a host-class allowlist. Compare the complete canonical origin so a
    /// profile for `nas-a:8080` cannot be reused for `nas-b` or another port.
    /// This check deliberately does not infer public/private reachability from
    /// a hostname: the policy has already required fresh owner approval, and
    /// DNS resolution is not a stable egress security boundary here.
    private func validateTransport(
        _ url: URL,
        descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata]
    ) throws {
        guard url.scheme?.lowercased() == "http",
              !descriptor.secretReferences.isEmpty else {
            return
        }

        var metadataByReference: [SecretReference: SecretPolicyMetadata] = [:]
        for item in metadata {
            guard metadataByReference[item.reference] == nil else {
                throw HTTPAdapterError.invalidParameter
            }
            metadataByReference[item.reference] = item
        }

        for reference in descriptor.secretReferences {
            guard let secret = metadataByReference[reference] else {
                throw HTTPAdapterError.insecureTransportDenied
            }

            let protocolMarkers = Set(secret.allowedProtocols.map { $0.lowercased() })
            guard protocolMarkers.contains("http") || protocolMarkers.contains("http-loopback") else {
                throw HTTPAdapterError.insecureTransportDenied
            }

            if protocolMarkers.contains("http-loopback"),
               !HTTPTransportSecurityPolicy.allowInsecureLoopback.permitsInsecureHTTP(
                   toHost: url.host ?? ""
               ) {
                throw HTTPAdapterError.insecureTransportDenied
            }

            let exactOrigin = secret.destinationBindings.contains { binding in
                binding.matches(
                    requestedProtocol: .http,
                    destination: descriptor.destination,
                    url: url.absoluteString
                )
            }
            guard exactOrigin else {
                throw HTTPAdapterError.insecureTransportDenied
            }
        }
    }

    private func makePlan(for descriptor: SecretOperationDescriptor) throws -> RequestPlan {
        guard descriptor.actionType == .httpRequest || descriptor.actionType == .apiRequest,
              let rawURL = descriptor.url,
              let url = URL(string: rawURL),
              url.user == nil,
              url.password == nil,
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host?.isEmpty == false,
              !rawURL.contains("secret://")
        else {
            throw HTTPAdapterError.invalidParameter
        }

        let method: HTTPMethod
        let auth: HTTPAuthStrategy
        let body: HTTPBody
        let responsePolicy: HTTPResponsePolicy

        if let payload = descriptor.payload {
            guard case let .http(operation) = payload else {
                throw HTTPAdapterError.invalidParameter
            }
            method = operation.method
            auth = operation.auth
            body = operation.body
            responsePolicy = operation.responsePolicy
            guard referencesMatch(operation.auth.referencedSecretReferences, descriptor.secretReferences) else {
                throw HTTPAdapterError.invalidParameter
            }
        } else {
            method = try parseMethod(descriptor.httpMethod)
            body = try legacyBody(from: descriptor)
            responsePolicy = descriptor.parameters["includeBodyPreview"] == "true"
                ? HTTPResponsePolicy(kind: .sanitizedPreview)
                : .metadataOnly
            if descriptor.actionType == .httpRequest,
               let passwordReference = reference(for: "passwordRef", in: descriptor) {
                let usernameReference = reference(for: "usernameRef", in: descriptor)
                auth = HTTPAuthStrategy(
                    kind: .basic,
                    username: descriptor.parameters["username"],
                    usernameReference: usernameReference,
                    passwordReference: passwordReference
                )
            } else if descriptor.actionType == .apiRequest,
                      let tokenReference = reference(for: "tokenRef", in: descriptor) {
                let headerName = descriptor.parameters["headerName"] ?? "Authorization"
                let scheme = descriptor.parameters["headerScheme"]
                    ?? (headerName.caseInsensitiveCompare("Authorization") == .orderedSame ? "Bearer" : nil)
                auth = HTTPAuthStrategy(
                    kind: headerName.caseInsensitiveCompare("Authorization") == .orderedSame
                        ? .bearer
                        : .apiKeyHeader,
                    valueReference: tokenReference,
                    headerName: headerName,
                    scheme: scheme
                )
            } else {
                auth = .none
            }
        }

        return RequestPlan(
            url: url,
            method: method,
            auth: try validateAuth(auth, descriptor: descriptor),
            body: try validateBody(body),
            responsePolicy: try validateResponsePolicy(responsePolicy, for: url, method: method)
        )
    }

    private func parseMethod(_ rawValue: String?) throws -> HTTPMethod {
        guard let rawValue, let method = HTTPMethod(rawValue: rawValue.uppercased()) else {
            throw HTTPAdapterError.invalidParameter
        }
        return method
    }

    private func legacyBody(from descriptor: SecretOperationDescriptor) throws -> HTTPBody {
        guard let body = descriptor.parameters["body"] else { return .none }
        guard body.utf8.count <= 65_536, !body.contains("secret://") else {
            throw HTTPAdapterError.invalidParameter
        }
        return .raw(body)
    }

    private func validateAuth(
        _ auth: HTTPAuthStrategy,
        descriptor: SecretOperationDescriptor
    ) throws -> HTTPAuthStrategy {
        let references = auth.referencedSecretReferences
        guard referencesMatch(references, descriptor.secretReferences) else {
            throw HTTPAdapterError.invalidParameter
        }
        switch auth.kind {
        case .none:
            guard references.isEmpty,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.valueReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil,
                  auth.cookieName == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .basic:
            guard auth.passwordReference != nil,
                  (auth.username != nil) != (auth.usernameReference != nil),
                  auth.username.map(Self.isSafeUsername) ?? true,
                  auth.valueReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil,
                  auth.cookieName == nil
            else { throw HTTPAdapterError.invalidParameter }
        case .bearer:
            guard auth.valueReference != nil,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.cookieName == nil,
                  auth.headerName == nil || auth.headerName?.caseInsensitiveCompare("Authorization") == .orderedSame,
                  auth.scheme.map(Self.isSafeAuthScheme) ?? true else {
                throw HTTPAdapterError.invalidParameter
            }
        case .apiKeyHeader, .customHeader:
            guard let headerName = auth.headerName,
                  Self.isAllowedSecretHeaderName(headerName),
                  Self.isSafeHeaderName(headerName),
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.cookieName == nil,
                  auth.scheme.map(Self.isSafeAuthScheme) ?? true,
                  auth.valueReference != nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .cookie:
            guard let cookieName = auth.cookieName,
                  Self.isSafeCookieName(cookieName),
                  auth.valueReference != nil,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .oauth2ClientCredentials, .oauth2RefreshToken, .clientCertificate, .hmacSigning:
            throw HTTPAdapterError.unsupportedStrategy
        }
        if let headerName = auth.headerName,
           !Self.isSafeHeaderName(headerName, allowingAuthorization: auth.kind == .bearer) {
            throw HTTPAdapterError.invalidParameter
        }
        if let scheme = auth.scheme, !Self.isSafeAuthScheme(scheme) {
            throw HTTPAdapterError.invalidParameter
        }
        return auth
    }

    private func validateBody(_ body: HTTPBody) throws -> HTTPBody {
        switch body.kind {
        case .none:
            guard body.content == nil, body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .raw:
            guard let content = body.content,
                  content.utf8.count <= 65_536,
                  !content.contains("secret://"),
                  body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .json:
            guard let content = body.content,
                  content.utf8.count <= 65_536,
                  !content.contains("secret://"),
                  (try? JSONSerialization.jsonObject(with: Data(content.utf8))) != nil,
                  body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .form:
            guard body.content == nil,
                  body.fields.count <= 128,
                  body.fields.allSatisfy({ key, value in
                      key.utf8.count <= 256 && value.utf8.count <= 4_096
                          && !key.contains("secret://") && !value.contains("secret://")
                  }) else { throw HTTPAdapterError.invalidParameter }
        }
        return body
    }

    private func validateResponsePolicy(
        _ policy: HTTPResponsePolicy,
        for url: URL,
        method: HTTPMethod
    ) throws -> HTTPResponsePolicy {
        guard (0...outputLimitBytes).contains(policy.maxBytes),
              policy.fields.count <= 32,
              policy.fields.allSatisfy({ field in
                  !field.isEmpty && field.utf8.count <= 128 && Self.isSafeJSONField(field)
              }) else {
            throw HTTPAdapterError.invalidParameter
        }
        if policy.kind == .captureCredential {
            throw HTTPAdapterError.unsupportedStrategy
        }
        if policy.selector != nil {
            // JSON selectors and header capture are not implemented. Reject
            // them instead of silently returning a different response shape.
            throw HTTPAdapterError.unsupportedStrategy
        }
        switch policy.kind {
        case .metadataOnly:
            guard policy.fields.isEmpty, policy.source == nil, policy.profileID == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .sanitizedPreview:
            guard policy.maxBytes > 0,
                  policy.fields.isEmpty,
                  policy.source == nil,
                  policy.profileID == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .structuredFields, .projectedJSON:
            guard policy.maxBytes > 0,
                  !policy.fields.isEmpty,
                  policy.source == nil || policy.source == .json,
                  let profileID = policy.profileID,
                  !profileID.isEmpty,
                  projectionProfileAllows(policy, profileID: profileID, for: url, method: method) else {
                throw HTTPAdapterError.invalidParameter
            }
        case .captureCredential:
            throw HTTPAdapterError.unsupportedStrategy
        }
        if policy.source == .header {
            throw HTTPAdapterError.unsupportedStrategy
        }
        return policy
    }

    private static func isValidProjectionProfile(_ profile: HTTPResponseProjectionProfile) -> Bool {
        guard !profile.id.isEmpty,
              profile.id.utf8.count <= 128,
              Self.normalizedOrigin(profile.origin) != nil,
              !profile.allowedMethods.isEmpty,
              profile.allowedMethods.count <= HTTPMethod.allCases.count,
              Set(profile.allowedMethods.map(\.rawValue)).count == profile.allowedMethods.count,
              Self.canonicalEndpointPath(profile.path) == profile.path,
              !profile.allowedJSONPointers.isEmpty,
              profile.allowedJSONPointers.count <= 64 else {
            return false
        }
        let canonical = profile.allowedJSONPointers.compactMap(Self.canonicalJSONPointer)
        return canonical.count == profile.allowedJSONPointers.count
            && Set(canonical).count == canonical.count
            && canonical.allSatisfy { !Self.containsSensitiveJSONPointer($0) }
    }

    private func projectionProfileAllows(
        _ policy: HTTPResponsePolicy,
        profileID: String,
        for url: URL,
        method: HTTPMethod
    ) -> Bool {
        guard !invalidResponseProjectionProfileIDs.contains(profileID),
              let profile = responseProjectionProfiles[profileID],
              Self.isValidProjectionProfile(profile),
              let profileOrigin = Self.normalizedOrigin(profile.origin),
              profileOrigin == Self.normalizedOrigin(url),
              profile.allowedMethods.contains(method),
              !profile.allowedJSONPointers.isEmpty else {
            return false
        }
        // The wire request keeps percent-encoding, so endpoint binding must
        // compare the encoded path.  A decoded comparison would let a request
        // to `/a%2Fb` match a profile authored for the endpoint `/a/b`.
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        let rawRequestPath = components.percentEncodedPath
        guard let requestPath = Self.canonicalEndpointPath(rawRequestPath.isEmpty ? "/" : rawRequestPath),
              profile.path == requestPath else {
            return false
        }
        let allowed = Set(profile.allowedJSONPointers.compactMap(Self.canonicalJSONPointer))
        return policy.fields.allSatisfy { field in
            guard let canonical = Self.canonicalJSONPointer(field) else { return false }
            return !Self.containsSensitiveJSONPointer(canonical) && allowed.contains(canonical)
        }
    }

    private func applyBody(_ body: HTTPBody, to request: inout URLRequest) throws {
        switch body.kind {
        case .none:
            return
        case .raw:
            request.httpBody = Data((body.content ?? "").utf8)
        case .json:
            let data = Data((body.content ?? "").utf8)
            guard (try? JSONSerialization.jsonObject(with: data)) != nil else {
                throw SecretOperationExecutionError.invalidParameter
            }
            request.httpBody = data
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        case .form:
            var components = URLComponents()
            components.queryItems = body.fields
                .sorted { $0.key < $1.key }
                .map { URLQueryItem(name: $0.key, value: $0.value) }
            guard let encoded = components.percentEncodedQuery else {
                throw SecretOperationExecutionError.invalidParameter
            }
            request.httpBody = Data(encoded.utf8)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        }
    }

    private func applyAuthentication(
        _ auth: HTTPAuthStrategy,
        descriptor: SecretOperationDescriptor,
        to request: inout URLRequest,
        secretBuffers: inout [Data],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> Bool {
        switch auth.kind {
        case .none:
            return false
        case .basic:
            guard let passwordReference = auth.passwordReference else {
                throw SecretOperationExecutionError.missingSecretReference
            }
            let passwordData = try await resolve(passwordReference)
            guard let password = String(data: passwordData, encoding: .utf8),
                  !password.isEmpty,
                  Self.isSafeHeaderValue(password) else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            secretBuffers.append(passwordData)
            let username: String
            if let usernameReference = auth.usernameReference {
                let usernameData = try await resolve(usernameReference)
                secretBuffers.append(usernameData)
                guard let resolved = String(data: usernameData, encoding: .utf8),
                      Self.isSafeUsername(resolved) else {
                    throw SecretOperationExecutionError.invalidSecretUTF8
                }
                username = resolved
            } else if let plainUsername = auth.username, !plainUsername.isEmpty {
                username = plainUsername
            } else {
                throw SecretOperationExecutionError.invalidParameter
            }
            let credentialsData = Data("\(username):\(password)".utf8)
            let headerData = Data("Basic \(credentialsData.base64EncodedString())".utf8)
            secretBuffers.append(credentialsData)
            secretBuffers.append(headerData)
            request.setValue(String(data: headerData, encoding: .utf8), forHTTPHeaderField: "Authorization")
            return true
        case .bearer, .apiKeyHeader, .customHeader, .cookie:
            guard let reference = auth.valueReference else {
                throw SecretOperationExecutionError.missingSecretReference
            }
            let valueData = try await resolve(reference)
            secretBuffers.append(valueData)
            guard let value = String(data: valueData, encoding: .utf8),
                  !value.isEmpty,
                  Self.isSafeHeaderValue(value),
                  auth.kind != .cookie || Self.isSafeCookieValue(value) else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            let headerName: String
            let headerValue: String
            switch auth.kind {
            case .bearer:
                headerName = auth.headerName ?? "Authorization"
                headerValue = auth.scheme.map { "\($0) \(value)" } ?? value
            case .apiKeyHeader, .customHeader:
                headerName = auth.headerName!
                headerValue = auth.scheme.map { "\($0) \(value)" } ?? value
            case .cookie:
                headerName = "Cookie"
                headerValue = "\(auth.cookieName!)=\(value)"
            default:
                throw SecretOperationExecutionError.invalidParameter
            }
            let headerData = Data(headerValue.utf8)
            secretBuffers.append(headerData)
            request.setValue(headerValue, forHTTPHeaderField: headerName)
            return true
        case .oauth2ClientCredentials, .oauth2RefreshToken, .clientCertificate, .hmacSigning:
            throw SecretOperationExecutionError.unavailable
        }
    }

    private func responsePreview(
        _ policy: HTTPResponsePolicy,
        body: String,
        hasSecretAuth: Bool
    ) throws -> String? {
        // A credential-bearing response can contain cookies, access tokens, or
        // refresh tokens that are not among the request secrets. An explicit
        // sanitized preview is allowed only for JSON that passes the
        // sensitive-field quarantine below; profile projections remain the
        // stricter App-owned allowlist path.
        if hasSecretAuth,
           policy.kind != .sanitizedPreview,
           policy.kind != .projectedJSON,
           policy.kind != .structuredFields {
            return nil
        }
        switch policy.kind {
        case .metadataOnly:
            return nil
        case .sanitizedPreview:
            if hasSecretAuth {
                guard let data = body.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
                      !Self.containsSensitiveResponseData(json),
                      !body.contains("secret://") else {
                    throw SecretOperationExecutionError.outputQuarantined
                }
            }
            return utf8Prefix(body, maxBytes: policy.maxBytes)
        case .structuredFields, .projectedJSON:
            guard let data = body.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            var selected: [String: Any] = [:]
            let fields = policy.fields
                .compactMap(Self.canonicalJSONPointer)
                .sorted { lhs, rhs in
                    lhs.split(separator: "/").count < rhs.split(separator: "/").count
                }
            for field in fields {
                let components = Self.jsonPointerComponents(field)
                guard let value = Self.jsonValue(at: components, in: object) else { continue }
                guard !Self.containsSensitiveResponseData(value) else {
                    throw SecretOperationExecutionError.outputQuarantined
                }
                Self.insertProjection(value, at: components, into: &selected)
            }
            let selectedData = try JSONSerialization.data(withJSONObject: selected, options: [.sortedKeys])
            guard selectedData.count <= policy.maxBytes,
                  let result = String(data: selectedData, encoding: .utf8) else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            return result
        case .captureCredential:
            throw SecretOperationExecutionError.unavailable
        }
    }

    private func sanitizedResponseBody(
        _ data: Data,
        secrets: [Data],
        fingerprints: [SecretOutputFingerprint]
    ) throws -> String {
        let safeData = try sanitizedResponseData(data, secrets: secrets, fingerprints: fingerprints)
        guard let body = String(data: safeData, encoding: .utf8) else {
            throw SecretOperationExecutionError.outputQuarantined
        }
        return body
    }

    /// Response headers are remote-controlled strings just like the body.
    /// They must pass the same fingerprint guard before being exposed to MCP.
    private func sanitizedResponseText(
        _ value: String?,
        secrets: [Data],
        fingerprints: [SecretOutputFingerprint]
    ) throws -> String? {
        guard let value else { return nil }
        _ = try sanitizedResponseData(Data(value.utf8), secrets: secrets, fingerprints: fingerprints)
        return value
    }

    /// Server-controlled response data is checked twice: the retained digest
    /// guard covers an SSH-session-style opaque fingerprint, while the
    /// resolved secret guard can detect bounded percent-decoding variants.
    /// Raw matches are quarantined here instead of returning the sanitizer's
    /// redacted placeholder as an apparently valid server response.
    private func sanitizedResponseData(
        _ data: Data,
        secrets: [Data],
        fingerprints: [SecretOutputFingerprint]
    ) throws -> Data {
        let result = ProcessResult(exitCode: 0, stdout: data, stderr: Data())
        guard case .sanitized = outputSanitizer.sanitize(result, fingerprints: fingerprints) else {
            throw SecretOperationExecutionError.outputQuarantined
        }
        guard case let .sanitized(sanitized) = outputSanitizer.sanitize(result, secrets: secrets),
              sanitized.stdout == data else {
            throw SecretOperationExecutionError.outputQuarantined
        }
        return data
    }

    private static func normalizedOrigin(_ rawOrigin: String) -> String? {
        guard let url = URL(string: rawOrigin),
              let scheme = url.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              let host = url.host,
              !host.isEmpty,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil,
              url.path.isEmpty || url.path == "/" else {
            return nil
        }
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        return "\(scheme)://\(host.lowercased()):\(port)"
    }

    private static func normalizedOrigin(_ url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(),
              let host = url.host,
              !host.isEmpty else { return nil }
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        return "\(scheme)://\(host.lowercased()):\(port)"
    }

    private static func canonicalEndpointPath(_ rawPath: String) -> String? {
        guard !rawPath.isEmpty,
              rawPath.hasPrefix("/"),
              rawPath.utf8.count <= 2_048,
              !rawPath.contains("?"),
              !rawPath.contains("#"),
              !rawPath.contains("\\"),
              rawPath.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            return nil
        }
        let lowered = rawPath.lowercased()
        guard !lowered.contains("%2e"),
              !lowered.contains("%2f"),
              !lowered.contains("%5c") else {
            return nil
        }
        let segments = rawPath.split(separator: "/", omittingEmptySubsequences: false)
        guard !segments.contains(where: { $0 == "." || $0 == ".." }) else {
            return nil
        }
        return rawPath
    }

    private static func canonicalJSONPointer(_ field: String) -> String? {
        let value = field.hasPrefix("/") ? field : "/\(field)"
        guard value.utf8.count <= 128,
              value != "/",
              value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }),
              !value.contains("\\") else {
            return nil
        }
        let components = jsonPointerComponents(value)
        guard !components.isEmpty,
              components.count <= 16,
              components.allSatisfy({ !$0.isEmpty && !$0.allSatisfy(\.isNumber) }) else {
            return nil
        }
        return "/" + components.map {
            $0.replacingOccurrences(of: "~", with: "~0")
                .replacingOccurrences(of: "/", with: "~1")
        }.joined(separator: "/")
    }

    private static func containsSensitiveJSONPointer(_ pointer: String) -> Bool {
        jsonPointerComponents(pointer).contains(where: isSensitiveResponseKey)
    }

    private static func jsonPointerComponents(_ pointer: String) -> [String] {
        guard pointer.first == "/" else { return [] }
        return pointer.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map {
            $0.replacingOccurrences(of: "~1", with: "/")
                .replacingOccurrences(of: "~0", with: "~")
        }
    }

    private static func jsonValue(at components: [String], in object: [String: Any]) -> Any? {
        var current: Any = object
        for component in components {
            guard let dictionary = current as? [String: Any],
                  let next = dictionary[component] else {
                return nil
            }
            current = next
        }
        return current
    }

    private static func insertProjection(
        _ value: Any,
        at components: [String],
        into result: inout [String: Any]
    ) {
        guard let first = components.first else { return }
        if components.count == 1 {
            result[first] = value
            return
        }
        var child = result[first] as? [String: Any] ?? [:]
        insertProjection(value, at: Array(components.dropFirst()), into: &child)
        result[first] = child
    }

    private static func containsSensitiveResponseData(_ value: Any) -> Bool {
        if let dictionary = value as? [String: Any] {
            for (key, child) in dictionary {
                if isSensitiveResponseKey(key) || containsSensitiveResponseData(child) {
                    return true
                }
            }
            return false
        }
        if let array = value as? [Any] {
            return array.contains(where: containsSensitiveResponseData)
        }
        if let string = value as? String {
            return string.contains("secret://")
        }
        return false
    }

    private static func isSensitiveResponseKey(_ key: String) -> Bool {
        let normalized = String(key
            .lowercased()
            .map { $0.isLetter || $0.isNumber ? $0 : Character("_") })
            .split(separator: "_", omittingEmptySubsequences: true)
            .joined(separator: "_")
        let sensitive = [
            "token", "password", "passwd", "pwd", "secret", "api_key", "apikey", "cookie",
            "set_cookie", "session", "session_id", "sessionid", "sid", "authorization", "auth",
            "credential", "private_key", "privatekey", "client_secret", "jwt", "bearer"
        ]
        return sensitive.contains(normalized)
            || normalized.contains("token")
            || normalized.contains("secret")
            || normalized.contains("password")
            || normalized.contains("cookie")
            || normalized.contains("session")
            || normalized.contains("credential")
            || normalized.contains("authorization")
    }

    private func reference(for parameter: String, in descriptor: SecretOperationDescriptor) -> SecretReference? {
        guard let rawReference = descriptor.parameters[parameter] else { return nil }
        return descriptor.secretReferences.first { $0.description == rawReference }
    }

    private func referencesMatch(_ lhs: [SecretReference], _ rhs: [SecretReference]) -> Bool {
        lhs.count == rhs.count
            && Set(lhs).count == lhs.count
            && Set(rhs).count == rhs.count
            && Set(lhs) == Set(rhs)
    }

    private func utf8Prefix(_ value: String, maxBytes: Int) -> String {
        guard maxBytes > 0 else { return "" }
        let data = Data(value.utf8)
        guard data.count > maxBytes else { return value }
        var length = maxBytes
        while length > 0 {
            if let prefix = String(data: data.prefix(length), encoding: .utf8) {
                return prefix
            }
            length -= 1
        }
        return ""
    }

    private func mapSessionError(_ error: HTTPSessionManagerError) -> SecretOperationExecutionError {
        switch error {
        case .sessionNotFound: return .sessionNotFound
        case .sessionExpired: return .sessionExpired
        case .scopeMismatch: return .sessionScopeMismatch
        case .sessionLimitReached: return .sessionLimitReached
        case .redirectRequiresReview: return .redirectRequiresReview
        case .responseTooLarge: return .outputLimitExceeded
        }
    }


    private static func isSafeHeaderName(
        _ name: String,
        allowingAuthorization: Bool = false
    ) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 128 else { return false }
        let forbidden = [
            "host", "content-length", "connection", "transfer-encoding",
            "authorization", "cookie", "set-cookie", "proxy-authorization",
            "proxy-authenticate", "forwarded", "via", "keep-alive", "te",
            "trailer", "upgrade", "x-forwarded-for",
            "x-forwarded-host", "x-forwarded-proto"
        ]
        let normalized = name.lowercased()
        if normalized == "authorization" {
            guard allowingAuthorization else { return false }
        } else if forbidden.contains(normalized)
                    || normalized.hasPrefix("proxy-")
                    || normalized.hasPrefix("x-forwarded-") {
            return false
        }
        return name.utf8.allSatisfy { byte in
            (byte >= 0x21 && byte <= 0x39 && byte != 0x22 && byte != 0x28 && byte != 0x29
                && byte != 0x2C && byte != 0x2F && byte != 0x3A && byte != 0x3B && byte != 0x3C
                && byte != 0x3D && byte != 0x3E && byte != 0x3F && byte != 0x40)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x5E && byte <= 0x7E)
        }
    }

    private static func isSafeCookieName(_ name: String) -> Bool {
        isSafeHeaderName(name) && name.lowercased() != "cookie"
    }

    private static func isSafeCookieValue(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            byte >= 0x21 && byte <= 0x7E && byte != 0x2C && byte != 0x3B
        }
    }

    /// HTTP token grammar (RFC 9110) plus a technical exclusion for fields
    /// that would corrupt HTTP framing. There is deliberately no vendor or
    /// API-name allowlist: which headers a target API accepts is the device
    /// owner's decision at approval time, not SVLT's.
    private static func isAllowedSecretHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 256 else { return false }
        let framingReserved: Set<String> = [
            "host", "content-length", "transfer-encoding", "connection", "expect"
        ]
        guard !framingReserved.contains(name.lowercased()) else { return false }
        // RFC 9110 token characters: tchar = "!" / "#" / "$" / "%" / "&" /
        // "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        let excluded: Set<UInt8> = [0x28, 0x29, 0x3C, 0x3E, 0x40, 0x2C, 0x3B, 0x3A,
                                    0x5C, 0x22, 0x2F, 0x5B, 0x5D, 0x3F, 0x3D, 0x7B, 0x7D]
        return name.utf8.allSatisfy { byte in
            byte > 0x20 && byte < 0x7F && !excluded.contains(byte)
        }
    }

    private static func isSafeAuthScheme(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        return value.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2D || byte == 0x2E || byte == 0x5F || byte == 0x7E
        }
    }

    private static func isSafeUsername(_ value: String) -> Bool {
        value.utf8.count <= 256 && isSafeHeaderValue(value)
    }

    private static func isSafeHeaderValue(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 16_384
            && !value.unicodeScalars.contains { $0.value == 0 || $0.value == 0x0A || $0.value == 0x0D }
    }

    private static func isSafeJSONField(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F && scalar.value != 0x22
        }
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
