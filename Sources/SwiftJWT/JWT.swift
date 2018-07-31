/**
 * Copyright IBM Corporation 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Cryptor
import Foundation

// MARK JWT

/**
 
 JSON Web Token with its header and claims.
 
 ### Usage Example: ###
 ````swift
 let jwt = JWT(header: Header([.typ:"JWT"]), claims: Claims([.name:"Kitura"]))
 let signedJWT = jwt.sign(using: .rs256(key, .privateKey))
 ````
 */

public struct JWT {
    
    /// The JWT header.
    public var header: Header
    
    /// The JWT claims
    public var claims: Claims
    
    /// Initialize a `JWT` instance.
    ///
    /// - Parameter header: A JSON Web Token header object.
    /// - Parameter claims: A JSON Web Token claims object.
    /// - Returns: A new instance of `JWT`.
    public init(header: Header, claims: Claims) {
        self.header = header
        self.claims = claims
    }
    
    init(header: [String:Any], claims: [String:Any]) {
        self.header = Header(header)
        self.claims = Claims(claims)
    }
    
    /// Sign the JWT using the given algorithm. 
    ///
    /// - Note: Sets header.alg with the name of the signing algorithm.
    ///
    /// - Parameter using algorithm: The algorithm to sign with.
    /// - Returns: A String with the encoded and signed JWT.
    /// - Throws: An error thrown during the encoding or signing.
    public mutating func sign(using algorithm: Algorithm) throws -> String? {
        header[.alg] = algorithm.name
        guard let encodedJwt = try encodeHeaderAndClaims() else {
            return nil
        }
        guard let signature = algorithm.sign(encodedJwt),
            let encodedSignature = Base64URL.encode(signature) else {
                return nil
        }
        return encodedJwt + "." + encodedSignature
    }
    
    /// Encode the JWT.
    ///
    /// - Note: Sets header.alg with 'none'.
    ///
    /// - Returns: A String with the encoded.
    /// - Throws: An error thrown during the encoding.
    public mutating func encode() throws -> String? {
        header[.alg] = "none"
        return try encodeHeaderAndClaims()
    }

    private func encodeHeaderAndClaims() throws -> String? {
        guard let encodedHeader = try header.encode(),
            let encodedClaims = try claims.encode() else {
                return nil
        }
        let encodedInput = encodedHeader + "." + encodedClaims
        return encodedInput
    }

    /// Verify the signature of the encoded JWT using the given algorithm.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter using algorithm: The algorithm to verify with.
    /// - Returns: A Bool indicating whether the verification was successful.
    /// - Throws: An error thrown during the verification.
    public static func verify(_ jwt: String, using algorithm: Algorithm) throws -> Bool {
        let components = jwt.components(separatedBy: ".")
        guard components.count == 3,
            let signature = Base64URL.decode(components[2]) else {
                return false
        }
        return algorithm.verify(signature: signature, for: components[0] + "." + components[1])
    }
    
    /// Decode the encoded JWT.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Returns: An instance of `JWT` if the decoding succeeds.
    /// - Throws: An error thrown during the decoding.
    public static func decode(_ jwt: String) throws -> JWT? {
        let components = jwt.components(separatedBy: ".")
        guard components.count == 2 || components.count == 3,
            let headerData = Base64URL.decode(components[0]),
            let claimsData = Base64URL.decode(components[1]),
            let header = (try JSONSerialization.jsonObject(with: headerData)) as? [String:Any],
            let claims = (try JSONSerialization.jsonObject(with: claimsData)) as? [String:Any] else {
                return nil
        }
        return JWT(header: header, claims: claims)
    }
    
    public static func checkValidMicroProfile(_ jwt: JWT) throws -> Bool {
        return true
    }

    /// Validate the JWT claims. Various claims are validated if they are present in the `Claims` object.
    /// Various validations require an input. In these cases, if the claim in question exists and the input
    /// is provided the validation will be performed. Otherwise, the validation is skipped.
    ///
    /// The following claims are validated: iss, aud, azp, at_hash, exp, nbf, iat.
    ///
    /// - Parameter issuer: An optional String to compare with the iss claim.
    /// - Parameter audience: An optional String to compare with the aud claim.
    /// - Returns: A value of `ValidateClaimsResult`.
    public func validateClaims(issuer: String?=nil, audience: String?=nil) -> ValidateClaimsResult {
        
        if let issuer = issuer,
            let jwtIssuer = claims[.iss] as? String,
            jwtIssuer != issuer {
            return .mismatchedIssuer
        }
        
        if let audience = audience,
            let jwtAudience = claims[.aud] {
            switch jwtAudience {
            case let value as [String]:
                if value.count == 0 {
                    return .emptyAudience
                }
                if value.count > 1 {
                    return .multipleAudiences
                }
                if value[0] != audience {
                    return .mismatchedAudience
                }
            case let value as String:
                if value != audience {
                    return .mismatchedAudience
                }
            default:
                return .invalidAudience
            }
        }
        
        if let _ = claims[.exp] {
            if let expirationDate = getDateFromClaim(.exp) {
                if expirationDate < Date() {
                    return .expired
                }
            }
            else {
                return .invalidExpiration
            }
        }
        
        if let _ = claims[.nbf] {
            if let notBeforeDate = getDateFromClaim(.nbf) {
                if notBeforeDate > Date() {
                    return .notBefore
                }
            }
            else {
                return .invalidNotBefore
            }
        }
        
        if let _ = claims[.iat] {
            if let issuedAtDate = getDateFromClaim(.iat) {
                if issuedAtDate > Date() {
                    return .issuedAt
                }
            }
            else {
                return .invalidIssuedAt
            }
        }
        
        return .success
    }
    
    private func getDateFromClaim(_ claim: ClaimKeys) -> Date? {
        if let jwtDate = claims[claim] {
            var date: Date?
            switch jwtDate {
            case let value as TimeInterval:
                date = Date(timeIntervalSince1970: value)
            case let value as Int:
                date = Date(timeIntervalSince1970: Double(value))
            case let value as String:
                guard let doubleValue = Double(value) else {
                    return nil
                }
                date = Date(timeIntervalSince1970: doubleValue)
            default:
                return nil
            }
            return date
        }
        return nil
    }
}

