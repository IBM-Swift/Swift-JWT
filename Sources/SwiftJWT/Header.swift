/**
 * Copyright IBM Corporation 2018
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

import Foundation

// MARK Header

/// A representation of a JSON Web Token header.
public struct Header: Codable {
    
    /// Type Header Parameter
    public var typ: String?
    /// Algorithm Header Parameter
    public internal(set) var alg: String?
    /// JSON Web Token Set URL Header Parameter
    public var jku : String?
    /// JSON Web Key Header Parameter
    public var jwk: String?
    /// Key ID Header Parameter
    public var kid: String?
    /// X.509 URL Header Parameter
    public var x5u: String?
    /// X.509 Certificate Chain Header Parameter
    public var x5c: [String]?
    /// X.509 Certificate SHA-1 Thumbprint Header Parameter
    public var x5t: String?
    /// X.509 Certificate SHA-256 Thumbprint Header Parameter
    public var x5tS256: String?
    /// Content Type Header Parameter
    public var cty: String?
    /// Critical Header Parameter
    public var crit: [String]?
    
    /// Initialize a `Header` instance.
    ///
    /// - Parameter typ: The Type Header Parameter
    /// - Parameter jku: The JSON Web Token Set URL Header Parameter
    /// - Parameter jwk: The JSON Web Key Header Parameter
    /// - Parameter kid: The Key ID Header Parameter
    /// - Parameter x5u: The X.509 URL Header Parameter
    /// - Parameter x5c: The X.509 Certificate SHA-1 Thumbprint Header Parameter
    /// - Parameter x5t: The X.509 Certificate Chain Header Parameter
    /// - Parameter x5tS256: X.509 Certificate SHA-256 Thumbprint Header Parameter
    /// - Parameter cty: The Content Type Header Parameter
    /// - Parameter crit: The Critical Header Parameter
    /// - Returns: A new instance of `Header`.
    public init(
        typ: String? = "JWT",
        jku: String? = nil,
        jwk: String? = nil,
        kid: String? = nil,
        x5u: String? = nil,
        x5c: [String]? = nil,
        x5t: String? = nil,
        x5tS256: String? = nil,
        cty: String? = nil,
        crit: [String]? = nil
    ) {
        self.typ = typ
        self.alg = nil
        self.jku = jku
        self.jwk = jwk
        self.kid = kid
        self.x5u = x5u
        self.x5c = x5c
        self.x5t = x5t
        self.x5tS256 = x5tS256
        self.cty = cty
        self.crit = crit
    }
    
    func encode() -> String? {
        guard let data = try? JSONEncoder().encode(self) else {
            return nil
        }
        return data.base64urlEncodedString()
    }
}
extension Header: Equatable {
    
    /// Function to check if two headers are equal. Required to conform to the equatable protocol.
    public static func == (lhs: Header, rhs: Header) -> Bool {
        return lhs.alg == rhs.alg &&
            lhs.crit == rhs.crit &&
            lhs.cty == rhs.cty &&
            lhs.jku == rhs.jku &&
            lhs.jwk == rhs.jwk &&
            lhs.kid == rhs.kid &&
            lhs.typ == rhs.typ &&
            lhs.x5c == rhs.x5c &&
            lhs.x5t == rhs.x5t &&
            lhs.x5tS256 == rhs.x5tS256 &&
            lhs.x5u == rhs.x5u
    }
}
