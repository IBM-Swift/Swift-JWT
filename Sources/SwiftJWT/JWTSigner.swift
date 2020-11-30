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

// MARK: JWTSigner

/**
 A struct that will be used to sign the JWT `Header` and `Claims` and generate a signed JWT.
 For RSA and ECDSA, the provided key should be a .utf8 encoded PEM String.
 ### Usage Example: ###
 ```swift
 let pemString = """
 -----BEGIN RSA PRIVATE KEY-----
 MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
 33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
 +jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
 AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
 3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
 uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
 2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
 GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
 Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
 6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
 fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
 Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
 FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
 -----END RSA PRIVATE KEY-----
 """
 let privateKey = pemString.data(using: .utf8)!
 let jwtSigner = JWTSigner.rs256(privateKey: privateKey)
 struct MyClaims: Claims {
    var name: String
 }
 let jwt = JWT(claims: MyClaims(name: "Kitura"))
 let signedJWT = try? jwt.sign(using: jwtSigner)
 ```
 */
public struct JWTSigner {
    
    /// The name of the algorithm that will be set in the "alg" header
    let name: String
    
    let signerAlgorithm: SignerAlgorithm

    init(name: String, signerAlgorithm: SignerAlgorithm) {
        self.name = name
        self.signerAlgorithm = signerAlgorithm
    }
    
    func sign(header: String, claims: String) throws -> String {
        return try signerAlgorithm.sign(header: header, claims: claims)
    }
    
    /// Initialize a JWTSigner using the RSA 256 bits algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func rs256(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "RS256", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha256))
    }
    
    /// Initialize a JWTSigner using the RSA 384 bits algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func rs384(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "RS384", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha384))
    }
    
    /// Initialize a JWTSigner using the RSA 512 bits algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func rs512(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "RS512", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha512))
    }
    
    /// Initialize a JWTSigner using the RSA-PSS 256 bits algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func ps256(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "PS256", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha256, usePSS: true))
    }
    
    /// Initialize a JWTSigner using the RSA-PSS 384 bits algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func ps384(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "PS384", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha384, usePSS: true))
    }
    
    /// Initialize a JWTSigner using the RSA-PSS 512 bits algorithm and the provided privateKey.
    /// This signer requires at least a 2048 bit RSA key.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with a "BEGIN RSA PRIVATE KEY" header.
    public static func ps512(privateKey: Data) -> JWTSigner {
        return JWTSigner(name: "PS512", signerAlgorithm: BlueRSA(key: privateKey, keyType: .privateKey, algorithm: .sha512, usePSS: true))
    }
    
    /// Initialize a JWTSigner using the HMAC 256 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs256(key: Data) -> JWTSigner {
        return JWTSigner(name: "HS256", signerAlgorithm: BlueHMAC(key: key, algorithm: .sha256))
    }
    
    /// Initialize a JWTSigner using the HMAC 384 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs384(key: Data) -> JWTSigner {
        return JWTSigner(name: "HS384", signerAlgorithm: BlueHMAC(key: key, algorithm: .sha384))
    }
    
    /// Initialize a JWTSigner using the HMAC 512 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs512(key: Data) -> JWTSigner {
        return JWTSigner(name: "HS512", signerAlgorithm: BlueHMAC(key: key, algorithm: .sha512))
    }
    
    /// Initialize a JWTSigner using the ECDSA SHA256 algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with either a "BEGIN EC PRIVATE KEY" or "BEGIN PRIVATE KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es256(privateKey: Data, signatureType: ECSignatureType = .rs) -> JWTSigner {
        return JWTSigner(name: "ES256", signerAlgorithm: BlueECSigner(key: privateKey, curve: .prime256v1, signatureType: signatureType))
    }
    
    /// Initialize a JWTSigner using the ECDSA SHA384 algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with either a "BEGIN EC PRIVATE KEY" or "BEGIN PRIVATE KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es384(privateKey: Data, signatureType: ECSignatureType = .rs) -> JWTSigner {
        return JWTSigner(name: "ES384", signerAlgorithm: BlueECSigner(key: privateKey, curve: .secp384r1, signatureType: signatureType))
    }
    
    /// Initialize a JWTSigner using the ECDSA SHA512 algorithm and the provided privateKey.
    /// - Parameter privateKey: The UTF8 encoded PEM private key, with either a "BEGIN EC PRIVATE KEY" or "BEGIN PRIVATE KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es512(privateKey: Data, signatureType: ECSignatureType = .rs) -> JWTSigner {
        return JWTSigner(name: "ES512", signerAlgorithm: BlueECSigner(key: privateKey, curve: .secp521r1, signatureType: signatureType))
    }
    
    /// Initialize a JWTSigner that will not sign the JWT. This is equivelent to using the "none" alg header.
    public static let none = JWTSigner(name: "none", signerAlgorithm: NoneAlgorithm())
}

