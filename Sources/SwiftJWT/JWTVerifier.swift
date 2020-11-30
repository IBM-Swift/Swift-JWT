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

// MARK: JWTVerifier

/**
 
 A struct that will be used to verify the signature of a JWT is valid for the provided `Header` and `Claims`.
 For RSA and ECDSA, the provided key should be a .utf8 encoded PEM String.
 ### Usage Example: ###
 ```swift
 let pemString = """
 -----BEGIN PUBLIC KEY-----
 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
 UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
 HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
 o2kQ+X5xK9cipRgEKwIDAQAB
 -----END PUBLIC KEY-----
 """
 let signedJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS2l0dXJhIn0.o2Rv_w1W6qfkldgb6FwzC3tAFEzo7WyYcLyykijCEqDbW8A7TwoFev85KGo_Bi7eNaSgZ6Q8jgkA31r8EDQWtSRg3_o5Zlq-ZCndyVeibgbyM2BMVUGcGzkUD2ikARfnb6GNGHr2waVeFSDehTN8WTLl0mGFxUE6wx5ZugR7My0"
 struct MyClaims: Claims {
    var name: String
 }
 let jwt = JWT(claims: MyClaims(name: "Kitura"))
 let publicKey = pemString.data(using: .utf8)!
 let jwtVerifier = JWTVerifier.rs256(publicKey: publicKey)
 let verified: Bool = jwt.verify(signedJWT, using: jwtVerifier)
 ```
 */
public struct JWTVerifier {    
    let verifierAlgorithm: VerifierAlgorithm
    
    init(verifierAlgorithm: VerifierAlgorithm) {
        self.verifierAlgorithm = verifierAlgorithm
    }
    
    func verify(jwt: String) -> Bool {
        return verifierAlgorithm.verify(jwt: jwt)
    }
    
    /// Initialize a JWTVerifier using the RSA 256 bits algorithm and the provided publicKey.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func rs256(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha256))
    }
    
    /// Initialize a JWTVerifier using the RSA 384 bits algorithm and the provided publicKey.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func rs384(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha384))
    }
    
    /// Initialize a JWTVerifier using the RSA 512 bits algorithm and the provided publicKey.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func rs512(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha512))
    }
    
    /// Initialize a JWTVerifier using the RSA 256 bits algorithm and the provided certificate.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN CERTIFICATE" header.
    public static func rs256(certificate: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha256))
    }
    
    /// Initialize a JWTVerifier using the RSA 384 bits algorithm and the provided certificate.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN CERTIFICATE" header.
    public static func rs384(certificate: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha384))
    }
    
    /// Initialize a JWTVerifier using the RSA 512 bits algorithm and the provided certificate.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN CERTIFICATE" header.
    public static func rs512(certificate: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha512))
    }
    
    /// Initialize a JWTVerifier using the RSA-PSS 256 bits algorithm and the provided publicKey.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func ps256(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha256, usePSS: true))
    }
    
    /// Initialize a JWTVerifier using the RSA-PSS 384 bits algorithm and the provided publicKey.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func ps384(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha384, usePSS: true))
    }
    
    /// Initialize a JWTVerifier using the RSA-PSS 512 bits algorithm and the provided publicKey.
    /// This verifier requires at least a 2048 bit RSA key.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    public static func ps512(publicKey: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha512, usePSS: true))
    }
    
    /// Initialize a JWTSigner using the HMAC 256 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs256(key: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueHMAC(key: key, algorithm: .sha256))
    }
    
    /// Initialize a JWTSigner using the HMAC 384 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs384(key: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueHMAC(key: key, algorithm: .sha384))
    }
    
    /// Initialize a JWTSigner using the HMAC 512 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs512(key: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueHMAC(key: key, algorithm: .sha512))
    }
    
    /// Initialize a JWTVerifier using the ECDSA SHA 256 algorithm and the provided public key.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es256(publicKey: Data, signatureType: ECSignatureType = .rs) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueECVerifier(key: publicKey, curve: .prime256v1, signatureType: signatureType))
    }
    
    /// Initialize a JWTVerifier using the ECDSA SHA 384 algorithm and the provided public key.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es384(publicKey: Data, signatureType: ECSignatureType = .rs) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueECVerifier(key: publicKey, curve: .secp384r1, signatureType: signatureType))
    }
    
    /// Initialize a JWTVerifier using the ECDSA SHA 512 algorithm and the provided public key.
    /// - Parameter publicKey: The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
    @available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
    public static func es512(publicKey: Data, signatureType: ECSignatureType = .rs) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueECVerifier(key: publicKey, curve: .secp521r1, signatureType: signatureType))
    }
    
    /// Initialize a JWTVerifier that will always return true when verifying the JWT. This is equivelent to using the "none" alg header.
    public static let none = JWTVerifier(verifierAlgorithm: NoneAlgorithm())
}
