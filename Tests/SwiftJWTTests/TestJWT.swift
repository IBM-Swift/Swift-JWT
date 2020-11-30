/**
 Copyright IBM Corporation 2017
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import XCTest
import Foundation

@testable import SwiftJWT

let rsaPrivateKey = read(fileName: "rsa_private_key")
let rsaPublicKey = read(fileName: "rsa_public_key")
let rsaDERPrivateKey = read(fileName: "privateRSA.der")
let rsaDERPublicKey = read(fileName: "publicRSA.der")
let ecdsaPrivateKey = read(fileName: "ecdsa_private_key")
let ecdsaPublicKey = read(fileName: "ecdsa_public_key")
let ec384PrivateKey = read(fileName: "ec384_private_key")
let ec384PublicKey = read(fileName: "ec384_public_key")
let ec512PrivateKey = read(fileName: "ec512_private_key")
let ec512PublicKey = read(fileName: "ec512_public_key")
let rsaJWTEncoder = JWTEncoder(jwtSigner: .rs256(privateKey: rsaPrivateKey))
let rsaJWTDecoder = JWTDecoder(jwtVerifier: .rs256(publicKey: rsaPublicKey))
let certPrivateKey = read(fileName: "cert_private_key")
let certificate = read(fileName: "certificate")
let rsaEncodedTestClaimJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.pOeiYYHuxBu27llpKrLfHX-tt0Cr41m3hn7d1_CPl7dRMksQRJC5U7AM2CkF8uyObwAKg88orK6eHlOQ0x2C4gDoG7WmgszpthOB6ZUTUPj_FNsn3z4fM8sFx3wON7jtRRSuULH13f-RjLoIFhY_VuqVhla3ybjnfbwjcsd8EqDumdFN6La5D0KugCgvuH51JaEjdHfwXkxkRsynmhv3jCpvRbUbforfEnDjyAImez2hd0Pnb3Vtqr-21z1vFWqqRiz_K-qSiO5NTaO1VbLg7SOYBB9hMAD-_6R2ZZh0JvFP7hycCftRIxTSDd5r0I9sQh9iqurVq03_h0ZjS9BwJQ"
let rsaPSSEncodedTestClaimJWT = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.gytxKF6HsfRI-dmyS0KsVoGquSWHTbosqmgBM_8UnTBZd56ThVdxZSTZzkVE0kS6SZdN7iogLiPqWzvGac0orTkf3XMbxecpHiO8b_BywIqrXhXcz84NFxrq5s8KL_LB8Cs9ro_5xmptp_fNtCedg9leju7VUzrEZP0hyTG_dlar2t7SWY47JD3rlgdaXEfkGgSuDgOO2CzBzqlbP7DUxTQ6OwI8RMNWAxeCalvWTgNQkb1DAy_2JKaga4zDnieUHMd2c_8iSt6SS9dLkxl4nih_2IjHJc73Qcg4Epx5CrhJXWg5CmKoTFDVgpMBGXJRIxT5qpAAx4qvRzlNgJVM2A"
let certificateEncodedTestClaimJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwic3ViIjoiMTIzNDU2Nzg5MCJ9.CpnzQLuWGfH5Kba36vg0ZZKBnzwlrIgapFVfBfk_nea-eej84ktHZANqIeolskZopRJ4DQ3oaLtHWEg16-ZsujxmkOdiAIbk0-C4QLOVFLZH78WLZAqkyNLS8rFuK9hloLNwz1j6VVUd1f0SOT-wIRzL0_0VRYqQd1bVcCj7wc7BmXENlOfHY7KGHS-6JX-EClT1DygDSoCmdvBExBf3vx0lwMIbP4ryKkyhOoU13ZfSUt1gpP9nZAfzqfRTPxZc_f7neiAlMlF6SzsedsskRCNegW8cg5e_NuVmZZkj0_bnswXFDMmIaxiPdtOEWkmyEOca-EHSwbO5PgCgXOIrgg"
// A `TestClaims` encoded using HMAC with "Super Secret Key" from "www.jwt.io"
let hmacEncodedTestClaimJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwic3ViIjoiMTIzNDU2Nzg5MCJ9.8kIE0ZCq1Vw7aW1kACpgJLcgY2DpTXgO6P5T3cdCuTs"
// A `TestClaims` encoded using es256 with `ecdsaPrivateKey`
let ecdsaEncodedTestClaimJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.z1nUPt7mJk5EZBJKrRiCRLSum1B5E5ucaMeuMqxcvnw3a5FnKC-XsR6rvBVdUPRVzWF6L9CHQuSBlDy579SqQA"
let jwtSigners: [String: JWTSigner] = ["0": .rs256(privateKey: rsaPrivateKey), "1": .rs256(privateKey: certPrivateKey)]
let jwtVerifiers: [String: JWTVerifier] = ["0": .rs256(publicKey: rsaPublicKey), "1": .rs256(certificate: certificate)]
let rsaJWTKidEncoder = JWTEncoder(keyIDToSigner: { kid in return jwtSigners[kid]})
let rsaJWTKidDecoder = JWTDecoder(keyIDToVerifier: { kid in return jwtVerifiers[kid]})

struct TestClaims: Claims, Equatable {
    var name: String?
    var admin: Bool?
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    init(name: String? = nil) {
        self.name = name
    }

    static func == (lhs: TestClaims, rhs: TestClaims) -> Bool {
        return lhs.name == rhs.name &&
        lhs.admin == rhs.admin &&
        lhs.iss == rhs.iss &&
        lhs.sub == rhs.sub &&
        lhs.aud ?? [""] == rhs.aud ?? [""] &&
        lhs.exp == rhs.exp &&
        lhs.nbf == rhs.nbf &&
        lhs.iat == rhs.iat &&
        lhs.jti == rhs.jti
    }
}

extension Header: Equatable {

    /// Function to check if two headers are equal. Required to conform to the equatable protocol.
    public static func == (lhs: Header, rhs: Header) -> Bool {
        return lhs.alg == rhs.alg &&
            lhs.crit ?? [] == rhs.crit ?? [] &&
            lhs.cty == rhs.cty &&
            lhs.jku == rhs.jku &&
            lhs.jwk == rhs.jwk &&
            lhs.kid == rhs.kid &&
            lhs.typ == rhs.typ &&
            lhs.x5c ?? [] == rhs.x5c ?? [] &&
            lhs.x5t == rhs.x5t &&
            lhs.x5tS256 == rhs.x5tS256 &&
            lhs.x5u == rhs.x5u
    }
}

struct MicroProfile: Claims {
    var name: String?
    var groups: [String]?
    var upn: String?
    var admin: Bool?
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    init(name: String) {
        self.name = name
    }
}
@available(macOS 10.12, iOS 10.0, *)
class TestJWT: XCTestCase {
    
    static var allTests: [(String, (TestJWT) -> () throws -> Void)] {
        return [
            ("testSignAndVerify", testSignAndVerify),
            ("testSignAndVerifyRSA", testSignAndVerifyRSA),
            ("testSignAndVerifyRSAPSS", testSignAndVerifyRSAPSS),
            ("testSignAndVerifyCert", testSignAndVerifyCert),
            ("testSignAndVerifyHMAC", testSignAndVerifyHMAC),
            ("testSignAndVerifyECDSA", testSignAndVerifyECDSA),
            ("testSignAndVerifyRSA384", testSignAndVerifyRSA384),
            ("testSignAndVerifyRSAPSS384", testSignAndVerifyRSAPSS384),
            ("testSignAndVerifyCert384", testSignAndVerifyCert384),
            ("testSignAndVerifyHMAC384", testSignAndVerifyHMAC384),
            ("testSignAndVerifyECDSA384", testSignAndVerifyECDSA384),
            ("testSignAndVerifyRSA512", testSignAndVerifyRSA512),
            ("testSignAndVerifyRSAPSS512", testSignAndVerifyRSAPSS512),
            ("testSignAndVerifyCert512", testSignAndVerifyCert512),
            ("testSignAndVerifyHMAC512", testSignAndVerifyHMAC512),
            ("testSignAndVerifyECDSA512", testSignAndVerifyECDSA512),
            ("testJWTEncoder", testJWTEncoder),
            ("testJWTDecoder", testJWTDecoder),
            ("testJWTCoderCycle", testJWTCoderCycle),
            ("testJWTEncoderKeyID", testJWTEncoderKeyID),
            ("testJWTDecoderKeyID", testJWTDecoderKeyID),
            ("testJWTCoderCycleKeyID", testJWTCoderCycleKeyID),
            ("testJWT", testJWT),
            ("testJWTRSAPSS", testJWTRSAPSS),
            ("testJWTUsingHMAC", testJWTUsingHMAC),
            ("testJWTUsingECDSA", testJWTUsingECDSA),
            ("testMicroProfile", testMicroProfile),
            ("testValidateClaims", testValidateClaims),
            ("testValidateClaimsLeeway", testValidateClaimsLeeway),
            ("testErrorPattenMatching", testErrorPattenMatching),
        ]
    }

    func testSignAndVerify() {
        do {
            try signAndVerify(signer: .none, verifier: .none)
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyRSA() {
        do {
            try signAndVerify(signer: .rs256(privateKey: rsaPrivateKey), verifier: .rs256(publicKey: rsaPublicKey))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyRSADERKey() {
        do {
            try signAndVerify(signer: .rs256(privateKey: rsaDERPrivateKey), verifier: .rs256(publicKey: rsaDERPublicKey))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyRSAPSS() {
        if #available(OSX 10.13, *) {
            do {
                try signAndVerify(signer: .ps256(privateKey: rsaPrivateKey), verifier: .ps256(publicKey: rsaPublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyCert() {
        do {
            try signAndVerify(signer: .rs256(privateKey: certPrivateKey), verifier: .rs256(certificate: certificate))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyHMAC() {
        do {
            let hmacData = "Super Secret Key".data(using: .utf8)!
            try signAndVerify(signer: .hs256(key: hmacData), verifier: .hs256(key: hmacData))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyECDSA() {
        if #available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *) {
            do {
                try signAndVerify(signer: .es256(privateKey: ecdsaPrivateKey), verifier: .es256(publicKey: ecdsaPublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyRSA384() {
        do {
            try signAndVerify(signer: .rs384(privateKey: rsaPrivateKey), verifier: .rs384(publicKey: rsaPublicKey))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyRSAPSS384() {
        if #available(OSX 10.13, *) {
            do {
                try signAndVerify(signer: .ps384(privateKey: rsaPrivateKey), verifier: .ps384(publicKey: rsaPublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyCert384() {
        do {
            try signAndVerify(signer: .rs384(privateKey: certPrivateKey), verifier: .rs384(certificate: certificate))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyHMAC384() {
        do {
            let hmacData = "Super Secret Key".data(using: .utf8)!
            try signAndVerify(signer: .hs384(key: hmacData), verifier: .hs384(key: hmacData))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyECDSA384() {
        if #available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *) {
            do {
                try signAndVerify(signer: .es384(privateKey: ec384PrivateKey), verifier: .es384(publicKey: ec384PublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyRSA512() {
        do {
            try signAndVerify(signer: .rs512(privateKey: rsaPrivateKey), verifier: .rs512(publicKey: rsaPublicKey))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyRSAPSS512() {
        if #available(OSX 10.13, iOS 11, *) {
            do {
                try signAndVerify(signer: .ps512(privateKey: rsaPrivateKey), verifier: .ps512(publicKey: rsaPublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyCert512() {
        do {
            try signAndVerify(signer: .rs512(privateKey: certPrivateKey), verifier: .rs512(certificate: certificate))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyHMAC512() {
        do {
            let hmacData = "Super Secret Key".data(using: .utf8)!
            try signAndVerify(signer: .hs512(key: hmacData), verifier: .hs512(key: hmacData))
        } catch {
            XCTFail("testSignAndVerify failed: \(error)")
        }
    }
    
    func testSignAndVerifyECDSA512() {
        if #available(OSX 10.13, iOS 11, tvOS 11.0, *) {
            do {
                try signAndVerify(signer: .es512(privateKey: ec512PrivateKey), verifier: .es512(publicKey: ec512PublicKey))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func testSignAndVerifyECDSA512ASN1() {
        if #available(OSX 10.13, iOS 11, tvOS 11.0, *) {
            do {
                try signAndVerify(signer: .es512(privateKey: ec512PrivateKey, signatureType: .asn1), verifier: .es512(publicKey: ec512PublicKey, signatureType: .asn1))
            } catch {
                XCTFail("testSignAndVerify failed: \(error)")
            }
        }
    }
    
    func signAndVerify(signer: JWTSigner, verifier: JWTVerifier) throws {
        var jwt = JWT(claims: TestClaims(name:"Kitura"))
        jwt.claims.name = "Kitura-JWT"
        XCTAssertEqual(jwt.claims.name, "Kitura-JWT")
        jwt.claims.iss = "issuer"
        jwt.claims.aud = ["clientID"]
        jwt.claims.iat = Date(timeIntervalSince1970: 1485949565.58463)
        jwt.claims.exp = Date(timeIntervalSince1970: 2485949565.58463)
        jwt.claims.nbf = Date(timeIntervalSince1970: 1485949565.58463)
        let signed = try jwt.sign(using: signer)
        let ok = JWT<TestClaims>.verify(signed, using: verifier)
        XCTAssertTrue(ok, "Verification failed")
        let decoded = try JWT<TestClaims>(jwtString: signed)
        check(jwt: decoded, algorithm: signer.name)
        XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
    }

    func check(jwt: JWT<TestClaims>, algorithm: String) {

        XCTAssertEqual(jwt.header.alg, algorithm, "Wrong .alg in decoded")
        XCTAssertEqual(jwt.claims.exp, Date(timeIntervalSince1970: 2485949565.58463), "Wrong .exp in decoded")
        XCTAssertEqual(jwt.claims.iat, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .iat in decoded")
        XCTAssertEqual(jwt.claims.nbf, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .nbf in decoded")
    }
    
    func checkMicroProfile(jwt: JWT<MicroProfile>, algorithm: String) {
        
        XCTAssertEqual(jwt.header.alg, "RS256", "Wrong .alg in decoded. MicroProfile only supports RS256.")
        XCTAssertEqual(jwt.claims.iss, "https://server.example.com", "Wrong .iss in decoded")
        XCTAssertEqual(jwt.claims.exp, Date(timeIntervalSince1970: 2485949565.58463), "Wrong .exp in decoded")
        XCTAssertEqual(jwt.claims.iat, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .iat in decoded")
        XCTAssertEqual(jwt.claims.aud ?? [""], ["clientID"], "Wrong .aud in decoded")
        XCTAssertEqual(jwt.claims.groups ?? [""], ["red-group", "green-group", "admin-group", "admin"], "Wrong .groups in decoded")

    }


    func testMicroProfile() {
        var jwt = JWT(claims: MicroProfile(name: "MP-JWT"))
        jwt.header.kid = "abc-1234567890"
        jwt.header.typ = "JWT"
        XCTAssertEqual(jwt.claims.name, "MP-JWT")
        jwt.claims.iss = "https://server.example.com"
        jwt.claims.aud = ["clientID"]
        jwt.claims.iat = Date(timeIntervalSince1970: 1485949565.58463)
        jwt.claims.exp = Date(timeIntervalSince1970: 2485949565.58463)
        jwt.claims.upn = "jdoe@server.example.com"
        jwt.claims.groups = ["red-group", "green-group", "admin-group", "admin"]
            
        // public key (MP-JWT needs to be signed)
        if let signed = try? jwt.sign(using: .rs256(privateKey: rsaPrivateKey)) {
            let ok = JWT<MicroProfile>.verify(signed, using: .rs256(publicKey: rsaPublicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = try? JWT<MicroProfile>(jwtString: signed) {
                checkMicroProfile(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to sign")
        }
        
        // certificate
        if let signed = try? jwt.sign(using: .rs256(privateKey: certPrivateKey)) {
            let ok = JWT<MicroProfile>.verify(signed, using: .rs256(certificate: certificate))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = try? JWT<MicroProfile>(jwtString: signed) {
                checkMicroProfile(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
    }

    // This test uses the rsaJWTEncoder to encode a JWT<TestClaims> as a JWT String.
    // It then decodes the resulting JWT String using the JWT init from String.
    // The test checks that the decoded JWT is the same as the JWT you started as well as the decoded rsaEncodedTestClaimJWT.
    func testJWTEncoder() {
        var jwt = JWT(claims: TestClaims())
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        jwt.claims.iat = Date(timeIntervalSince1970: 1516239022)
        do {
            let jwtString = try rsaJWTEncoder.encodeToString(jwt)
            let decodedJWTString = try JWT<TestClaims>(jwtString: jwtString)
            let decodedTestClaimJWT = try JWT<TestClaims>(jwtString: rsaEncodedTestClaimJWT)
            // Setting the alg field on the header since the decoded JWT will have had the alg header set in the signing process.
            jwt.header.alg = "RS256"
            XCTAssertEqual(jwt.claims, decodedJWTString.claims)
            XCTAssertEqual(jwt.header, decodedJWTString.header)
            XCTAssertEqual(jwt.claims, decodedTestClaimJWT.claims)
            XCTAssertEqual(jwt.header, decodedTestClaimJWT.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }

    // This test uses the rsaJWTDecoder to decode the rsaEncodedTestClaimJWT as a JWT<TestClaims>.
    // The test checks that the decoded JWT is the same as the JWT that was originally encoded.
    func testJWTDecoder() {
        var jwt = JWT(claims: TestClaims())
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        jwt.claims.iat = Date(timeIntervalSince1970: 1516239022)
        do {
            let decodedJWT = try rsaJWTDecoder.decode(JWT<TestClaims>.self, fromString: rsaEncodedTestClaimJWT)
            jwt.header.alg = "RS256"
            XCTAssertEqual(decodedJWT.claims, jwt.claims)
            XCTAssertEqual(decodedJWT.header, jwt.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }

    // This test encoded and then decoded a JWT<TestClaims> and checks you get the original JWT back with only the alg header changed.
    func testJWTCoderCycle() {
        var jwt = JWT(claims: TestClaims())
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        do {
            let jwtData = try rsaJWTEncoder.encode(jwt)
            let decodedJWT = try rsaJWTDecoder.decode(JWT<TestClaims>.self, from: jwtData)
            jwt.header.alg = "RS256"
            XCTAssertEqual(decodedJWT.claims, jwt.claims)
            XCTAssertEqual(decodedJWT.header, jwt.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }

    // This test uses the rsaJWTKidEncoder to encode a JWT<TestClaims> as a JWT String using the kid header to select the JWTSigner.
    // It then decodes the resulting JWT String using the JWT init from String.
    // The test checks that the decoded JWT is the same as the JWT you started as well as the decoded certificateEncodedTestClaimJWT.
    func testJWTEncoderKeyID() {
        var jwt = JWT(claims: TestClaims())
        jwt.header.kid = "0"
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        do {
            let jwtString = try rsaJWTKidEncoder.encodeToString(jwt)
            let decodedJWTString = try JWT<TestClaims>(jwtString: jwtString)
            jwt.header.alg = "RS256"
            XCTAssertEqual(jwt.claims, decodedJWTString.claims)
            XCTAssertEqual(jwt.header, decodedJWTString.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }

    // This test uses the rsaJWTKidDecoder to decode the certificateEncodedTestClaimJWT as a JWT<TestClaims> using the kid header to select the JWTVerifier.
    // The test checks that the decoded JWT is the same as the JWT that was originally encoded.
    func testJWTDecoderKeyID() {
        var jwt = JWT(claims: TestClaims())
        jwt.header.kid = "1"
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        do {
            let decodedJWT = try rsaJWTKidDecoder.decode(JWT<TestClaims>.self, fromString: certificateEncodedTestClaimJWT)
            jwt.header.alg = "RS256"
            XCTAssertEqual(decodedJWT.claims, jwt.claims)
            XCTAssertEqual(decodedJWT.header, jwt.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }
    
    // This test encoded and then decoded a JWT<TestClaims> and checks you get the original JWT back with only the alg header changed.
    // The kid header is used to select the rsa private and public keys for encoding/decoding.
    func testJWTCoderCycleKeyID() {
        var jwt = JWT(claims: TestClaims())
        jwt.header.kid = "1"
        jwt.claims.sub = "1234567890"
        jwt.claims.name = "John Doe"
        jwt.claims.admin = true
        do {
            let jwtData = try rsaJWTKidEncoder.encode(jwt)
            let decodedJWT = try rsaJWTKidDecoder.decode(JWT<TestClaims>.self, from: jwtData)
            jwt.header.alg = "RS256"
            XCTAssertEqual(decodedJWT.claims, jwt.claims)
            XCTAssertEqual(decodedJWT.header, jwt.header)
        } catch {
            XCTFail("Failed to encode JTW: \(error)")
        }
    }

    // From jwt.io
    func testJWT() {
        let ok = JWT<TestClaims>.verify(rsaEncodedTestClaimJWT, using: .rs256(publicKey: rsaPublicKey))
        XCTAssertTrue(ok, "Verification failed")
        
        if let decoded = try? JWT<TestClaims>(jwtString: rsaEncodedTestClaimJWT) {
            XCTAssertEqual(decoded.header.alg, "RS256", "Wrong .alg in decoded")
            XCTAssertEqual(decoded.header.typ, "JWT", "Wrong .typ in decoded")
            
            XCTAssertEqual(decoded.claims.sub, "1234567890", "Wrong .sub in decoded")
            XCTAssertEqual(decoded.claims.name, "John Doe", "Wrong .name in decoded")
            XCTAssertEqual(decoded.claims.admin, true, "Wrong .admin in decoded")
            XCTAssertEqual(decoded.claims.iat, Date(timeIntervalSince1970: 1516239022), "Wrong .iat in decoded")
            
            
            XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
        }
        else {
            XCTFail("Failed to decode")
        }
    }
    
    // From jwt.io
    func testJWTRSAPSS() {
        if #available(OSX 10.13, *) {
            let ok = JWT<TestClaims>.verify(rsaPSSEncodedTestClaimJWT, using: .ps256(publicKey: rsaPublicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = try? JWT<TestClaims>(jwtString: rsaPSSEncodedTestClaimJWT) {
                XCTAssertEqual(decoded.header.alg, "PS256", "Wrong .alg in decoded")
                XCTAssertEqual(decoded.header.typ, "JWT", "Wrong .typ in decoded")
                
                XCTAssertEqual(decoded.claims.sub, "1234567890", "Wrong .sub in decoded")
                XCTAssertEqual(decoded.claims.name, "John Doe", "Wrong .name in decoded")
                XCTAssertEqual(decoded.claims.admin, true, "Wrong .admin in decoded")
                XCTAssertEqual(decoded.claims.iat, Date(timeIntervalSince1970: 1516239022), "Wrong .iat in decoded")
                
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
    }
    
    func testJWTUsingHMAC() {
        guard let hmacData = "Super Secret Key".data(using: .utf8) else {
            return XCTFail("Failed to convert hmacKey to Data")
        }
        let ok = JWT<TestClaims>.verify(hmacEncodedTestClaimJWT, using: .hs256(key: hmacData))
        XCTAssertTrue(ok, "Verification failed")
        
        if let decoded = try? JWT<TestClaims>(jwtString: hmacEncodedTestClaimJWT) {
            XCTAssertEqual(decoded.header.alg, "HS256", "Wrong .alg in decoded")
            XCTAssertEqual(decoded.header.typ, "JWT", "Wrong .typ in decoded")
            
            XCTAssertEqual(decoded.claims.sub, "1234567890", "Wrong .sub in decoded")
            XCTAssertEqual(decoded.claims.name, "John Doe", "Wrong .name in decoded")
            XCTAssertEqual(decoded.claims.admin, true, "Wrong .admin in decoded")
            
            XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
        }
        else {
            XCTFail("Failed to decode")
        }
    }
    
    // Test using a JWT generated from jwt.io using es256 with `ecdsaPrivateKey` for interoperability.
    func testJWTUsingECDSA() {
        if #available(OSX 10.13, iOS 11, tvOS 11.0, *) {
            let ok = JWT<TestClaims>.verify(ecdsaEncodedTestClaimJWT, using: .es256(publicKey: ecdsaPublicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = try? JWT<TestClaims>(jwtString: ecdsaEncodedTestClaimJWT) {
                XCTAssertEqual(decoded.header.alg, "ES256", "Wrong .alg in decoded")
                XCTAssertEqual(decoded.header.typ, "JWT", "Wrong .typ in decoded")
                
                XCTAssertEqual(decoded.claims.sub, "1234567890", "Wrong .sub in decoded")
                XCTAssertEqual(decoded.claims.name, "John Doe", "Wrong .name in decoded")
                XCTAssertEqual(decoded.claims.admin, true, "Wrong .admin in decoded")
                XCTAssertEqual(decoded.claims.iat, Date(timeIntervalSince1970: 1516239022), "Wrong .iat in decoded")
                
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
    }
    
    func testValidateClaims() {
        var jwt = JWT(claims: TestClaims(name:"Kitura"))
        jwt.claims.exp = Date()
        XCTAssertEqual(jwt.validateClaims(), .expired, "Validation failed")
        jwt.claims.exp = nil
        jwt.claims.iat = Date(timeIntervalSinceNow: 10)
        XCTAssertEqual(jwt.validateClaims(), .issuedAt, "Validation failed")
        jwt.claims.iat = nil
        jwt.claims.nbf = Date(timeIntervalSinceNow: 10)
        XCTAssertEqual(jwt.validateClaims(), .notBefore, "Validation failed")
    }
    
    func testValidateClaimsLeeway() {
        var jwt = JWT(claims: TestClaims(name:"Kitura"))
        jwt.claims.exp = Date()
        XCTAssertEqual(jwt.validateClaims(leeway: 20), .success, "Validation failed")
        jwt.claims.exp = nil
        jwt.claims.iat = Date(timeIntervalSinceNow: 10)
        XCTAssertEqual(jwt.validateClaims(leeway: 20), .success, "Validation failed")
        jwt.claims.iat = nil
        jwt.claims.nbf = Date(timeIntervalSinceNow: 10)
        XCTAssertEqual(jwt.validateClaims(leeway: 20), .success, "Validation failed")
    }
    
    func testErrorPattenMatching() {
        do {
            let _ = try JWT<TestClaims>(jwtString: "InvalidString",  verifier: .rs256(publicKey: rsaPublicKey))
        } catch JWTError.invalidJWTString {
            // Caught correct error
        } catch {
            XCTFail("Incorrect error thrown: \(error)")
        }
    }
}

func read(fileName: String) -> Data {
    do {
        var pathToTests = #file
        if pathToTests.hasSuffix("TestJWT.swift") {
            pathToTests = pathToTests.replacingOccurrences(of: "TestJWT.swift", with: "")
        }
        let fileData = try Data(contentsOf: URL(fileURLWithPath: "\(pathToTests)\(fileName)"))
        XCTAssertNotNil(fileData, "Failed to read in the \(fileName) file")
        return fileData
    } catch {
        XCTFail("Error in \(fileName).")
        exit(1)
    }
}
