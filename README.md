<p align="center">
<a href="http://kitura.io/">
<img src="https://raw.githubusercontent.com/Kitura/Kitura/master/Sources/Kitura/resources/kitura-bird.svg?sanitize=true" height="100" alt="Kitura">
</a>
</p>


<p align="center">
<a href="https://kitura.github.io/Swift-JWT/index.html">
<img src="https://img.shields.io/badge/apidoc-SwiftJWT-1FBCE4.svg?style=flat" alt="APIDoc">
</a>
<a href="https://travis-ci.org/Kitura/Swift-JWT">
<img src="https://travis-ci.org/Kitura/Swift-JWT.svg?branch=master" alt="Build Status - Master">
</a>
<img src="https://img.shields.io/badge/os-macOS-green.svg?style=flat" alt="macOS">
<img src="https://img.shields.io/badge/os-linux-green.svg?style=flat" alt="Linux">
<img src="https://img.shields.io/badge/license-Apache2-blue.svg?style=flat" alt="Apache 2">
<a href="http://swift-at-ibm-slack.mybluemix.net/">
<img src="http://swift-at-ibm-slack.mybluemix.net/badge.svg" alt="Slack Status">
</a>
</p>


# SwiftJWT
An implementation of [JSON Web Token](https://tools.ietf.org/html/rfc7519) using Swift. JWTs offer a lightweight and compact format for transmitting information between parties, and the information can be verified and trusted due to JWTs being digitally signed.

For more information on JSON Web Tokens, their use cases and how they work, we recommend visiting [jwt.io](https://jwt.io/introduction/).

**Reminder:** JWTs sent as JWS do **not** encrypt data, so never send anything sensitive or confidential in a JWT. This library does not currently support JWE.

## Swift version
The latest version of Swift-JWT requires **Swift 4.0** or later. You can download this version of the Swift binaries by following this [link](https://swift.org/download/). Compatibility with other Swift versions is not guaranteed.

## Usage

### Swift Package Manager

#### Add dependencies
Add the `Swift-JWT` package to the dependencies within your application’s `Package.swift` file. Substitute `"x.x.x"` with the latest `Swift-JWT` [release](https://github.com/Kitura/Swift-JWT/releases).
```swift
.package(url: "https://github.com/Kitura/Swift-JWT.git", from: "x.x.x")
```
Add `SwiftJWT` to your target's dependencies:
```swift
.target(name: "example", dependencies: ["SwiftJWT"]),
```
#### Import package
```swift
import SwiftJWT
```

### Cocoapods

To include `Swift-JWT` in a project using CocoaPods, add `SwiftJWT` to your Podfile:
```
pod 'SwiftJWT'
```
## Getting Started

### The JWT model

In its compact form, a JSON Web Tokens consist of three sections of Base64Url encoded JSON, separated by dots (.).  
These section are: Headers, Claims and the Signature.
Therefore, a JWT typically looks like the following: xxxxx.yyyyy.zzzzz

#### Header

The Header struct contains the fields of the JSON Web Token header as defined by [RFC7515](https://tools.ietf.org/html/rfc7515#section-4).   
The "typ" header will default to "JWT". The "alg" header will be set to the algorithm name when you sign the JWT.  
The other Header fields can be set when initializing the Header or by changing them directly on the Header object.

```swift
let myHeader = Header(kid: "KeyID1")
```

#### Claims

Claims are statements about an entity (typically, the user) and additional data.
The Claims are defined by creating a Swift type that conforms to the `Claims` protocol. The fields of this type represent the information that will be shared using the JWT.  

A list of recommended claims is defined in [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1).

```swift
struct MyClaims: Claims {
    let iss: String
    let sub: String
    let exp: Date
    let admin: Bool
}
let myClaims = MyClaims(iss: "Kitura", sub: "John", exp: Date(timeIntervalSinceNow: 3600), admin: true)
```
##### ClaimsExamples

This library includes some example `Claims` structs as defined by their online specifications:
 - `ClaimsStandardJWT` as defined in [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1).
 - `ClaimsMicroProfile` as defined [here](http://microprofile.io/project/eclipse/microprofile-jwt-auth/spec/src/main/asciidoc/interoperability.asciidoc).
 - `ClaimsOpenID.swift` as defined [here](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).

#### JWT

The JWT struct represents the `Header` and `Claims` of a JSON Web Token.  
You can initialize a JWT by decoding a JWT String, or by providing the JWT Header and Claims.

```swift
let myJWT = JWT(header: myHeader, claims: myClaims)
```

### Signing and Verifying JSON web tokens

#### Creating public and private keys

To sign and verify a JWT using an RSA algorithm, you must provide a public and private key. This could be the contents of a .key file generated via the following Terminal commands:

```
$ ssh-keygen -t rsa -b 4096 -m PEM -f privateKey.key
# Don't add a passphrase
$ openssl rsa -in privateKey.key -pubout -outform PEM -out privateKey.key.pub
```

This will create a public and private key pair on your system, and the contents of the private key can be passed into a Swift variable using the following code:

```swift
let privateKeyPath = URL(fileURLWithPath: getAbsolutePath(relativePath: "/path/to/privateKey.key"))
let privateKey: Data = try Data(contentsOf: privateKeyPath, options: .alwaysMapped)
let publicKeyPath = URL(fileURLWithPath: getAbsolutePath(relativePath: "/path/to/publicKey.key"))
let publicKey: Data = try Data(contentsOf: publicKeyPath, options: .alwaysMapped)
```

For details on creating elliptic curve public and private keys, view the [BlueECC README.txt](https://github.com/Kitura/BlueECC).

#### Sign a JWT using a JWTSigner

The struct JWTSigner contains the algorithms that can be used to sign a JWT.

Initialize a JWTSigner using the static function corresponding to the desired RSA algorithm:

```swift
let jwtSigner = JWTSigner.rs256(privateKey: privateKey)
```
To generate a signed JWT string, call the `sign` function on your JWT instance, passing in a JWTSigner:

```swift
let signedJWT = try myJWT.sign(using: jwtSigner)
```

The resulting `signedJWT` will be a `String` of the form:
```
<encoded header>.<encoded claims>.<signature>
```
**Note:** The sign function sets the alg (algorithm) field of the header.

#### Verify a JWT using JWTVerifier

The struct JWTVerifier contains the algorithms that can be used to verify a JWT.

Initialize a JWTVerifier using the static function corresponding to the desired RSA algorithm:

```swift
let jwtVerifier = JWTVerifier.rs256(publicKey: publicKey)
```
To verify a signed JWT string, call the static `verify` function, passing in your JWT string and the JWTVerifier:

```swift
let verified = JWT<MyClaims>.verify(signedJWT, using: jwtVerifier)
```
The `verified` field will be a `bool` that is true if the signature is verified.


#### Supported Algorithms

The supported algorithms for signing and verifying JWTs are:

* RS256 - RSASSA-PKCS1-v1_5 using SHA-256
* RS384 - RSASSA-PKCS1-v1_5 using SHA-384
* RS512 - RSASSA-PKCS1-v1_5 using SHA-512
* HS256 - HMAC using using SHA-256
* HS384 - HMAC using using SHA-384
* HS512 - HMAC using using SHA-512
* ES256 - ECDSA using using SHA-256 and a P-256 curve
* ES384 - ECDSA using using SHA-384 and a P-384 curve
* ES512 - ECDSA using using SHA-512 and a P-521 curve
* PS256 - RSA-PSS using SHA-256
* PS384 - RSA-PSS using SHA-384
* PS512 - RSA-PSS using SHA-512
* none - Don't sign or verify the JWT

Note: ECDSA and RSA-PSS algorithms require a minimum Swift version of 4.1.


#### Using ASN1 encoding for ECDSA signature

In some cases the ASN1 encoding for ECDSA signatures might be necessary. To use this, a `signatureType: ECSignatureType` parameter can be used for the `JWTSigner` and `JWTVerifier` like this:

```swift
let jwtSigner = JWTSigner.es512(privateKey: privateKey, signatureType: .asn1)
let jwtVerifier = JWTVerifier.es512(publicKey: publicKey, signatureType: .asn1)
```


### Validate claims

The `validateClaims` function validates the standard `Date` claims of a JWT instance.
The following claims are validated if they are present in the `Claims` object:
- exp (expiration date)
- nbf (not before date)
- iat (issued at date)

The method returns `ValidateClaimsResult` - an struct that list the various reasons for validation failure.
If the validation succeeds `ValidateClaimsResult.success` is returned.
The `leeway` parameter is the `TimeInterval` in seconds that a standard `Date` claim will be valid outside of the specified time. This can be used to account for clock skew between issuers and verifiers.

```swift
let validationResult = verified.validateClaims(leeway: 10)
if validationResult != .success {
    print("Claims validation failed: ", validationResult)
}
```

### Decode a JWT from a JWT string

A JWT struct can be initialized from a JWT string.  If a JWTVerifier is provided it will be used to verify the signature before initialization

```swift
let newJWT = try JWT<MyClaims>(jwtString: signedJWT, verifier: jwtVerifier)
```

### JWTEncoder and JWTDecoder

The JWTEncoder and JWTDecoder classes encode and decode JWT Strings using the same API as JSONEncoder and JSONDecoder:

```swift
 let jwtEncoder = JWTEncoder(jwtSigner: jwtSigner)
 let jwtString = try jwtEncoder.encodeToString(myJWT)

 let jwtDecoder = JWTDecoder(jwtVerifier: jwtVerifier)
 let jwt = try jwtDecoder.decode(JWT<MyClaims>.self, fromString: jwtString)
```

Because JWTEncoder and JWTDecoder conform to [KituraContract's](https://github.com/Kitura/KituraContracts/blob/master/Sources/KituraContracts/Contracts.swift) BodyEncoder and BodyDecoder protocols, they can be used as a [custom coder](https://developer.ibm.com/swift/2018/09/01/kitura-custom-encoders-and-decoders/) in Codable routes for sending and receiving JWTs:

```swift
 router.encoders[MediaType(type: .application, subType: "jwt")] = { return jwtEncoder }
 router.decoders[MediaType(type: .application, subType: "jwt")] = { return jwtDecoder }
```

This allows for the use of JWT's in information exchange. By sending and receiving JWT's you can ensure the sending is who they say they are and verify the content hasn't been tampered with.

## API Documentation
For more information visit our [API reference](https://kitura.github.io/Swift-JWT/index.html).

## Community

We love to talk server-side Swift, and Kitura. Join our [Slack](http://swift-at-ibm-slack.mybluemix.net/) to meet the team!

## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](https://github.com/Kitura/Swift-JWT/blob/master/LICENSE).
