<h1 align="center">
  <br>
  <a href="https://www.gimly.io/"><img src="https://images.squarespace-cdn.com/content/v1/5eb2942c4ac101328fe42dc2/1588768338657-JXDRVS09OBP3CUROD2ML/Gimly+Logo_Wit_Transparant_geen+text.png?format=1500w" alt="Gimly" width="150"></a>
  <br>DID-Auth Self Issued OpenID Provider (SIOP)  
  <br>
</h1>

An authentication library for having clients/people as Self Issued OpenID Provider as specified in the OpenID Connect working group [spec](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)

## Introduction
DID SIOP is an extension of OpenID Connect to allow End-users to use OpenID Providers (OPs) that they control. Using Self-Issued OPs, End-users can authenticate themselves and present claims directly to the Relying Parties (RPs), typically a webapp,  without relying on a third-party Identity Provider. This makes the solution fully self sovereign, as it does not rely on any third parties and strictly happens peer 2 peer, but still uses the OpenID Connect protocol.

The term Self-Issued comes from the fact that the End-users issue self-signed ID Tokens to prove validity of the identifiers and claims. This is a trust model different from that of the rest of OpenID Connect where OP is run by the third party who issues ID Tokens on behalf of the End-user upon End-user's consent. 

## Service
The DID Auth SIOP library consists of a group of services and classes to:

- Resolve DIDs using DIFs [did-resolver](https://github.com/decentralized-identity/did-resolver) and Sphereon's [Universal registrar and resolver client](https://github.com/Sphereon-Opensource/did-uni-client)
- Verify and Create JWTs using DIDs
- Client Auth Service to create and verify Authentication Requests
- RP Auth Service to verify an Authenticaiton response on the RP side
- RP Session, to create and verify bearer access tokens


## DID resolution

### Description
Resolves the DID to a DID document using the DID method provided in didUrl and using DIFs [did-resolver](https://github.com/decentralized-identity/did-resolver) and Sphereons [Universal registrar and resolver client](https://github.com/Sphereon-Opensource/did-uni-client). 

This process allows to retrieve public keys and verificationMethod material, as well as services provided by a DID controller. To be used in both the webapp and mobile applications. Uses the did-uni-client, but could use other DIF did-resolver drivers as well. The benefit of the uni client is that it can resolve many different DID methods. Since the resolution is provided by the mentioned external dependencies we suffice with a usage example.

#### Usage
```typescript
import { Resolver } from 'did-resolver'
import uni from '@sphereon/did-uni-client'

const uniResolver = uni.getResolver();
const resolver = new Resolver(uniResolver);

resolver.resolve('did:eosio:example').then(doc => console.log)
```


## JWT and DID creation and verification
### Create JWT

Creates a signed JWT given a DID which becomes the issuer, a signer function, and a payload over which the signature is created.


#### Data Interface
```typescript
export interface JWTPayload { // This is a standard JWT payload described on for instance https://jwt.io
  iss?: string
  sub?: string
  aud?: string | string[]
  iat?: number
  nbf?: number
  exp?: number
  rexp?: number
  [x: string]: any
}

export interface JWTHeader { // This is a standard JWT header
    typ: 'JWT'
    alg: string             // The JWT signing algorithm to use. Supports: [ES256K, ES256K-R, Ed25519, EdDSA], Defaults to: ES256K
    [x: string]: any
}

export interface JWTOptions {
    issuer: string          // The DID of the issuer (signer) of JWT
    signer: Signer          // A signer function, eg: `ES256KSigner` or `EdDSASigner`
    expiresIn?: number      // optional expiration time
    canonicalize?: boolean  // optional flag to canonicalize header and payload before signing
}
```

#### Usage
````typescript
const signer = ES256KSigner(process.env.PRIVATE_KEY);
createDidJWT({requested: ['name', 'phone']}, {issuer: 'did:eosio:example', signer}).then(jwt => console.log)
````

### Verify JWT
Verifies the given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT, and the DID Document of the issuer of the JWT, using the resolver mentioned earlier. The checks performed include, general JWT decoding, DID resolution, Proof purposes

proof purposes allows restriction of verification methods to the ones specifically listed, otherwise the 'authentication' verification method of the resolved DID document will be used

#### Data Interface
Verify options:
```typescript
export interface JWTVerifyOptions {
  audience?: string                            // DID of the recipient of the JWT
  callbackUrl?: string                         // callback url in JWT
  resolver?: Resolvable                        // DID resolver as mentiond above
  skewTime?: number                            // Allow to skey time in the expiration check with this amount
  proofPurpose?: ProofPurposeTypes             // Restrict to this proof purpose type in the DID resolution
}
```
Response:
```typescript
export interface VerifiedJWT {
    payload: Partial<JWTPayload>                // Standard partial JWT payload, see above
    didResolutionResult: DIDResolutionResult    // The DID resolution
    issuer?: string                             // The DID that issued the JWT
    signer?: VerificationMethod                 // The verification method that issued the JWT
    jwt: string                                 // The JWT itself
}

export interface VerificationMethod {
    id: string                      // The id of the key
    type: string                    // authentication, assertionMethod etc (see DID spec)
    controller: string              // The controller of the Verification method
    publicKeyBase58?: string        // Public key in base58 if any
    publicKeyJwk?: JsonWebKey       // Public key in JWK if any
    publicKeyHex?: string           // Public key in hex if any
    blockchainAccountId?: string    // optional blockchain account id associated with the DID
    ethereumAddress?: string        // deprecated
}
```

#### Usage
```typescript
verifyDidJWT(jwt, resolver, {audience: '6B2bRWU3F7j3REx3vkJ..', callbackUrl: 'https://example.com/callback'}).then(obj => {
       const did = obj.issuer                           // DID of signer
       const payload = obj.payload
       const doc = obj.didResolutionResult.didDocument  // DID Document of signer
       const jwt = obj.jwt                              // JWT 
       const signerKeyId = obj.signer.id                // ID of key in DID document that signed JWT
       ...
   });
```
