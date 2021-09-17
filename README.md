<h1 align="center">
  <br>
  <a href="https://www.gimly.io/"><img src="https://images.squarespace-cdn.com/content/v1/5eb2942c4ac101328fe42dc2/1588768338657-JXDRVS09OBP3CUROD2ML/Gimly+Logo_Wit_Transparant_geen+text.png?format=1500w" alt="Gimly" width="150"></a>
  <br>DID-Auth Self Issued OpenID Provider (SIOP)  
  <br>
</h1>

An authentication library for having clients/people as Self Issued OpenID Provider as specified in the OpenID Connect working group.

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

## Steps involved

Flow diagram:

![flow diagram](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/did-auth-siop/master/docs/auth-flow-diagram.txt)


1. Client initiates an Auth request by POST-ing to /did-siop/v1/authentications
2. RP receives the request and creates the authentication request as JWT, signs it and returns the response as an OpenID Connect URI 
   1. JWT example:
    ```json
    // JWT Header
    {
      "alg": "ES256K",
      "typ": "JWT",
      "jwk": "{Auth JWK here}",
    }
     
    // JWT Payload
    {
      "scope": "openid did_authn",
      "iss": "did:eosio:example-rp",
      "response_type": "id_token",
      "client_id": "<redirect-uri>",
      "nonce": "<random-nonce>",
      "registration": { /* chapter 9 siop spec */
          "redirect_uris": ["https://acme.com/example-redirect"],
          "response_types": "id_token",
          "id_token_signed_response_alg": ["RS256", "ES256", "ES256K", "EdDSA"],
          "request_object_signing_alg": ["RS256", "ES256", "ES256K", "EdDSA"],
          "access_token_signing_alg": ["RS256", "ES256", "ES256K", "EdDSA"],
          "access_token_encryption_alg_values_supported": ["ECDH-ES"],
          "access_token_encryption_enc_values_supported": ["A128GCM", "A256GCM"],
          "jwks_uri": "https://uniresolver.test.sphereon.com/did/1.0/identifiers/did:eosio:example-rp"
      },
      "claims": {
        /* TODO */
      
      }
    }
    ```
   
   2. JWS scheme (JWS Compact Serialization, https://datatracker.ietf.org/doc/html/rfc7515#section-7.1): 
   
   `BASE64URL(UTF8(JWS Protected Header)) || '.' ||
   BASE64URL(JWS Payload) || '.' ||
   BASE64URL(JWS Signature)`

   3. URI: 
   ```
   openid://?response_type=id_token
      &client_id=https%3A%2F%2Fapp.acme.com%2Fexample
      &scope=openid%20did_authn
      &request=<auth-request-JWS>
   ```
3. Client receives the Auth Request URI in the response body
4. Client verifies it and
5. Client creates the authentication response as follows:
   1. Create an ID token as shown below:

    ````json
    // JWT encoded ID Token
    // JWT Header
    {
      "alg": "ES256K",
      "typ": "JWT",
      "kid": "did:eosio:example-client#auth-key-1",
    }
    // JWT Payload
    {
      "iss": "did:eosio:example-client",
      "sub": "{thumbprint of the sub_jwk}",
      "aud": "did:eosio:example-rp",
      "iat": 1620252000,
      "exp": 1620252600,
      "nonce": "<random-nonce>"
     }
    }
    ````

    2. Sign the ID token using the DID key (kid) using JWS scheme (JWS Compact Serialization, https://datatracker.ietf.org/doc/html/rfc7515#section-7.1) and send it to the RP:

   `BASE64URL(UTF8(JWS Protected Header)) || '.' ||
   BASE64URL(JWS Payload) || '.' ||
   BASE64URL(JWS Signature)`

6. Client posts to /did-siop/v1/sessions
7. RP receives the ID token (auth response), verifies it (signature & client DID) and
8. Issues an access token. Create an Authenticated Key Exchange response and return that to the client
9. Client receives the access token and
10. verifies the Authenticated Key Exchange response and the access token in it
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


## Auth Request Service

### createRequestJWT
Create a signed URL encoded URI with a signed DidAuth request token

#### Data Interface
```typescript
export interface DidAuthRequestCall {
    redirectUri: string;                // The redirect URI
    hexPrivateKey: string;              // The private key used to sign
    kid: string;                        // The DID Key id
    issuer: string;                     // The issuer DID
    responseMode?: string;              // How the response should be handled (fragment, form_post, query)
    claims?: RequestClaims;             // The UserInfo and ID Token
}

export interface RequestClaims {
    userinfo?: UserInfo;                // Standard OpenID Connect UserInfo.
    id_token?: IdToken;                 // Standard OpenID Connect ID Token
}

createRequestJWT(didAuthRequestCall: DidAuthRequestCall): Promise<{
    uri: string;
}>;
```

#### Usage
```typescript
createRequestJWT({
    redirectUri: 'https://example.com/',
    hexPrivateKey: 'a3...',
    kid: 'did:eosio:example#key-0',
    issuer: 'did:esoio:example',
    responseMode: 'query'
})
    .then(uri => console.log(uri));

// Output: openid://?response_type=id_token&client_id=https%3A%2F%2Fexample.com%2F&scope=openid%20did_authn&request=<JWT>

```


### verifyJWTRequest
Verifies a DidAuth ID Request Token

#### Data Interface
```typescript
export interface SIOPRequest extends JWTPayload {
    iss: string;                            // literal "https://self-issued.me"
    scope: Scope;                           // literal "openid did_authn"
    response_type: ResponseType;            // literal "id_token"
    client_id: string;                      // The OpenID client id
    nonce: string;                          // The nonce, a random generated string (v4 uuid)
    did_doc?: DIDDocument;                  // optional: The (resolved) DID Document conforming to the DID spec
    claims?: RequestClaims;                 // optional: The UserInfo and ID Token
}

export interface RequestClaims {
    userinfo?: UserInfo;                    // optional: Standard OpenID Connect UserInfo.
    id_token?: IdToken;                     // optional: Standard OpenID Connect ID Token
}

export interface DIDDocument {              // Standard DID Document, see DID spec for explanation
    '@context'?: 'https://www.w3.org/ns/did/v1' | string | string[]
    id: string
    alsoKnownAs?: string[]
    controller?: string | string[]
    verificationMethod?: VerificationMethod[]
    authentication?: (string | VerificationMethod)[]
    assertionMethod?: (string | VerificationMethod)[]
    keyAgreement?: (string | VerificationMethod)[]
    capabilityInvocation?: (string | VerificationMethod)[]
    capabilityDelegation?: (string | VerificationMethod)[]
    service?: ServiceEndpoint[]
}

verifyJWTRequest(didAuthJwt: string): Promise<SIOPRequest>;
```
#### Usage

````typescript
const jwt = await createRequestJWT({
    redirectUri: 'https://example.com/',
    hexPrivateKey: 'a3...',
    kid: 'did:eosio:example#key-0',
    issuer: 'did:esoio:example',
    responseMode: 'query'
});

verifyJWTRequest(jwt).then(req => {
    console.log(`nonce: ${req.nonce}`)
    // output: nonce: 5c1d29c1-cf7d-4e14-9305-9db46d8c1916
})

````


### createAuthResponse
Creates a DidAuth Response Object

#### Usage
````typescript
export interface DidAuthResponseCall {
    hexPrivateKey: string;                  // The private key in hex
    did: string;                            // The DID
    redirectUri: string;                    // The redirect URI
    nonce?: string;                         // The nonce (random v4 UUID)
    responseMode?: ResponseMode;     // Response mode
    claims?: ResponseClaims;
}

createAuthResponse(didAuthResponse: DidAuthResponseCall): Promise<UriResponse>;
````


## Relying Party Auth Service

### verifyAuthResponse
Verifies a DidAuth ID Response Token and the audience. Return a DID Auth Validation Response, which contains the JWT payload as well as the verification method that signed the JWT.

#### Data interface
````typescript

export interface DidAuthValidationResponse {
    signatureValidation: boolean;               // Whether the signature needs to be validated (defaults tot true)
    signer: VerificationMethod;                 // DID VerificationMethod  (described already before)
    payload: JWTPayload;                        // The JWT Payload (described already before)
}


verifyAuthResponse(idToken: string, audience: string): Promise<DidAuthValidationResponse>;
````

#### Usage
````typescript
verifyAuthResponse('ey....', 'my-audience').then(resp => {
    console.log(JSON.stringify(resp.signer));
    // output: 
    //{
    //    id: 'did:eosio:example#key-0',
    //    type: 'authentication',
    //    controller: 'did:eosio:example',
    //    publicKeyHex: '1a3b....'
    //}
    
    console.log(resp.payload.nonce);
    // output: 5c1d29c1-cf7d-4e14-9305-9db46d8c1916
});
````

## Relying Party Session

### createAccessToken
Creates an access token as a JWS placed in an Authenticated Key Exchange response. Uses the response from the above verifyAuthResponse call as input.

#### Data Interface
````typescript
export interface DidAuthValidationResponse {
    signatureValidation: boolean;               // Whether the signature needs to be validated (defaults tot true)
    signer: VerificationMethod;                 // DID VerificationMethod  (described already before)
    payload: JWTPayload;                        // The JWT Payload (described already before)
}

export interface AkeResponse {
    version: 1;                                 // Version 1 of the Authenticated Key Exchange Response
    signed_payload: AkeSigned;                  // The signed (encrypted) payload
    jws: string;                                // The JWS
    did?: string;                               // The DID associated with the response
}

export interface AkeSigned {
    //JWT Header: typ:JWT

    version: 1;                                 // Version 1 of the Authenticated Key Exchange Response

    // Encrypted access token
    encrypted_access_token: string;             // The encrypted access token

    // ID Token nonce
    nonce: string;                              // The nonce (random v4 uuid)
    kid?: string;                               // The DID key id
    iat: number;                                // Issued at (time)
    iss: string;                                // Identity of the issuer (DID)
}

createAccessToken(validation: DidAuthValidationResponse, opts?: { [key: string]: string | number; }): Promise<AkeResponse>;
````

#### Usage
````typescript
const didAuthValResponse = await verifyAuthResponse('ey....', 'my-audience');

createAccessToken(didAuthValResponse).then(akeResp => {
    console.log(`did: ${akeResp.did}`);
    // output: did: did:eosio:example
    console.log(akeResp.signed_payload.nonce);
    // output: 5c1d29c1-cf7d-4e14-9305-9db46d8c1916
})
````

### verifyAccessToken
Verifies the bearer access token on the RP side as received from the OP/client. Throws an error if the token is invalid, otherwise returns the JWT

#### Data Interface
````typescript
export interface JWTPayload { // A default JWT Payload
    iss?: string
    sub?: string
    aud?: string | string[]
    iat?: number
    nbf?: number
    exp?: number
    rexp?: number
    [x: string]: any
}
verifyAccessToken(accessToken: string, opts?: { [key: string]: string | number; }): Promise<JWTPayload>;
````

#### Usage
````typescript
verifyAccessToken('ey......').then(jwt => {
    console.log(`iss: ${jwt.iss}`);
    // output: iss: did:eosio:example
})
````
## Class and Flow diagram of the interactions

DID JWTs:

[![](https://mermaid.ink/img/eyJjb2RlIjoiY2xhc3NEaWFncmFtXG5jbGFzcyBEaWRSZXNvbHV0aW9uT3B0aW9ucyB7XG4gICAgPDxpbnRlcmZhY2U-PlxuICAgIGFjY2VwdD86IHN0cmluZ1xufVxuY2xhc3MgUmVzb2x2YWJsZSB7XG4gICAgPDxpbnRlcmZhY2U-PlxuICAgIHJlc29sdmUoZGlkVXJsOiBzdHJpbmcsIG9wdGlvbnM6IERpZFJlc29sdXRpb25PcHRpb25zKSBQcm9taXNlKERpZFJlc29sdXRpb25SZXN1bHQpXG59XG5EaWRSZXNvbHV0aW9uT3B0aW9ucyA8LS0gUmVzb2x2YWJsZVxuRElEUmVzb2x1dGlvblJlc3VsdCA8LS0gUmVzb2x2YWJsZVxuXG5jbGFzcyAgRElEUmVzb2x1dGlvblJlc3VsdCB7XG4gIGRpZFJlc29sdXRpb25NZXRhZGF0YTogRElEUmVzb2x1dGlvbk1ldGFkYXRhXG4gIGRpZERvY3VtZW50OiBESUREb2N1bWVudCB8IG51bGxcbiAgZGlkRG9jdW1lbnRNZXRhZGF0YTogRElERG9jdW1lbnRNZXRhZGF0YVxufVxuRElERG9jdW1lbnRNZXRhZGF0YSA8LS0gRElEUmVzb2x1dGlvblJlc3VsdFxuRElERG9jdW1lbnQgPC0tIERJRFJlc29sdXRpb25SZXN1bHRcblxuY2xhc3MgRElERG9jdW1lbnRNZXRhZGF0YSB7XG4gIGNyZWF0ZWQ_OiBzdHJpbmdcbiAgdXBkYXRlZD86IHN0cmluZ1xuICBkZWFjdGl2YXRlZD86IGJvb2xlYW5cbiAgdmVyc2lvbklkPzogc3RyaW5nXG4gIG5leHRVcGRhdGU_OiBzdHJpbmdcbiAgbmV4dFZlcnNpb25JZD86IHN0cmluZ1xuICBlcXVpdmFsZW50SWQ_OiBzdHJpbmdcbiAgY2Fub25pY2FsSWQ_OiBzdHJpbmdcbn1cblxuY2xhc3MgRElERG9jdW1lbnQge1xuICAgIDw8aW50ZXJmYWNlPj5cbiAgICAnQGNvbnRleHQnPzogJ2h0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEnIHwgc3RyaW5nIHwgc3RyaW5nW11cbiAgICBpZDogc3RyaW5nXG4gICAgYWxzb0tub3duQXM_OiBzdHJpbmdbXVxuICAgIGNvbnRyb2xsZXI_OiBzdHJpbmcgfCBzdHJpbmdbXVxuICAgIHZlcmlmaWNhdGlvbk1ldGhvZD86IFZlcmlmaWNhdGlvbk1ldGhvZFtdXG4gICAgYXV0aGVudGljYXRpb24_OiAoc3RyaW5nIHwgVmVyaWZpY2F0aW9uTWV0aG9kKVtdXG4gICAgYXNzZXJ0aW9uTWV0aG9kPzogKHN0cmluZyB8IFZlcmlmaWNhdGlvbk1ldGhvZClbXVxuICAgIGtleUFncmVlbWVudD86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBjYXBhYmlsaXR5SW52b2NhdGlvbj86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBjYXBhYmlsaXR5RGVsZWdhdGlvbj86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBzZXJ2aWNlPzogU2VydmljZUVuZHBvaW50W11cbn1cblZlcmlmaWNhdGlvbk1ldGhvZCA8LS0gRElERG9jdW1lbnRcblxuY2xhc3MgVmVyaWZpY2F0aW9uTWV0aG9kIHtcbiAgICA8PGludGVyZmFjZT4-XG4gICAgaWQ6IHN0cmluZ1xuICAgIHR5cGU6IHN0cmluZ1xuICAgIGNvbnRyb2xsZXI6IHN0cmluZ1xuICAgIHB1YmxpY0tleUJhc2U1OD86IHN0cmluZ1xuICAgIHB1YmxpY0tleUp3az86IEpzb25XZWJLZXlcbiAgICBwdWJsaWNLZXlIZXg_OiBzdHJpbmdcbiAgICBibG9ja2NoYWluQWNjb3VudElkPzogc3RyaW5nXG4gICAgZXRoZXJldW1BZGRyZXNzPzogc3RyaW5nXG59XG5cbmNsYXNzIEpXVFBheWxvYWQge1xuICAgIDw8aW50ZXJmYWNlPj5cbiAgICBpc3M6IHN0cmluZ1xuICAgIHN1Yj86IHN0cmluZ1xuICAgIGF1ZD86IHN0cmluZyB8IHN0cmluZ1tdXG4gICAgaWF0PzogbnVtYmVyXG4gICAgbmJmPzogbnVtYmVyXG4gICAgZXhwPzogbnVtYmVyXG4gICAgcmV4cD86IG51bWJlclxufVxuY2xhc3MgSldUSGVhZGVyIHsgLy8gVGhpcyBpcyBhIHN0YW5kYXJkIEpXVCBoZWFkZXJcbiAgICB0eXA6ICdKV1QnXG4gICAgYWxnOiBzdHJpbmcgICAvLyBUaGUgSldUIHNpZ25pbmcgYWxnb3JpdGhtIHRvIHVzZS4gU3VwcG9ydHM6IFtFUzI1NkssIEVTMjU2Sy1SLCBFZDI1NTE5LCBFZERTQV0sIERlZmF1bHRzIHRvOiBFUzI1NktcbiAgICBbeDogc3RyaW5nXTogYW55XG59XG5cbmNsYXNzIFZlcmlmaWNhdGlvbk1ldGhvZCB7XG4gIGlkOiBzdHJpbmdcbiAgdHlwZTogc3RyaW5nXG4gIGNvbnRyb2xsZXI6IHN0cmluZ1xuICBwdWJsaWNLZXlCYXNlNTg_OiBzdHJpbmdcbiAgcHVibGljS2V5SndrPzogSnNvbldlYktleVxuICBwdWJsaWNLZXlIZXg_OiBzdHJpbmdcbiAgYmxvY2tjaGFpbkFjY291bnRJZD86IHN0cmluZ1xuICBldGhlcmV1bUFkZHJlc3M_OiBzdHJpbmdcbn1cblxuSnNvbldlYktleSA8fC0tIFZlcmlmaWNhdGlvbk1ldGhvZFxuY2xhc3MgSnNvbldlYktleSB7XG4gIGFsZz86IHN0cmluZ1xuICBjcnY_OiBzdHJpbmdcbiAgZT86IHN0cmluZ1xuICBleHQ_OiBib29sZWFuXG4gIGtleV9vcHM_OiBzdHJpbmdbXVxuICBraWQ_OiBzdHJpbmdcbiAga3R5OiBzdHJpbmdcbiAgbj86IHN0cmluZ1xuICB1c2U_OiBzdHJpbmdcbiAgeD86IHN0cmluZ1xuICB5Pzogc3RyaW5nXG59XG5cblxuY2xhc3MgRGlkSldUIHtcbiAgICA8PHNlcnZpY2U-PlxuICAgIGNyZWF0ZURpZEpXVChwYXlsb2FkOiBKV1RQYXlsb2FkLCBvcHRpb25zOiBKV1RPcHRpb25zLCBoZWFkZXI6IEpXVEpIZWFkZXIpIFByb21pc2Uoc3RyaW5nKVxuICAgIHZlcmlmeURpZEpXVChqd3Q6IHN0cmluZywgcmVzb2x2ZXI6IFJlc29sdmFibGUpIFByb21pc2UoYm9vbGVhbilcbn1cbkpXVFBheWxvYWQgPC0tIERpZEpXVFxuSldUT3B0aW9ucyA8LS0gRGlkSldUXG5KV1RIZWFkZXIgPC0tIERpZEpXVFxuUmVzb2x2YWJsZSA8LS0gRGlkSldUXG4iLCJtZXJtYWlkIjp7InRoZW1lIjoiZGVmYXVsdCJ9LCJ1cGRhdGVFZGl0b3IiOmZhbHNlLCJhdXRvU3luYyI6ZmFsc2UsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)](https://mermaid-js.github.io/mermaid-live-editor/edit##eyJjb2RlIjoiY2xhc3NEaWFncmFtXG5jbGFzcyBEaWRSZXNvbHV0aW9uT3B0aW9ucyB7XG4gICAgPDxpbnRlcmZhY2U-PlxuICAgIGFjY2VwdD86IHN0cmluZ1xufVxuY2xhc3MgUmVzb2x2YWJsZSB7XG4gICAgPDxpbnRlcmZhY2U-PlxuICAgIHJlc29sdmUoZGlkVXJsOiBzdHJpbmcsIG9wdGlvbnM6IERpZFJlc29sdXRpb25PcHRpb25zKSBQcm9taXNlKERpZFJlc29sdXRpb25SZXN1bHQpXG59XG5EaWRSZXNvbHV0aW9uT3B0aW9ucyA8LS0gUmVzb2x2YWJsZVxuRElEUmVzb2x1dGlvblJlc3VsdCA8LS0gUmVzb2x2YWJsZVxuXG5jbGFzcyAgRElEUmVzb2x1dGlvblJlc3VsdCB7XG4gIGRpZFJlc29sdXRpb25NZXRhZGF0YTogRElEUmVzb2x1dGlvbk1ldGFkYXRhXG4gIGRpZERvY3VtZW50OiBESUREb2N1bWVudCB8IG51bGxcbiAgZGlkRG9jdW1lbnRNZXRhZGF0YTogRElERG9jdW1lbnRNZXRhZGF0YVxufVxuRElERG9jdW1lbnRNZXRhZGF0YSA8LS0gRElEUmVzb2x1dGlvblJlc3VsdFxuRElERG9jdW1lbnQgPC0tIERJRFJlc29sdXRpb25SZXN1bHRcblxuY2xhc3MgRElERG9jdW1lbnRNZXRhZGF0YSB7XG4gIGNyZWF0ZWQ_OiBzdHJpbmdcbiAgdXBkYXRlZD86IHN0cmluZ1xuICBkZWFjdGl2YXRlZD86IGJvb2xlYW5cbiAgdmVyc2lvbklkPzogc3RyaW5nXG4gIG5leHRVcGRhdGU_OiBzdHJpbmdcbiAgbmV4dFZlcnNpb25JZD86IHN0cmluZ1xuICBlcXVpdmFsZW50SWQ_OiBzdHJpbmdcbiAgY2Fub25pY2FsSWQ_OiBzdHJpbmdcbn1cblxuY2xhc3MgRElERG9jdW1lbnQge1xuICAgIDw8aW50ZXJmYWNlPj5cbiAgICAnQGNvbnRleHQnPzogJ2h0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEnIHwgc3RyaW5nIHwgc3RyaW5nW11cbiAgICBpZDogc3RyaW5nXG4gICAgYWxzb0tub3duQXM_OiBzdHJpbmdbXVxuICAgIGNvbnRyb2xsZXI_OiBzdHJpbmcgfCBzdHJpbmdbXVxuICAgIHZlcmlmaWNhdGlvbk1ldGhvZD86IFZlcmlmaWNhdGlvbk1ldGhvZFtdXG4gICAgYXV0aGVudGljYXRpb24_OiAoc3RyaW5nIHwgVmVyaWZpY2F0aW9uTWV0aG9kKVtdXG4gICAgYXNzZXJ0aW9uTWV0aG9kPzogKHN0cmluZyB8IFZlcmlmaWNhdGlvbk1ldGhvZClbXVxuICAgIGtleUFncmVlbWVudD86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBjYXBhYmlsaXR5SW52b2NhdGlvbj86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBjYXBhYmlsaXR5RGVsZWdhdGlvbj86IChzdHJpbmcgfCBWZXJpZmljYXRpb25NZXRob2QpW11cbiAgICBzZXJ2aWNlPzogU2VydmljZUVuZHBvaW50W11cbn1cblZlcmlmaWNhdGlvbk1ldGhvZCA8LS0gRElERG9jdW1lbnRcblxuY2xhc3MgVmVyaWZpY2F0aW9uTWV0aG9kIHtcbiAgICA8PGludGVyZmFjZT4-XG4gICAgaWQ6IHN0cmluZ1xuICAgIHR5cGU6IHN0cmluZ1xuICAgIGNvbnRyb2xsZXI6IHN0cmluZ1xuICAgIHB1YmxpY0tleUJhc2U1OD86IHN0cmluZ1xuICAgIHB1YmxpY0tleUp3az86IEpzb25XZWJLZXlcbiAgICBwdWJsaWNLZXlIZXg_OiBzdHJpbmdcbiAgICBibG9ja2NoYWluQWNjb3VudElkPzogc3RyaW5nXG4gICAgZXRoZXJldW1BZGRyZXNzPzogc3RyaW5nXG59XG5cbmNsYXNzIEpXVFBheWxvYWQge1xuICAgIDw8aW50ZXJmYWNlPj5cbiAgICBpc3M6IHN0cmluZ1xuICAgIHN1Yj86IHN0cmluZ1xuICAgIGF1ZD86IHN0cmluZyB8IHN0cmluZ1tdXG4gICAgaWF0PzogbnVtYmVyXG4gICAgbmJmPzogbnVtYmVyXG4gICAgZXhwPzogbnVtYmVyXG4gICAgcmV4cD86IG51bWJlclxufVxuY2xhc3MgSldUSGVhZGVyIHsgLy8gVGhpcyBpcyBhIHN0YW5kYXJkIEpXVCBoZWFkZXJcbiAgICB0eXA6ICdKV1QnXG4gICAgYWxnOiBzdHJpbmcgICAvLyBUaGUgSldUIHNpZ25pbmcgYWxnb3JpdGhtIHRvIHVzZS4gU3VwcG9ydHM6IFtFUzI1NkssIEVTMjU2Sy1SLCBFZDI1NTE5LCBFZERTQV0sIERlZmF1bHRzIHRvOiBFUzI1NktcbiAgICBbeDogc3RyaW5nXTogYW55XG59XG5cbmNsYXNzIFZlcmlmaWNhdGlvbk1ldGhvZCB7XG4gIGlkOiBzdHJpbmdcbiAgdHlwZTogc3RyaW5nXG4gIGNvbnRyb2xsZXI6IHN0cmluZ1xuICBwdWJsaWNLZXlCYXNlNTg_OiBzdHJpbmdcbiAgcHVibGljS2V5SndrPzogSnNvbldlYktleVxuICBwdWJsaWNLZXlIZXg_OiBzdHJpbmdcbiAgYmxvY2tjaGFpbkFjY291bnRJZD86IHN0cmluZ1xuICBldGhlcmV1bUFkZHJlc3M_OiBzdHJpbmdcbn1cblxuSnNvbldlYktleSA8fC0tIFZlcmlmaWNhdGlvbk1ldGhvZFxuY2xhc3MgSnNvbldlYktleSB7XG4gIGFsZz86IHN0cmluZ1xuICBjcnY_OiBzdHJpbmdcbiAgZT86IHN0cmluZ1xuICBleHQ_OiBib29sZWFuXG4gIGtleV9vcHM_OiBzdHJpbmdbXVxuICBraWQ_OiBzdHJpbmdcbiAga3R5OiBzdHJpbmdcbiAgbj86IHN0cmluZ1xuICB1c2U_OiBzdHJpbmdcbiAgeD86IHN0cmluZ1xuICB5Pzogc3RyaW5nXG59XG5cblxuY2xhc3MgRGlkSldUIHtcbiAgICA8PHNlcnZpY2U-PlxuICAgIGNyZWF0ZURpZEpXVChwYXlsb2FkOiBKV1RQYXlsb2FkLCBvcHRpb25zOiBKV1RPcHRpb25zLCBoZWFkZXI6IEpXVEpIZWFkZXIpIFByb21pc2Uoc3RyaW5nKVxuICAgIHZlcmlmeURpZEpXVChqd3Q6IHN0cmluZywgcmVzb2x2ZXI6IFJlc29sdmFibGUpIFByb21pc2UoYm9vbGVhbilcbn1cbkpXVFBheWxvYWQgPC0tIERpZEpXVFxuSldUT3B0aW9ucyA8LS0gRGlkSldUXG5KV1RIZWFkZXIgPC0tIERpZEpXVFxuUmVzb2x2YWJsZSA8LS0gRGlkSldUXG4iLCJtZXJtYWlkIjoie1xuICBcInRoZW1lXCI6IFwiZGVmYXVsdFwiXG59IiwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOmZhbHNlLCJ1cGRhdGVEaWFncmFtIjp0cnVlfQ)


Services and objects:

![img.png](img.png)


