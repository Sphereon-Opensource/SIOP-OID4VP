
## AuthenticationResponse class


### createJwtFromRequestJWT

Creates an AuthenticationResponse object from the OP side, using the AuthenticationRequest of the RP and its verification as input together with settings from the OP. The Authentication Response contains the ID token as well as optional Verifiable Presentations conforming to the Submission Requirements sent by the RP.

#### Data interface

```typescript
export interface AuthenticationResponseOpts {
    redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
    registration: ResponseRegistrationOpts;      // Registration options
    checkLinkedDomain?: CheckLinkedDomain; // When the link domain should be checked
    presentationVerificationCallback?: PresentationVerificationCallback; // Callback function to verify the presentations
    signatureType: InternalSignature | ExternalSignature; // Using an internal/private key signature, or hosted signature
    nonce?: string;                              // Allows to override the nonce, otherwise the nonce of the request will be used
    state?: string;                              // Allows to override the state, otherwise the state of the request will be used
    responseMode?: ResponseMode;                 // Response mode should be form in case a mobile device is being used together with a browser
    did: string;                                 // The DID of the OP
    vp?: VerifiablePresentationResponseOpts[];   // Verifiable Presentations with location and format
    expiresIn?: number;                          // Expiration
}

export interface VerifiablePresentationResponseOpts extends VerifiablePresentationPayload {
    location: PresentationLocation;
}

export enum PresentationLocation {
    VP_TOKEN = 'vp_token', // VP will be the toplevel vp_token
    ID_TOKEN = 'id_token', // VP will be part of the id_token in the verifiable_presentations location
}

export interface VerifyAuthenticationRequestOpts {
    verification: InternalVerification | ExternalVerification;   // To use internal verification or external hosted verification
    nonce?: string;                                              // If provided the nonce in the request needs to match
    verifyCallback?: VerifyCallback                              // Callback function to verify the domain linkage credential 
}

export interface AuthenticationResponsePayload extends JWTPayload {
    iss: ResponseIss.SELF_ISSUED_V2 | string;                      // The SIOP V2 spec mentions this is required
    sub: string;                                                   // did (or thumbprint of sub_jwk key when type is jkt)
    sub_jwk?: JWK;                                                  // JWK containing DID key if subtype is did, or thumbprint if it is JKT
    aud: string;                                                   // redirect_uri from request
    exp: number;                                                  // expiration time
    iat: number;                                                  // issued at
    state: string;                                                 // The state which should match the AuthRequest state
    nonce: string;                                                 // The nonce which should match the AuthRequest nonce
    did: string;                                                   // The DID of the OP
    registration?: DiscoveryMetadataPayload;                       // The registration metadata from the OP
    registration_uri?: string;                                     // The URI of the registration metadata if it is returned by reference/URL
    verifiable_presentations?: VerifiablePresentationPayload[];    // Verifiable Presentations
    vp_token?: VerifiablePresentationPayload;
}

export interface AuthenticationResponseWithJWT {
    jwt: string;                                 // The signed Response JWT 
    nonce: string;                               // The nonce which should match the nonce from the request
    state: string;                               // The state which should match the state from the request
    payload: AuthenticationResponsePayload;      // The unsigned payload object 
    verifyOpts?: VerifyAuthenticationRequestOpts;// The Authentication Request verification parameters that were used
    responseOpts: AuthenticationResponseOpts;    // The Authentication Response options used during generation of the Response
}

static async createJWTFromRequestJWT(requestJwt: string, responseOpts: SIOP.AuthenticationResponseOpts, verifyOpts: SIOP.VerifyAuthenticationRequestOpts): Promise<SIOP.AuthenticationResponseWithJWT>
```

#### Usage

```typescript
 const responseOpts: AuthenticationResponseOpts = {
  checkLinkedDomain: CheckLinkedDomain.NEVER,
  redirectUri: "https://acme.com/hello",
  registration: {
    authorizationEndpoint: 'www.myauthorizationendpoint.com',
    idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
    issuer: ResponseIss.SELF_ISSUED_V2,
    responseTypesSupported: [ResponseType.ID_TOKEN],
    subjectSyntaxTypesSupported: ['did:ethr:'],
    vpFormats: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
    },
    registrationBy: {
      type: PassBy.REFERENCE,
      referenceUri: "https://rp.acme.com/siop/jwts",
    },
  },
  signatureType: {
    did: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
    hexPrivateKey: "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
    kid: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#controller"
  },
  did: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
  responseMode: ResponseMode.POST,
}
const verifyOpts: VerifyAuthenticationRequestOpts = {
    verification: {
        resolveOpts: {
          subjectSyntaxTypesSupported: ['did:ethr:'],
        },
        mode: VerificationMode.INTERNAL,
    }
}
createJWTFromRequestJWT('ey....', responseOpts, verifyOpts).then(resp => {
    console.log(resp.payload.sub);
    // output: did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0
    console.log(resp.nonce);
    // output: 5c1d29c1-cf7d-4e14-9305-9db46d8c1916
});
```

### verifyJWT

Verifies the OPs Authentication Response JWT on the RP side as received from the OP/client. Throws an error if the token is invalid, otherwise returns the Verified JWT.

#### Data Interface

```typescript
export interface VerifiedAuthenticationResponseWithJWT extends VerifiedJWT {
    payload: AuthenticationResponsePayload;      // The unsigned authentication response payload
    verifyOpts: VerifyAuthenticationResponseOpts;// The authentication request payload
}

export interface AuthenticationResponsePayload extends JWTPayload {
    iss: ResponseIss.SELF_ISSUED_V2 | string;   // The SIOP V2 spec mentions this is required, but current implementations use the kid/did here
    sub: string;                                // did (or thumbprint of sub_jwk key when type is jkt)
    sub_jwk?: JWK;                               // Sub Json webkey
    aud: string;                                // redirect_uri from request
    exp: number;                                // Expiration time
    iat: number;                                // Issued at time
    state: string;                              // State value
    nonce: string;                              // Nonce
    did: string;                                // DID of the OP
    registration?: DiscoveryMetadataPayload;    // Registration metadata
    registration_uri?: string;                  // Registration URI if metadata is hosted by the OP
    verifiable_presentations?: VerifiablePresentationPayload[]; // Verifiable Presentations as part of the id token
    vp_token?: VerifiablePresentationPayload;   // Verifiable Presentation (the vp_token)
}

export interface VerifiedJWT {
    payload: Partial<JWTPayload>; // The JWT payload
    didResolutionResult: DIDResolutionResult;    // DID resolution result including DID document
    issuer: string;                              // The issuer (did) of the JWT
    signer: VerificationMethod;                  // The matching verification method from the DID that was used to sign
    jwt: string;                                 // The JWT
}

export interface JWTPayload { // A default JWT Payload
    iss?: string
    sub?: string
    aud?: string | string[]
    iat?: number
    nbf?: number
    type?: string;
    exp?: number
    rexp?: number
    jti?: string;
    [x: string]: any
}

export interface VerifyAuthenticationResponseOpts {
    verification: InternalVerification | ExternalVerification;  // To use internal verification or external hosted verification
    nonce?: string;                                             // To verify the response against the supplied nonce
    state?: string;                                             // To verify the response against the supplied state
    audience: string;                                           // The audience/redirect_uri
    claims?: ClaimOpts;                                         // The claims, typically the same values used during request creation
    verifyCallback?: VerifyCallback;                            // Callback function to verify the domain linkage credential 
    presentationVerificationCallback?: PresentationVerificationCallback; // Callback function to verify the verifiable presentations
}

static async verifyJWT(jwt:string, verifyOpts: VerifyAuthenticationResponseOpts): Promise<VerifiedAuthenticationResponseWithJWT>
```

#### Usage

```typescript
const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const NONCE = "5c1d29c1-cf7d-4e14-9305-9db46d8c1916";
const verifyOpts: VerifyAuthenticationResponseOpts = {
    audience: "https://rp.acme.com/siop/jwts",
    nonce: NONCE,
    verification: {
        resolveOpts: {
          subjectSyntaxTypesSupported: ['did:ethr:'],
        },
        mode: VerificationMode.INTERNAL,
    }
}

verifyJWT('ey......', verifyOpts).then(jwt => {
    console.log(`nonce: ${jwt.payload.nonce}`);
    // output: nonce: 5c1d29c1-cf7d-4e14-9305-9db46d8c1916
})
```
