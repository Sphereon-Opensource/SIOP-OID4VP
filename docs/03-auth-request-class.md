
## AuthenticationRequest class


In the previous chapter we have seen the high level OP and RP classes. These classes use the Authentication Request and Response objects explained in this chapter and the next chapter. If you want you can do most interactions using these classes at a lower level. This however means you will not get automatic resolution of values passed by reference like for instance request and registration data.

### createURI

Create a signed URL encoded URI with a signed SIOP Authentication request

#### Data Interface

```typescript
interface AuthenticationRequestURI extends SIOPURI {
    jwt?: string;                                    // The JWT when requestBy was set to mode Reference, undefined if the mode is Value
    requestOpts: AuthenticationRequestOpts;          // The supplied request opts as passed in to the method
    requestPayload: AuthenticationRequestPayload;    // The json payload that ends up signed in the JWT
}

export type SIOPURI = {
    encodedUri: string;                  // The encode JWT as URI
    encodingFormat: UrlEncodingFormat;   // The encoding format used
};

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8
export interface AuthenticationRequestOpts {
    authorizationEndpoint?: string;
    redirectUri: string;                // The redirect URI
    requestBy: ObjectBy;                // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
    signatureType: InternalSignature | ExternalSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication)
    checkLinkedDomain?: CheckLinkedDomain; // determines how we'll handle the linked domains for this RP
    responseMode?: ResponseMode;        // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
    responseContext?: ResponseContext;  // Defines the context of these opts. Either RP side or OP side
    responseTypesSupported?: ResponseType[];
    claims?: ClaimOpts;                 // The claims, uncluding presentation definitions
    registration: RequestRegistrationOpts; // Registration metadata options
    nonce?: string;                     // An optional nonce, will be generated if not provided
    state?: string;                     // An optional state, will be generated if not provided
    scopesSupported?: Scope[];
    subjectTypesSupported?: SubjectType[];
    requestObjectSigningAlgValuesSupported?: SigningAlgo[];
    revocationVerificationCallback?: RevocationVerificationCallback;
    // slint-disable-next-line @typescript-eslint/no-explicit-any
    // [x: string]: any;
}

static async createURI(opts: SIOP.AuthenticationRequestOpts): Promise<SIOP.AuthenticationRequestURI>
```

#### Usage

```typescript
const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";
const HEX_KEY = "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f";
const DID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
const KID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1";

const opts: AuthenticationRequestOpts = {
  checkLinkedDomain: CheckLinkedDomain.NEVER,
  requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
  redirectUri: EXAMPLE_REDIRECT_URL,
  requestBy: {
    type: PassBy.VALUE,
  },
  signatureType: {
    hexPrivateKey: HEX_KEY,
    did: DID,
    kid: KID,
  },
  registration: {
    idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
    requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
    responseTypesSupported: [ResponseType.ID_TOKEN],
    scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
    subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
    subjectTypesSupported: [SubjectType.PAIRWISE],
    vpFormatsSupported: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
    },
    registrationBy: {
      type: PassBy.VALUE,
    },
  },
};

AuthenticationRequest.createURI(opts)
    .then(uri => console.log(uri.encodedUri));

// Output: 
// openid://
//      ?response_type=id_token
//      &scope=openid
//      &client_id=did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0
//      &redirect_uri=https://acme.com/hello&iss=did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0
//      &response_mode=post
//      &response_context=rp
//      &nonce=HxhBU9jBRVP51Z6J0eQ5AxeKoWK9ChApWRrumIqnixc
//      &state=cbde3cdc5389f3be94063be3
//      &registration={
//          "id_token_signing_alg_values_supported":["EdDSA","ES256"],
//          "request_object_signing_alg_values_supported":["EdDSA","ES256"],
//          "response_types_supported":["id_token"],
//          "scopes_supported":["openid did_authn","openid"],
//          "subject_types_supported":["pairwise"],
//          "subject_syntax_types_supported":["did:ethr:","did"],
//          "vp_formats":{
//              "ldp_vc":{
//                  "proof_type":["EcdsaSecp256k1Signature2019","EcdsaSecp256k1Signature2019"]
//              }
//          }
//      }
//      &request=eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAja2V5cy0xIiwidHlwIjoiSldUIn0.eyJpYXQiOjE2NjQ0Mzk3MzMsImV4cCI6MTY2NDQ0MDMzMywicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FjbWUuY29tL2hlbGxvIiwiaXNzIjoiZGlkOmV0aHI6MHgwMTA2YTJlOTg1YjFFMURlOUI1ZGRiNGFGNmRDOWU5MjhGNGU5OUQwIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJyZXNwb25zZV9jb250ZXh0IjoicnAiLCJub25jZSI6Ikh4aEJVOWpCUlZQNTFaNkowZVE1QXhlS29XSzlDaEFwV1JydW1JcW5peGMiLCJzdGF0ZSI6ImNiZGUzY2RjNTM4OWYzYmU5NDA2M2JlMyIsInJlZ2lzdHJhdGlvbiI6eyJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVkRFNBIiwiRVMyNTYiXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFZERTQSIsIkVTMjU2Il0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJpZF90b2tlbiJdLCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCBkaWRfYXV0aG4iLCJvcGVuaWQiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOlsicGFpcndpc2UiXSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDpldGhyOiIsImRpZCJdLCJ2cF9mb3JtYXRzIjp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSJdfX19fQ.owSdQP3ZfOyHryCIO86zB5qenzd5l2AUcEZhA3TvlUWNDJyhhzIgZmBgzV4OMilczr2AJss5HGqxHPmBRTaHcQ

```

### verifyJWT

Verifies a SIOP Authentication Request JWT. Throws an error if the verification fails. Returns the verified JWT and metadata if the verification succeeds.

#### Data Interface

```typescript
export interface VerifiedAuthenticationRequestWithJWT extends VerifiedJWT {
    payload: AuthenticationRequestPayload;       // The unsigned Authentication Request payload
    presentationDefinitions?: PresentationDefinitionWithLocation[]; // The optional presentation definition objects that the RP requests 
    verifyOpts: VerifyAuthenticationRequestOpts; // The verification options for the authentication request
}

export interface VerifiedJWT {
    payload: Partial<JWTPayload>;            // The JWT payload
    didResolutionResult: DIDResolutionResult;// DID resolution result including DID document
    issuer: string;                          // The issuer (did) of the JWT
    signer: VerificationMethod;              // The matching verification method from the DID that was used to sign
    jwt: string;                             // The JWT
}

export interface VerifyAuthenticationRequestOpts {
    verification: InternalVerification | ExternalVerification;  // To use internal verification or external hosted verification
    nonce?: string; // If provided the nonce in the request needs to match
    verifyCallback?: VerifyCallback;
}

export interface DIDResolutionResult {
    didResolutionMetadata: DIDResolutionMetadata // Did resolver metadata
    didDocument: DIDDocument                     // The DID document
    didDocumentMetadata: DIDDocumentMetadata     // DID document metadata
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

static async verifyJWT(jwt:string, opts: SIOP.VerifyAuthenticationRequestOpts): Promise<SIOP.VerifiedAuthenticationRequestWithJWT>
```

#### Usage

```typescript
const verifyOpts: VerifyAuthenticationRequestOpts = {
    verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          subjectSyntaxTypesSupported: ['did:ethr'],
        }
    }
}
const jwt = 'ey..........' // JWT created by RP
AuthenticationRequest.verifyJWT(jwt).then(req => {
    console.log(`issuer: ${req.issuer}`);
    console.log(JSON.stringify(req.signer));
});
// issuer: "did:ethr:0x56C4b92D4a6083Fcee825893A29023cDdfff5c66"
// "signer": {
//      "id": "did:ethr:0x56C4b92D4a6083Fcee825893A29023cDdfff5c66#controller",
//      "type": "EcdsaSecp256k1RecoveryMethod2020",
//      "controller": "did:ethr:0x56C4b92D4a6083Fcee825893A29023cDdfff5c66",
//      "blockchainAccountId": "0x56C4b92D4a6083Fcee825893A29023cDdfff5c66@eip155:1"
// }
```
