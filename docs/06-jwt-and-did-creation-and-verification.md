
## JWT and DID creation and verification


Please note that this chapter is about low level JWT functions, which normally aren't used by end users of this library. Typically, you use the AuthenticationRequest and Response classes (low-level) or the OP and RP classes (high-level).

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
    jti?: string;

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

```typescript
const signer = ES256KSigner(process.env.PRIVATE_KEY);
createDidJWT({requested: ['name', 'phone']}, {issuer: 'did:eosio:example', signer}).then(jwt => console.log)
```

### Verify JWT

Verifies the given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT, and the DID Document of the issuer of the JWT, using the resolver mentioned earlier. The checks performed include, general JWT decoding, DID resolution, Proof purposes.

Proof purposes allow restriction of verification methods to the ones specifically listed, otherwise the 'authentication' verification method of the resolved DID document will be used.

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
export interface JWTVerified {
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
verifyDidJWT(jwt, resolver, {audience: '6B2bRWU3F7j3REx3vkJ..'}).then(verifiedJWT => {
    const did = verifiedJWT.issuer;                          // DID of signer
    const payload = verifiedJWT.payload;                     // The JHT payload
    const doc = verifiedJWT.didResolutionResult.didDocument; // DID Document of signer
    const jwt = verifiedJWT.jwt;                             // JWS in string format 
    const signerKeyId = verifiedJWT.signer.id;               // ID of key in DID document that signed JWT
...
});
```

### Verify Linked Domain with DID

Verifies whether a domain linkage credential is valid

#### Data Interface

Verify callback:

```typescript
export declare type VerifyCallback = (args: IVerifyCallbackArgs) => Promise<IVerifyCredentialResult>; // The callback function to verify the Domain Linkage Credential
```

```typescript
export interface IVerifyCallbackArgs {
    credential: DomainLinkageCredential; // The domain linkage credential to be verified
    proofFormat?: ProofFormatTypesEnum; // Whether it is a JWT or JsonLD credential
}
```

```typescript
export interface IVerifyCredentialResult {
    verified: boolean; // The result of the domain linkage credential verification
}
```

```typescript
export enum CheckLinkedDomain {
  NEVER = 'never', // We don't want to verify Linked domains
  IF_PRESENT = 'if_present', // If present, did-auth-siop will check the linked domain, if exist and not valid, throws an exception
  ALWAYS = 'always', // We'll always check the linked domains, if not exist or not valid, throws an exception
}
```

#### Usage

```typescript
const verifyCallback = async (args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => {
  const keyPair = await Ed25519VerificationKey2020.from(VC_KEY_PAIR);
  const suite = new Ed25519Signature2020({ key: keyPair });
  suite.verificationMethod = keyPair.id;
  return await vc.verifyCredential({ credential: args.credential, suite, documentLoader: new DocumentLoader().getLoader() });
};
```

```typescript
const rp = RP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
      .addVerifyCallback((args: IVerifyCallbackArgs) => verifyCallback(args))
      ...
```

```typescript
const op = OP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
      .addVerifyCallback((args: IVerifyCallbackArgs) => verifyCallback(args))
      ...
```

### Verify Revocation

Verifies whether a verifiable credential contained verifiable presentation is revoked

#### Data Interface

```typescript
export type RevocationVerificationCallback = (
    vc: W3CVerifiableCredential, // The Verifiable Credential to be checked
    type: VerifiableCredentialTypeFormat // Whether it is a LDP or JWT Verifiable Credential
) => Promise<IRevocationVerificationStatus>;
```

```typescript
export interface IRevocationVerificationStatus {
  status: RevocationStatus; // Valid or invalid
  error?: string;
}
```

```typescript
export enum RevocationVerification {
  NEVER = 'never', // We don't want to verify revocation
  IF_PRESENT = 'if_present', // If credentialStatus is present, did-auth-siop will verify revocation. If present and not valid an exception is thrown
  ALWAYS = 'always', // We'll always check the revocation, if not present or not valid, throws an exception
}
```

#### Usage

```typescript
  const verifyRevocation = async (
    vc: W3CVerifiableCredential,
    type: VerifiableCredentialTypeFormat
):Promise<IRevocationVerificationStatus> => {
  // Logic to verify the credential status
  ...
  return { status, error }
};
```

```typescript
import {verifyRevocation} from "./Revocation";

const rp = RP.builder()
.withRevocationVerification(RevocationVerification.ALWAYS)
.withRevocationVerificationCallback((vc, type) => verifyRevocation(vc, type))
```

### Verify Presentation Callback

The callback function to verify the verifiable presentation

#### Data interface

```typescript
export type PresentationVerificationCallback = (args: IVerifiablePresentation) => Promise<PresentationVerificationResult>;
```

```typescript
export type IVerifiablePresentation = IPresentation & IHasProof
```

```typescript
export type PresentationVerificationResult = { verified: boolean };
```

#### Usage

JsonLD

```typescript
import {PresentationVerificationResult} from "./SIOP.types";

const verifyPresentation = async (vp: IVerifiablePresentation): Promise<PresentationVerificationResult> => {
  const keyPair = await Ed25519VerificationKey2020.from(VC_KEY_PAIR);
  const suite = new Ed25519Signature2020({key: keyPair});
  suite.verificationMethod = keyPair.id;
  // If the credentials are not verified individually by the library,
  // it needs to be implemented. In this example, the library does it.
  const { verified } = await vc.verify({presentation: vp, suite, challenge: 'challenge', documentLoader: new DocumentLoader().getLoader()});
  return Promise.resolve({ verified })
};
```
or

JWT

```typescript
import {IVerifiablePresentation} from "@sphereon/ssi-types";

const verifyPresentation = async (vp: IVerifiablePresentation): Promise<PresentationVerificationResult> => {
  // If the credentials are not verified individually by the library,
  // it needs to be implemented. In this example, the library does it.
  await verifyCredentialJWT(jwtVc, getResolver({ subjectSyntaxTypesSupported: ['did:key:']}))
  return Promise.resolve({ verified: true })
}
```

```typescript
const rp = RP.builder()
      .withPresentationVerification((args) => verifyPresentation(args))
      ...
```
