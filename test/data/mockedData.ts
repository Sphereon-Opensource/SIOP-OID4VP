import { DIDDocument } from 'did-resolver';

import { JWTHeader, SIOP } from '../../src';
import { CredentialFormat, ResponseContext, ResponseMode, SubjectIdentifierType } from '../../src/types/SIOP.types';

export const DIDAUTH_HEADER: JWTHeader = {
  typ: "JWT",
  alg: "ES256K",
  kid: "did:ethr:0x416e6e6162656c2e4c65652e452d412d506f652e#key1",
};

export const DIDAUTH_REQUEST_PAYLOAD: SIOP.AuthenticationRequestPayload = {
  iss: "did:ethr:0x416e6e6162656c2e4c65652e452d412d506f652e", // DIDres of the RP (kid must point to a key in this DIDres Document)
  scope: SIOP.Scope.OPENID, // MUST be "openid did_authn"
  response_type: SIOP.ResponseType.ID_TOKEN, // MUST be ID Token
  response_context: ResponseContext.RP,
  response_mode: ResponseMode.POST,
  redirect_uri: "http://app.example/demo", // Redirect URI after successful authentication
  client_id: "http://app.example/demo",
  nonce: "n-0S6_WzA2M", // MUST be a random string from a high-entropy source
  state: "af0ifjsldkj",
  registration: {
    did_methods_supported: ['did:ethr:'],
    subject_identifiers_supported: SubjectIdentifierType.DID,
    credential_formats_supported: [CredentialFormat.JSON_LD, CredentialFormat.JWT]
  },
  /*registration: {
      subject_types_supported: SubjectType.PAIRWISE,
      scopes_supported: Scope.OPENID,
      request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
      issuer: ResponseIss.SELF_ISSUED_V2,
      response_types_supported: ResponseType.ID_TOKEN,
      id_token_signing_alg_values_supported: [KeyAlgo.EDDSA, KeyAlgo.ES256K],
      authorization_endpoint: Schema.OPENID
      /!*!// either using jwks_uri or jwks
      jwks_uri: ""
          "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
      id_token_signed_response_alg: SIOP.KeyAlgo.ES256K,*!/
  },*/
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156,
};

export const DIDAUTH_RESPONSE_PAYLOAD: SIOP.AuthenticationResponsePayload = {
  iss: "did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111", // SIOP.ResponseIss.SELF_ISSUED_V2, // MUST be https://self-issued.me/v2, but implementations use DIDs here. Resolution is based on this
  sub: "QS+5mH5GqVxuah94+D9wV97mMKZ6iMzW1op4B4s02Jk=", // Thumbprint of the sub_jwk
  aud: "http://app.example/demo", // MUST be client_id from the Request Object
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156, // Unix Timestamp; Date and time when the Token was issued.
  sub_type: SubjectIdentifierType.DID,
  state: "af0ifjsldkj",
  nonce: "6a6b57a9d4e1a130b0edbe1ec4ae8823",
  sub_jwk: {
    crv: "secp256k1",
    kid: "did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111#keys-1",
    kty: "EC",
    x: "7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    y: "3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o",
  },
  did: "did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111",
};


export const DID_DOCUMENT_PUBKEY_B58: DIDDocument = {
  assertionMethod: [], capabilityDelegation: [], capabilityInvocation: [], keyAgreement: [],
  "@context": "https://w3id.org/did/v1",
  id: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
  controller: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
  authentication: ["did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1"],
  verificationMethod: [
    {
      id: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
      publicKeyBase58:
        "PSPfR29Snu5yxJcLHf2t6SyJ9mttet19ECkDHr4HY3FD5YC8ZenjvspPSAGSpaQ8B8kXADV97WSd7JqaNAUTn8YG",
    },
  ]
};

export const DID_DOCUMENT_PUBKEY_JWK: DIDDocument = {
  assertionMethod: [], capabilityDelegation: [], capabilityInvocation: [], keyAgreement: [],
  "@context": "https://w3id.org/did/v1",
  id: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
  controller: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
  authentication: [
    "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
  ],
  verificationMethod: [
    {
      id:
        "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
      publicKeyJwk: {
        kty: "EC",
        crv: "secp256k1",
        x: "62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a",
        y: "1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159",
        kid: "JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
      },
    },
  ]
};
