import { DIDDocument, Resolvable, VerificationMethod } from 'did-resolver';
import { JWK } from 'jose/types';

import { JWTPayload } from './JWT-types';
import { OidcClaim, VerifiablePresentation } from './SSI-Types';

export const expirationTime = 10 * 60;

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8
export interface SIOPRequestOpts {
  // OPUri?: string;
  redirectUri: string;
  requestBy: ObjectBy;
  registrationType: RegistrationType;
  signatureType: InternalSignature | ExternalSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext;
  claims?: OidcClaim;
  keySigningAlgorithm?: KeyAlgorithm;
  nonce?: string;
  state?: string;
}

export interface SIOPRequest extends JWTPayload {
  scope: string;
  response_type: ResponseType;
  client_id: string;
  redirect_uri: string;
  id_token_hint?: string; // TODO:  idtokenhint parameter value, as specified in Section 3.1.2. If the ID Token is encrypted to the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE.
  iss: string;
  response_mode: ResponseMode;
  response_context: ResponseContext;
  registration?: RegistrationJwksUri | RegistrationJwks; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  registration_uri?: string; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.2.

  request?: string; // TODO Request Object value, as specified in Section 6.1. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.
  request_uri?: string; //URL where Request Object value can be retrieved from, as specified in Section 6.2.

  state?: string;
  nonce?: string;
  did_doc?: DIDDocument;
  claims?: OidcClaim; // claims parameter value, as specified in Section 5.5.
}

export interface SIOPResponse extends JWTPayload {
  iss: ResponseIss.SELF_ISSUED_V2;
  sub: string; //did
  aud: string;
  exp?: number;
  iat?: number;
  nonce: string;
  did: string;
  vp?: VerifiablePresentation;
  claims?: ResponseClaims;
  sub_jwk: JWK;
}

export interface SIOPDiscoveryMetadata {
  authorization_endpoint: Schema.OPENID | string;
  issuer: ResponseIss.SELF_ISSUED_V2;
  response_types_supported: [ResponseType.ID_TOKEN];
  scopes_supported: Scope[];
  subject_types_supported: SubjectType[];
  id_token_signing_alg_values_supported: KeyAlgo[];
  request_object_signing_alg_values_supported: SigningAlgo[];
}

export interface RPRegistrationMetadata {
  subject_identifiers_supported: SubjectIdentifierType[];
  did_methods_supported: string[];
}

export type ObjectBy = {
  type: PassBy.REFERENCE | PassBy.VALUE;
  referenceUri?: string; // for REFERENCE
};

export interface RegistrationType extends ObjectBy {
  id_token_encrypted_response_alg?: EncKeyAlgorithm;
  id_token_encrypted_response_enc?: EncSymmetricAlgorithmCode;
}

export interface RegistrationJwksUri {
  jwks_uri: string;
  id_token_signed_response_alg: KeyAlgorithm;
}

export interface RegistrationJwks {
  jwks: JWK;
}

export enum EncSymmetricAlgorithmCode {
  XC20P = 'XC20P', // default
}

export enum EncKeyAlgorithm {
  ECDH_ES = 'ECDH-ES', // default
}

export enum PassBy {
  REFERENCE = 'REFERENCE',
  VALUE = 'VALUE',
}

export enum ResponseContext {
  RP = 'rp',
  OP = 'op',
  WALLET = 'wallet',
}

export interface InternalSignature {
  hexPrivateKey: string; // hex private key Only secp256k1 format
  did: string;
  kid?: string; // Optional: key identifier
}

export interface NoSignature {
  hexPublicKey: string; // hex public key
  did: string;
  kid?: string; // Optional: key identifier
}

export interface ExternalSignature {
  signatureUri: string; // url to call to generate a signature
  did: string;
  authZToken?: string; // Optional: bearer token to use to the call
  hexPublicKey?: string; // Optional: hex encoded public key to compute JWK key, if not possible from DID Document
  kid?: string; // Optional: key identifier. default did#keys-1
}

export interface SIOPRequestWithJWT {
  jwt: string;
  nonce: string;
  state: string;
  origRequest: SIOPRequest;
  origOpts: SIOPRequestOpts;
}

export const isRequestOpts = (object: SIOPRequestOpts | ResponseOpts): object is SIOPRequestOpts =>
  'requestBy' in object;

export const isResponseOpts = (object: SIOPRequestOpts | ResponseOpts): object is ResponseOpts => 'did' in object;

export interface ResponseOpts {
  redirectUri: string;
  signatureType: InternalSignature | ExternalSignature;
  nonce: string;
  state: string;
  registrationType: RegistrationType;
  responseMode?: ResponseMode;
  did: string;
  vp?: VerifiablePresentation;
}

export interface InternalVerification {
  registry?: string;
  rpcUrl?: string;
  didUrlResolver?: string;
}

export interface ExternalVerification {
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
  didUrlResolver?: string;
}

export interface VerifyRequestOpts {
  verificationType?: InternalVerification | ExternalVerification;
  resolver: Resolvable;
  nonce?: string;
  redirectUri?: string;
}

/*

export interface IdToken {
    [x: string]: unknown;
}

export interface UserInfo {
    [x: string]: unknown;
}

export interface RequestClaims {
    userinfo?: UserInfo;
    id_token?: IdToken;
}
*/
export interface ResponseClaims {
  verified_claims?: string;
  encryption_key?: JsonWebKey;
}

/*
export interface DidAuthRequestCall {
    redirectUri: string;
    hexPrivateKey: string;
    kid: string;
    issuer: string;
    responseMode?: string;
    responseContext?: string;
    claims?: RequestClaims;
}

export interface DidAuthResponseCall {
    hexPrivateKey: string;
    did: string;
    redirectUri: string;
    nonce?: string;
    responseMode?: ResponseMode;
    claims?: ResponseClaims;
}
*/

export interface DidAuthValidationResponse {
  signatureValidation: boolean;
  signer: VerificationMethod;
  payload: JWTPayload;
}

export declare enum ResponseMode {
  FRAGMENT = 'fragment',
  FORM_POST = 'form_post',
  POST = 'post',
  QUERY = 'query',
}

export interface SignatureResponse {
  jws: string;
}

export declare enum UrlEncodingFormat {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
}

export declare type SIOPURI = {
  encodedUri: string;
  encodingFormat: UrlEncodingFormat;
};

export interface UriResponse extends SIOPURI {
  responseMode?: ResponseMode;
  bodyEncoded?: string;
}

export interface SIOPURIRequest extends SIOPURI {
  jwt?: string;
}

export declare enum KeyType {
  EC = 'EC',
}

export declare enum KeyCurve {
  SECP256k1 = 'secp256k1',
  ED25519 = 'ed25519',
}

export declare enum SigningAlgo {
  EDDSA = 'EdDSA',
  RS256 = 'RS256',
  ES256 = 'ES256',
  ES256K = 'ES256K',
  NONE = 'none',
}

export declare enum KeyAlgo {
  // ES256KR = "ES256K-R",
  EDDSA = 'EdDSA',
  RS256 = 'RS256',
  ES256 = 'ES256',
  ES256K = 'ES256K',
}

export declare enum Scope {
  OPENID_DIDAUTHN = 'openid did_authn',
  OPENID = 'openid',
}

export declare enum ResponseType {
  ID_TOKEN = 'id_token',
}

export declare enum SubjectIdentifierType {
  JKT = 'jkt',
  DID = 'did',
}

export declare enum SubjectType {
  PUBLIC = 'public',
  PAIRWISE = 'pairwise',
}

export declare enum Schema {
  OPENID = 'openid:',
}

export declare enum ResponseIss {
  SELF_ISSUED_V2 = 'https://self-issued.me/v2',
}
