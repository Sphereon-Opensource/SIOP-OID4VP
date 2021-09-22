import { DIDDocument, VerificationMethod } from 'did-resolver';
import { JWK } from 'jose/types';

import { JWTPayload, VerifiedJWT } from './JWT.types';
import { OidcClaim, ResolveOpts, VerifiablePresentation } from './SSI.types';

export const expirationTime = 10 * 60;

export interface EnterpriseAuthZToken extends JWTPayload {
  did: string;
  enterpriseName: string;
  nonce: string;
}

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8
export interface AuthenticationRequestOpts {
  redirectUri: string;
  requestBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext;
  claims?: OidcClaim;
  // keySigningAlgorithm?: KeyAlgorithm;
  registration: RequestRegistrationOpts;
  nonce?: string;
  state?: string;

  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

// https://openid.net/specs/openid-connect-implicit-1_0.html#AuthenticationRequest
export interface AuthenticationRequestPayload extends JWTPayload, RequestRegistrationPayload {
  scope: string;
  response_type: ResponseType;
  client_id: string; // did of RP
  redirect_uri: string;
  id_token_hint?: string; // TODO:  idtokenhint parameter value, as specified in Section 3.1.2. If the ID Token is encrypted to the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE.
  // iss: string;
  response_mode: ResponseMode;
  response_context: ResponseContext;
  // registration?: RPRegistrationMetadataPayload /*| RegistrationJwksUri | RegistrationJwks*/; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  // registration_uri?: string; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.2.

  request?: string; // TODO Request Object value, as specified in Section 6.1. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.
  request_uri?: string; //URL where Request Object value can be retrieved from, as specified in Section 6.2.

  state?: string;
  nonce?: string;
  did_doc?: DIDDocument;
  claims?: OidcClaim; // claims parameter value, as specified in Section 5.5.
}

export interface RequestRegistrationPayload {
  registration?: RPRegistrationMetadataPayload /*| RegistrationJwksUri | RegistrationJwks*/; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  registration_uri?: string;
}

export interface VerifiedAuthenticationRequestWithJWT extends VerifiedJWT {
  payload: AuthenticationRequestPayload;
  verifyOpts: VerifyAuthenticationRequestOpts;
  /* didResolutionResult: DIDResolutionResult;
     issuer?: string;
     signer?: VerificationMethod;
     jwt: string;*/
}

/**
 *
 */
export interface AuthenticationRequestWithJWT {
  jwt: string;
  nonce: string;
  state: string;
  payload: AuthenticationRequestPayload;
  opts: AuthenticationRequestOpts;
}

export interface AuthenticationResponseOpts {
  // redirectUri: string;
  signatureType: InternalSignature | ExternalSignature;
  nonce?: string;
  state?: string;
  registration: ResponseRegistrationOpts;
  responseMode?: ResponseMode;
  did: string;
  vp?: VerifiablePresentation;
  expiresIn?: number;
}

export interface AuthenticationResponsePayload extends JWTPayload {
  iss: ResponseIss.SELF_ISSUED_V2 | string; // The SIOP V2 spec mentions this is required, but current implementations use the kid/did here
  sub: string; //did (or thumbprint of sub_jwk key when type is jkt)
  aud: string; // redirect_uri from request
  exp?: number;
  iat?: number;
  state: string;
  nonce: string;
  did: string;
  registration?: DiscoveryMetadataPayload;
  registration_uri?: string;
  vp?: VerifiablePresentation;
  claims?: ResponseClaims;
  sub_type: SubjectIdentifierType;
  sub_jwk: JWK;
}

/**
 *
 */
export interface AuthenticationResponseWithJWT {
  jwt: string;
  nonce: string;
  state: string;
  payload: AuthenticationResponsePayload;
  verifyOpts?: VerifyAuthenticationRequestOpts;
  responseOpts: AuthenticationResponseOpts;
}
export interface RequestRegistrationOpts extends RPRegistrationMetadataOpts {
  registrationBy: RegistrationType;

  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

export interface DiscoveryMetadataOpts {
  authorizationEndpoint?: Schema.OPENID | string;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: KeyAlgo[] | KeyAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  dids_supported: boolean;
  did_methods_supported: string[] | string;
  credential_supported: boolean;
  credential_endpoint: string;
  credential_formats_supported: CredentialType[] | CredentialType;
  credential_claims_supported: string[] | string;
  credential_name: string;
}

export interface DiscoveryMetadataPayload {
  authorization_endpoint: Schema | string;
  issuer: ResponseIss;
  response_types_supported: [ResponseType] | ResponseType;
  scopes_supported: Scope[] | Scope;
  subject_types_supported: SubjectType[] | SubjectType;
  id_token_signing_alg_values_supported: KeyAlgo[] | KeyAlgo;
  request_object_signing_alg_values_supported: SigningAlgo[] | SigningAlgo;
  dids_supported: boolean;
  did_methods_supported: string[] | string;
  credential_supported: boolean;
  credential_endpoint: string;
  credential_formats_supported: CredentialType[] | CredentialType;
  credential_claims_supported: string[] | string;
  credential_name: string;
  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

export interface ResponseRegistrationOpts extends DiscoveryMetadataOpts {
  registrationBy: RegistrationType;

  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

export interface RPRegistrationMetadataOpts {
  subjectIdentifiersSupported: SubjectIdentifierType[] | SubjectIdentifierType;
  didMethodsSupported?: string[] | string;
  credential_formats_supported: CredentialType[] | CredentialType;
}

export interface RPRegistrationMetadataPayload {
  subject_identifiers_supported: SubjectIdentifierType[] | SubjectIdentifierType;
  did_methods_supported?: string[] | string;
  credential_formats_supported: CredentialType[] | CredentialType;
}

export type ObjectBy = {
  type: PassBy.REFERENCE | PassBy.VALUE;
  referenceUri?: string; // for REFERENCE
};

export interface RegistrationType extends ObjectBy {
  id_token_encrypted_response_alg?: EncKeyAlgorithm;
  id_token_encrypted_response_enc?: EncSymmetricAlgorithmCode;
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
  hexPublicKey?: string; // Optional: hex encoded public key to compute JWK key, if not possible from DIDres Document
  kid?: string; // Optional: key identifier. default did#keys-1
}

export enum VerificationMode {
  INTERNAL,
  EXTERNAL,
}

export interface InternalVerification {
  mode: VerificationMode;
  /*registry?: string;
    rpcUrl?: string;*/
  // didUrlResolver?: string;
  resolveOpts?: ResolveOpts;
}

export interface ExternalVerification {
  mode: VerificationMode;
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
  resolveOpts?: ResolveOpts;
  // didUrlResolver?: string;
}

export interface VerifyAuthenticationRequestOpts {
  verification: InternalVerification | ExternalVerification;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string;
  // redirectUri?: string;
}

export interface VerifyAuthenticationResponseOpts {
  verification: InternalVerification | ExternalVerification;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // mandatory?
  state?: string; // mandatory?
  audience: string;
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

export interface VerifiedAuthenticationResponseWithJWT extends VerifiedJWT {
  payload: AuthenticationResponsePayload;
  verifyOpts: VerifyAuthenticationResponseOpts;
  /* didResolutionResult: DIDResolutionResult;
     issuer?: string;
     signer?: VerificationMethod;
     jwt: string;*/
}

export enum ResponseMode {
  FRAGMENT = 'fragment',
  FORM_POST = 'form_post',
  POST = 'post',
  QUERY = 'query',
}

export interface SignatureResponse {
  jws: string;
}

export enum UrlEncodingFormat {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
}

export type SIOPURI = {
  encodedUri: string;
  encodingFormat: UrlEncodingFormat;
};

export interface UriResponse extends SIOPURI {
  responseMode?: ResponseMode;
  bodyEncoded?: string;
}

export interface AuthenticationRequestURI extends SIOPURI {
  jwt?: string;
  requestOpts: AuthenticationRequestOpts;
  requestPayload: AuthenticationRequestPayload;
}

export enum KeyType {
  EC = 'EC',
}

export enum KeyCurve {
  SECP256k1 = 'secp256k1',
  ED25519 = 'ed25519',
}

export enum SigningAlgo {
  EDDSA = 'EdDSA',
  RS256 = 'RS256',
  ES256 = 'ES256',
  ES256K = 'ES256K',
  NONE = 'none',
}

export enum KeyAlgo {
  // ES256KR = "ES256K-R",
  EDDSA = 'EdDSA',
  RS256 = 'RS256',
  ES256 = 'ES256',
  ES256K = 'ES256K',
}

export enum Scope {
  OPENID = 'openid',
  OPENID_DIDAUTHN = 'openid did_authn',
}

export enum ResponseType {
  ID_TOKEN = 'id_token',
}

export enum SubjectIdentifierType {
  JKT = 'jkt',
  DID = 'did',
}

export enum CredentialType {
  JSON_LD = 'w3cvc-jsonld',
  JWT = 'jwt',
}

export enum SubjectType {
  PUBLIC = 'public',
  PAIRWISE = 'pairwise',
}

export enum Schema {
  OPENID = 'openid:',
}

export enum ResponseIss {
  SELF_ISSUED_V1 = 'https://self-issued.me',
  SELF_ISSUED_V2 = 'https://self-issued.me/v2',
}

export const isInternalSignature = (
  object: InternalSignature | ExternalSignature | NoSignature
): object is InternalSignature => 'hexPrivateKey' in object && 'did' in object;

export const isExternalSignature = (
  object: InternalSignature | ExternalSignature | NoSignature
): object is ExternalSignature => 'signatureUri' in object && 'did' in object;

export const isNoSignature = (object: InternalSignature | ExternalSignature | NoSignature): object is NoSignature =>
  'hexPublicKey' in object && 'did' in object;

export const isRequestOpts = (
  object: AuthenticationRequestOpts | AuthenticationResponseOpts
): object is AuthenticationRequestOpts => 'requestBy' in object;

export const isResponseOpts = (
  object: AuthenticationRequestOpts | AuthenticationResponseOpts
): object is AuthenticationResponseOpts => 'did' in object;

export const isRequestPayload = (
  object: AuthenticationRequestPayload | AuthenticationResponsePayload
): object is AuthenticationRequestPayload => 'response_mode' in object && 'response_type' in object;

export const isResponsePayload = (
  object: AuthenticationRequestPayload | AuthenticationResponsePayload
): object is AuthenticationResponsePayload => 'iss' in object && 'aud' in object;

export const isInternalVerification = (
  object: InternalVerification | ExternalVerification
): object is InternalVerification => object.mode === VerificationMode.INTERNAL; /* && !isExternalVerification(object)*/
export const isExternalVerification = (
  object: InternalVerification | ExternalVerification
): object is ExternalVerification =>
  object.mode === VerificationMode.EXTERNAL; /*&& 'verifyUri' in object || 'authZToken' in object*/
