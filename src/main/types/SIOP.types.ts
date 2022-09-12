import { Format, PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';
import {
  IPresentation as PEPresentation,
  IVerifiableCredential,
  IVerifiablePresentation as PEVerifiablePresentation
} from '@sphereon/ssi-types';
import {DIDDocument as DIFDIDDocument, VerificationMethod} from 'did-resolver';
import { JWK } from 'jose';

import { EcdsaSignature, JWTPayload, LinkedDataProof, ResolveOpts, VerifiedJWT } from './';

export const expirationTime = 10 * 60;

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8
export interface AuthenticationRequestOpts {
  authorizationEndpoint?: string;
  redirectUri: string; // The redirect URI
  requestBy: ObjectBy; // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
  checkLinkedDomain?: CheckLinkedDomain; // determines how we'll handle the linked domains for this RP
  responseMode?: ResponseMode; // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
  responseContext?: ResponseContext; // Defines the context of these opts. Either RP side or OP side
  responseTypesSupported?: ResponseType[];
  claims?: ClaimOpts; // The claims
  registration: RequestRegistrationOpts; // Registration metadata options
  nonce?: string; // An optional nonce, will be generated if not provided
  state?: string; // An optional state, will be generated if not provided
  scopesSupported?: Scope[];
  subjectTypesSupported?: SubjectType[];
  requestObjectSigningAlgValuesSupported?: SigningAlgo[];
  revocationVerificationCallback?: RevocationVerificationCallback
  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

// https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html#section-10
export interface AuthenticationRequestPayload extends JWTPayload, RequestRegistrationPayload {
  scope: string;
  response_type: ResponseType;
  client_id: string; // did of RP
  redirect_uri: string;
  id_token_hint?: string; // TODO:  idtokenhint parameter value, as specified in Section 3.1.2. If the ID Token is encrypted to the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE.
  // iss: string;
  response_mode: ResponseMode;
  claims?: ClaimPayload; // claims parameter value, as specified in Section 5.5.
  registration?: RPRegistrationMetadataPayload;
  registration_uri?: string;
  //response_context: ResponseContext;
  request?: string; // TODO Request Object value, as specified in Section 6.1. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.

  request_uri?: string; //URL where Request Object value can be retrieved from, as specified in Section 6.2.
  // state?: string;
  // nonce: string;
  // did_doc?: DIDDocument;
  /**
   * Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed. The RP determines the type if ID token returned based on the comparison of the iss and sub claims values (see(see Section 12.1). In order to preserve compatibility with existing OpenID Connect deployments, the OP MAY return an ID token that does not fulfill the requirements as expressed in this parameter. So the RP SHOULD be prepared to reliably handle such an outcome.
   */
  id_token_type?: string;
}

export interface RequestRegistrationPayload {
  registration?: RPRegistrationMetadataPayload; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  registration_uri?: string;
}

export interface VerifiedAuthenticationRequestWithJWT extends VerifiedJWT {
  payload: AuthenticationRequestPayload; // The unsigned Authentication Request payload
  presentationDefinitions?: PresentationDefinitionWithLocation[]; // The optional presentation definition objects that the RP requests
  verifyOpts: VerifyAuthenticationRequestOpts; // The verification options for the authentication request
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
  redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
  registration: ResponseRegistrationOpts;
  checkLinkedDomain?: CheckLinkedDomain;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  nonce?: string;
  state?: string;
  responseMode?: ResponseMode;
  did: string;
  vp?: VerifiablePresentationResponseOpts[];
  expiresIn?: number;
}

export interface AuthenticationResponsePayload extends JWTPayload {
  iss: ResponseIss.SELF_ISSUED_V2 | string; // The SIOP V2 spec mentions this is required, but current implementations use the kid/did here
  sub: string; // did (or thumbprint of sub_jwk key when type is jkt)
  // sub_type: SubjectIdentifierType;
  sub_jwk: JWK;
  aud: string; // redirect_uri from request
  exp: number; // Expiration time
  iat: number; // Issued at time
  state: string; // State value
  nonce: string; // Nonce
  did: string; // DID of the OP
  registration?: DiscoveryMetadataPayload; // Registration metadata
  registration_uri?: string; // Registration URI if metadata is hosted by the OP
  verifiable_presentations?: VerifiablePresentationPayload[]; // Verifiable Presentations as part of the id token
  // fixme All of the above is the id token. We need to create a new interface of the above and reference that here as id_token
  vp_token?: VerifiablePresentationPayload; // Verifiable Presentation (the vp_token)
  // claims?: ResponseClaims;
}

/*

export interface OidcClaimJson {
  essential?: boolean;
  value?: string;
  values?: string[];
}

export interface OidcClaimRequest {
  [x: string]: null | OidcClaimJson;
}*/

export interface VerifiablePresentationsPayload {
  presentation_definition: PresentationDefinitionV1 | PresentationDefinitionV2;
}

export interface IdTokenClaimPayload {
  verifiable_presentations?: VerifiablePresentationsPayload[];

  [x: string]: unknown;
}

export interface VpTokenClaimPayload {
  response_type: string;
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2;
  presentation_definition_uri?: string;
  nonce: string;
  [x: string]: unknown;
}

export interface ClaimOpts {
  presentationDefinitions?: PresentationDefinitionWithLocation[];
}

export interface ClaimPayload {
  id_token?: IdTokenClaimPayload;
  vp_token?: VpTokenClaimPayload;

  [x: string]: unknown;
}

export interface DIDDocument extends DIFDIDDocument {
  owner?: string;
  created?: string;
  updated?: string;
  proof?: LinkedDataProof;
}

export interface PresentationDefinitionWithLocation {
  location: PresentationLocation;
  definition: PresentationDefinitionV1 | PresentationDefinitionV2;
}

export interface VerifiablePresentationResponseOpts extends VerifiablePresentationPayload {
  location: PresentationLocation;
}

export enum PresentationLocation {
  VP_TOKEN = 'vp_token',
  ID_TOKEN = 'id_token',
}

/**
 * A wrapper for verifiablePresentation
 *
 */
export interface VerifiablePresentationPayload {
  format: VerifiablePresentationTypeFormat;
  presentation: PEPresentation;
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
  //TODO add the check: Mandatory if PassBy.Value
  vpFormats?: Format;
  //TODO add the check: Mandatory if PassBy.Value
  authorizationEndpoint?: Schema.OPENID | string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  //TODO add the check: Mandatory if PassBy.Value
  issuer?: ResponseIss;
  jwksUri?: string;
  registrationEndpoint?: string;
  //TODO add the check: Mandatory if PassBy.Value
  responseTypesSupported?: ResponseType[] | ResponseType;
  responseModesSupported?: ResponseMode[] | ResponseMode;
  grantTypesSupported?: GrantType[] | GrantType;
  acrValuesSupported?: AuthenticationContextReferences[] | AuthenticationContextReferences;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  idTokenEncryptionAlgValuesSupported?: KeyAlgo[] | KeyAlgo;
  idTokenEncryptionEncValuesSupported?: string[] | string;
  userinfoSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  userinfoEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  userinfoEncryptionEncValuesSupported?: string[] | string;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectEncryptionEncValuesSupported?: string[] | string;
  tokenEndpointAuthMethodsSupported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod;
  tokenEndpointAuthSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  displayValuesSupported?: unknown[] | unknown;
  claimTypesSupported?: ClaimType[] | ClaimType;
  claimsSupported?: string[] | string;
  serviceDocumentation?: string;
  claimsLocalesSupported?: string[] | string;
  uiLocalesSupported?: string[] | string;
  claimsParameterSupported?: boolean;
  requestParameterSupported?: boolean;
  requestUriParameterSupported?: boolean;
  requireRequestUriRegistration?: boolean;
  opPolicyUri?: string;
  opTosUri?: string;
  //TODO add the check: Mandatory if PassBy.Value
  subjectSyntaxTypesSupported?: string[] | string;
  idTokenTypesSupported?: IdTokenType[] | IdTokenType;

  // didsSupported?: boolean;
  // didMethodsSupported?: string[] | string;
  // credentialSupported?: boolean;
  // credentialEndpoint?: string;
  // credentialFormatsSupported?: CredentialFormat[];
  // credentialClaimsSupported?: string[] | string;
  // credentialName?: string;
}

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8.2
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
export interface DiscoveryMetadataPayload {
  acr_values_supported?: AuthenticationContextReferences[] | AuthenticationContextReferences;
  authorization_endpoint: Schema | string;
  claims_locales_supported?: string[] | string;
  /**
   * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
   */
  claims_supported?: string[] | string;
  /**
   * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
   */
  claim_types_supported?: ClaimType[] | ClaimType;

  /**
   * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
   */
  display_values_supported?: unknown[] | unknown;
  grant_types_supported?: GrantType[] | GrantType;
  id_token_encryption_alg_values_supported?: KeyAlgo[] | KeyAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
   */
  //TODO: maybe add an enum for this with: A256GCM, A128CBC-HS256, ...
  id_token_encryption_enc_values_supported?: string[] | string;
  id_token_signing_alg_values_supported: SigningAlgo[] | SigningAlgo;
  issuer: ResponseIss;
  jwks_uri?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  // marked as required by https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  registration_endpoint?: string;
  response_types_supported: ResponseType[] | ResponseType;
  response_modes_supported?: ResponseMode[] | ResponseMode;
  scopes_supported: Scope[] | Scope;
  subject_types_supported: SubjectType[] | SubjectType;
  userinfo_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  userinfo_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  request_object_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
   */
  request_object_encryption_enc_values_supported?: string[] | string;
  request_object_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod;
  token_endpoint_auth_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
   */
  userinfo_encryption_enc_values_supported?: string[] | string;
  service_documentation?: string;
  ui_locales_supported?: string[] | string;
  claims_parameter_supported?: boolean;
  request_parameter_supported?: boolean;
  request_uri_parameter_supported?: boolean;
  require_request_uri_registration?: boolean;
  op_policy_uri?: string;
  op_tos_uri?: string;
  subject_syntax_types_supported: string[] | string;
  id_token_types_supported?: IdTokenType[] | IdTokenType;
  vp_formats: Format;
  // dids_supported: boolean;
  // did_methods_supported: string[] | string;
  // credential_supported: boolean;
  // credential_endpoint: string;
  // credential_formats_supported: CredentialFormat[] | CredentialFormat;
  // credential_claims_supported: string[] | string;
  // credential_name: string;
  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

export interface ResponseRegistrationOpts extends DiscoveryMetadataOpts {
  registrationBy: RegistrationType;

  // slint-disable-next-line @typescript-eslint/no-explicit-any
  // [x: string]: any;
}

export interface RPRegistrationMetadataOpts {
  //TODO add the check: Mandatory if PassBy.Value
  requestObjectSigningAlgValuesSupported?: SigningAlgo[];
  //TODO add the check: Mandatory if PassBy.Value
  responseTypesSupported?: ResponseType[];
  //TODO add the check: Mandatory if PassBy.Value
  scopesSupported?: Scope[];
  //TODO add the check: Mandatory if PassBy.Value
  subjectTypesSupported?: SubjectType[];
  //TODO add the check: Mandatory if PassBy.Value
  subjectSyntaxTypesSupported?: string[];
  idTokenSigningAlgValuesSupported?: SigningAlgo[];
  //TODO add the check: Mandatory if PassBy.Value
  vpFormatsSupported?: Format;
  //TODO: ask @nklomp about this value, I couldn't find it anywhere in the old versions of protocol
  // subjectIdentifiersSupported: SubjectIdentifierType[] | SubjectIdentifierType;
  // didMethodsSupported?: string[] | string;
  // credentialFormatsSupported: CredentialFormat[] | CredentialFormat;
}

export interface RPRegistrationMetadataPayload {
  id_token_signing_alg_values_supported: SigningAlgo[];
  id_token_types_supported?: IdTokenType[];
  request_object_signing_alg_values_supported: SigningAlgo[];
  response_types_supported: ResponseType[];
  scopes_supported: Scope[];
  subject_syntax_types_supported: string[];
  subject_types_supported: SubjectType[];
  vp_formats: Format;
}

export interface CommonSupportedMetadata {
  subject_syntax_types_supported?: string[];
  vp_formats: Format;
}

export type ObjectBy = {
  type: PassBy.REFERENCE | PassBy.VALUE;
  referenceUri?: string; // for REFERENCE
};

export enum AuthenticationContextReferences {
  PHR = 'phr',
  PHRH = 'phrh',
}

export enum ClaimType {
  NORMAL = 'normal',
  AGGREGATED = 'aggregated',
  DISTRIBUTED = 'distributed',
}

export enum IdTokenType {
  SUBJECT_SIGNED = 'subject_signed',
  ATTESTER_SIGNED = 'attester_signed',
}

export interface RegistrationType extends ObjectBy {
  id_token_encrypted_response_alg?: EncKeyAlgorithm;
  id_token_encrypted_response_enc?: EncSymmetricAlgorithmCode;
}

export enum VerifiablePresentationTypeFormat {
  JWT_VP = 'jwt_vp',
  LDP_VP = 'ldp_vp',
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
}

export enum CheckLinkedDomain {
  NEVER = 'never', // We don't want to verify Linked domains
  IF_PRESENT = 'if_present', // If present, did-auth-siop will check the linked domain, if exist and not valid, throws an exception
  ALWAYS = 'always', // We'll always check the linked domains, if not exist or not valid, throws an exception
}
export interface InternalSignature {
  hexPrivateKey: string; // hex private key Only secp256k1 format
  did: string;
  kid?: string; // Optional: key identifier
}

export interface SuppliedSignature {
  signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>;
  did: string;
  kid: string;
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
  resolveOpts: ResolveOpts;
  revocationOpts?: RevocationOpts
}

export interface ExternalVerification {
  mode: VerificationMode;
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
  resolveOpts: ResolveOpts;
  revocationOpts?: RevocationOpts
}

export interface VerifyAuthenticationRequestOpts {
  verification: InternalVerification | ExternalVerification; // To use internal verification or external hosted verification
  checkLinkedDomain?: CheckLinkedDomain;
  revocationVerificationCallback?: RevocationVerificationCallback;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // If provided the nonce in the request needs to match
  // redirectUri?: string;
}

export interface VerifyAuthenticationResponseOpts {
  verification: InternalVerification | ExternalVerification;
  checkLinkedDomain?: CheckLinkedDomain;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // mandatory? // To verify the response against the supplied nonce
  state?: string; // mandatory? // To verify the response against the supplied state
  audience: string; // The audience/redirect_uri
  claims?: ClaimOpts; // The claims, typically the same values used during request creation
  //revocationVerificationCallback: RevocationVerificationCallback
}

export interface ResponseClaims {
  verified_claims?: string;
  encryption_key?: JsonWebKey;
}

export interface DidAuthValidationResponse {
  signatureValidation: boolean;
  signer: VerificationMethod;
  payload: JWTPayload;
}

export interface VerifiedAuthenticationResponseWithJWT extends VerifiedJWT {
  payload: AuthenticationResponsePayload;
  verifyOpts: VerifyAuthenticationResponseOpts;
}

export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  IMPLICIT = 'implicit',
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
  encodedUri: string; // The encode JWT as URI
  encodingFormat: UrlEncodingFormat; // The encoding format used
};

export interface UriResponse extends SIOPURI {
  responseMode?: ResponseMode; // The response mode as passed in during creation
  bodyEncoded?: string; // The URI encoded body (JWS)
}

export interface AuthenticationRequestURI extends SIOPURI {
  jwt?: string; // The JWT when requestBy was set to mode Reference, undefined if the mode is Value
  requestOpts: AuthenticationRequestOpts; // The supplied request opts as passed in to the method
  requestPayload: AuthenticationRequestPayload; // The json payload that ends up signed in the JWT
}

export interface ParsedAuthenticationRequestURI extends SIOPURI {
  jwt: string;
  requestPayload: AuthenticationRequestPayload; // The json payload that ends up signed in the JWT
  registration: RPRegistrationMetadataPayload;
}

export enum KeyType {
  EC = 'EC',
}

export enum KeyCurve {
  SECP256k1 = 'secp256k1',
  ED25519 = 'ed25519',
}

export enum TokenEndpointAuthMethod {
  CLIENT_SECRET_POST = 'client_secret_post',
  CLIENT_SECRET_BASIC = 'client_secret_basic',
  CLIENT_SECRET_JWT = 'client_secret_jwt',
  PRIVATE_KEY_JWT = 'private_key_jwt',
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
  //added based on the https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery
  PROFILE = 'profile',
  EMAIL = 'email',
  ADDRESS = 'address',
  PHONE = 'phone',
}

export enum ResponseType {
  ID_TOKEN = 'id_token',
  VP_TOKEN = 'vp_token',
}

export enum SubjectIdentifierType {
  JKT = 'jkt',
  DID = 'did',
}

export enum CredentialFormat {
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

export const isInternalSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is InternalSignature =>
  'hexPrivateKey' in object && 'did' in object;

export const isExternalSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is ExternalSignature =>
  'signatureUri' in object && 'did' in object;

export const isSuppliedSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is SuppliedSignature =>
  'signature' in object;

export const isNoSignature = (object: InternalSignature | ExternalSignature | NoSignature): object is NoSignature =>
  'hexPublicKey' in object && 'did' in object;

export const isRequestOpts = (object: AuthenticationRequestOpts | AuthenticationResponseOpts): object is AuthenticationRequestOpts =>
  'requestBy' in object;

export const isResponseOpts = (object: AuthenticationRequestOpts | AuthenticationResponseOpts): object is AuthenticationResponseOpts =>
  'did' in object;

export const isRequestPayload = (object: AuthenticationRequestPayload | AuthenticationResponsePayload): object is AuthenticationRequestPayload =>
  'response_mode' in object && 'response_type' in object;

export const isResponsePayload = (object: AuthenticationRequestPayload | AuthenticationResponsePayload): object is AuthenticationResponsePayload =>
  'iss' in object && 'aud' in object;

export const isInternalVerification = (object: InternalVerification | ExternalVerification): object is InternalVerification =>
  object.mode === VerificationMode.INTERNAL; /* && !isExternalVerification(object)*/
export const isExternalVerification = (object: InternalVerification | ExternalVerification): object is ExternalVerification =>
  object.mode === VerificationMode.EXTERNAL; /*&& 'verifyUri' in object || 'authZToken' in object*/

export const isVP = (object: PEVerifiablePresentation | PEPresentation): object is PEVerifiablePresentation => 'presentation' in object;
export const isPresentation = (object: PEVerifiablePresentation | PEPresentation): object is PEPresentation => 'presentation_submission' in object;

export enum RevocationStatus {
  VALID = 'valid',
  INVALID = 'invalid'
}

export interface IRevocationVerificationStatus {
  status: RevocationStatus
  error?: string
}

export enum RevocationVcType { // TODO this enum is already somewhere
  LDP_VC = 'ldp_vc',
  JWT_VC = 'jwt_vc',
}

export type RevocationVerificationCallback = (vc: IVerifiableCredential, type: RevocationVcType) => Promise<IRevocationVerificationStatus>

export enum RevocationVerification {
  NEVER = 'never', // We don't want to verify revocation
  IF_PRESENT = 'if_present', // If credentialStatus is present, did-auth-siop will verify revocation. If present and not valid an exception is thrown
  ALWAYS = 'always', // We'll always check the revocation, if not present or not valid, throws an exception
}

export interface RevocationOpts {
  revocationVerification: RevocationVerification,
  revocationVerificationCallback?: RevocationVerificationCallback;
}
