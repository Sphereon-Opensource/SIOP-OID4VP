// noinspection JSUnusedGlobalSymbols

import { PresentationSignCallBackParams } from '@sphereon/pex';
import { Format, PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';
import {
  IPresentation,
  IVerifiablePresentation,
  PresentationSubmission,
  W3CVerifiableCredential,
  W3CVerifiablePresentation,
} from '@sphereon/ssi-types';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { DIDDocument as DIFDIDDocument, VerificationMethod } from 'did-resolver';

import { EcdsaSignature, JWTPayload, LinkedDataProof, ResolveOpts, VerifiedJWT } from './';

export const expirationTime = 10 * 60;

// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
// request and request_uri parameters MUST NOT be included in Request Objects.
export type RequestObjectPayload = Omit<AuthorizationRequestPayload, 'request' | 'request_uri'>;
export type RequestObjectJwt = string;

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8

export interface RequestObjectPayloadProperties {
  scope: string; // from openid-connect-self-issued-v2-1_0-ID1
  responseType: string; // from openid-connect-self-issued-v2-1_0-ID1
  clientId: string; // from openid-connect-self-issued-v2-1_0-ID1
  redirectUri: string; // from openid-connect-self-issued-v2-1_0-ID1
  idTokenHint?: string; // from openid-connect-self-issued-v2-1_0-ID1
  claims?: ClaimOpts; // from openid-connect-self-issued-v2-1_0-ID1 look at https://openid.net/specs/openid-connect-core-1_0.html#Claims
  nonce?: string; // An optional nonce, will be generated if not provided
  state?: string; // An optional state, will be generated if not provided
  authorizationEndpoint?: string;
  responseMode?: ResponseMode; // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
  responseTypesSupported?: ResponseType[] | ResponseType;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
}

export interface RequestObjectOpts {
  requestBy: RequestBy; // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
}

interface AuthorizationRequestCommonOpts extends RequestObjectOpts, RequestObjectPayloadProperties {
  // Yes, this includes the payload properties both at the root level as well as in the requestBy.request property. That is to support OAuth2 together or without a requestObject  {
  uriScheme?: string; // Use a custom scheme for the URI. By default openid:// will be used

  // requestBy: RequestBy; // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
  // signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
  checkLinkedDomain?: CheckLinkedDomain; // determines how we'll handle the linked domains for this RP
  // revocationVerificationCallback?: RevocationVerificationCallback;
}

export interface AuthorizationRequestOptsVD1 extends AuthorizationRequestCommonOpts {
  registration?: RequestRegistrationOpts; // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
  registrationUri?: string; // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
}

export interface AuthorizationRequestOptsVD11 extends AuthorizationRequestCommonOpts {
  clientMetadata?: RequestRegistrationOpts; // from openid-connect-self-issued-v2-1_0-11 look at https://openid.net/specs/openid-connect-registration-1_0.html
  clientMetadataUri?: string; // from openid-connect-self-issued-v2-1_0-11
  idTokenType?: string; // OPTIONAL. Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed.
}

export type AuthorizationRequestOpts = AuthorizationRequestOptsVD1 | AuthorizationRequestOptsVD11;

export interface AuthorizationRequestCommonPayload extends JWTPayload {
  scope: string; // REQUIRED. As specified in Section 3.1.2 of [OpenID.Core].
  response_type: ResponseType; // REQUIRED. Constant string value id_token.
  client_id: string; // REQUIRED. RP's identifier at the Self-Issued OP.
  redirect_uri: string; // REQUIRED. URI to which the Self-Issued OP Response will be sent

  id_token_hint?: string; // OPTIONAL. As specified in Section 3.1.2 of [OpenID.Core]. If the ID Token is encrypted for the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE.
  claims?: ClaimPayload; // OPTIONAL. As specified in Section 5.5 of [OpenID.Core]
  request?: string; // OPTIONAL. Request Object value, as specified in Section 6.1 of [OpenID.Core]. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.
  request_uri?: string; // OPTIONAL. URL where Request Object value can be retrieved from, as specified in Section 6.2 of [OpenID.Core].

  nonce: string;
  state: string;
  response_mode?: ResponseMode; // This specification introduces a new response mode post in accordance with [OAuth.Responses]. This response mode is used to request the Self-Issued OP to deliver the result of the authentication process to a certain endpoint using the HTTP POST method. The additional parameter response_mode is used to carry this value.
}

export interface AuthorizationRequestPayloadVID1 extends AuthorizationRequestCommonPayload, RequestRegistrationPayloadProperties {}

export interface AuthorizationRequestPayloadVD11
  extends AuthorizationRequestCommonPayload,
    RequestClientMetadataPayloadProperties,
    RequestIdTokenPayloadProperties {}

// https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html#section-10
export type AuthorizationRequestPayload = AuthorizationRequestPayloadVID1 | AuthorizationRequestPayloadVD11;

export type JWTVcPresentationProfileAuthenticationRequestPayload = RequestIdTokenPayloadProperties;

export interface RequestIdTokenPayloadProperties {
  id_token_type?: string; // OPTIONAL. Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed. The RP determines the type if ID token returned based on the comparison of the iss and sub claims values (see(see Section 12.1). In order to preserve compatibility with existing OpenID Connect deployments, the OP MAY return an ID token that does not fulfill the requirements as expressed in this parameter. So the RP SHOULD be prepared to reliably handle such an outcome.
}

export interface RequestClientMetadataPayloadProperties {
  client_metadata?: unknown; // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
  client_metadata_uri?: string; // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
}

export interface RequestRegistrationPayloadProperties {
  registration?: RPRegistrationMetadataPayload; //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  registration_uri?: string; // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in 2.2.1.
}

export interface VerifiedAuthorizationRequest extends VerifiedJWT {
  authorizationRequest: AuthorizationRequestPayload;
  payload: RequestObjectPayload; // The unsigned Request payload
  presentationDefinitions?: PresentationDefinitionWithLocation[]; // The optional presentation definition objects that the RP requests
  verifyOpts: VerifyAuthorizationRequestOpts; // The verification options for the authentication request
  version: SupportedVersion;
}

export type PresentationVerificationResult = { verified: boolean };

export type PresentationVerificationCallback = (args: VerifiablePresentationPayload) => Promise<PresentationVerificationResult>;

export type PresentationSignCallback = (args: PresentationSignCallBackParams) => Promise<W3CVerifiablePresentation>;

export interface AuthorizationResponseOpts {
  redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
  registration: ResponseRegistrationOpts;
  checkLinkedDomain?: CheckLinkedDomain;

  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  nonce?: string;
  state?: string;
  responseMode?: ResponseMode;
  did: string;
  expiresIn?: number;
  accessToken?: string;
  tokenType?: string;
  refreshToken?: string;
  presentationExchange?: PresentationExchangeOpts;
}

export interface PresentationExchangeOpts {
  presentationVerificationCallback?: PresentationVerificationCallback;
  presentationSignCallback?: PresentationSignCallback;
  vps?: VerifiablePresentationWithLocation[];
  _vp_token?: { presentation_submission: PresentationSubmission };
}

export interface IDTokenPayload extends JWTPayload {
  iss?: ResponseIss.SELF_ISSUED_V2 | string;
  sub?: string; // did (or thumbprint of sub_jwk key when type is jkt)
  aud?: string; // redirect_uri from request
  iat?: number; // Issued at time
  exp?: number; // Expiration time
  auth_time?: number;
  nonce?: string;
  _vp_token?: {
    /*
      This profile currently supports including only a single VP in the VP Token.
      In such cases, as defined in section 5.2 of OpenID4VP ID1, when the Self-Issued OP returns a single VP in the vp_token,
      VP Token is not an array, and a single VP is passed as a vp_token. In this case, the descriptor map would contain a simple path expression “$”.
      * It's not clear from the ID1 specs how to handle presentation submission in case of multiple VPs
    */
    presentation_submission: PresentationSubmission;
  };
}

export interface AuthorizationResponsePayload {
  access_token?: ResponseIss.SELF_ISSUED_V2 | string;
  token_type?: string;
  refresh_token?: string;
  expires_in: number;
  state: string;
  id_token: string;
  vp_token?: VerifiablePresentationPayload[] | VerifiablePresentationPayload;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export interface VerifiablePresentationsPayload {
  presentation_definition: PresentationDefinitionV1 | PresentationDefinitionV2;
}

export interface IdTokenClaimPayload {
  verifiable_presentations?: VerifiablePresentationsPayload[];

  [x: string]: unknown;
}

export interface VpTokenClaimPayload {
  response_type?: string;
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2;
  presentation_definition_uri?: string;
  nonce?: string;

  [x: string]: unknown;
}

export interface VpTokenClaimOpts {
  presentationDefinition?: PresentationDefinitionV1 | PresentationDefinitionV2;
  presentationDefinitionUri?: string;
}

export interface ClaimOpts {
  idToken?: IDTokenPayload;
  vpToken?: VpTokenClaimOpts;
}

export interface ClaimPayload {
  id_token?: IDTokenPayload;
  vp_token?: VpTokenClaimPayload;
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

export interface VerifiablePresentationWithLocation extends VerifiablePresentationPayload {
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
  presentation: IVerifiablePresentation;
}

/**
 *
 */
export interface AuthorizationResponseResult {
  idToken: string;
  nonce: string;
  state: string;
  idTokenPayload: IDTokenPayload;
  responsePayload: AuthorizationResponsePayload;
  verifyOpts?: VerifyAuthorizationRequestOpts;
  responseOpts: AuthorizationResponseOpts;
}

interface DiscoveryMetadataCommonOpts {
  //TODO add the check: Mandatory if PassBy.Value
  authorizationEndpoint?: Schema | string;
  // this is a confusion point. In the interop profile it mentions "https://self-issued.me/v2/openid-vc", but in the SIOPv2 it's mentioning "https://self-issued.me/v2"
  // @Niels also created an issue here: https://github.com/decentralized-identity/jwt-vc-presentation-profile/issues/63 so we can keep an eye on this for clarification
  //TODO add the check: Mandatory if PassBy.Value
  issuer?: ResponseIss | string;
  //TODO add the check: Mandatory if PassBy.Value
  responseTypesSupported?: ResponseType[] | ResponseType;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  //TODO add the check: Mandatory if PassBy.Value
  subjectSyntaxTypesSupported?: string[];
  tokenEndpoint?: string; // from openid connect discovery 1_0
  userinfoEndpoint?: string; // from openid connect discovery 1_0
  jwksUri?: string; // from openid connect discovery 1_0
  registrationEndpoint?: string; // from openid connect discovery 1_0
  responseModesSupported?: ResponseMode[] | ResponseMode; // from openid connect discovery 1_0
  grantTypesSupported?: GrantType[] | GrantType; // from openid connect discovery 1_0
  acrValuesSupported?: AuthenticationContextReferences[] | AuthenticationContextReferences; // from openid connect discovery 1_0
  idTokenEncryptionAlgValuesSupported?: KeyAlgo[] | KeyAlgo; // from openid connect discovery 1_0
  idTokenEncryptionEncValuesSupported?: string[] | string; // from openid connect discovery 1_0
  userinfoSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo; // from openid connect discovery 1_0
  userinfoEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo; // from openid connect discovery 1_0
  userinfoEncryptionEncValuesSupported?: string[] | string; // from openid connect discovery 1_0
  requestObjectEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo; // from openid connect discovery 1_0
  requestObjectEncryptionEncValuesSupported?: string[] | string; // from openid connect discovery 1_0
  tokenEndpointAuthMethodsSupported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod; // from openid connect discovery 1_0
  tokenEndpointAuthSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo; // from openid connect discovery 1_0
  displayValuesSupported?: string[] | string; // from openid connect discovery 1_0
  claimTypesSupported?: ClaimType[] | ClaimType; // from openid connect discovery 1_0
  claimsSupported?: string[] | string; // recommended, from openid connect discovery 1_0
  serviceDocumentation?: string; // from openid connect discovery 1_0
  claimsLocalesSupported?: string[] | string; // from openid connect discovery 1_0
  uiLocalesSupported?: string[] | string; // from openid connect discovery 1_0
  claimsParameterSupported?: boolean; // from openid connect discovery 1_0
  requestParameterSupported?: boolean; // from openid connect discovery 1_0
  requestUriParameterSupported?: boolean; // from openid connect discovery 1_0
  requireRequestUriRegistration?: boolean; // from openid connect discovery 1_0
  opPolicyUri?: string; // from openid connect discovery 1_0
  opTosUri?: string; // from openid connect discovery 1_0
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

//same for jwt_vc
interface DiscoveryMetadataOptsVID1 extends DiscoveryMetadataCommonOpts {
  clientId?: string; // from oidc4vp
  redirectUris?: string[] | string; // from oidc4vp
  clientName?: string; // from oidc4vp
  tokenEndpointAuthMethod?: string; // from oidc4vp
  applicationType?: string; // from oidc4vp
  responseTypes?: string; // from oidc4vp, also name suggests array
  grantTypes?: string; // from oidc4vp, also name suggests array
  //TODO add the check: Mandatory if PassBy.Value
  vpFormats?: Format; // from oidc4vp
}

interface JWT_VCDiscoveryMetadataOpts extends DiscoveryMetadataOptsVID1 {
  logoUri?: string;
  clientPurpose?: string;
}

interface DiscoveryMetadataOptsVD11 extends DiscoveryMetadataCommonOpts {
  idTokenTypesSupported?: IdTokenType[] | IdTokenType;
  vpFormatsSupported?: Format; // from oidc4vp
}

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8.2
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
interface DiscoveryMetadataCommonPayload {
  authorization_endpoint: Schema | string;
  issuer: ResponseIss;
  response_types_supported: ResponseType[] | ResponseType;
  scopes_supported: Scope[] | Scope;
  subject_types_supported: SubjectType[] | SubjectType;
  id_token_signing_alg_values_supported: SigningAlgo[] | SigningAlgo;
  request_object_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  subject_syntax_types_supported: string[];
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  // marked as required by https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  registration_endpoint?: string;
  response_modes_supported?: ResponseMode[] | ResponseMode;
  grant_types_supported?: GrantType[] | GrantType;
  acr_values_supported?: AuthenticationContextReferences[] | AuthenticationContextReferences;
  id_token_encryption_alg_values_supported?: KeyAlgo[] | KeyAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
   */
  //TODO: maybe add an enum for this with: A256GCM, A128CBC-HS256, ...
  id_token_encryption_enc_values_supported?: string[] | string;
  userinfo_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  userinfo_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
   */
  userinfo_encryption_enc_values_supported?: string[] | string;
  request_object_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
   */
  request_object_encryption_enc_values_supported?: string[] | string;
  token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod;
  token_endpoint_auth_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
  /**
   * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
   */
  display_values_supported?: unknown[] | unknown;
  /**
   * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
   */
  claim_types_supported?: ClaimType[] | ClaimType;
  /**
   * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
   */
  claims_supported?: string[] | string;
  service_documentation?: string;
  claims_locales_supported?: string[] | string;
  ui_locales_supported?: string[] | string;
  claims_parameter_supported?: boolean;
  request_parameter_supported?: boolean;
  request_uri_parameter_supported?: boolean;
  require_request_uri_registration?: boolean;
  op_policy_uri?: string;
  op_tos_uri?: string;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

interface DiscoveryMetadataPayloadVID1 extends DiscoveryMetadataCommonPayload {
  client_id: string;
  redirectUris: string[];
  client_name?: string;
  token_endpoint_auth_method: string;
  application_type: string;
  response_types: string;
  grant_types: string;
  vp_formats: Format;
}

interface JWT_VCDiscoveryMetadataPayload extends DiscoveryMetadataPayloadVID1 {
  logo_uri?: string;
  client_purpose?: string;
}

interface DiscoveryMetadataPayloadVD11 extends DiscoveryMetadataCommonPayload {
  id_token_types_supported?: IdTokenType[] | IdTokenType;
  vp_formats_supported?: Format; // from oidc4vp
}

export type DiscoveryMetadataPayload = DiscoveryMetadataPayloadVID1 | JWT_VCDiscoveryMetadataPayload | DiscoveryMetadataPayloadVD11;

export type DiscoveryMetadataOpts = JWT_VCDiscoveryMetadataOpts | DiscoveryMetadataOptsVID1 | DiscoveryMetadataOptsVD11;

export type RequestRegistrationOpts = RPRegistrationMetadataOpts & { registrationBy: RegistrationType };

export type ResponseRegistrationOpts = DiscoveryMetadataOpts & { registrationBy: RegistrationType };

export type RPRegistrationMetadataOpts = Pick<
  DiscoveryMetadataOpts,
  | 'clientId'
  | 'idTokenSigningAlgValuesSupported'
  | 'requestObjectSigningAlgValuesSupported'
  | 'responseTypesSupported'
  | 'scopesSupported'
  | 'subjectTypesSupported'
  | 'subjectSyntaxTypesSupported'
  | 'vpFormatsSupported'
  | 'clientName'
  | 'logoUri'
  | 'clientPurpose'
> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
};

export type RPRegistrationMetadataPayload = Pick<
  DiscoveryMetadataPayload,
  | 'client_id'
  | 'id_token_signing_alg_values_supported'
  | 'request_object_signing_alg_values_supported'
  | 'response_types_supported'
  | 'scopes_supported'
  | 'subject_types_supported'
  | 'subject_syntax_types_supported'
  | 'vp_formats'
  | 'client_name'
  | 'logo_uri'
  | 'client_purpose'
> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
};

export interface CommonSupportedMetadata {
  subject_syntax_types_supported?: string[];
  vp_formats: Format;
}

export interface RequestBy extends ObjectBy {
  request?: RequestObjectPayloadProperties; // for pass by value
}

export interface ObjectBy {
  type: PassBy;
  referenceUri?: string; // for pass by reference
}

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

export enum VerifiableCredentialTypeFormat {
  LDP_VC = 'ldp_vc',
  JWT_VC = 'jwt_vc',
}

export enum EncSymmetricAlgorithmCode {
  XC20P = 'XC20P', // default
}

export enum EncKeyAlgorithm {
  ECDH_ES = 'ECDH-ES', // default
}

export enum PassBy {
  NONE = 'NONE',
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

export interface Verification {
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
  mode: VerificationMode;
  resolveOpts: ResolveOpts;
  revocationOpts?: RevocationOpts;
  supportedVersions?: SupportedVersion[];
}

export type InternalVerification = Verification;

export interface ExternalVerification extends Verification {
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
}

export interface VerifyAuthorizationRequestOpts {
  verification: InternalVerification | ExternalVerification; // To use internal verification or external hosted verification
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // If provided the nonce in the request needs to match
  // redirectUri?: string;
  verifyCallback?: VerifyCallback;
}

export interface VerifyAuthorizationResponseOpts {
  verification: InternalVerification | ExternalVerification;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // mandatory? // To verify the response against the supplied nonce
  state?: string; // mandatory? // To verify the response against the supplied state
  audience: string; // The audience/redirect_uri
  claims?: ClaimOpts; // The claims, typically the same values used during request creation
  verifyCallback?: VerifyCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
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

export interface VerifiedAuthenticationResponse extends VerifiedJWT {
  payload: IDTokenPayload;
  verifyOpts: VerifyAuthorizationResponseOpts;
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
  encodedUri: string; // The encoded URI
  encodingFormat: UrlEncodingFormat; // The encoding format used
};

export interface UriResponse extends SIOPURI {
  responseMode?: ResponseMode; // The response mode as passed in during creation
  bodyEncoded?: string; // The URI encoded body (JWS)
}

export interface AuthorizationRequestURI extends SIOPURI {
  scheme: string;
  requestObjectBy: ObjectBy; // The supplied request opts as passed in to the method
  authorizationRequestPayload: AuthorizationRequestPayload; // The authorization request payload
  requestObjectJwt?: RequestObjectJwt; // The JWT request object
}

export interface ParsedAuthorizationRequestURI extends SIOPURI {
  scheme: string;
  requestObjectJwt?: RequestObjectJwt;
  authorizationRequestPayload: AuthorizationRequestPayload; // The json payload that ends up signed in the JWT
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

export enum SubjectSyntaxTypesSupportedValues {
  DID = 'did',
  JWK_THUMBPRINT = 'urn:ietf:params:oauth:jwk-thumbprint',
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
  OPENID_VC = 'openid-vc:',
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

export const isRequestOpts = (object: AuthorizationRequestOpts | AuthorizationResponseOpts): object is AuthorizationRequestOpts =>
  'requestBy' in object;

export const isResponseOpts = (object: RequestObjectOpts | AuthorizationResponseOpts): object is RequestObjectOpts => 'did' in object;

export const isRequestPayload = (
  object: RequestObjectPayload | AuthorizationResponsePayload | IDTokenPayload
): object is AuthorizationRequestPayload => 'response_mode' in object && 'response_type' in object;

export const isResponsePayload = (object: RequestObjectPayload | IDTokenPayload): object is IDTokenPayload => 'iss' in object && 'aud' in object;

export const isInternalVerification = (object: InternalVerification | ExternalVerification): object is InternalVerification =>
  object.mode === VerificationMode.INTERNAL; /* && !isExternalVerification(object)*/
export const isExternalVerification = (object: InternalVerification | ExternalVerification): object is ExternalVerification =>
  object.mode === VerificationMode.EXTERNAL; /*&& 'verifyUri' in object || 'authZToken' in object*/

export const isVP = (object: IVerifiablePresentation | IPresentation): object is IVerifiablePresentation => 'presentation' in object;
export const isPresentation = (object: IVerifiablePresentation | IPresentation): object is IPresentation => 'presentation_submission' in object;

export enum RevocationStatus {
  VALID = 'valid',
  INVALID = 'invalid',
}

export interface IRevocationVerificationStatus {
  status: RevocationStatus;
  error?: string;
}

export type RevocationVerificationCallback = (
  vc: W3CVerifiableCredential,
  type: VerifiableCredentialTypeFormat
) => Promise<IRevocationVerificationStatus>;

export enum RevocationVerification {
  NEVER = 'never', // We don't want to verify revocation
  IF_PRESENT = 'if_present', // If credentialStatus is present, did-auth-siop will verify revocation. If present and not valid an exception is thrown
  ALWAYS = 'always', // We'll always check the revocation, if not present or not valid, throws an exception
}

export interface RevocationOpts {
  revocationVerification: RevocationVerification;
  revocationVerificationCallback?: RevocationVerificationCallback;
}

export enum SupportedVersion {
  SIOPv2_ID1 = 'SIOPv2_ID1',
  SIOPv2_D11 = 'SIOPv2_D11',
  JWT_VC_PRESENTATION_PROFILE_v1 = 'JWT_VC_PRESENTATION_PROFILE_v1',
}
