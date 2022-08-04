import { IPresentation as PEPresentation, IVerifiablePresentation as PEVerifiablePresentation } from '@sphereon/pex';
import { PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';
import { DIDDocument as DIFDIDDocument, VerificationMethod } from 'did-resolver';
import { JWK } from 'jose/types';

import { EcdsaSignature, JWTPayload, VerifiedJWT } from './JWT.types';
import { LinkedDataProof, ResolveOpts } from './SSI.types';

export const expirationTime = 10 * 60;

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8
export interface AuthenticationRequestOpts {
  redirectUri: string; // The redirect URI
  requestBy: ObjectBy; // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
  responseMode?: ResponseMode; // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
  responseContext?: ResponseContext; // Defines the context of these opts. Either RP side or OP side
  claims?: ClaimOpts; // The claims
  registration: RequestRegistrationOpts; // Registration metadata options
  nonce?: string; // An optional nonce, will be generated if not provided
  state?: string; // An optional state, will be generated if not provided

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
  /**
   * ASCII [RFC20] string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User. The defined values are:
   * page
   * The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view. If the display parameter is not specified, this is the default display mode.
   * popup
   * The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window. The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
   * touch
   * The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
   * wap
   * The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
   * The Authorization Server MAY also attempt to detect the capabilities of the User Agent and present an appropriate display.
   */
  display?: string;
  /**
   * Space-delimited, case-sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are:
   * none
   * The Authorization Server MUST NOT display any authentication or consent user interface pages. An error is returned if an End-User is not already authenticated or the Client does not have pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request. The error code will typically be login_required, interaction_required. This can be used as a method to check for existing authentication and/or consent.
   * login
   * The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot reauthenticate the End-User, it MUST return an error, typically login_required.
   * consent
   * The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client. If it cannot obtain consent, it MUST return an error, typically consent_required.
   * select_account
   * The Authorization Server SHOULD prompt the End-User to select a user account. This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple accounts that they might have current sessions for. If it cannot obtain an account selection choice made by the End-User, it MUST return an error, typically account_selection_required.
   * The prompt parameter can be used by the Client to make sure that the End-User is still present for the current session or to bring attention to the request. If this parameter contains none with any other value, an error is returned.
   */
  prompt?: string;
  max_age?: string; // Maximum Authentication Age.
  /**
   * End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation). An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
   */
  ui_locales?: string;
  /**
   * End-User's preferred languages and scripts for Claims being returned, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
   */
  claims_locales?: string;
  /**
   * Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service. It is RECOMMENDED that the hint value match the value used for discovery. This value MAY also be a phone number in the format specified for the phone_number Claim. The use of this parameter is left to the OP's discretion.
   */
  login_hint?: string;
  /**
   * Requested Authentication Context Class Reference values. Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this authentication request, with the values appearing in order of preference. The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value, as specified in Section 2.2. The acr Claim is requested as a Voluntary Claim by this parameter.
   */
  acr_values?: string;
  // iss: string;
  response_mode: ResponseMode;
  response_context: ResponseContext;

  request?: string; // TODO Request Object value, as specified in Section 6.1. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.
  request_uri?: string; //URL where Request Object value can be retrieved from, as specified in Section 6.2.

  state?: string;
  nonce: string;
  did_doc?: DIDDocument;
  claims?: ClaimPayload; // claims parameter value, as specified in Section 5.5.
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
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  nonce?: string;
  state?: string;
  registration: ResponseRegistrationOpts;
  responseMode?: ResponseMode;
  did: string;
  vp?: VerifiablePresentationResponseOpts[];
  expiresIn?: number;
}

export interface AuthenticationResponsePayload extends JWTPayload {
  iss: ResponseIss.SELF_ISSUED_V2 | string; // The SIOP V2 spec mentions this is required, but current implementations use the kid/did here
  sub: string; // did (or thumbprint of sub_jwk key when type is jkt)
  sub_type: SubjectIdentifierType;
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

//FIXME: based on https://openid.net/specs/openid-connect-core-1_0.html#IDToken we can have following properties in here:
/**
 * iss
 * REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
 * sub
 * REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
 * aud
 * REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
 * exp
 * REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
 * iat
 * REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
 * auth_time
 * Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
 * nonce
 * String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
 * acr
 * OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The acr value is a case sensitive string.
 * amr
 * OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The definition of particular values to be used in the amr Claim is beyond the scope of this specification. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The amr value is an array of case sensitive strings.
 * azp
 * OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party. It MAY be included even when the authorized party is the same as the sole audience. The azp value is a case sensitive string containing a StringOrURI value.
 */
export interface IdTokenClaimPayload {
  verifiable_presentations?: VerifiablePresentationsPayload[];

  [x: string]: unknown;
}

export interface VpTokenClaimPayload {
  presentation_definition: PresentationDefinitionV1 | PresentationDefinitionV2;

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
  authorizationEndpoint?: Schema.OPENID | string;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  scopesSupported?: Scope[] | Scope;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  subjectTypesSupported?: SubjectType[] | SubjectType;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  idTokenSigningAlgValuesSupported?: KeyAlgo[] | KeyAlgo;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  didsSupported?: boolean;
  didMethodsSupported?: string[] | string;
  credentialSupported?: boolean;
  credentialEndpoint?: string;
  credentialFormatsSupported?: CredentialFormat[] | CredentialFormat;
  credentialClaimsSupported?: string[] | string;
  credentialName?: string;
}

export interface DiscoveryMetadataPayload {
  authorization_endpoint: Schema | string;
  issuer: ResponseIss;
  //FIXME should it be ResponseType[]? and based on https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery should we remove the single?
  response_types_supported: [ResponseType] | ResponseType;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  scopes_supported: Scope[] | Scope;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  subject_types_supported: SubjectType[] | SubjectType;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  id_token_signing_alg_values_supported: KeyAlgo[] | KeyAlgo;
  //FIXME: should we remove the single one? (https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery)
  request_object_signing_alg_values_supported: SigningAlgo[] | SigningAlgo;
  //FIXME: we might wanna add the following: REQUIRED. A JSON array of strings representing URI scheme identifiers and optionally method names of supported Subject Syntax Types defined in {#sub-syntax-type}. When Subject Syntax Type is JWK Thumbprint, valid value is urn:ietf:params:oauth:jwk-thumbprint defined in [JWK-Thumbprint-URI]. When Subject Syntax Type is Decentralized Identifier, valid values MUST be a did: prefix followed by a supported DID method without a : suffix. For example, support for the DID method with a method-name "example" would be represented by did:example. Support for all DID methods is indicated by sending did without any method-name.
  //subject_syntax_types_supported: string[]
  //FIXME: we might wanna add the following: OPTIONAL. A JSON array of strings containing the list of ID token types supported by the OP, the default value is attester_signed. The ID Token types defined in this specification are:
  //id_token_types_supported?: string[]
  //FIXME: we might wanna add the following: ? (the spec is not clear whether its REQUIRED or OPTIONAL). self-issued id token, i.e. the id token is signed with key material under the end-user's control.
  //subject_signed: IdToken
  //FIXME: we might wanna add the following: ? (the spec is not clear whether its REQUIRED or OPTIONAL). the id token is issued by the party operating the OP, i.e. this is the classical id token as defined in [OpenID.Core].
  //attester_signed: IdToken
  //FIXME: probably don't need this anymore
  dids_supported: boolean;
  //FIXME: probably don't need this anymore
  did_methods_supported: string[] | string;
  //FIXME: probably don't need this anymore
  credential_supported: boolean;
  //FIXME: probably don't need this anymore
  credential_endpoint: string;
  //FIXME: probably don't need this anymore. plus we have to separate Metadata Error Response and Metadata Success Response
  credential_formats_supported: CredentialFormat[] | CredentialFormat;
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
  credentialFormatsSupported: CredentialFormat[] | CredentialFormat;
}

export interface RPRegistrationMetadataPayload {
  subject_identifiers_supported: SubjectIdentifierType[] | SubjectIdentifierType;
  did_methods_supported?: string[] | string;
  credential_formats_supported: CredentialFormat[] | CredentialFormat;
}

export interface CommonSupportedMetadata {
  did_methods_supported?: string[];
  credential_formats_supported: string[];
}

export type ObjectBy = {
  type: PassBy.REFERENCE | PassBy.VALUE;
  referenceUri?: string; // for REFERENCE
};

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
}

export interface ExternalVerification {
  mode: VerificationMode;
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
  resolveOpts: ResolveOpts;
}

export interface VerifyAuthenticationRequestOpts {
  verification: InternalVerification | ExternalVerification; // To use internal verification or external hosted verification
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // If provided the nonce in the request needs to match
  // redirectUri?: string;
}

export interface VerifyAuthenticationResponseOpts {
  verification: InternalVerification | ExternalVerification;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // mandatory? // To verify the response against the supplied nonce
  state?: string; // mandatory? // To verify the response against the supplied state
  audience: string; // The audience/redirect_uri
  claims?: ClaimOpts; // The claims, typically the same values used during request creation
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
  PHONE = 'phone'
}

export enum ResponseType {
  ID_TOKEN = 'id_token',
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
