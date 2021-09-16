import {DIDDocument, VerificationMethod} from "did-resolver";
import {JWK} from "jose/types";

import {JWTPayload} from "./JWT-types";
import {OidcClaim, VerifiablePresentation} from "./SSI-Types";

export const expirationTime = 10 * 60;

export interface DidAuthRequest extends JWTPayload {
    iss: string;
    scope: Scope;
    response_type: ResponseType;
    response_mode: ResponseMode;
    response_context: ResponseContext;
    registration: RegistrationJwksUri | RegistrationJwks;
    client_id: string;
    state?: string;
    nonce?: string;
    did_doc?: DIDDocument;
    claims?: OidcClaim;
}

export interface DidAuthResponse extends JWTPayload {
    iss: ResponseIss.SELF_ISSUE;
    sub: string;
    aud: string;
    exp?: number;
    iat?: number;
    nonce: string;
    did: string;
    vp?: VerifiablePresentation;
    claims?: ResponseClaims;
    sub_jwk: JWK;
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
    XC20P = "XC20P", // default
}


export enum EncKeyAlgorithm {
    ECDH_ES = "ECDH-ES", // default
}


export enum PassBy {
    REFERENCE = "REFERENCE",
    VALUE = "VALUE",
}

export enum ResponseContext {
    RP = "rp",
    WALLET = "wallet",
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

export interface AuthRequestResponse {
    jwt: string;
    nonce: string;
    state: string;
}

export const isRequestOpts = (
    object: RequestOpts | ResponseOpts
): object is RequestOpts => "requestBy" in object;

export const isResponseOpts = (
    object: RequestOpts | ResponseOpts
): object is ResponseOpts => "did" in object;


export interface RequestOpts {
    OPUri?: string;
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
    FRAGMENT = "fragment",
    FORM_POST = "form_post",
    QUERY = "query"
}

export interface SignatureResponse {
    jws: string;
}

export declare enum UrlEncodingFormat {
    FORM_URL_ENCODED = "application/x-www-form-urlencoded"
}

export declare type UriDidAuth = {
    urlEncoded: string;
    encoding: UrlEncodingFormat;
};

export interface UriResponse extends UriDidAuth {
    responseMode?: ResponseMode;
    bodyEncoded?: string;
}

export declare enum KeyType {
    EC = "EC"
}

export declare enum KeyCurve {
    SECP256k1 = "secp256k1",
    ED25519 = "ed25519"

}

export declare enum KeyAlgo {
    // ES256KR = "ES256K-R",
    EDDSA = "EdDSA",
    // RS256 = "RS256",
    ES256K = "ES256K"
}

export declare enum Scope {
    OPENID_DIDAUTHN = "openid did_authn"
}

export declare enum ResponseType {
    ID_TOKEN = "id_token"
}

export declare enum ResponseIss {
    SELF_ISSUE = "https://self-issued.me/v2"
}
