
import { DIDDocument, VerificationMethod } from "did-resolver";
import {JWKECKey, JWTPayload} from "./JWT-types";

export declare const expirationTime: number;
export interface DidAuthRequest extends JWTPayload {
    iss: string;
    scope: Scope;
    response_type: ResponseType;
    client_id: string;
    nonce: string;
    did_doc?: DIDDocument;
    claims?: RequestClaims;
}
export interface DidAuthResponse extends JWTPayload {
    iss: ResponseIss.SELF_ISSUE;
    sub: string;
    aud: string;
    exp?: number;
    iat?: number;
    nonce?: string;
    claims?: ResponseClaims;
    sub_jwk: JWKECKey;
}
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
export interface ResponseClaims {
    verified_claims?: string;
    encryption_key?: JsonWebKey;
}
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
    responseMode?: DidAuthResponseMode;
    claims?: ResponseClaims;
}
export interface DidAuthValidationResponse {
    signatureValidation: boolean;
    signer: VerificationMethod;
    payload: JWTPayload;
}
export declare enum DidAuthResponseMode {
    FRAGMENT = "fragment",
    FORM_POST = "form_post",
    QUERY = "query"
}
export declare enum UrlEncodingFormat {
    FORM_URL_ENCODED = "application/x-www-form-urlencoded"
}
export declare type UriDidAuth = {
    urlEncoded: string;
    encoding: UrlEncodingFormat;
};
export interface UriResponse extends UriDidAuth {
    responseMode?: DidAuthResponseMode;
    bodyEncoded?: string;
}

export declare enum KeyType {
    EC = "EC"
}
export declare enum KeyCurve {
    SECP256k1 = "secp256k1"
}
export declare enum KeyAlgo {
    // ES256KR = "ES256K-R",
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
