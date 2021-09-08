import type {DIDResolutionResult, VerificationMethod} from 'did-resolver'
import type {JWK} from "jose/types";
import {ProofPurposeTypes} from "did-jwt/lib/JWT";

export type Signer = (data: string | Uint8Array) => Promise<string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>


export interface JWTOptions {
    issuer: string
    signer: Signer
    expiresIn?: number
    canonicalize?: boolean
}

export interface VerifyOptions {
    audience?: string
    callbackUrl?: string
    skewTime?: number
    /** See https://www.w3.org/TR/did-spec-registries/#verification-relationships */
    proofPurpose?: ProofPurposeTypes
}

export interface JWSCreationOptions {
    canonicalize?: boolean
}

export interface DIDAuthenticator {
    authenticators: VerificationMethod[]
    issuer: string
    didResolutionResult: DIDResolutionResult
}


export interface JWTDecoded {
    header: JWTHeader
    payload: JWTPayload
    signature: string
    data: string
}

export interface JWSDecoded {
    header: JWTHeader
    payload: string
    signature: string
    data: string
}


export interface JWTHeader {
    typ: 'JWT'
    alg: string
    jwk?: string;
    jku?: string;
    kid?: string;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [x: string]: any
}

export interface JWTPayload {
    iss?: string
    sub?: string
    aud?: string | string[]
    iat?: number
    nbf?: number
    exp?: number
    rexp?: number
    jti?: string

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [x: string]: any
}

export interface VerifiedJWT {
    payload: Partial<JWTPayload>
    didResolutionResult: DIDResolutionResult
    issuer?: string
    signer?: VerificationMethod
    jwt: string
}

export interface PublicKeyTypes {
    [name: string]: string[]
}



export interface JWKECKey extends JWK {
    kty: "EC";
    crv: ECCurve;
    x: string;
    y: string;
    d?: string;
}

export declare type ECCurve = "P-256" | "secp256k1" | "P-384" | "P-521";


