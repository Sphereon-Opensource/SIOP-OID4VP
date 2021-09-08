import {verifyJWT as verifyDidJWT, createJWT as createDidJWT} from "did-jwt/lib/JWT";
import {JWTHeader, JWTOptions, JWTPayload, VerifiedJWT, VerifyOptions} from "./JWT";



export async function verifyJWT(
    jwt: string,
    options: VerifyOptions = {
        audience: undefined,
        callbackUrl: undefined,
        skewTime: undefined,
        proofPurpose: undefined,
    }
): Promise<VerifiedJWT> {
    //todo add resolver
    return verifyDidJWT(jwt, options);
}




export async function createJWT(
    payload: Partial<JWTPayload>,
    { issuer, signer, expiresIn, canonicalize }: JWTOptions,
    header: Partial<JWTHeader> = {}
): Promise<string> {
    return createDidJWT(payload, {issuer, signer, alg: header.alg, expiresIn, canonicalize}, header);
}

