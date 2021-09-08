import {verifyJWT as verifyDidJWT, createJWT as createDidJWT} from "did-jwt/lib/JWT";
import {JWTHeader, JWTOptions, JWTPayload, VerifiedJWT, VerifyOptions} from "./JWT";



export async function verify(
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



/**
 *  Creates a signed JWT given an address which becomes the issuer, a signer function, and a payload for which the signature is over.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(jwt => {
 *      ...
 *  })
 *
 *  @param    {Object}            payload               payload object
 *  @param    {Object}            [options]             an unsigned credential object
 *  @param    {String}            options.issuer        The DID of the issuer (signer) of JWT
 *  @param    {Signer}            options.signer        a `Signer` function, Please see `ES256KSigner` or `EdDSASigner`
 *  @param    {boolean}           options.canonicalize  optional flag to canonicalize header and payload before signing
 *  @param    {Object}            header                optional object to specify or customize the JWT header
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a signed JSON Web Token or rejects with an error
 */
export async function create(
    payload: Partial<JWTPayload>,
    { issuer, signer, expiresIn, canonicalize }: JWTOptions,
    header: Partial<JWTHeader> = {}
): Promise<string> {
    return createDidJWT(payload, {issuer, signer, alg: header.alg, expiresIn, canonicalize}, header);
}

