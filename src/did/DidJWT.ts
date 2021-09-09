import {verifyJWT, createJWT, JWTPayload, JWTOptions, JWTHeader, JWTVerifyOptions} from "did-jwt/lib/JWT";
import {VerifiedJWT} from "../JWT";
import {Resolvable} from "did-resolver";


/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyJWT('did:eosio:example', {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did // DID of signer
 *      const payload = obj.payload
 *      const doc = obj.doc // DID Document of signer
 *      const jwt = obj.jwt
 *      const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
 *      ...
 *  })
 *
 *  @param    {String}            jwt                a JSON Web Token to verifyDidJWT
 *  @param resolver
 *  @param    {Object}            [options]           an unsigned credential object
 *  @param    {String}            options.audience    DID of the recipient of the JWT
 *  @param    {String}            options.callbackUrl callback url in JWT
 *  @return   {Promise<Object, Error>}               a promise which resolves with a response object or rejects with an error
 */
export async function verifyDidJWT(
    jwt: string,
    resolver: Resolvable,
    options: JWTVerifyOptions = {
        resolver: resolver,
        audience: undefined,
        callbackUrl: undefined,
        skewTime: undefined,
        proofPurpose: undefined,
    }
): Promise<VerifiedJWT> {
    return verifyJWT(jwt, options);
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
export async function createDidJWT(
    payload: Partial<JWTPayload>,
    { issuer, signer, expiresIn, canonicalize }: JWTOptions,
    header: Partial<JWTHeader> = {}
): Promise<string> {
    return createJWT(payload, {issuer, signer, alg: header.alg, expiresIn, canonicalize}, header);
}

