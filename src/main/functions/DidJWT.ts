import { createJWT, decodeJWT, EdDSASigner, ES256KSigner, hexToBytes, JWTHeader, JWTOptions, JWTPayload, JWTVerifyOptions, verifyJWT } from 'did-jwt';
import { JWTDecoded } from 'did-jwt/lib/JWT';
import { Resolvable } from 'did-resolver';

import { DEFAULT_PROOF_TYPE, PROOF_TYPE_EDDSA } from '../config';
import {
  AuthorizationRequestOpts,
  AuthorizationResponseOpts,
  EcdsaSignature,
  expirationTime,
  IDTokenPayload,
  isExternalSignature,
  isInternalSignature,
  isResponseOpts,
  isResponsePayload,
  isSuppliedSignature,
  KeyAlgo,
  RequestObjectPayload,
  ResponseIss,
  SignatureResponse,
  SIOPErrors,
  VerifiedJWT,
} from '../types';

import { isEd25519DidKeyMethod, isEd25519JWK, postWithBearerToken } from './';

/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyDidJWT('did:key:example', resolver, {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did                 // DIDres of signer
 *      const payload = obj.payload
 *      const doc = obj.doc                 // DIDres Document of signer
 *      const JWT = obj.JWT                 // JWT
 *      const signerKeyId = obj.signerKeyId // ID of key in DIDres document that signed JWT
 *      ...
 *  })
 *
 *  @param    {String}            jwt                   a JSON Web Token to verify
 *  @param    {Resolvable}        resolver
 *  @param    {JWTVerifyOptions}  [options]             Options
 *  @param    {String}            options.audience      DID of the recipient of the JWT
 *  @param    {String}            options.callbackUrl   callback url in JWT
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a response object or rejects with an error
 */
export async function verifyDidJWT(jwt: string, resolver: Resolvable, options: JWTVerifyOptions): Promise<VerifiedJWT> {
  return verifyJWT(jwt, { resolver, ...options });
}

/**
 *  Creates a signed JWT given an address which becomes the issuer, a signer function, and a payload for which the signature is over.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(JWT => {
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
  header: Partial<JWTHeader>
): Promise<string> {
  return createJWT(payload, { issuer, signer, alg: header.alg, expiresIn, canonicalize }, header);
}

export async function signDidJwtPayload(payload: IDTokenPayload | RequestObjectPayload, opts: AuthorizationRequestOpts | AuthorizationResponseOpts) {
  const isResponse = isResponseOpts(opts) || isResponsePayload(payload);
  if (isResponse) {
    if (!payload.iss || payload.iss !== ResponseIss.SELF_ISSUED_V2) {
      throw new Error(SIOPErrors.NO_SELFISSUED_ISS);
    }
  }
  if (isInternalSignature(opts.signatureType)) {
    return signDidJwtInternal(payload, isResponse ? payload.iss : opts.signatureType.did, opts.signatureType.hexPrivateKey, opts.signatureType.kid);
  } else if (isExternalSignature(opts.signatureType)) {
    return signDidJwtExternal(payload, opts.signatureType.signatureUri, opts.signatureType.authZToken, opts.signatureType.kid);
  } else if (isSuppliedSignature(opts.signatureType)) {
    return signDidJwtSupplied(payload, isResponse ? payload.iss : opts.signatureType.did, opts.signatureType.signature, opts.signatureType.kid);
  } else {
    throw new Error(SIOPErrors.BAD_SIGNATURE_PARAMS);
  }
}

async function signDidJwtInternal(
  payload: IDTokenPayload | RequestObjectPayload,
  issuer: string,
  hexPrivateKey: string,
  kid?: string
): Promise<string> {
  // todo: Create method. We are doing roughly the same multiple times
  const algo =
    isEd25519DidKeyMethod(issuer) ||
    isEd25519DidKeyMethod(payload.kid) ||
    isEd25519DidKeyMethod(kid) ||
    isEd25519DidKeyMethod(payload.sub) ||
    isEd25519JWK(payload.sub_jwk)
      ? KeyAlgo.EDDSA
      : KeyAlgo.ES256K;
  // const request = !!payload.client_id;
  const signer = algo == KeyAlgo.EDDSA ? EdDSASigner(hexToBytes(hexPrivateKey)) : ES256KSigner(hexToBytes(hexPrivateKey.replace('0x', '')));

  const header = {
    alg: algo,
    kid: kid || `${payload.sub}#keys-1`,
  };
  const options = {
    issuer,
    signer,
    expiresIn: expirationTime,
  };

  return await createDidJWT({ ...payload }, options, header);
}

async function signDidJwtExternal(
  payload: IDTokenPayload | RequestObjectPayload,
  signatureUri: string,
  authZToken: string,
  kid?: string
): Promise<string> {
  // todo: Create method. We are doing roughly the same multiple times
  const alg = isEd25519DidKeyMethod(payload.sub) || isEd25519DidKeyMethod(payload.iss) || isEd25519DidKeyMethod(kid) ? KeyAlgo.EDDSA : KeyAlgo.ES256K;

  const body = {
    issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.sub,
    payload,
    type: alg === KeyAlgo.EDDSA ? PROOF_TYPE_EDDSA : DEFAULT_PROOF_TYPE,
    expiresIn: expirationTime,
    alg,
    selfIssued: payload.iss.includes(ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
    kid,
  };

  const response = await postWithBearerToken(signatureUri, body, authZToken);
  return ((await response.json()) as SignatureResponse).jws;
}

async function signDidJwtSupplied(
  payload: IDTokenPayload | RequestObjectPayload,
  issuer: string,
  signer: (data: string | Uint8Array) => Promise<EcdsaSignature | string>,
  kid: string
): Promise<string> {
  // todo: Create method. We are doing roughly the same multiple times
  const algo =
    isEd25519DidKeyMethod(issuer) ||
    isEd25519DidKeyMethod(payload.kid) ||
    isEd25519DidKeyMethod(kid) ||
    isEd25519DidKeyMethod(payload.sub) ||
    isEd25519JWK(payload.sub_jwk)
      ? KeyAlgo.EDDSA
      : KeyAlgo.ES256K;
  const header = {
    alg: algo,
    kid,
  };
  const options = {
    issuer,
    signer,
    expiresIn: expirationTime,
  };

  return await createDidJWT({ ...payload }, options, header);
}

export function getAudience(jwt: string) {
  const { payload } = decodeJWT(jwt);
  if (!payload) {
    throw new Error(SIOPErrors.NO_AUDIENCE);
  } else if (!payload.aud) {
    return undefined;
  } else if (Array.isArray(payload.aud)) {
    throw new Error(SIOPErrors.INVALID_AUDIENCE);
  }

  return payload.aud;
}

//TODO To enable automatic registration, it cannot be a did, but HTTPS URL
function assertIssSelfIssuedOrDid(payload: JWTPayload) {
  if (!payload.sub || !payload.sub.startsWith('did:') || !payload.iss || !isIssSelfIssued(payload)) {
    throw new Error(SIOPErrors.NO_ISS_DID);
  }
}

export function getSubDidFromPayload(payload: JWTPayload, header?: JWTHeader): string {
  assertIssSelfIssuedOrDid(payload);

  if (isIssSelfIssued(payload)) {
    let did;
    if (payload.sub && payload.sub.startsWith('did:')) {
      did = payload.sub;
    }
    if (!did && header && header.kid && header.kid.startsWith('did:')) {
      did = header.kid.split('#')[0];
    }
    if (did) {
      return did;
    }
  }
  return payload.sub;
}

export function isIssSelfIssued(payload: JWTPayload): boolean {
  return payload.iss.includes(ResponseIss.SELF_ISSUED_V1) || payload.iss.includes(ResponseIss.SELF_ISSUED_V2);
}

export function getIssuerDidFromJWT(jwt: string): string {
  const { payload } = parseJWT(jwt);
  return getSubDidFromPayload(payload);
}

export function parseJWT(jwt: string): JWTDecoded {
  const decodedJWT = decodeJWT(jwt);
  const { payload, header } = decodedJWT;
  if (!payload || !header) {
    throw new Error(SIOPErrors.NO_JWT);
  }
  return decodedJWT;
}

export function getMethodFromDid(did: string): string {
  if (!did) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  const split = did.split(':');
  if (split.length == 1 && did.length > 0) {
    return did;
  } else if (!did.startsWith('did:') || split.length < 2) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }

  return split[1];
}

export function getNetworkFromDid(did: string): string {
  const network = 'mainnet'; // default
  const split = did.split(':');
  if (!did.startsWith('did:') || split.length < 2) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }

  if (split.length === 4) {
    return split[2];
  } else if (split.length > 4) {
    return `${split[2]}:${split[3]}`;
  }
  return network;
}

/**
 * Since the OIDC SIOP spec incorrectly uses 'did:<method>:' and calls that a method, we have to fix it
 * @param didOrMethod
 */
export function toSIOPRegistrationDidMethod(didOrMethod: string) {
  let prefix = didOrMethod;
  if (!didOrMethod.startsWith('did:')) {
    prefix = 'did:' + didOrMethod;
  }
  const split = prefix.split(':');
  return `${split[0]}:${split[1]}`;
}
