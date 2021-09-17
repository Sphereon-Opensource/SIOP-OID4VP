import { decodeJWT, EdDSASigner, ES256KSigner } from 'did-jwt';
import { createJWT, JWTHeader, JWTOptions, JWTPayload, JWTVerifyOptions, verifyJWT } from 'did-jwt/lib/JWT';
import { JWTDecoded } from 'did-jwt/src/JWT';
import { Resolvable } from 'did-resolver';

import { DEFAULT_PROOF_TYPE, PROOF_TYPE_EDDSA } from '../config';
import { DidAuth } from '../types';
import {
  expirationTime,
  isRequestOpts,
  KeyAlgo,
  ResponseIss,
  ResponseOpts,
  SignatureResponse,
  SIOPRequest,
  SIOPRequestOpts,
  SIOPResponse,
} from '../types/DidAuth-types';
import { VerifiedJWT } from '../types/JWT-types';
import { KeyUtils } from '../util';
import { base58ToBase64String } from '../util/Encodings';
import { postWithBearerToken } from '../util/HttpUtils';
import { isEd25519DidKeyMethod, isEd25519JWK, isExternalSignature, isInternalSignature } from '../util/KeyUtils';

import { didJwt } from './index';

/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyDidJWT('did:eosio:example', resolver, {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did                 // DID of signer
 *      const payload = obj.payload
 *      const doc = obj.doc                 // DID Document of signer
 *      const jwt = obj.jwt                 // JWT
 *      const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
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
  return createJWT(payload, { issuer, signer, alg: header.alg, expiresIn, canonicalize }, header);
}

export async function signDidJwtPayload(payload: SIOPRequest | SIOPResponse, opts: SIOPRequestOpts | ResponseOpts) {
  if (isInternalSignature(opts.signatureType)) {
    return didJwt.signDidJwtInternal(
      payload,
      isRequestOpts(opts) ? opts.signatureType.did : ResponseIss.SELF_ISSUED_V2,
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid
    );
  } else if (isExternalSignature(opts.signatureType)) {
    return didJwt.signDidJwtExternal(
      payload,
      opts.signatureType.signatureUri,
      opts.signatureType.authZToken,
      opts.signatureType.kid
    );
  } else {
    throw new Error('BAD_PARAMS');
  }
}

export async function signDidJwtInternal(
  payload: SIOPRequest | SIOPResponse,
  issuer: string,
  hexPrivateKey: string,
  kid?: string
) {
  const algo = isEd25519DidKeyMethod(issuer) || isEd25519JWK(payload.sub_jwk) ? KeyAlgo.EDDSA : KeyAlgo.ES256K;
  // const request = !!payload.client_id;
  const signer =
    algo == KeyAlgo.EDDSA
      ? EdDSASigner(base58ToBase64String(KeyUtils.getBase58PrivateKeyFromHexPrivateKey(hexPrivateKey)))
      : ES256KSigner(hexPrivateKey.replace('0x', ''));

  const header = {
    alg: algo,
    kid: kid || (issuer === ResponseIss.SELF_ISSUED_V2 ? `${payload.did}#keys-1` : issuer),
  };
  const options = {
    issuer,
    signer,
    expiresIn: DidAuth.expirationTime,
  };

  return await createDidJWT({ ...payload }, options, header);
}

export async function signDidJwtExternal(
  payload: SIOPRequest | SIOPResponse,
  signatureUri: string,
  authZToken: string,
  kid?: string
): Promise<string> {
  const alg =
    isEd25519DidKeyMethod(payload.did) || isEd25519DidKeyMethod(payload.iss)
      ? DidAuth.KeyAlgo.EDDSA
      : DidAuth.KeyAlgo.ES256K;

  const body = {
    issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.did,
    payload,
    type: alg === DidAuth.KeyAlgo.EDDSA ? PROOF_TYPE_EDDSA : DEFAULT_PROOF_TYPE,
    expiresIn: expirationTime,
    alg,
    selfIssued: payload.iss.includes(DidAuth.ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
    kid,
  };

  const response = await postWithBearerToken(signatureUri, body, authZToken);
  return ((await response.json()) as SignatureResponse).jws;
}

export function getAudience(jwt: string) {
  const { payload } = decodeJWT(jwt);
  if (!payload) {
    throw new Error('NO_AUDIENCE');
  } else if (!payload.aud) {
    return undefined;
  } else if (Array.isArray(payload.aud)) {
    throw new Error('INVALID_AUDIENCE');
  }

  return payload.aud;
}

export function getIssuerDid(jwt: string): string {
  const { payload } = parseJWT(jwt);
  if (!payload.iss) {
    throw new Error('NO_ISS_DID');
  }

  if (payload.iss === DidAuth.ResponseIss.SELF_ISSUED_V2) {
    return (payload as SIOPResponse).did;
  } else {
    return payload.iss;
  }
}

export function parseJWT(jwt: string): JWTDecoded {
  const decodedJWT = decodeJWT(jwt);
  const { payload, header } = decodedJWT;
  if (!payload || !header) {
    throw new Error('NO_ISS_DID');
  }
  return decodedJWT;
}

export function getNetworkFromDid(did: string): string {
  const network = 'mainnet'; // default
  const splitDidFormat = did.split(':');
  if (splitDidFormat.length === 4) {
    return splitDidFormat[2];
  }
  if (splitDidFormat.length > 4) {
    return `${splitDidFormat[2]}:${splitDidFormat[3]}`;
  }
  return network;
}
