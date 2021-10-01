import { EdDSASigner, ES256KSigner } from 'did-jwt';
import { Resolvable } from 'did-resolver';

import {
  createJWT,
  decodeJWT,
  JWTDecoded,
  JWTHeader,
  JWTOptions,
  JWTPayload,
  JWTVerifyOptions,
  verifyJWT,
} from '../../did-jwt-fork/JWT';
import { DEFAULT_PROOF_TYPE, PROOF_TYPE_EDDSA } from '../config';
import { PEManager } from '../index';
import { JWT, SIOP, SIOPErrors } from '../types';
import {
  AuthenticationRequestOpts,
  AuthenticationRequestPayload,
  AuthenticationResponseOpts,
  AuthenticationResponsePayload,
  expirationTime,
  isExternalSignature,
  isInternalSignature,
  isResponseOpts,
  isResponsePayload,
  KeyAlgo,
  PresentationExchangeContext,
  ResponseIss,
  SignatureResponse,
} from '../types/SIOP.types';

import { base58ToBase64String } from './Encodings';
import { postWithBearerToken } from './HttpUtils';
import { isEd25519DidKeyMethod, isEd25519JWK } from './Keys';

import { Keys } from './index';

/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyDidJWT('did:eosio:example', resolver, {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
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
export async function verifyDidJWT(
  jwt: string,
  resolver: Resolvable,
  options: JWTVerifyOptions
): Promise<JWT.VerifiedJWT> {
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

export async function signDidJwtPayload(
  payload: AuthenticationRequestPayload | AuthenticationResponsePayload,
  opts: AuthenticationRequestOpts | AuthenticationResponseOpts
) {
  const isResponse = isResponseOpts(opts) || isResponsePayload(payload);
  if (isResponse) {
    if (!payload.iss || payload.iss !== ResponseIss.SELF_ISSUED_V2) {
      throw new Error(SIOPErrors.NO_SELFISSUED_ISS);
    }
  }
  if (isInternalSignature(opts.signatureType)) {
    return signDidJwtInternal(
      payload,
      isResponse ? payload.iss : opts.signatureType.did,
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid
    );
  } else if (isExternalSignature(opts.signatureType)) {
    return signDidJwtExternal(
      payload,
      opts.signatureType.signatureUri,
      opts.signatureType.authZToken,
      opts.signatureType.kid
    );
  } else {
    throw new Error(SIOPErrors.BAD_SIGNATURE_PARAMS);
  }
}

async function signDidJwtInternal(
  payload: AuthenticationRequestPayload | AuthenticationResponsePayload,
  issuer: string,
  hexPrivateKey: string,
  kid?: string
) {
  const algo =
    isEd25519DidKeyMethod(issuer) || isEd25519DidKeyMethod(payload.kid) || isEd25519JWK(payload.sub_jwk)
      ? KeyAlgo.EDDSA
      : KeyAlgo.ES256K;
  // const request = !!payload.client_id;
  const signer =
    algo == KeyAlgo.EDDSA
      ? EdDSASigner(base58ToBase64String(Keys.getBase58PrivateKeyFromHexPrivateKey(hexPrivateKey)))
      : ES256KSigner(hexPrivateKey.replace('0x', ''));

  const header = {
    alg: algo,
    kid: kid || `${payload.did}#keys-1`,
  };
  const options = {
    issuer,
    signer,
    expiresIn: SIOP.expirationTime,
  };

  return await createDidJWT({ ...payload }, options, header);
}

async function signDidJwtExternal(
  payload: AuthenticationRequestPayload | AuthenticationResponsePayload,
  signatureUri: string,
  authZToken: string,
  kid?: string
): Promise<string> {
  const alg =
    isEd25519DidKeyMethod(payload.did) || isEd25519DidKeyMethod(payload.iss) ? SIOP.KeyAlgo.EDDSA : SIOP.KeyAlgo.ES256K;

  const body = {
    issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.did,
    payload,
    type: alg === SIOP.KeyAlgo.EDDSA ? PROOF_TYPE_EDDSA : DEFAULT_PROOF_TYPE,
    expiresIn: expirationTime,
    alg,
    selfIssued: payload.iss.includes(SIOP.ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
    kid,
  };

  const response = await postWithBearerToken(signatureUri, body, authZToken);
  return ((await response.json()) as SignatureResponse).jws;
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

function assertIssSelfIssuedOrDid(payload: JWTPayload) {
  if (!payload.iss || !(payload.iss.startsWith('did:') || isIssSelfIssued(payload))) {
    throw new Error(SIOPErrors.NO_ISS_DID);
  }
}

export function getIssuerDidFromPayload(payload: JWTPayload, header?: JWTHeader): string {
  assertIssSelfIssuedOrDid(payload);

  if (isIssSelfIssued(payload)) {
    let did;
    if (payload.did) {
      did = payload.did;
    }
    if (!did && header && header.kid && header.kid.startsWith('did:')) {
      did = header.kid.split('#')[0];
    }
    if (did) {
      return did;
    }
  }
  return payload.iss;
}

export function isIssSelfIssued(payload: JWTPayload): boolean {
  return payload.iss.includes(ResponseIss.SELF_ISSUED_V1) || payload.iss.includes(ResponseIss.SELF_ISSUED_V2);
}

export function getIssuerDidFromJWT(jwt: string): string {
  const { payload } = parseJWT(jwt);
  return getIssuerDidFromPayload(payload);
}

export function parseJWT(jwt: string): JWTDecoded {
  const decodedJWT = decodeJWT(jwt);
  const { payload, header } = decodedJWT;
  if (!payload || !header) {
    throw new Error(SIOPErrors.NO_ISS_DID);
  }
  // Here we have to fetch the presentation_definition part of the decoded jwt
  if (PEManager.findValidPresentationDefinition(payload)) {
    payload['peContext'] = PresentationExchangeContext.PE;
  } else {
    payload['peContext'] = PresentationExchangeContext.NO_PE;
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
  return `${split[0]}:${split[1]}:`;
}
