import {
  createJWT,
  decodeJWT,
  EdDSASigner,
  ES256KSigner,
  ES256Signer,
  hexToBytes,
  JWTHeader,
  JWTOptions,
  JWTPayload,
  JWTVerifyOptions,
  Signer,
  verifyJWT,
} from 'did-jwt';
import { JWTDecoded } from 'did-jwt/lib/JWT';
import { Resolvable } from 'did-resolver';

import { ClaimPayloadCommonOpts } from '../authorization-request';
import { AuthorizationResponseOpts } from '../authorization-response';
import { post } from '../helpers';
import { RequestObjectOpts } from '../request-object';
import {
  DEFAULT_EXPIRATION_TIME,
  IDTokenPayload,
  isExternalSignature,
  isInternalSignature,
  isResponseOpts,
  isResponsePayload,
  isSuppliedSignature,
  RequestObjectPayload,
  ResponseIss,
  SignatureResponse,
  SigningAlgo,
  SIOPErrors,
  SIOPResonse,
  VerifiedJWT,
} from '../types';

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
  console.log('verifyDidJWT')
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
  console.log('createDidJWT')
  return createJWT(payload, { issuer, signer, expiresIn, canonicalize }, header);
}

export async function signDidJwtPayload(
  payload: IDTokenPayload | RequestObjectPayload,
  opts: RequestObjectOpts<ClaimPayloadCommonOpts> | AuthorizationResponseOpts
) {
  console.log('signDidJwtPayload')
  const isResponse = isResponseOpts(opts) || isResponsePayload(payload);
  if (isResponse) {
    if (!payload.iss || (payload.iss !== ResponseIss.SELF_ISSUED_V2 && payload.iss !== payload.sub)) {
      throw new Error(SIOPErrors.NO_SELFISSUED_ISS);
    }
  }
  if (isInternalSignature(opts.signatureType)) {
    console.log('isInternalSignature')
    return signDidJwtInternal(
      payload,
      isResponse ? payload.iss : opts.signatureType.did,
      opts.signatureType.hexPrivateKey,
      opts.signatureType.alg,
      opts.signatureType.kid,
      opts.signatureType.customJwtSigner
    );
  } else if (isExternalSignature(opts.signatureType)) {
    return signDidJwtExternal(
      payload,
      opts.signatureType.signatureUri,
      opts.signatureType.authZToken,
      opts.signatureType.alg,
      opts.signatureType.kid
    );
  } else if (isSuppliedSignature(opts.signatureType)) {
    return signDidJwtSupplied(
      payload,
      isResponse ? payload.iss : opts.signatureType.did,
      opts.signatureType.signature,
      opts.signatureType.alg,
      opts.signatureType.kid
    );
  } else {
    throw new Error(SIOPErrors.BAD_SIGNATURE_PARAMS);
  }
}

async function signDidJwtInternal(
  payload: IDTokenPayload | RequestObjectPayload,
  issuer: string,
  hexPrivateKey: string,
  alg: SigningAlgo,
  kid: string,
  customJwtSigner?: Signer
): Promise<string> {
  console.log('signDidJwtInternal')
  const signer = determineSigner(alg, hexPrivateKey, customJwtSigner);
  const header = {
    alg,
    kid,
  };
  const options = {
    issuer,
    signer,
    expiresIn: DEFAULT_EXPIRATION_TIME,
  };

  return await createDidJWT({ ...payload }, options, header);
}

async function signDidJwtExternal(
  payload: IDTokenPayload | RequestObjectPayload,
  signatureUri: string,
  authZToken: string,
  alg: SigningAlgo,
  kid?: string
): Promise<string> {
  console.log('signDidJwtExternal')
  const body = {
    issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.sub,
    payload,
    expiresIn: DEFAULT_EXPIRATION_TIME,
    alg,
    selfIssued: payload.iss.includes(ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
    kid,
  };

  const response: SIOPResonse<SignatureResponse> = await post(signatureUri, JSON.stringify(body), { bearerToken: authZToken });
  return response.successBody.jws;
}

async function signDidJwtSupplied(
  payload: IDTokenPayload | RequestObjectPayload,
  issuer: string,
  signer: Signer,
  alg: SigningAlgo,
  kid: string
): Promise<string> {
  console.log('signDidJwtSupplied')
  const header = {
    alg,
    kid,
  };
  const options = {
    issuer,
    signer,
    expiresIn: DEFAULT_EXPIRATION_TIME,
  };

  return await createDidJWT({ ...payload }, options, header);
}

const determineSigner = (alg: SigningAlgo, hexPrivateKey?: string, customSigner?: Signer): Signer => {
  console.log('signDidJwtInternal')
  if (customSigner) {
    return customSigner;
  } else if (!hexPrivateKey) {
    throw new Error('no private key provided');
  }
  const privateKey = hexToBytes(hexPrivateKey.replace('0x', ''));
  switch (alg) {
    case SigningAlgo.EDDSA:
      return EdDSASigner(privateKey);
    case SigningAlgo.ES256:
      return ES256Signer(privateKey);
    case SigningAlgo.ES256K:
      return ES256KSigner(privateKey);
    case SigningAlgo.RS256:
      throw Error('RS256 is not supported yet');
  }
};

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
  return payload.iss.includes(ResponseIss.SELF_ISSUED_V1) || payload.iss.includes(ResponseIss.SELF_ISSUED_V2) || payload.iss === payload.sub;
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
    throw new Error(SIOPErrors.BAD_PARAMS + 'did should be usable');
  }
  const split = did.split(':');
  if (split.length == 1 && did.length > 0) {
    return did;
  } else if (!did.startsWith('did:') || split.length < 2) {
    throw new Error(SIOPErrors.BAD_PARAMS + 'did should start with prefix \'did:\'');
  }

  return split[1];
}

export function getNetworkFromDid(did: string): string {
  const network = 'mainnet'; // default
  const split = did.split(':');
  if (!did.startsWith('did:') || split.length < 2) {
    throw new Error(SIOPErrors.BAD_PARAMS + 'did should start with prefix \'did:\'');
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
