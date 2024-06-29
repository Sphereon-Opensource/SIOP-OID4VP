import { calculateJwkThumbprintUri, getDigestAlgorithmFromJwkThumbprintUri } from '../helpers';

import SIOPErrors from './Errors';
import { JWK, JwtHeader, JwtPayload } from './JWT.types';

export type JwtVerificationType = 'id-token' | 'request-object';

interface DidJwtVerifier {
  method: 'did';
  type: JwtVerificationType;

  didUrl: string;
}

interface X5cJwtVerifier {
  method: 'x5c';
  type: JwtVerificationType;

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  chain: Array<string>;

  /**
   * The jwt issuer
   */
  issuer: string;
}

type JwkJwtVerifier =
  | {
      method: 'jwk';
      type: 'id-token';

      jwk: JsonWebKey;
      jwkThumbprint: string;
    }
  | {
      method: 'jwk';
      type: 'request-object';

      jwk: JsonWebKey;
      jwkThumbprint?: never;
    };

interface CustomJwtVerifier extends Record<string, unknown> {
  method: 'custom';
}

export type JwtVerifier = DidJwtVerifier | X5cJwtVerifier | CustomJwtVerifier | JwkJwtVerifier;

export type JwtVerifierWithContext = JwtVerifier;

export const getJwtVerifierWithContext = async (
  jwt: { header: JwtHeader; payload: JwtPayload },
  type: JwtVerificationType,
): Promise<JwtVerifierWithContext> => {
  if (jwt.header.kid?.startsWith('did:')) {
    if (!jwt.header.kid.includes('#')) throw new Error(`${SIOPErrors.ERROR_INVALID_JWT}. '${type}' contains an invalid kid header.`);
    return { method: 'did', didUrl: jwt.header.kid, type };
  } else if (jwt.header.x5c) {
    if (!Array.isArray(jwt.header.x5c) || typeof jwt.header.x5c.some((cert) => typeof cert !== 'string')) {
      throw new Error(`${SIOPErrors.ERROR_INVALID_JWT}. '${type}' contains an invalid x5c header.`);
    }
    return { method: 'x5c', chain: jwt.header.x5c, issuer: jwt.payload.iss, type };
  } else if (jwt.header.jwk) {
    if (typeof jwt.header.jwk !== 'object') throw new Error(`${SIOPErrors.ERROR_INVALID_JWT} '${type}' contains an invalid jwk header.`);
    if (type === 'id-token') {
      if (typeof jwt.payload.sub_jwk !== 'string') throw new Error(`${SIOPErrors.ERROR_INVALID_JWT} '${type}' is missing the sub_jwk claim.`);

      const jwkThumbPrintUri = jwt.payload.sub_jwk;
      const digestAlgorithm = await getDigestAlgorithmFromJwkThumbprintUri(jwkThumbPrintUri);
      const selfComputedJwkThumbPrintUri = await calculateJwkThumbprintUri(jwt.header.jwk as JWK, digestAlgorithm);

      if (selfComputedJwkThumbPrintUri !== jwkThumbPrintUri) {
        throw new Error(`${SIOPErrors.ERROR_INVALID_JWT} '${type}' contains an invalid sub_jwk claim.`);
      }

      return { method: 'jwk', type, jwk: jwt.header.jwk, jwkThumbprint: jwt.payload.sub_jwk };
    }

    return { method: 'jwk', type, jwk: jwt.header.jwk };
  } else {
    return { method: 'custom', type };
  }
};

export type VerifyJwtCallback = (jwtVerifier: JwtVerifier, jwt: { header: JwtHeader; payload: JwtPayload; raw: string }) => Promise<boolean>;
