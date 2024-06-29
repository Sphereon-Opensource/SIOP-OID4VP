import { calculateJwkThumbprintUri, getDigestAlgorithmFromJwkThumbprintUri } from '../helpers';

import { JWK, JwtHeader, JwtPayload } from './JWT.types';

export type JwtVerificationContext = { type: 'id-token' } | { type: 'request-object' };

interface DidJwtVerifier {
  method: 'did';

  didUrl: string;
}

interface X5cJwtVerifier {
  method: 'x5c';

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

interface JwkJwtVerifier {
  method: 'jwk';

  jwk: JsonWebKey;
  jwkThumbprint: string;
}

interface CustomJwtVerifier extends Record<string, unknown> {
  method: 'custom';
}

export type JwtVerifier = DidJwtVerifier | X5cJwtVerifier | CustomJwtVerifier | JwkJwtVerifier;

export type JwtVerifierWithContext = JwtVerifier & JwtVerificationContext;

export const getJwtVerifierWithContext = async (
  jwt: { header: JwtHeader; payload: JwtPayload },
  type: JwtVerifierWithContext['type'],
): Promise<JwtVerifierWithContext> => {
  if (jwt.header.kid?.startsWith('did:')) {
    if (!jwt.header.kid.includes('#')) throw new Error('TODO');
    return { method: 'did', didUrl: jwt.header.kid, type };
  } else if (jwt.header.x5c) {
    if (!Array.isArray(jwt.header.x5c) || typeof jwt.header.x5c.some((cert) => typeof cert !== 'string')) throw new Error('TODO');
    return { method: 'x5c', chain: jwt.header.x5c, issuer: jwt.payload.iss, type };
  } else if (jwt.header.jwk) {
    if (typeof jwt.header.jwk !== 'object') throw new Error('TODO');
    if (typeof jwt.payload.sub_jwk !== 'string') throw new Error('Invalid JWT. Missing sub_jwk claim.');

    const jwkThumbPrintUri = jwt.payload.sub_jwk;
    const digestAlgorithm = await getDigestAlgorithmFromJwkThumbprintUri(jwkThumbPrintUri);
    const selfComputedJwkThumbPrintUri = await calculateJwkThumbprintUri(jwt.header.jwk as JWK, digestAlgorithm);

    if (selfComputedJwkThumbPrintUri !== jwkThumbPrintUri) throw new Error('Invalid JWT. Thumbprint mismatch.');
    return { method: 'jwk', type, jwk: jwt.header.jwk, jwkThumbprint: jwt.payload.sub_jwk };
  } else {
    return { method: 'custom', type };
  }
};

export type VerifyJwtCallback = (
  jwtVerifier: JwtVerifier & JwtVerificationContext,
  jwt: { header: JwtHeader; payload: JwtPayload; raw: string },
) => Promise<boolean>;
