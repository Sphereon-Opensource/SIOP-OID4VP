import { decodeJWT } from 'did-jwt';
import { Resolvable } from 'did-resolver';

import { RPSession } from './RPSession';
import { verifyDidJWT } from './did/DidJWT';
import { DidAuth } from './types';
import { DidAuthValidationResponse } from './types/DidAuth-types';

export class RPAuthService {
  private resolver: Resolvable;

  constructor(opts?: { resolver: Resolvable }) {
    this.setResolver(opts.resolver);
  }

  /**
   * Sets the resolver to use for Relying Party Auth
   * @param resolver
   */
  setResolver(resolver: Resolvable) {
    this.resolver = resolver;
  }

  /**
   * Verifies a DidAuth ID Response Token
   *
   * @param idToken ID token to be validated
   * @param audience expected audience
   */
  async verifyAuthResponse(idToken: string, audience: string): Promise<DidAuthValidationResponse> {
    const { payload } = decodeJWT(idToken);
    if (payload.iss !== DidAuth.ResponseIss.SELF_ISSUED_V2) {
      throw new Error('NO_SELFISSUED_ISS');
    }

    const verifiedJWT = await verifyDidJWT(idToken, this.resolver, {
      audience,
    });

    if (!verifiedJWT || !verifiedJWT.payload) {
      throw Error('ERROR_VERIFYING_SIGNATURE');
    }
    if (!verifiedJWT.payload.nonce) {
      throw Error('NO_NONCE');
    }

    return {
      signatureValidation: true,
      signer: verifiedJWT.signer,
      payload: {
        did: verifiedJWT.didResolutionResult.didDocument,
        ...verifiedJWT.payload,
      },
    };
  }

  createSession(opts?: {
    privateKey?: string;
    kid?: string;
    did?: string;
    audience?: string;
    expiration?: {
      requestToken: number;
      accessToken: number;
    };
  }): RPSession {
    const sessionOpts = {
      resolver: this.resolver,
      ...opts,
    };
    return new RPSession(sessionOpts);
  }
}
