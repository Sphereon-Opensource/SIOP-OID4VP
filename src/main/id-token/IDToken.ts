import { JWTHeader } from 'did-jwt';

import { assertValidVerifyOpts } from '../authorization-response/Opts';
import { getResolver, getSubDidFromPayload, parseJWT, signDidJwtPayload, validateLinkedDomainWithDid, verifyDidJWT } from '../functions';
import {
  AuthorizationRequestPayload,
  AuthorizationResponseOpts,
  CheckLinkedDomain,
  IDTokenJwt,
  IDTokenPayload,
  JWTPayload,
  ResponseIss,
  SIOPErrors,
  VerifiedAuthenticationResponse,
  VerifyAuthorizationResponseOpts,
} from '../types';

import { createIDTokenPayload } from './Payload';

export class IDToken {
  private _header?: JWTHeader;
  private _payload?: IDTokenPayload;
  private _jwt?: IDTokenJwt;
  private readonly _responseOpts: AuthorizationResponseOpts;

  private constructor(jwt?: IDTokenJwt, payload?: IDTokenPayload, responseOpts?: AuthorizationResponseOpts) {
    this._jwt = jwt;
    this._payload = payload;
    this._responseOpts = responseOpts;
  }

  public static async fromAuthorizationRequestPayload(
    authorizationRequestPayload: AuthorizationRequestPayload,
    responseOpts: AuthorizationResponseOpts
  ) {
    return new IDToken(undefined, await createIDTokenPayload(authorizationRequestPayload, responseOpts), responseOpts);
  }

  public static async fromIDToken(jwt: IDTokenJwt, verifyOpts?: VerifyAuthorizationResponseOpts) {
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const idToken = new IDToken(jwt, undefined);
    if (verifyOpts) {
      await idToken.verify(verifyOpts);
    }
    return idToken;
  }

  public async payload(): Promise<IDTokenPayload> {
    if (!this._payload) {
      if (!this._jwt) {
        throw new Error(SIOPErrors.NO_JWT);
      }
      const { header, payload } = this.parseAndVerifyJwt();
      this._header = header;
      this._payload = payload;
    }
    return this._payload;
  }

  public async jwt(): Promise<IDTokenJwt> {
    if (!this._jwt) {
      if (!this.responseOpts) {
        throw Error(SIOPErrors.BAD_SIGNATURE_PARAMS);
      }
      this._jwt = await signDidJwtPayload(this._payload, this.responseOpts);
      const { header, payload } = this.parseAndVerifyJwt();
      this._header = header;
      this._payload = payload;
    }
    return this._jwt;
  }

  private parseAndVerifyJwt(): { header: JWTHeader; payload: IDTokenPayload } {
    const { header, payload } = parseJWT(this._jwt);
    this.assertValidResponseJWT({ header, payload });
    const idTokenPayload = payload as IDTokenPayload;
    return { header, payload: idTokenPayload };
  }

  /**
   * Verifies a SIOP ID Response JWT on the RP Side
   *
   * @param idToken ID token to be validated
   * @param verifyOpts
   */
  public async verify(verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedAuthenticationResponse> {
    assertValidVerifyOpts(verifyOpts);

    const { header, payload } = parseJWT(await this.jwt());
    this.assertValidResponseJWT({ header, payload });

    const verifiedJWT = await verifyDidJWT(await this.jwt(), getResolver(verifyOpts.verification.resolveOpts), {
      audience: verifyOpts.audience,
    });

    const issuerDid = getSubDidFromPayload(payload);
    if (verifyOpts.verification.checkLinkedDomain && verifyOpts.verification.checkLinkedDomain !== CheckLinkedDomain.NEVER) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, verifyOpts.verification.checkLinkedDomain);
    } else if (!verifyOpts.verification.checkLinkedDomain) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, CheckLinkedDomain.IF_PRESENT);
    }
    const verPayload = verifiedJWT.payload as IDTokenPayload;
    this.assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });
    // Enforces verifyPresentationCallback function on the RP side,
    if (!verifyOpts?.presentationVerificationCallback) {
      throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING);
    }
    return {
      signer: verifiedJWT.signer,
      didResolutionResult: verifiedJWT.didResolutionResult,
      jwt: await this.jwt(),
      verifyOpts,
      issuer: issuerDid,
      payload: {
        ...verPayload,
      },
    };
  }

  static async verify(idTokenJwt: IDTokenJwt, verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedAuthenticationResponse> {
    const idToken = await IDToken.fromIDToken(idTokenJwt, verifyOpts);
    const verifiedIdToken = await idToken.verify(verifyOpts);

    return {
      ...verifiedIdToken,
    };
  }

  private assertValidResponseJWT(opts: { header: JWTHeader; payload?: JWTPayload; verPayload?: IDTokenPayload; audience?: string }) {
    if (!opts.header) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    if (opts.payload) {
      if (opts.payload.iss !== ResponseIss.SELF_ISSUED_V2) {
        throw new Error(`${SIOPErrors.NO_SELFISSUED_ISS}, got: ${opts.payload.iss}`);
      }
    }

    if (opts.verPayload) {
      if (!opts.verPayload.nonce) {
        throw Error(SIOPErrors.NO_NONCE);
      } else if (!opts.verPayload.exp || opts.verPayload.exp < Date.now() / 1000) {
        throw Error(SIOPErrors.EXPIRED);
        /*} else if (!opts.verPayload.iat || opts.verPayload.iat > (Date.now() / 1000)) {
                          throw Error(SIOPErrors.EXPIRED);*/
        // todo: Add iat check
      }
      if ((opts.verPayload.aud && !opts.audience) || (!opts.verPayload.aud && opts.audience)) {
        throw Error(SIOPErrors.BAD_PARAMS);
      } else if (opts.audience && opts.audience != opts.verPayload.aud) {
        throw Error(SIOPErrors.INVALID_AUDIENCE);
      }
    }
  }

  get header(): JWTHeader {
    return this._header;
  }
  get responseOpts(): AuthorizationResponseOpts {
    return this._responseOpts;
  }
}
