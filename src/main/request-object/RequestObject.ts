import { decodeJWT } from 'did-jwt';

import { assertValidAuthorizationRequestOpts } from '../authorization-request/Opts';
import { signDidJwtPayload } from '../functions';
import { AuthorizationRequestOpts, RequestObjectJwt, RequestObjectOpts, RequestObjectPayload, SIOPErrors } from '../types';

import { assertValidRequestObjectPayload, createRequestObjectPayload } from './Payload';

export class RequestObject {
  private payload: RequestObjectPayload;
  private jwt: RequestObjectJwt;
  private readonly opts: RequestObjectOpts;

  private constructor(opts?: AuthorizationRequestOpts | RequestObjectOpts, payload?: RequestObjectPayload, jwt?: string) {
    this.opts = RequestObject.mergeOAuth2AndOpenIdProperties(opts);
    this.payload = payload;
    this.jwt = jwt;
  }

  public static async fromAuthorizationRequestOpts(authorizationRequestOpts: AuthorizationRequestOpts) {
    assertValidAuthorizationRequestOpts(authorizationRequestOpts);
    const opts = RequestObject.mergeOAuth2AndOpenIdProperties(authorizationRequestOpts);
    return new RequestObject(authorizationRequestOpts, await createRequestObjectPayload(opts));
  }

  public static async fromJwt(requestObjectJwt: RequestObjectJwt) {
    return new RequestObject(undefined, undefined, requestObjectJwt);
  }

  public static async fromPayload(requestObjectPayload: RequestObjectPayload, authorizationRequestOpts: AuthorizationRequestOpts) {
    return new RequestObject(authorizationRequestOpts, requestObjectPayload);
  }

  private static mergeOAuth2AndOpenIdProperties(opts: AuthorizationRequestOpts | RequestObjectOpts) {
    if (!opts.requestBy) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const mergedOpts = JSON.parse(JSON.stringify(opts));
    mergedOpts.requestBy.request = { ...mergedOpts, ...mergedOpts.requestBy.request };
    delete mergedOpts.requestBy.request['requestBy'];
    return mergedOpts;
  }

  public async getJwt(): Promise<RequestObjectJwt> {
    if (!this.jwt) {
      if (!this.payload) {
        throw Error(`Cannot create JWT if there is no payload`);
      } else if (!this.opts) {
        throw Error(SIOPErrors.BAD_PARAMS);
      }
      this.removeRequestProperties();
      this.jwt = await signDidJwtPayload(this.payload, this.opts);
    }
    return this.jwt;
  }

  public async getPayload(): Promise<RequestObjectPayload> {
    if (!this.payload) {
      if (!this.jwt) {
        throw Error(SIOPErrors.NO_JWT);
      }
      this.payload = decodeJWT(await this.getJwt()) as RequestObjectPayload;
      this.removeRequestProperties();
      assertValidRequestObjectPayload(this.payload);
    }
    return this.payload;
  }

  public getOptions(): RequestObjectOpts | undefined {
    return this.opts;
  }

  private removeRequestProperties(): void {
    if (this.payload) {
      // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
      // request and request_uri parameters MUST NOT be included in Request Objects.
      delete this.payload.request;
      delete this.payload.request_uri;
    }
  }
}
