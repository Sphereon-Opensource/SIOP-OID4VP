import { decodeJWT } from 'did-jwt';

import { AuthorizationRequestOpts } from '../authorization-request';
import { assertValidAuthorizationRequestOpts } from '../authorization-request/Opts';
import { fetchByReferenceOrUseByValue, signDidJwtPayload } from '../functions';
import { AuthorizationRequestPayload, RequestObjectJwt, RequestObjectPayload, SIOPErrors } from '../types';

import { assertValidRequestObjectOpts } from './Opts';
import { assertValidRequestObjectPayload, createRequestObjectPayload } from './Payload';
import { RequestObjectOpts } from './types';

export class RequestObject {
  private payload: RequestObjectPayload;
  private jwt: RequestObjectJwt;
  private readonly opts: RequestObjectOpts;

  private constructor(opts?: AuthorizationRequestOpts | RequestObjectOpts, payload?: RequestObjectPayload, jwt?: string) {
    this.opts = opts ? RequestObject.mergeOAuth2AndOpenIdProperties(opts) : undefined;
    this.payload = payload;
    this.jwt = jwt;
  }

  /**
   * Create a request object that typically is used as a JWT on RP side, typically this method is called automatically when creating an Authorization Request, but you could use it directly!
   *
   * @param authorizationRequestOpts Request Object options to build a Request Object
   * @remarks This method is used to generate a SIOP request Object.
   * First it generates the request object payload, and then it a signed JWT can be accessed on request.
   *
   * Normally you will want to use the Authorization Request class. That class creates a URI that includes the JWT from this class in the URI
   * If you do use this class directly, you can call the `convertRequestObjectToURI` afterwards to get the URI.
   * Please note that the Authorization Request allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this class,
   * the URI will be constructed based on the Request Object only!
   */
  public static async fromOpts(authorizationRequestOpts: AuthorizationRequestOpts) {
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

  public static async fromAuthorizationRequestPayload(payload: AuthorizationRequestPayload): Promise<RequestObject | undefined> {
    const requestObjectJwt =
      payload.request || payload.request_uri ? await fetchByReferenceOrUseByValue(payload.request_uri, payload.request, true) : undefined;
    return requestObjectJwt ? await RequestObject.fromJwt(requestObjectJwt) : undefined;
  }

  public async toJwt(): Promise<RequestObjectJwt> {
    if (!this.jwt) {
      if (!this.opts) {
        throw Error(SIOPErrors.BAD_PARAMS);
      } else if (!this.payload) {
        throw Error(`Cannot create JWT if there is no payload`);
      }
      this.removeRequestProperties();
      if (this.payload.registration_uri) {
        delete this.payload.registration;
      }
      assertValidRequestObjectPayload(this.payload);

      this.jwt = await signDidJwtPayload(this.payload, this.opts);
    }
    return this.jwt;
  }

  public async getPayload(): Promise<RequestObjectPayload> {
    if (!this.payload) {
      if (!this.jwt) {
        throw Error(SIOPErrors.NO_JWT);
      }
      this.payload = decodeJWT(this.jwt).payload as RequestObjectPayload;
      this.removeRequestProperties();
    }
    assertValidRequestObjectPayload(this.payload);
    return this.payload;
  }

  public async assertValid(): Promise<void> {
    if (this.options) {
      assertValidRequestObjectOpts(this.options, false);
    }
    assertValidRequestObjectPayload(await this.getPayload());
  }

  public get options(): RequestObjectOpts | undefined {
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

  private static mergeOAuth2AndOpenIdProperties(opts: AuthorizationRequestOpts | RequestObjectOpts) {
    if (!opts) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const isAuthReq = opts['requestObject'] !== undefined;
    const mergedOpts = JSON.parse(JSON.stringify(opts));
    mergedOpts.requestObject.payload = isAuthReq
      ? { ...mergedOpts, ...mergedOpts['requestObject']?.payload }
      : { ...mergedOpts, ...mergedOpts.request };
    delete mergedOpts?.request?.requestObject;
    return isAuthReq ? mergedOpts.requestObject : mergedOpts;
  }
}
