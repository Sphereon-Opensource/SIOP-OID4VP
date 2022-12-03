import { decodeJWT } from 'did-jwt';

import { PresentationExchange } from '../PresentationExchange';
import { decodeUriAsJson, encodeJsonAsURI, fetchByReferenceOrUseByValue } from '../functions';
import { assertValidRequestObjectPayload } from '../request-object/Payload';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestOpts,
  AuthorizationRequestPayload,
  AuthorizationRequestURI,
  PassBy,
  RequestBy,
  RequestObjectPayload,
  RequestObjectResult,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  UrlEncodingFormat,
} from '../types';

import AuthorizationRequest from './AuthorizationRequest';
import { assertValidRPRegistrationMedataPayload } from './Payload';

export default class URI {
  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  public async create(opts: AuthorizationRequestOpts): Promise<AuthorizationRequestURI> {
    const requestObject = await RequestObject.fromAuthorizationRequestOpts(opts);
    const authorizationRequest = await AuthorizationRequest.createAuthorizationRequest(opts, await requestObject.getJwt());
    const result = await this.fromRequest(opts, authorizationRequest);
    return { authorizationRequest, ...result, ...{ requestObject: await requestObject.getJwt() } };
  }

  public async parseAndResolve(uri: string) {
    const { uriScheme, requestObject, authorizationRequest } = await this.parseAndResolveRequestUri(uri);
    if (requestObject) {
      assertValidRequestObjectPayload(decodeJWT(requestObject) as RequestObjectPayload);
    }
    const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      authorizationRequest['registration_uri'],
      authorizationRequest['registration']
    );
    assertValidRPRegistrationMedataPayload(registrationMetadata);

    return { uriScheme, requestObject, authorizationRequest, registrationMetadata };
  }

  /**
   * Create a URI from the request object, typically you will want to use the createURI version!
   *
   * @remarks This method is used to generate a SIOP request Object with info provided by the RP.
   * First it generates the request object payload, and then it creates the signed JWT.
   *
   * Please note that the createURI method allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this method,
   * the URI will be constructed based on the Request Object only!
   */
  async fromRequestObject(request: RequestObjectResult): Promise<AuthorizationRequestURI> {
    return await this.fromRequest(request.opts, request.requestObject);
  }

  /**
   * Creates an URI Request
   * @param opts Options to define the Uri Request
   * @param request
   *
   */
  private async fromRequest(
    opts: { uriScheme?: string; requestBy: RequestBy },
    request: AuthorizationRequestPayload | string
  ): Promise<AuthorizationRequestURI> {
    const scheme = opts.uriScheme ? (opts.uriScheme.endsWith('://') ? opts.uriScheme : `${opts.uriScheme}://`) : 'openid://';
    const isJwt = typeof request === 'string';
    const requestObject = isJwt ? request : request.request;
    if (isJwt && (!requestObject || !requestObject.startsWith('ey'))) {
      throw Error(SIOPErrors.NO_JWT);
    }
    const requestObjectPayload: RequestObjectPayload = requestObject ? (decodeJWT(requestObject) as RequestObjectPayload) : undefined;

    if (requestObjectPayload) {
      // Only used to validate if it contains a presentation definition
      await PresentationExchange.findValidPresentationDefinitions(requestObjectPayload);

      assertValidRequestObjectPayload(requestObjectPayload);
      // fixme. This should not be fetched at all. We should inspect the opts
      const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
        requestObjectPayload['registration_uri'],
        requestObjectPayload['registration']
      );
      assertValidRPRegistrationMedataPayload(registrationMetadata);
    }
    const authorizationRequest: AuthorizationRequestPayload = isJwt ? (requestObjectPayload as AuthorizationRequestPayload) : request;
    if (!authorizationRequest) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const type = opts.requestBy?.type;
    if (!type) {
      throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
    }

    if (type === PassBy.REFERENCE) {
      if (!opts.requestBy.referenceUri) {
        throw new Error(SIOPErrors.NO_REFERENCE_URI);
      }
      authorizationRequest.request_uri = opts.requestBy.referenceUri;
      delete authorizationRequest.request;
    } else if (type === PassBy.VALUE) {
      authorizationRequest.request = requestObject;
      delete authorizationRequest.request_uri;
    }
    return {
      encodedUri: `${scheme}?${encodeJsonAsURI(authorizationRequest)}`,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      requestBy: opts.requestBy,
      authorizationRequest,
      requestObject,
    };
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  parse(uri: string): { uriScheme: string; authorizationRequest: AuthorizationRequestPayload } {
    // We strip the uri scheme before passing it to the decode function
    const uriScheme: string = uri.match(/^.*:\/\/\??/)[0];
    const authorizationRequest = decodeUriAsJson(uri.replace(/^.*:\/\/\??/, '')) as AuthorizationRequestPayload;
    return { uriScheme, authorizationRequest };
  }

  protected async parseAndResolveRequestUri(uri: string) {
    const { authorizationRequest, uriScheme } = this.parse(uri);
    const requestObject = await fetchByReferenceOrUseByValue(authorizationRequest.request_uri, authorizationRequest.request, true);
    return { uriScheme, authorizationRequest, requestObject };
  }
}
