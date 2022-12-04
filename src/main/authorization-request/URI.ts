import { decodeJWT } from 'did-jwt';

import { PresentationExchange } from '../PresentationExchange';
import { decodeUriAsJson, encodeJsonAsURI, fetchByReferenceOrUseByValue } from '../functions';
import { assertValidRequestObjectPayload } from '../request-object/Payload';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestOpts,
  AuthorizationRequestPayload,
  AuthorizationRequestURI,
  ObjectBy,
  PassBy,
  RequestBy,
  RequestObjectJwt,
  RequestObjectPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  UrlEncodingFormat,
} from '../types';

import AuthorizationRequest from './AuthorizationRequest';
import { assertValidRPRegistrationMedataPayload } from './Payload';

export class URI implements AuthorizationRequestURI {
  private readonly _scheme: string;
  private readonly _requestObjectJwt: RequestObjectJwt | undefined;
  private readonly _authorizationRequestPayload: AuthorizationRequestPayload;
  private readonly _encodedUri: string; // The encoded URI
  private readonly _encodingFormat: UrlEncodingFormat;
  // private _requestObjectBy: ObjectBy;

  private _registrationMetadataPayload: RPRegistrationMetadataPayload;

  private constructor({ scheme, encodedUri, encodingFormat, authorizationRequestPayload, requestObjectJwt }: Partial<AuthorizationRequestURI>) {
    this._scheme = scheme;
    this._encodedUri = encodedUri;
    this._encodingFormat = encodingFormat;
    this._authorizationRequestPayload = authorizationRequestPayload;
    this._requestObjectJwt = requestObjectJwt;
  }

  public static async fromValue(uri: string): Promise<URI> {
    const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(uri);
    const requestObjectPayload = requestObjectJwt ? (decodeJWT(requestObjectJwt) as RequestObjectPayload) : undefined;
    if (requestObjectPayload) {
      assertValidRequestObjectPayload(requestObjectPayload);
    }

    const result = new URI({
      scheme,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      encodedUri: uri,
      authorizationRequestPayload,
      requestObjectJwt,
    });
    result._registrationMetadataPayload = registrationMetadata;
    return result;
  }

  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  public static async fromOpts(opts: AuthorizationRequestOpts): Promise<URI> {
    const authorizationRequest = await AuthorizationRequest.fromOpts(opts);
    return await URI.fromAuthorizationRequest(authorizationRequest);
  }

  public async toAuthorizationRequest(): Promise<AuthorizationRequest> {
    return await AuthorizationRequest.fromURI(this);
  }

  get requestObjectBy(): ObjectBy {
    if (!this.requestObjectJwt) {
      return { type: PassBy.NONE };
    }
    if (this.authorizationRequestPayload.request_uri) {
      return { type: PassBy.REFERENCE, referenceUri: this.authorizationRequestPayload.request_uri };
    }
    return { type: PassBy.VALUE };
  }

  get metadataObjectBy(): ObjectBy {
    if (!this.authorizationRequestPayload.registration_uri && !this.authorizationRequestPayload.registration) {
      return { type: PassBy.NONE };
    }
    if (this.authorizationRequestPayload.registration_uri) {
      return { type: PassBy.REFERENCE, referenceUri: this.authorizationRequestPayload.registration_uri };
    }
    return { type: PassBy.VALUE };
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
  static async fromRequestObject(requestObject: RequestObject): Promise<URI> {
    return await URI.fromAuthorizationRequestPayload(requestObject.options, await requestObject.toJwt());
  }

  static async fromAuthorizationRequest(authorizationRequest: AuthorizationRequest): Promise<URI> {
    return await URI.fromAuthorizationRequestPayload(authorizationRequest.options, authorizationRequest.payload, authorizationRequest.requestObject);
  }

  /**
   * Creates an URI Request
   * @param opts Options to define the Uri Request
   * @param request
   *
   */
  private static async fromAuthorizationRequestPayload(
    opts: { uriScheme?: string; requestBy: RequestBy },
    request: AuthorizationRequestPayload | string,
    requestObject?: RequestObject
  ): Promise<URI> {
    const scheme = opts.uriScheme ? (opts.uriScheme.endsWith('://') ? opts.uriScheme : `${opts.uriScheme}://`) : 'openid://';
    const isJwt = typeof request === 'string';
    const requestObjectJwt = requestObject ? await requestObject.toJwt() : isJwt ? request : request.request;
    if (isJwt && (!requestObjectJwt || !requestObjectJwt.startsWith('ey'))) {
      throw Error(SIOPErrors.NO_JWT);
    }
    const requestObjectPayload: RequestObjectPayload = requestObjectJwt ? (decodeJWT(requestObjectJwt) as RequestObjectPayload) : undefined;

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
      authorizationRequest.request = requestObjectJwt;
      delete authorizationRequest.request_uri;
    }
    return new URI({
      scheme,
      encodedUri: `${scheme}?${encodeJsonAsURI(authorizationRequest)}`,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      // requestObjectBy: opts.requestBy,
      authorizationRequestPayload: authorizationRequest,
      requestObjectJwt: requestObjectJwt,
    });
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  public static parse(uri: string): { scheme: string; authorizationRequestPayload: AuthorizationRequestPayload } {
    // We strip the uri scheme before passing it to the decode function
    const scheme: string = uri.match(/^.*:\/\/\??/)[0];
    const authorizationRequestPayload = decodeUriAsJson(uri.replace(/^.*:\/\/\??/, '')) as AuthorizationRequestPayload;
    return { scheme, authorizationRequestPayload };
  }

  public static async parseAndResolve(uri: string) {
    const { authorizationRequestPayload, scheme } = this.parse(uri);
    const requestObjectJwt = await fetchByReferenceOrUseByValue(authorizationRequestPayload.request_uri, authorizationRequestPayload.request, true);
    const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      authorizationRequestPayload['registration_uri'],
      authorizationRequestPayload['registration']
    );
    assertValidRPRegistrationMedataPayload(registrationMetadata);
    return { scheme, authorizationRequestPayload, requestObjectJwt, registrationMetadata };
  }

  get encodingFormat(): UrlEncodingFormat {
    return this._encodingFormat;
  }

  get encodedUri(): string {
    return this._encodedUri;
  }

  get authorizationRequestPayload(): AuthorizationRequestPayload {
    return this._authorizationRequestPayload;
  }

  get requestObjectJwt(): RequestObjectJwt | undefined {
    return this._requestObjectJwt;
  }

  get scheme(): string {
    return this._scheme;
  }

  get registrationMetadataPayload(): RPRegistrationMetadataPayload {
    return this._registrationMetadataPayload;
  }
}
