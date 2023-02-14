import { AuthorizationRequest, URI, VerifyAuthorizationRequestOpts } from '../authorization-request';
import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  PresentationExchangeOpts,
  VerifiablePresentationWithLocation,
} from '../authorization-response';
import { encodeJsonAsURI, formPost, post } from '../helpers';
import {
  AuthorizationResponseResult,
  ContentType,
  ExternalVerification,
  InternalVerification,
  ParsedAuthorizationRequestURI,
  ResponseMode,
  SIOPErrors,
  SIOPResonse,
  UrlEncodingFormat,
  VerifiedAuthorizationRequest,
} from '../types';

import { Builder } from './Builder';
import { createResponseOptsFromBuilderOrExistingOpts, createVerifyRequestOptsFromBuilderOrExistingOpts } from './Opts';
import { AuthorizationEvents } from '../types/Events';

export const opEventEmitter = new (require('events').EventEmitter)();

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _createResponseOptions: AuthorizationResponseOpts;
  private readonly _verifyRequestOptions: Partial<VerifyAuthorizationRequestOpts>;

  private constructor(opts: { builder?: Builder; responseOpts?: AuthorizationResponseOpts; verifyOpts?: VerifyAuthorizationRequestOpts }) {
    this._createResponseOptions = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this._verifyRequestOptions = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  get createResponseOptions(): AuthorizationResponseOpts {
    return this._createResponseOptions;
  }

  get verifyRequestOptions(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyRequestOptions;
  }

  // TODO SK Can you please put some documentation on it?
  public async postAuthenticationResponse(authorizationResponse: AuthorizationResponseResult): Promise<Response> {
    const response = await formPost(authorizationResponse.responsePayload.idToken.aud, authorizationResponse.responsePayload.id_token, {
      contentType: ContentType.FORM_URL_ENCODED,
    });
    return response.origResponse;
  }

  /**
   * This method tries to infer the SIOP specs version based on the request payload.
   * If the version cannot be inferred or is not supported it throws an exception.
   * This method needs to be called to ensure the OP can handle the request
   * @param requestJwtOrUri
   * @param requestOpts
   */

  public async verifyAuthorizationRequest(
    requestJwtOrUri: string | URI,
    requestOpts?: { nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthorizationRequest> {
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestJwtOrUri).catch((error: Error) => {
      opEventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, requestJwtOrUri, error);
      throw error;
    });
    opEventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, authorizationRequest);

    return authorizationRequest
      .verify(this.newVerifyAuthorizationRequestOpts({ ...requestOpts }))
      .then((verifiedAuthorizationRequest: VerifiedAuthorizationRequest) => {
        opEventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, authorizationRequest);
        return verifiedAuthorizationRequest;
      })
      .catch((error) => {
        opEventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, authorizationRequest, error);
        throw error;
      });
  }

  public async createAuthorizationResponse(
    authorizationRequest: VerifiedAuthorizationRequest,
    responseOpts?: {
      nonce?: string;
      state?: string;
      audience?: string;
      verification?: InternalVerification | ExternalVerification;
      presentationExchange?: {
        vps?: VerifiablePresentationWithLocation[];
      };
    }
  ): Promise<AuthorizationResponse> {
    const authorizationResponse: AuthorizationResponse = await AuthorizationResponse.fromVerifiedAuthorizationRequest(
      authorizationRequest,
      this.newAuthorizationResponseOpts(responseOpts)
    ).catch((error: Error) => {
      opEventEmitter.emit(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, authorizationResponse, error);
      throw error;
    });
    opEventEmitter.emit(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, authorizationResponse);

    return authorizationResponse;
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthorizationResponse(authorizationResponse: AuthorizationResponse): Promise<Response> {
    if (
      !authorizationResponse ||
      (authorizationResponse.options.responseMode &&
        !(authorizationResponse.options.responseMode == ResponseMode.POST || authorizationResponse.options.responseMode == ResponseMode.FORM_POST))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    const payload = await authorizationResponse.payload;
    const idToken = await authorizationResponse.idToken.payload();
    const uri = encodeJsonAsURI(payload);
    return post(idToken.aud, uri, { contentType: ContentType.FORM_URL_ENCODED })
      .then((result: SIOPResonse<unknown>) => {
        opEventEmitter.emit(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, authorizationResponse);
        return result.origResponse;
      })
      .catch((error: Error) => {
        opEventEmitter.emit(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, authorizationResponse, error);
        throw error;
      });
  }

  /**
   * Create an Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthorizationRequestURI(encodedUri: string): Promise<ParsedAuthorizationRequestURI> {
    const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(encodedUri);

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      scheme: scheme,
      requestObjectJwt,
      authorizationRequestPayload,
      registration: registrationMetadata,
    };
  }

  private newAuthorizationResponseOpts(opts?: {
    nonce?: string;
    state?: string;
    audience?: string;
    presentationExchange?: PresentationExchangeOpts;
  }): AuthorizationResponseOpts {
    return {
      ...(opts?.audience ? { redirectUri: opts.audience } : {}),
      ...this._createResponseOptions,
      ...(opts?.nonce ? { nonce: opts.nonce } : {}),
      ...(opts?.state ? { state: opts.state } : {}),
      ...(opts?.presentationExchange ? { presentationExchange: opts.presentationExchange } : {}),
    };
  }

  private newVerifyAuthorizationRequestOpts(opts?: {
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    // verifyCallback?: VerifyCallback;
  }): VerifyAuthorizationRequestOpts {
    return {
      ...this._verifyRequestOptions,
      nonce: opts?.nonce || this._verifyRequestOptions.nonce,
      verification: opts?.verification || this._verifyRequestOptions.verification,
      // wellknownDIDverifyCallback: opts?.verifyCallback,
    };
  }

  public static fromOpts(responseOpts: AuthorizationResponseOpts, verifyOpts: VerifyAuthorizationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new Builder();
  }
}
