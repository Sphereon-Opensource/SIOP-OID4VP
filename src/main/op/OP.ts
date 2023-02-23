import EventEmitter from 'events';

import { AuthorizationRequest, URI, VerifyAuthorizationRequestOpts } from '../authorization-request';
import { AuthorizationResponse, AuthorizationResponseOpts, PresentationExchangeResponseOpts } from '../authorization-response';
import { encodeJsonAsURI, post } from '../helpers';
import {
  AuthorizationEvent,
  AuthorizationEvents,
  ContentType,
  ExternalSignature,
  ExternalVerification,
  InternalSignature,
  InternalVerification,
  ParsedAuthorizationRequestURI,
  RegisterEventListener,
  ResponseMode,
  SIOPErrors,
  SIOPResonse,
  SuppliedSignature,
  UrlEncodingFormat,
  VerifiedAuthorizationRequest,
} from '../types';

import { Builder } from './Builder';
import { createResponseOptsFromBuilderOrExistingOpts, createVerifyRequestOptsFromBuilderOrExistingOpts } from './Opts';

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _createResponseOptions: AuthorizationResponseOpts;
  private readonly _verifyRequestOptions: Partial<VerifyAuthorizationRequestOpts>;
  private readonly _eventEmitter?: EventEmitter;

  private constructor(opts: { builder?: Builder; responseOpts?: AuthorizationResponseOpts; verifyOpts?: VerifyAuthorizationRequestOpts }) {
    this._createResponseOptions = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this._verifyRequestOptions = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
    this._eventEmitter = opts.builder?.eventEmitter;
  }

  get createResponseOptions(): AuthorizationResponseOpts {
    return this._createResponseOptions;
  }

  get verifyRequestOptions(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyRequestOptions;
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
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestJwtOrUri)
      .then((result: AuthorizationRequest) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, { subject: result });
        return result;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, { subject: requestJwtOrUri, error });
        throw error;
      });

    return authorizationRequest
      .verify(this.newVerifyAuthorizationRequestOpts({ ...requestOpts }))
      .then((verifiedAuthorizationRequest: VerifiedAuthorizationRequest) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, { subject: verifiedAuthorizationRequest.authorizationRequest });
        return verifiedAuthorizationRequest;
      })
      .catch((error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, { subject: authorizationRequest, error });
        throw error;
      });
  }

  public async createAuthorizationResponse(
    authorizationRequest: VerifiedAuthorizationRequest,
    responseOpts?: {
      nonce?: string;
      state?: string;
      audience?: string;
      signature?: InternalSignature | ExternalSignature | SuppliedSignature;
      verification?: InternalVerification | ExternalVerification;
      presentationExchange?: PresentationExchangeResponseOpts;
    }
  ): Promise<AuthorizationResponse> {
    return AuthorizationResponse.fromVerifiedAuthorizationRequest(authorizationRequest, this.newAuthorizationResponseOpts(responseOpts))
      .then((authorizationResponse: AuthorizationResponse) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, { subject: authorizationResponse });
        return authorizationResponse;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, { subject: authorizationRequest, error });
        throw error;
      });
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
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { subject: authorizationResponse });
        return result.origResponse;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, { subject: authorizationResponse, error });
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
    signature?: InternalSignature | ExternalSignature | SuppliedSignature;
    presentationExchange?: PresentationExchangeResponseOpts;
  }): AuthorizationResponseOpts {
    return {
      ...this._createResponseOptions,
      ...(opts?.audience ? { redirectUri: opts.audience } : {}),
      ...(opts?.nonce ? { nonce: opts.nonce } : {}),
      ...(opts?.state ? { state: opts.state } : {}),
      ...(opts?.presentationExchange ? { presentationExchange: opts.presentationExchange } : {}),
      ...(opts?.signature ? { signature: opts.signature } : {}),
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
      verification: { ...this._verifyRequestOptions.verification, ...opts?.verification },
      // wellknownDIDverifyCallback: opts?.verifyCallback,
    };
  }

  private async emitEvent(type: AuthorizationEvents, payload: { subject: unknown; error?: Error }): Promise<void> {
    if (this._eventEmitter) {
      this._eventEmitter.emit(type, new AuthorizationEvent(payload));
    }
  }

  public addEventListener(register: RegisterEventListener) {
    if (!this._eventEmitter) {
      throw Error('Cannot add listeners if no event emitter is available');
    }
    const events = Array.isArray(register.event) ? register.event : [register.event];
    for (const event of events) {
      this._eventEmitter.addListener(event, register.listener);
    }
  }

  public static fromOpts(responseOpts: AuthorizationResponseOpts, verifyOpts: VerifyAuthorizationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new Builder();
  }
}
