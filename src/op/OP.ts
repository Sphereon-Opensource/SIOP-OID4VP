import { EventEmitter } from 'events';

import { v4 as uuidv4 } from 'uuid';

import { AuthorizationRequest, URI, VerifyAuthorizationRequestOpts } from '../authorization-request';
import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  AuthorizationResponseWithCorrelationId,
  PresentationExchangeResponseOpts,
} from '../authorization-response';
import { encodeJsonAsURI, post } from '../helpers';
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion';
import {
  AuthorizationEvent,
  AuthorizationEvents,
  ContentType,
  ExternalVerification,
  InternalVerification,
  ParsedAuthorizationRequestURI,
  RegisterEventListener,
  ResponseMode,
  SIOPErrors,
  SIOPResonse,
  SuppliedSignature,
  SupportedVersion,
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

  /**
   * This method tries to infer the SIOP specs version based on the request payload.
   * If the version cannot be inferred or is not supported it throws an exception.
   * This method needs to be called to ensure the OP can handle the request
   * @param requestJwtOrUri
   * @param requestOpts
   */

  public async verifyAuthorizationRequest(
    requestJwtOrUri: string | URI,
    requestOpts?: { correlationId?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthorizationRequest> {
    const correlationId = requestOpts?.correlationId || uuidv4();
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestJwtOrUri)
      .then((result: AuthorizationRequest) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, { correlationId, subject: result });
        return result;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, {
          correlationId,
          subject: requestJwtOrUri,
          error,
        });
        throw error;
      });

    const verification = {
      ...requestOpts?.verification,
      ...{
        resolveOpts: {
          ...requestOpts?.verification?.resolveOpts,
          ...{
            jwtVerifyOpts: {
              ...requestOpts?.verification?.resolveOpts?.jwtVerifyOpts,
              ...{
                policies: {
                  ...requestOpts?.verification?.resolveOpts?.jwtVerifyOpts?.policies,
                  aud: false,
                },
              },
            },
          },
        },
      },
    };
    return authorizationRequest
      .verify(this.newVerifyAuthorizationRequestOpts({ ...requestOpts, verification, correlationId }))
      .then((verifiedAuthorizationRequest: VerifiedAuthorizationRequest) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, {
          correlationId,
          subject: verifiedAuthorizationRequest.authorizationRequest,
        });
        return verifiedAuthorizationRequest;
      })
      .catch((error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, {
          correlationId,
          subject: authorizationRequest,
          error,
        });
        throw error;
      });
  }

  public async createAuthorizationResponse(
    authorizationRequest: VerifiedAuthorizationRequest,
    responseOpts?: {
      version?: SupportedVersion;
      correlationId?: string;
      audience?: string;
      signature?: /*InternalSignature | ExternalSignature |*/ SuppliedSignature;
      verification?: InternalVerification | ExternalVerification;
      presentationExchange?: PresentationExchangeResponseOpts;
    }
  ): Promise<AuthorizationResponseWithCorrelationId> {
    if (authorizationRequest.correlationId && responseOpts?.correlationId && authorizationRequest.correlationId !== responseOpts.correlationId) {
      throw new Error(
        `Request correlation id ${authorizationRequest.correlationId} is different from option correlation id ${responseOpts.correlationId}`
      );
    }
    let version = responseOpts?.version;
    const rpSupportedVersions = authorizationRequestVersionDiscovery(authorizationRequest.authorizationRequestPayload);
    if (version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(version)) {
      throw Error(`RP does not support spec version ${version}, supported versions: ${rpSupportedVersions.toString()}`);
    } else if (!version) {
      version = rpSupportedVersions.reduce(
        (previous, current) => (current.valueOf() > previous.valueOf() ? current : previous),
        SupportedVersion.SIOPv2_ID1
      );
    }
    const correlationId = responseOpts?.correlationId || authorizationRequest.correlationId || uuidv4();
    try {
      const response = await AuthorizationResponse.fromVerifiedAuthorizationRequest(
        authorizationRequest,
        this.newAuthorizationResponseOpts({
          ...responseOpts,
          version,
          correlationId,
        })
      );
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, {
        correlationId,
        subject: response,
      });
      return { correlationId, response, redirectURI: authorizationRequest.redirectURI };
    } catch (error: any) {
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, {
        correlationId,
        subject: authorizationRequest.authorizationRequest,
        error,
      });
      throw error;
    }
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthorizationResponse(authorizationResponse: AuthorizationResponseWithCorrelationId): Promise<Response> {
    const { correlationId, response } = authorizationResponse;
    if (!correlationId) {
      throw Error('No correlation Id provided');
    }
    if (
      !response ||
      (response.options.responseMode &&
        !(response.options.responseMode == ResponseMode.POST || response.options.responseMode == ResponseMode.FORM_POST))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    const request = response.authorizationRequest;
    if (!request) {
      throw Error('Cannot submit an authorization response without a request present');
    }
    const payload = await response.payload;
    const idToken = await response.idToken.payload();
    const redirectURI = authorizationResponse.redirectURI || idToken?.aud;
    const authResponseAsURI = encodeJsonAsURI(payload);
    return post(redirectURI, authResponseAsURI, { contentType: ContentType.FORM_URL_ENCODED })
      .then((result: SIOPResonse<unknown>) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { correlationId, subject: response });
        return result.origResponse;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, { correlationId, subject: response, error });
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

  private newAuthorizationResponseOpts(opts: {
    correlationId: string;
    version?: SupportedVersion;
    audience?: string;
    signature?: /*InternalSignature | ExternalSignature | */ SuppliedSignature;
    presentationExchange?: PresentationExchangeResponseOpts;
  }): AuthorizationResponseOpts {
    return {
      ...this._createResponseOptions,
      ...(opts?.audience ? { redirectUri: opts.audience } : {}),
      ...(opts?.presentationExchange ? { presentationExchange: opts.presentationExchange } : {}),
      ...(opts?.signature
        ? { signature: opts.signature }
        : this._createResponseOptions?.signature
        ? { signature: this._createResponseOptions.signature }
        : {}),
    };
  }

  private newVerifyAuthorizationRequestOpts(opts: {
    correlationId: string;
    verification?: InternalVerification | ExternalVerification;
    // verifyCallback?: VerifyCallback;
  }): VerifyAuthorizationRequestOpts {
    return {
      ...this._verifyRequestOptions,
      correlationId: opts.correlationId,
      verification: { ...this._verifyRequestOptions.verification, ...opts?.verification },
      // wellknownDIDverifyCallback: opts?.verifyCallback,
    };
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: {
      correlationId: string;
      subject: AuthorizationRequest | AuthorizationResponse | string | URI;
      error?: Error;
    }
  ): Promise<void> {
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

  get createResponseOptions(): AuthorizationResponseOpts {
    return this._createResponseOptions;
  }

  get verifyRequestOptions(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyRequestOptions;
  }
}
