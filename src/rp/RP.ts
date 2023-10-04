import { EventEmitter } from 'events';

import { v4 as uuidv4 } from 'uuid';

import {
  AuthorizationRequest,
  ClaimPayloadCommonOpts,
  CreateAuthorizationRequestOpts,
  PropertyTarget,
  RequestObjectPayloadOpts,
  RequestPropertyWithTargets,
  URI,
} from '../authorization-request';
import { mergeVerificationOpts } from '../authorization-request/Opts';
import { AuthorizationResponse, PresentationDefinitionWithLocation, VerifyAuthorizationResponseOpts } from '../authorization-response';
import { getNonce, getState } from '../helpers';
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationResponsePayload,
  CheckLinkedDomain,
  ExternalVerification,
  InternalVerification,
  PassBy,
  RegisterEventListener,
  ResponseURIType,
  SIOPErrors,
  SupportedVersion,
  VerifiedAuthorizationResponse,
} from '../types';

import { createRequestOptsFromBuilderOrExistingOpts, createVerifyResponseOptsFromBuilderOrExistingOpts, isTargetOrNoTargets } from './Opts';
import { RPBuilder } from './RPBuilder';
import { IRPSessionManager } from './types';

export class RP {
  get sessionManager(): IRPSessionManager {
    return this._sessionManager;
  }

  private readonly _createRequestOptions: CreateAuthorizationRequestOpts;
  private readonly _verifyResponseOptions: Partial<VerifyAuthorizationResponseOpts>;
  private readonly _eventEmitter?: EventEmitter;
  private readonly _sessionManager?: IRPSessionManager;

  private constructor(opts: {
    builder?: RPBuilder;
    createRequestOpts?: CreateAuthorizationRequestOpts;
    verifyResponseOpts?: VerifyAuthorizationResponseOpts;
  }) {
    // const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._createRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload } };
    this._verifyResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) };
    this._eventEmitter = opts.builder?.eventEmitter;
    this._sessionManager = opts.builder?.sessionManager;
  }

  public static fromRequestOpts(opts: CreateAuthorizationRequestOpts): RP {
    return new RP({ createRequestOpts: opts });
  }

  public static builder(opts?: { requestVersion?: SupportedVersion }): RPBuilder {
    return RPBuilder.newInstance(opts?.requestVersion);
  }

  public async createAuthorizationRequest(opts: {
    correlationId: string;
    nonce: string | RequestPropertyWithTargets<string>;
    state: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
    version?: SupportedVersion;
    requestByReferenceURI?: string;
    redirectURI_TODO_NOT_IMPLEMENTED?: string; // todo: response_uri/redirect_uri is not hooked up from opts!
    responseURIType_TODO_NOT_IMEPLEMENTED?: ResponseURIType; // todo: response_uri/redirect_uri is not hooked up from opts!
  }): Promise<AuthorizationRequest> {
    const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts);
    return AuthorizationRequest.fromOpts(authorizationRequestOpts)
      .then((authorizationRequest: AuthorizationRequest) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
          correlationId: opts.correlationId,
          subject: authorizationRequest,
        });
        return authorizationRequest;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
          correlationId: opts.correlationId,
          error,
        });
        throw error;
      });
  }

  public async createAuthorizationRequestURI(opts: {
    correlationId: string;
    nonce: string | RequestPropertyWithTargets<string>;
    state: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
    version?: SupportedVersion;
    requestByReferenceURI?: string;
    redirectURI?: string;
  }): Promise<URI> {
    const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts);

    return await URI.fromOpts(authorizationRequestOpts)
      .then(async (uri: URI) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
          correlationId: opts.correlationId,
          subject: await AuthorizationRequest.fromOpts(authorizationRequestOpts),
        });
        return uri;
      })
      .catch((error: Error) => {
        this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
          correlationId: opts.correlationId,
          error,
        });
        throw error;
      });
  }

  public async signalAuthRequestRetrieved(opts: { correlationId: string; error?: Error }) {
    if (!this.sessionManager) {
      throw Error(`Cannot signal auth request retrieval when no session manager is registered`);
    }
    const state = await this.sessionManager.getRequestStateByCorrelationId(opts.correlationId, true);
    this.emitEvent(opts?.error ? AuthorizationEvents.ON_AUTH_REQUEST_SENT_FAILED : AuthorizationEvents.ON_AUTH_REQUEST_SENT_SUCCESS, {
      correlationId: opts.correlationId,
      ...(!opts?.error ? { subject: state.request } : {}),
      ...(opts?.error ? { error: opts.error } : {}),
    });
  }

  public async verifyAuthorizationResponse(
    authorizationResponsePayload: AuthorizationResponsePayload,
    opts?: {
      correlationId?: string;
      audience?: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[];
    }
  ): Promise<VerifiedAuthorizationResponse> {
    const state = opts?.state || this.verifyResponseOptions.state;
    let correlationId: string | undefined = opts?.correlationId || state;
    let authorizationResponse: AuthorizationResponse;
    try {
      authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload);
    } catch (error: any) {
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_FAILED, {
        correlationId: correlationId ?? uuidv4(), // correlation id cannot be derived from state in payload possible, hence a uuid as fallback
        subject: authorizationResponsePayload,
        error,
      });
      throw error;
    }

    try {
      const verifyAuthenticationResponseOpts = await this.newVerifyAuthorizationResponseOpts(authorizationResponse, {
        ...opts,
        correlationId,
      });
      correlationId = verifyAuthenticationResponseOpts.correlationId ?? correlationId;
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, {
        correlationId,
        subject: authorizationResponse,
      });

      const verifiedAuthorizationResponse = await authorizationResponse.verify(verifyAuthenticationResponseOpts);
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, {
        correlationId,
        subject: authorizationResponse,
      });
      return verifiedAuthorizationResponse;
    } catch (error) {
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, {
        correlationId,
        subject: authorizationResponse,
        error,
      });
      throw error;
    }
  }

  get createRequestOptions(): CreateAuthorizationRequestOpts {
    return this._createRequestOptions;
  }

  get verifyResponseOptions(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyResponseOptions;
  }

  private newAuthorizationRequestOpts(opts: {
    correlationId: string;
    nonce: string | RequestPropertyWithTargets<string>;
    state: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
    version?: SupportedVersion;
    requestByReferenceURI?: string;
    redirectURI?: string;
  }): CreateAuthorizationRequestOpts {
    const nonceWithTarget =
      typeof opts.nonce === 'string'
        ? { propertyValue: opts.nonce, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.nonce as RequestPropertyWithTargets<string>);
    const stateWithTarget =
      typeof opts.state === 'string'
        ? { propertyValue: opts.state, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.state as RequestPropertyWithTargets<string>);
    const claimsWithTarget =
      opts?.claims && !('propertyValue' in opts.claims)
        ? { propertyValue: opts.claims, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.claims as RequestPropertyWithTargets<ClaimPayloadCommonOpts>);

    const version = opts?.version ?? this._createRequestOptions.version;
    if (!version) {
      throw Error(SIOPErrors.NO_REQUEST_VERSION);
    }
    const referenceURI = opts.requestByReferenceURI ?? this._createRequestOptions?.requestObject?.reference_uri;
    const redirectURI =
      opts.redirectURI ?? this._createRequestOptions.requestObject.payload?.redirect_uri ?? this._createRequestOptions.payload?.redirect_uri;
    if (!redirectURI) {
      throw Error(`A redirect URI is required at this point`);
    } else {
      if (this._createRequestOptions.requestObject.payload?.redirect_uri || !this._createRequestOptions.payload?.redirect_uri) {
        this._createRequestOptions.requestObject.payload.redirect_uri = redirectURI;
      }
      if (this._createRequestOptions.payload?.redirect_uri) {
        this._createRequestOptions.payload.redirect_uri = redirectURI;
      }
    }

    const newOpts = { ...this._createRequestOptions, version };
    newOpts.requestObject.payload = newOpts.requestObject.payload ?? ({} as RequestObjectPayloadOpts<ClaimPayloadCommonOpts>);
    newOpts.payload = newOpts.payload ?? {};
    if (referenceURI) {
      if (newOpts.requestObject.passBy && newOpts.requestObject.passBy !== PassBy.REFERENCE) {
        throw Error(`Cannot pass by reference with uri ${referenceURI} when mode is ${newOpts.requestObject.passBy}`);
      }
      newOpts.requestObject.reference_uri = referenceURI;
      newOpts.requestObject.passBy = PassBy.REFERENCE;
    }

    const state = getState(stateWithTarget.propertyValue);
    if (stateWithTarget.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, stateWithTarget.targets)) {
        newOpts.payload.state = state;
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, stateWithTarget.targets)) {
        newOpts.requestObject.payload.state = state;
      }
    }

    const nonce = getNonce(state, nonceWithTarget.propertyValue);
    if (nonceWithTarget.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, nonceWithTarget.targets)) {
        newOpts.payload.nonce = nonce;
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, nonceWithTarget.targets)) {
        newOpts.requestObject.payload.nonce = nonce;
      }
    }
    if (claimsWithTarget?.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, claimsWithTarget.targets)) {
        newOpts.payload.claims = { ...newOpts.payload.claims, ...claimsWithTarget.propertyValue };
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, claimsWithTarget.targets)) {
        newOpts.requestObject.payload.claims = { ...newOpts.requestObject.payload.claims, ...claimsWithTarget.propertyValue };
      }
    }
    return newOpts;
  }

  private async newVerifyAuthorizationResponseOpts(
    authorizationResponse: AuthorizationResponse,
    opts: {
      correlationId: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      audience?: string;
      checkLinkedDomain?: CheckLinkedDomain;
      presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[];
    }
  ): Promise<VerifyAuthorizationResponseOpts> {
    let correlationId = opts?.correlationId ?? this._verifyResponseOptions.correlationId;
    let state = opts?.state ?? this._verifyResponseOptions.state;
    let nonce = opts?.nonce ?? this._verifyResponseOptions.nonce;
    if (this.sessionManager) {
      const resNonce = (await authorizationResponse.getMergedProperty('nonce', false)) as string;
      const resState = (await authorizationResponse.getMergedProperty('state', false)) as string;
      correlationId = await this.sessionManager.getCorrelationIdByNonce(resNonce, false);
      if (!correlationId) {
        correlationId = await this.sessionManager.getCorrelationIdByState(resState, false);
      }
      if (!correlationId) {
        correlationId = nonce;
      }
      const requestState = await this.sessionManager.getRequestStateByCorrelationId(correlationId, false);
      if (requestState) {
        const reqNonce: string = await requestState.request.getMergedProperty('nonce');
        const reqState: string = await requestState.request.getMergedProperty('state');
        nonce = nonce ?? reqNonce;
        state = state ?? reqState;
      }
    }
    return {
      ...this._verifyResponseOptions,
      ...opts,
      correlationId,
      audience:
        opts?.audience ??
        this._verifyResponseOptions.audience ??
        this._verifyResponseOptions.verification.resolveOpts.jwtVerifyOpts.audience ??
        this._createRequestOptions.payload.client_id,
      state,
      nonce,
      verification: mergeVerificationOpts(this._verifyResponseOptions, opts),
      presentationDefinitions: opts?.presentationDefinitions ?? this._verifyResponseOptions.presentationDefinitions,
    };
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: { correlationId: string; subject?: AuthorizationRequest | AuthorizationResponse | AuthorizationResponsePayload; error?: Error }
  ): Promise<void> {
    if (this._eventEmitter) {
      try {
        this._eventEmitter.emit(type, new AuthorizationEvent(payload));
      } catch (e) {
        //Let's make sure events do not cause control flow issues
        console.log(`Could not emit event ${type} for ${payload.correlationId} initial error if any: ${payload?.error}`);
      }
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
}
