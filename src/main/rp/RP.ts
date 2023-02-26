import EventEmitter from 'events';

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
import { AuthorizationResponse, PresentationDefinitionWithLocation, VerifyAuthorizationResponseOpts } from '../authorization-response';
import { getNonce, getState } from '../helpers';
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationResponsePayload,
  CheckLinkedDomain,
  ExternalVerification,
  InternalVerification,
  RegisterEventListener,
  SIOPErrors,
  SupportedVersion,
  VerifiedAuthenticationResponse,
} from '../types';

import Builder from './Builder';
import { createRequestOptsFromBuilderOrExistingOpts, createVerifyResponseOptsFromBuilderOrExistingOpts, isTargetOrNoTargets } from './Opts';
import { IReplayRegistry } from './types';

export class RP {
  get replayRegistry(): IReplayRegistry {
    return this._replayRegistry;
  }

  private readonly _createRequestOptions: CreateAuthorizationRequestOpts;
  private readonly _verifyResponseOptions: Partial<VerifyAuthorizationResponseOpts>;
  private readonly _eventEmitter?: EventEmitter;
  private readonly _replayRegistry?: IReplayRegistry;

  private constructor(opts: {
    builder?: Builder;
    createRequestOpts?: CreateAuthorizationRequestOpts;
    verifyResponseOpts?: VerifyAuthorizationResponseOpts;
  }) {
    // const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._createRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload } };
    this._verifyResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) };
    this._eventEmitter = opts.builder?.eventEmitter;
    this._replayRegistry = opts.builder?.replayRegistry;
  }

  public static fromRequestOpts(opts: CreateAuthorizationRequestOpts): RP {
    return new RP({ createRequestOpts: opts });
  }

  public static builder(opts?: { requestVersion?: SupportedVersion }): Builder {
    return Builder.newInstance(opts?.requestVersion);
  }

  public async createAuthorizationRequest(opts: {
    correlationId: string;
    nonce: string | RequestPropertyWithTargets<string>;
    state: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
    version?: SupportedVersion;
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
    version?: SupportedVersion;
    nonce: string | RequestPropertyWithTargets<string>;
    state: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
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
  ): Promise<VerifiedAuthenticationResponse> {
    const state = opts.state || this.verifyResponseOptions.state;
    let correlationId: string | undefined = opts.correlationId || state;
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

      const verifiedAuthenticationResponse = await authorizationResponse.verify(verifyAuthenticationResponseOpts);
      this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, {
        correlationId,
        subject: authorizationResponse,
      });
      return verifiedAuthenticationResponse;
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

    const newOpts = { ...this._createRequestOptions, version };
    newOpts.requestObject.payload = newOpts.requestObject.payload ?? ({} as RequestObjectPayloadOpts<ClaimPayloadCommonOpts>);
    newOpts.payload = newOpts.payload ?? {};

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
    let correlationId = opts?.correlationId || this._verifyResponseOptions.correlationId;
    let state = opts?.state || this._verifyResponseOptions.state;
    let nonce = opts?.nonce || this._verifyResponseOptions.nonce;
    if (this.replayRegistry) {
      const resNonce = (await authorizationResponse.getMergedProperty('nonce', false)) as string;
      const resState = (await authorizationResponse.getMergedProperty('state', false)) as string;
      correlationId = await this.replayRegistry.getCorrelationIdByNonce(resNonce, false);
      if (!correlationId) {
        correlationId = await this.replayRegistry.getCorrelationIdByState(resState, false);
      }
      if (!correlationId) {
        correlationId = nonce;
      }
      const requestState = await this.replayRegistry.getRequestStateByCorrelationId(correlationId, false);
      if (requestState) {
        const reqNonce: string = await requestState.request.getMergedProperty('nonce');
        const reqState: string = await requestState.request.getMergedProperty('state');
        nonce = nonce ?? reqNonce;
        state = state ?? reqState;
      }
    }
    return {
      ...this._verifyResponseOptions,
      correlationId,
      audience:
        opts?.audience ||
        this._verifyResponseOptions.audience ||
        this._verifyResponseOptions.verification.resolveOpts.jwtVerifyOpts.audience ||
        this._createRequestOptions.payload.client_id,
      state,
      nonce,
      verification: opts?.verification || this._verifyResponseOptions.verification,
      presentationDefinitions: opts?.presentationDefinitions || this._verifyResponseOptions.presentationDefinitions,
    };
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: { correlationId: string; subject?: AuthorizationRequest | AuthorizationResponse | AuthorizationResponsePayload; error?: Error }
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
}
