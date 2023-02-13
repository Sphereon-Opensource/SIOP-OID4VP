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
  AuthorizationResponsePayload,
  CheckLinkedDomain,
  ExternalVerification,
  InternalVerification,
  SIOPErrors,
  SupportedVersion,
  VerifiedAuthenticationResponse,
} from '../types';

import Builder from './Builder';
import { createRequestOptsFromBuilderOrExistingOpts, createVerifyResponseOptsFromBuilderOrExistingOpts, isTargetOrNoTargets } from './Opts';
import { eventEmitter } from './NonceReplayRegistry';
import { AuthorizationEvents } from '../types/Events';

export class RP {
  private readonly _createRequestOptions: CreateAuthorizationRequestOpts;
  private readonly _verifyResponseOptions: Partial<VerifyAuthorizationResponseOpts>;

  private constructor(opts: {
    builder?: Builder;
    createRequestOpts?: CreateAuthorizationRequestOpts;
    verifyResponseOpts?: VerifyAuthorizationResponseOpts;
  }) {
    // const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._createRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload } };
    this._verifyResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) };
  }

  public static fromRequestOpts(opts: CreateAuthorizationRequestOpts): RP {
    return new RP({ createRequestOpts: opts });
  }

  public static builder(opts?: { requestVersion?: SupportedVersion }): Builder {
    return Builder.newInstance(opts?.requestVersion);
  }

  get createRequestOptions(): CreateAuthorizationRequestOpts {
    return this._createRequestOptions;
  }

  get verifyResponseOptions(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyResponseOptions;
  }

  public async createAuthorizationRequest(opts?: {
    version?: SupportedVersion;
    nonce?: string | RequestPropertyWithTargets<string>;
    state?: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
  }): Promise<AuthorizationRequest> {
    const nonce = opts?.nonce && typeof opts.nonce === 'string' ? { propertyValue: opts.nonce } : (opts?.nonce as RequestPropertyWithTargets<string>);
    const state = opts?.state && typeof opts.state === 'string' ? { propertyValue: opts.state } : (opts?.state as RequestPropertyWithTargets<string>);
    const claims =
      opts?.claims && !('propertyValue' in opts.claims)
        ? { propertyValue: opts.claims }
        : (opts?.claims as RequestPropertyWithTargets<ClaimPayloadCommonOpts>);

    const authorizationRequest = await AuthorizationRequest.fromOpts(this.newAuthorizationRequestOpts({ version: opts.version, nonce, state, claims }));
    eventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST, authorizationRequest);

    return authorizationRequest
  }

  public async createAuthorizationRequestURI(opts?: {
    version?: SupportedVersion;
    nonce?: string | RequestPropertyWithTargets<string>;
    state?: string | RequestPropertyWithTargets<string>;
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
  }): Promise<URI> {
    const nonce =
      opts?.nonce && typeof opts?.nonce === 'string' ? { propertyValue: opts.nonce } : (opts?.nonce as RequestPropertyWithTargets<string>);
    const state =
      opts?.state && typeof opts?.state === 'string' ? { propertyValue: opts.state } : (opts?.state as RequestPropertyWithTargets<string>);
    const claims =
      opts?.claims && !('propertyValue' in opts.claims)
        ? { propertyValue: opts.claims }
        : (opts?.claims as RequestPropertyWithTargets<ClaimPayloadCommonOpts>);

    const authorizationRequestOpts = this.newAuthorizationRequestOpts({ version: opts.version, nonce, state, claims })
    eventEmitter.emit(AuthorizationEvents.ON_AUTH_REQUEST, await AuthorizationRequest.fromOpts(authorizationRequestOpts));

    return await URI.fromOpts(authorizationRequestOpts);
  }

  public async verifyAuthorizationResponse(
    authorizationResponsePayload: AuthorizationResponsePayload,
    opts?: {
      audience?: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[];
    }
  ): Promise<VerifiedAuthenticationResponse> {
    const verifyAuthenticationResponseOpts = this.newVerifyAuthorizationResponseOpts({
      ...opts,
    });
    const authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload);

    return await authorizationResponse.verify(verifyAuthenticationResponseOpts);
  }

  private newAuthorizationRequestOpts(opts?: {
    version?: SupportedVersion;
    nonce?: RequestPropertyWithTargets<string>;
    state?: RequestPropertyWithTargets<string>;
    claims?: RequestPropertyWithTargets<ClaimPayloadCommonOpts>;
  }): CreateAuthorizationRequestOpts {
    const version = opts?.version ?? this._createRequestOptions.version;
    if (!version) {
      throw Error(SIOPErrors.NO_REQUEST_VERSION);
    }

    const newOpts = { ...this._createRequestOptions, version };
    newOpts.requestObject.payload = newOpts.requestObject.payload ?? ({} as RequestObjectPayloadOpts<ClaimPayloadCommonOpts>);
    newOpts.payload = newOpts.payload ?? {};

    const state = opts.state?.propertyValue ? opts.state.propertyValue : getState(opts?.state?.propertyValue);
    if (opts.state?.propertyValue && isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.state.targets)) {
      newOpts.payload.state = state;
    }
    if (opts.state?.propertyValue && isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, opts.state.targets)) {
      newOpts.requestObject.payload.state = state;
    }

    const nonce = opts.nonce?.propertyValue ? opts.nonce.propertyValue : getNonce(state, opts?.nonce?.propertyValue);
    if (opts.nonce?.propertyValue && isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.nonce.targets)) {
      newOpts.payload.nonce = nonce;
    }
    if (opts.nonce?.propertyValue && isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, opts.nonce.targets)) {
      newOpts.requestObject.payload.nonce = nonce;
    }
    if (opts?.claims?.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.nonce.targets)) {
        newOpts.payload.claims = { ...newOpts.payload.claims, ...opts.claims.propertyValue };
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, opts.nonce.targets)) {
        newOpts.requestObject.payload.claims = { ...newOpts.requestObject.payload.claims, ...opts.claims.propertyValue };
      }
    }
    return newOpts;
  }

  private newVerifyAuthorizationResponseOpts(opts?: {
    state?: string;
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    audience?: string;
    checkLinkedDomain?: CheckLinkedDomain;
    presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[];
  }): VerifyAuthorizationResponseOpts {
    return {
      ...this._verifyResponseOptions,
      audience: opts?.audience || this._verifyResponseOptions.audience,
      state: opts?.state || this._verifyResponseOptions.state,
      nonce: opts?.nonce || this._verifyResponseOptions.nonce,
      verification: opts?.verification || this._verifyResponseOptions.verification,
      presentationDefinitions: opts?.presentationDefinitions || this._verifyResponseOptions.presentationDefinitions,
    };
  }
}
