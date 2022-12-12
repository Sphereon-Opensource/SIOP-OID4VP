import { AuthorizationRequest, ClaimPayloadCommonOpts, CreateAuthorizationRequestOpts, URI } from '../authorization-request';
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
import { createRequestOptsFromBuilderOrExistingOpts, createVerifyResponseOptsFromBuilderOrExistingOpts } from './Opts';

export class RP {
  private readonly _createRequestOptions: CreateAuthorizationRequestOpts;
  private readonly _verifyResponseOptions: Partial<VerifyAuthorizationResponseOpts>;

  private constructor(opts: {
    builder?: Builder;
    createRequestOpts?: CreateAuthorizationRequestOpts;
    verifyResponseOpts?: VerifyAuthorizationResponseOpts;
  }) {
    const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._createRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload, claims }, claims };
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
    nonce?: string;
    state?: string;
    claims?: ClaimPayloadCommonOpts;
  }): Promise<AuthorizationRequest> {
    return await AuthorizationRequest.fromOpts(this.newAuthorizationRequestOpts(opts));
  }

  public async createAuthorizationRequestURI(opts?: {
    version?: SupportedVersion;
    nonce?: string;
    state?: string;
    claims?: ClaimPayloadCommonOpts;
  }): Promise<URI> {
    return await URI.fromOpts(this.newAuthorizationRequestOpts(opts));
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
    nonce?: string;
    state?: string;
    claims?: ClaimPayloadCommonOpts;
  }): CreateAuthorizationRequestOpts {
    const state = opts?.state || getState(opts?.state);
    const nonce = opts?.nonce || getNonce(state, opts?.nonce);
    const version = opts?.version ?? this._createRequestOptions.version;
    if (!version) {
      throw Error(SIOPErrors.NO_REQUEST_VERSION);
    }
    const claims = opts?.claims || this._createRequestOptions.claims;
    return {
      ...this._createRequestOptions,
      version,
      payload: { ...this._createRequestOptions.payload, state, nonce },
      claims,
    };
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
