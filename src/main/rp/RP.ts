import { AuthorizationRequest, CreateAuthorizationRequestOpts } from '../authorization-request';
import { URI } from '../authorization-request/URI';
import { AuthorizationResponse, ClaimOpts, VerifyAuthorizationResponseOpts } from '../authorization-response';
import { verifyPresentations } from '../authorization-response/OpenID4VP';
import { getNonce, getState } from '../helpers';
import {
  AuthorizationResponsePayload,
  CheckLinkedDomain,
  ExternalVerification,
  InternalVerification,
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
    this._createRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload, claims } };
    this._verifyResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts), claims };
  }

  public static fromRequestOpts(opts: CreateAuthorizationRequestOpts): RP {
    return new RP({ createRequestOpts: opts });
  }

  public static builder(): Builder {
    return new Builder();
  }

  get createRequestOptions(): CreateAuthorizationRequestOpts {
    return this._createRequestOptions;
  }

  get verifyResponseOptions(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyResponseOptions;
  }

  public async createAuthorizationRequest(opts?: { nonce?: string; state?: string }): Promise<AuthorizationRequest> {
    return await AuthorizationRequest.fromOpts(this.newAuthorizationRequestOpts(opts));
  }
  public async createAuthorizationRequestURI(opts?: { nonce?: string; state?: string }): Promise<URI> {
    return await URI.fromOpts(this.newAuthorizationRequestOpts(opts));
  }

  public async verifyAuthorizationResponse(
    authorizationResponsePayload: AuthorizationResponsePayload,
    opts?: {
      audience?: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      claims?: ClaimOpts;
    }
  ): Promise<VerifiedAuthenticationResponse> {
    const verifyAuthenticationResponseOpts = this.newVerifyAuthorizationResponseOpts({
      ...opts,
    });
    await verifyPresentations(authorizationResponsePayload, verifyAuthenticationResponseOpts);
    const authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload);
    return await authorizationResponse.verify(verifyAuthenticationResponseOpts);
  }

  private newAuthorizationRequestOpts(opts?: { nonce?: string; state?: string }): CreateAuthorizationRequestOpts {
    const state = opts?.state || getState(opts?.state);
    const nonce = opts?.nonce || getNonce(state, opts?.nonce);
    return {
      ...this._createRequestOptions,
      payload: { ...this._createRequestOptions.payload, state, nonce },
    };
  }

  private newVerifyAuthorizationResponseOpts(opts?: {
    state?: string;
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    claims?: ClaimOpts;
    audience?: string;
    checkLinkedDomain?: CheckLinkedDomain;
  }): VerifyAuthorizationResponseOpts {
    return {
      ...this._verifyResponseOptions,
      audience: opts?.audience || this._verifyResponseOptions.audience,
      state: opts?.state || this._verifyResponseOptions.state,
      nonce: opts?.nonce || this._verifyResponseOptions.nonce,
      claims: { ...this._verifyResponseOptions.claims, ...opts.claims },
      verification: opts?.verification || this._verifyResponseOptions.verification,
    };
  }
}
