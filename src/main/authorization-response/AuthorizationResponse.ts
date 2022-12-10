import { AuthorizationRequest } from '../authorization-request';
import { VerifyAuthorizationRequestOpts } from '../authorization-request';
import { assertValidVerifyAuthorizationRequestOpts } from '../authorization-request/Opts';
import { IDToken } from '../id-token';
import {
  AuthorizationResponsePayload,
  SIOPErrors,
  VerifiablePresentationPayload,
  VerifiedAuthenticationResponse,
  VerifiedAuthorizationRequest,
} from '../types';

import { assertValidVerifiablePresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';
import { createResponsePayload } from './Payload';
import { PresentationExchange } from './PresentationExchange';
import { AuthorizationResponseOpts, VerifyAuthorizationResponseOpts } from './types';

export class AuthorizationResponse {
  private readonly _authorizationRequest?: AuthorizationRequest | undefined;
  // private _requestObject?: RequestObject | undefined
  private readonly _idToken?: IDToken;
  private readonly _payload: AuthorizationResponsePayload;

  private readonly _options?: AuthorizationResponseOpts;

  constructor({
    authorizationResponsePayload,
    idToken,
    responseOpts,
    authorizationRequest,
  }: {
    authorizationResponsePayload: AuthorizationResponsePayload;
    idToken: IDToken;
    responseOpts?: AuthorizationResponseOpts;
    authorizationRequest?: AuthorizationRequest;
  }) {
    this._authorizationRequest = authorizationRequest;
    this._options = responseOpts;
    this._idToken = idToken;
    this._payload = authorizationResponsePayload;
  }

  /**
   * Creates a SIOP Response Object
   *
   * @param requestObject
   * @param responseOpts
   * @param verifyOpts
   */
  static async fromRequestObject(
    requestObject: string,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts: VerifyAuthorizationRequestOpts
  ): Promise<AuthorizationResponse> {
    assertValidVerifyAuthorizationRequestOpts(verifyOpts);
    assertValidResponseOpts(responseOpts);
    if (!requestObject || !requestObject.startsWith('ey')) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestObject);
    return AuthorizationResponse.fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts);
  }

  static async fromPayload(
    authorizationResponsePayload: AuthorizationResponsePayload,
    responseOpts?: AuthorizationResponseOpts
  ): Promise<AuthorizationResponse> {
    if (!authorizationResponsePayload) {
      throw new Error(SIOPErrors.NO_RESPONSE);
    }
    if (responseOpts) {
      assertValidResponseOpts(responseOpts);
    }
    const idToken = await IDToken.fromIDToken(authorizationResponsePayload.id_token);
    return new AuthorizationResponse({ authorizationResponsePayload, idToken, responseOpts });
  }

  static async fromAuthorizationRequest(
    authorizationRequest: AuthorizationRequest,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts?: VerifyAuthorizationRequestOpts
  ): Promise<AuthorizationResponse> {
    assertValidResponseOpts(responseOpts);
    if (!authorizationRequest) {
      throw new Error(SIOPErrors.NO_REQUEST);
    }
    if (verifyOpts) {
      await authorizationRequest.verify(verifyOpts);
    }
    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(authorizationRequest.payload);
    const idToken = await IDToken.fromAuthorizationRequestPayload(authorizationRequest.payload, responseOpts);
    const idTokenPayload = await idToken.payload();
    const authorizationResponsePayload = await createResponsePayload(authorizationRequest, idTokenPayload, responseOpts);
    await assertValidVerifiablePresentations({
      presentationDefinitions,
      presentationPayloads: authorizationResponsePayload.vp_token as VerifiablePresentationPayload[] | VerifiablePresentationPayload,
      verificationCallback: responseOpts.presentationExchange?.presentationVerificationCallback,
    });

    return new AuthorizationResponse({
      authorizationResponsePayload,
      idToken,
      responseOpts,
      authorizationRequest,
    });
  }

  static async fromVerifiedAuthorizationRequest(
    verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: AuthorizationResponseOpts
  ): Promise<AuthorizationResponse> {
    return await AuthorizationResponse.fromAuthorizationRequest(verifiedAuthorizationRequest.authorizationRequest, responseOpts);
  }

  public async verify(verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedAuthenticationResponse> {
    // TODO: Add response verification next to idToken verification
    return await this.idToken.verify(verifyOpts);
  }

  get authorizationRequest(): AuthorizationRequest | undefined {
    return this._authorizationRequest;
  }

  get payload(): AuthorizationResponsePayload {
    return this._payload;
  }

  get options(): AuthorizationResponseOpts | undefined {
    return this._options;
  }

  get idToken(): IDToken {
    return this._idToken;
  }
}
