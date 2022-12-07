import AuthorizationRequest from '../authorization-request/AuthorizationRequest';
import { assertValidVerifyAuthorizationRequestOpts } from '../authorization-request/Opts';
import { IDToken } from '../id-token/IDToken';
import {
  AuthorizationResponseOpts,
  AuthorizationResponsePayload,
  SIOPErrors,
  VerifiablePresentationPayload,
  VerifiedAuthenticationResponse,
  VerifiedAuthorizationRequest,
  VerifyAuthorizationRequestOpts,
  VerifyAuthorizationResponseOpts,
} from '../types';

import { assertValidVerifiablePresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';
import { createResponsePayload } from './Payload';

export class AuthorizationResponse {
  get idToken(): IDToken {
    return this._idToken;
  }

  constructor({
    authorizationResponsePayload,
    idToken,
    responseOpts,
    authorizationRequest,
  }: {
    authorizationResponsePayload: AuthorizationResponsePayload;
    idToken: IDToken;
    responseOpts: AuthorizationResponseOpts;
    authorizationRequest?: AuthorizationRequest;
  }) {
    this._authorizationRequest = authorizationRequest;
    this._options = responseOpts;
    this._idToken = idToken;
    this._payload = authorizationResponsePayload;
  }

  private readonly _authorizationRequest?: AuthorizationRequest | undefined;
  // private _requestObject?: RequestObject | undefined
  private readonly _idToken?: IDToken;
  private readonly _payload: AuthorizationResponsePayload;

  private readonly _options: AuthorizationResponseOpts;

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
    const verifiedRequest = await authorizationRequest.verify(verifyOpts);
    return AuthorizationResponse.fromVerifiedAuthorizationRequest(verifiedRequest, responseOpts);
  }

  // TODO SK Can you please put some documentation on it?
  static async fromVerifiedAuthorizationRequest(
    authorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: AuthorizationResponseOpts
  ): Promise<AuthorizationResponse> {
    const idToken = await IDToken.fromAuthorizationRequestPayload(authorizationRequest.authorizationRequestPayload, responseOpts);
    const idTokenPayload = await idToken.payload();
    const authorizationResponsePayload = await createResponsePayload(authorizationRequest, idTokenPayload, responseOpts);
    await assertValidVerifiablePresentations({
      presentationDefinitions: authorizationRequest.presentationDefinitions,
      presentationPayloads: authorizationResponsePayload.vp_token as VerifiablePresentationPayload[] | VerifiablePresentationPayload,
      verificationCallback: responseOpts.presentationExchange?.presentationVerificationCallback,
    });

    return new AuthorizationResponse({
      authorizationResponsePayload,
      idToken,
      responseOpts,
      authorizationRequest: authorizationRequest.authorizationRequest,
    });
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

  get options(): AuthorizationResponseOpts {
    return this._options;
  }
}
