import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponse } from '../authorization-response';
import {
  AuthorizationEvents,
  AuthorizationRequestState,
  AuthorizationRequestStateStatus,
  AuthorizationResponseState,
  AuthorizationResponseStateStatus
} from '../types/Events';
import { RequestObjectPayload } from '../types';
import { rpEventEmitter } from './RP';

export class ReplayRegistry  {
  private authorizationRequests: Map<string, AuthorizationRequestState>= new Map<string, AuthorizationRequestState>();
  private authorizationResponses: Map<string, AuthorizationResponseState> = new Map<string, AuthorizationResponseState>();

  public constructor() {
    rpEventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, this.onAuthorizationRequestCreatedSuccess.bind(this));
    rpEventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, this.onAuthorizationResponseReceivedSuccess.bind(this));
    rpEventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, this.onAuthorizationResponseVerifiedSuccess.bind(this));
    rpEventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, this.onAuthorizationResponseReceivedFailed.bind(this));
  }

  private async onAuthorizationRequestCreatedSuccess(authorizationRequest: AuthorizationRequest): Promise<void> {
    try {
      if (!authorizationRequest) {
        return;
      }

      const timestamp = Date.now()
      const payload: RequestObjectPayload | undefined = await authorizationRequest.requestObject.getPayload()
      if (!payload) {
        throw new Error('Request does not contain a payload')
      }
      this.authorizationRequests.set(payload.nonce, { payload, status: AuthorizationRequestStateStatus.CREATED, timestamp, lastUpdated: timestamp })
    } catch (error: any) {
      // TODO handle error
    }
  }

  private async onAuthorizationResponseReceivedSuccess(authorizationResponse: AuthorizationResponse): Promise<void> {
    try {
      if (!authorizationResponse) {
        return;
      }

      const timestamp = Date.now()
      const payload = await authorizationResponse.idToken.payload()
      this.authorizationResponses.set(payload.nonce, { payload, status: AuthorizationResponseStateStatus.RECEIVED, timestamp: timestamp, lastUpdated: timestamp })
    } catch (error: any) {
      // TODO handle error
    }
  }

  private async onAuthorizationResponseReceivedFailed(authorizationResponse: AuthorizationResponse, error: Error): Promise<void> {
    try {
      if (!authorizationResponse) {
        return;
      }

      const timestamp = Date.now()
      const payload = await authorizationResponse.idToken.payload()
      const authorizationRequestState: AuthorizationResponseState = this.authorizationResponses.get(payload.nonce)
      authorizationRequestState.error = error
      authorizationRequestState.status = AuthorizationResponseStateStatus.ERROR
      authorizationRequestState.lastUpdated = timestamp
      this.authorizationResponses.set(payload.nonce, authorizationRequestState)
    } catch (error: any) {
      // TODO handle error
    }
  }

  private async onAuthorizationResponseVerifiedSuccess(authorizationResponse: AuthorizationResponse): Promise<void> {
    try {
      if (!authorizationResponse) {
        return;
      }

      const timestamp = Date.now()
      const payload = await authorizationResponse.idToken.payload()

      this.authorizationRequests.delete(payload.nonce)

      const authorizationRequestState: AuthorizationResponseState = this.authorizationResponses.get(payload.nonce)
      authorizationRequestState.status = AuthorizationResponseStateStatus.VERIFIED
      authorizationRequestState.lastUpdated = timestamp
      this.authorizationResponses.set(payload.nonce, authorizationRequestState)
    } catch (error: any) {
      // TODO handle error
    }
  }

  public async getAuthorizationRequests(): Promise<Map<string, AuthorizationRequestState>> {
    return new Map(this.authorizationRequests)
  }

  public async getAuthorizationResponses(): Promise<Map<string, AuthorizationResponseState>> {
    return new Map(this.authorizationResponses)
  }

  public async verify(authorizationResponse: AuthorizationResponse): Promise<void> {
    if (!authorizationResponse.idToken) {
      return Promise.reject(Error('No idToken present in response'));
    }

    const payload = await authorizationResponse.idToken.payload()
    if (!payload.nonce) {
      return Promise.reject(Error('No nonce present in idToken'));
    }

    if (!this.authorizationRequests.has(payload.nonce)) {
      return Promise.reject(Error(`No authorization request present matching nonce: ${payload.nonce}`));
    }

    const requestPayload = this.authorizationRequests.get(payload.nonce)
    if (requestPayload.payload.state !== authorizationResponse.payload.state) {
      return Promise.reject(Error(`Response state: ${authorizationResponse.payload.state} does not match request state`));
    }
  }
}
