import EventEmitter from 'events';

import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponse } from '../authorization-response';
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationRequestState,
  AuthorizationRequestStateStatus,
  AuthorizationResponseState,
  AuthorizationResponseStateStatus,
  RequestObjectPayload,
} from '../types';

export class ReplayRegistry {
  private authorizationRequests: Map<string, AuthorizationRequestState> = new Map<string, AuthorizationRequestState>();
  private authorizationResponses: Map<string, AuthorizationResponseState> = new Map<string, AuthorizationResponseState>();

  public constructor(eventEmitter: EventEmitter) {
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, this.onAuthorizationRequestCreatedSuccess.bind(this));
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, this.onAuthorizationResponseReceivedSuccess.bind(this));
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, this.onAuthorizationResponseVerifiedSuccess.bind(this));
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, this.onAuthorizationResponseVerifiedFailed.bind(this));
  }

  private async onAuthorizationRequestCreatedSuccess(event: AuthorizationEvent<AuthorizationRequest>): Promise<void> {
    try {
      if (!event) {
        throw new Error('event not present');
      }

      const payload: RequestObjectPayload | undefined = await event.getSubject.requestObject.getPayload();
      if (!payload) {
        throw new Error('Request does not contain a payload');
      }
      this.authorizationRequests.set(payload.nonce, {
        payload,
        status: AuthorizationRequestStateStatus.CREATED,
        timestamp: event.getTimestamp,
        lastUpdated: event.getTimestamp,
      });
    } catch (error: unknown) {
      // TODO VDX-166 handle error
    }
  }

  private async onAuthorizationResponseReceivedSuccess(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    try {
      if (!event) {
        throw new Error('event not present');
      }

      const payload = await event.getSubject.idToken.payload();
      this.authorizationResponses.set(payload.nonce, {
        payload,
        status: AuthorizationResponseStateStatus.RECEIVED,
        timestamp: event.getTimestamp,
        lastUpdated: event.getTimestamp,
      });
    } catch (error: unknown) {
      // TODO VDX-166 handle error
    }
  }

  private async onAuthorizationResponseVerifiedFailed(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    try {
      if (!event) {
        throw new Error('event not present');
      }

      const payload = await event.getSubject.idToken.payload();
      const authorizationRequestState: AuthorizationResponseState = this.authorizationResponses.get(payload.nonce);
      authorizationRequestState.error = event.getError;
      authorizationRequestState.status = AuthorizationResponseStateStatus.ERROR;
      authorizationRequestState.lastUpdated = event.getTimestamp;
      this.authorizationResponses.set(payload.nonce, authorizationRequestState);
    } catch (error: unknown) {
      // TODO VDX-166 handle error
    }
  }

  private async onAuthorizationResponseVerifiedSuccess(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    try {
      if (!event) {
        throw new Error('event not present');
      }

      const payload = await event.getSubject.idToken.payload();

      this.authorizationRequests.delete(payload.nonce);

      const authorizationRequestState: AuthorizationResponseState = this.authorizationResponses.get(payload.nonce);
      authorizationRequestState.status = AuthorizationResponseStateStatus.VERIFIED;
      authorizationRequestState.lastUpdated = event.getTimestamp;
      this.authorizationResponses.set(payload.nonce, authorizationRequestState);
    } catch (error: unknown) {
      // TODO VDX-166 handle error
    }
  }

  public async getAuthorizationRequests(): Promise<Map<string, AuthorizationRequestState>> {
    return new Map(this.authorizationRequests);
  }

  public async getAuthorizationResponses(): Promise<Map<string, AuthorizationResponseState>> {
    return new Map(this.authorizationResponses);
  }

  public async verify(authorizationResponse: AuthorizationResponse): Promise<void> {
    if (!authorizationResponse.idToken) {
      return Promise.reject(Error('No idToken present in response'));
    }

    const payload = await authorizationResponse.idToken.payload();
    if (!payload.nonce) {
      return Promise.reject(Error('No nonce present in idToken'));
    }

    if (!this.authorizationRequests.has(payload.nonce)) {
      return Promise.reject(Error(`No authorization request present matching nonce: ${payload.nonce}`));
    }

    const requestPayload = this.authorizationRequests.get(payload.nonce);
    if (requestPayload.payload.state !== authorizationResponse.payload.state) {
      return Promise.reject(Error(`Response state: ${authorizationResponse.payload.state} does not match request state`));
    }
  }
}
