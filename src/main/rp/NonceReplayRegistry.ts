import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponse } from '../authorization-response';
import {
  AuthorizationEvents,
  AuthorizationRequestEvent,
  AuthorizationResponseEvent
} from '../types/Events';
import { IDTokenPayload } from '../types';

export const eventEmitter = new (require('events').EventEmitter)();

export class NonceReplayRegistry {
  private authorizationRequests: Array<AuthorizationRequestEvent> = [];
  private authorizationResponses: Array<AuthorizationResponseEvent> = [];
  private responseLock = false;
  private requestLock = false;

  public constructor() {
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST, this.onAuthorizationRequest.bind(this));
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE, this.onAuthorizationResponse.bind(this));
  }

  private async onAuthorizationRequest(authorizationRequest: AuthorizationRequest): Promise<void> {
    if (!authorizationRequest) {
      return;
    }

    await this.updateAuthorizationRequests(async () => this.authorizationRequests.push({ authorizationRequest, timestamp: Date.now() }));
  }

  private async onAuthorizationResponse(authorizationResponse: AuthorizationResponse): Promise<void> {
    if (!authorizationResponse) {
      return;
    }

    authorizationResponse.idToken.payload().then(async (idTokenPayload: IDTokenPayload) => {
      const filter = async (array, callback) => {
        const fail = Symbol();
        return (await Promise.all(array.map(async item => (await callback(item)) ? item : fail))).filter(result => result !== fail);
      }

      await this.updateAuthorizationRequests(async () => this.authorizationRequests = await filter(this.authorizationRequests, async (event: AuthorizationRequestEvent) => {
        const request_payload = await event.authorizationRequest.requestObject.getPayload()
        return request_payload.nonce !== idTokenPayload.nonce && request_payload.state !== authorizationResponse.payload.state;
      }))

      await this.updateAuthorizationResponses(async () => this.authorizationResponses.push({ authorizationResponse, timestamp: Date.now() }));
    })
  }

  private async updateAuthorizationRequests(callback: () => Promise<any>): Promise<void> {
    while (this.requestLock) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    this.requestLock = true;
    await callback();
    this.requestLock = false;
  }

  private async updateAuthorizationResponses(callback: () => Promise<any>): Promise<void> {
    while (this.responseLock) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    this.responseLock = true;
    await callback();
    this.responseLock = false;
  }

  public async getAuthorizationRequests(): Promise<Array<AuthorizationRequestEvent>> {
    return [...this.authorizationRequests]
  }

  public async getAuthorizationResponses(): Promise<Array<AuthorizationResponseEvent>> {
    return [...this.authorizationResponses]
  }

  public async verify(authorizationResponse: AuthorizationResponse): Promise<void> {
    if (!authorizationResponse.idToken) {
      return Promise.reject(Error('No idToken present in response'));
    }

    return authorizationResponse.idToken.payload().then(async (idTokenPayload: IDTokenPayload) => {
      if (!idTokenPayload.nonce) {
        return Promise.reject(Error('No nonce present in idToken'));
      }

      const promises = this.authorizationRequests.map(async (event: AuthorizationRequestEvent) => {
        const request_payload = await event.authorizationRequest.requestObject.getPayload()
        return request_payload.nonce === idTokenPayload.nonce && request_payload.state === authorizationResponse.payload.state;
      });

      const match = (await Promise.all(promises)).some((result: Awaited<boolean>) => result);

      if (!match) {
        return Promise.reject(Error(`No authorization request present matching nonce: ${idTokenPayload.nonce} and state: ${authorizationResponse.payload.state}`));
      }
    })
  }
}
