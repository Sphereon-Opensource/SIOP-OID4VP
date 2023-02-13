import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponse } from '../authorization-response';

export interface AuthorizationRequestEvent {
  authorizationRequest: AuthorizationRequest
  timestamp: number
}

export interface AuthorizationResponseEvent {
  authorizationResponse: AuthorizationResponse
  timestamp: number
}

export enum AuthorizationEvents {
  ON_AUTH_REQUEST = 'onAuthRequest',
  ON_AUTH_RESPONSE = 'onAuthResponse'
}
