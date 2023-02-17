import { IDTokenPayload, RequestObjectPayload } from './SIOP.types';

export interface AuthorizationRequestState {
  payload?: RequestObjectPayload;
  status: AuthorizationRequestStateStatus;
  timestamp: number;
  lastUpdated: number;
  error?: Error;
}

export interface AuthorizationResponseState {
  payload?: IDTokenPayload;
  status: AuthorizationResponseStateStatus;
  timestamp: number;
  lastUpdated: number;
  error?: Error;
}

export enum AuthorizationRequestStateStatus {
  CREATED = 'created',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error',
}

export enum AuthorizationResponseStateStatus {
  CREATED = 'created',
  SENT = 'sent',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error',
}
