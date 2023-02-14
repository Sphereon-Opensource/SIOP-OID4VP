import { IDTokenPayload, RequestObjectPayload } from './SIOP.types';

export interface AuthorizationRequestState {
  payload?: RequestObjectPayload
  status: AuthorizationRequestStateStatus
  timestamp: number
  lastUpdated: number
  error?: Error
}

export interface AuthorizationResponseState {
  payload?: IDTokenPayload
  status: AuthorizationResponseStateStatus
  timestamp: number
  lastUpdated: number
  error?: Error
}

export enum AuthorizationEvents {
  ON_AUTH_REQUEST_CREATED_SUCCESS = 'onAuthRequestCreatedSuccess',
  ON_AUTH_REQUEST_CREATED_FAILED = 'onAuthRequestCreatedFailed',

  ON_AUTH_REQUEST_RECEIVED_SUCCESS = 'onAuthRequestReceivedSuccess',
  ON_AUTH_REQUEST_RECEIVED_FAILED = 'onAuthRequestReceivedFailed',

  ON_AUTH_REQUEST_VERIFIED_SUCCESS = 'onAuthRequestVerifiedSuccess',
  ON_AUTH_REQUEST_VERIFIED_FAILED = 'onAuthRequestVerifiedFailed',

  ON_AUTH_RESPONSE_CREATE_SUCCESS = 'onAuthResponseSentSuccess',
  ON_AUTH_RESPONSE_CREATE_FAILED = 'onAuthResponseSentFailed',

  ON_AUTH_RESPONSE_SENT_SUCCESS = 'onAuthResponseSentSuccess',
  ON_AUTH_RESPONSE_SENT_FAILED = 'onAuthResponseSentFailed',

  ON_AUTH_RESPONSE_RECEIVED_SUCCESS = 'onAuthResponseReceivedSuccess',
  ON_AUTH_RESPONSE_RECEIVED_FAILED = 'onAuthResponseReceivedFailed',

  ON_AUTH_RESPONSE_VERIFIED_SUCCESS = 'onAuthResponseVerifiedSuccess',
  ON_AUTH_RESPONSE_VERIFIED_FAILED = 'onAuthResponseReceivedFailed',
}

export enum AuthorizationRequestStateStatus {
  CREATED = 'created',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error'
}

export enum AuthorizationResponseStateStatus {
  CREATED = 'created',
  SENT = 'sent',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error'
}
