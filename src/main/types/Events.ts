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

export class AuthorizationEvent<T> {
  private readonly subject: T;
  private readonly error?: Error;
  private readonly timestamp: number;

  public constructor(args: { subject: T; error?: Error }) {
    this.timestamp = Date.now();
    this.subject = args.subject;
    this.error = args.error;
  }

  get getSubject(): T {
    return this.subject;
  }

  get getTimestamp(): number {
    return this.timestamp;
  }

  get getError(): Error {
    return this.error;
  }

  public hasError(): boolean {
    return !!this.error;
  }
}
