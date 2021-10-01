import Ajv from 'ajv';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import RPBuilder from './RPBuilder';
import { State } from './functions';
import { getResolver } from './functions/DIDResolution';
import { AuthenticationRequestOptsSchema } from './schemas/AuthenticationRequestOpts.schema';
import { SIOP } from './types';
import {
  AuthenticationRequestOpts,
  AuthenticationRequestURI,
  ExternalVerification,
  InternalVerification,
  RequestRegistrationOpts,
  VerificationMode,
  VerifiedAuthenticationResponseWithJWT,
  VerifyAuthenticationResponseOpts,
} from './types/SIOP.types';

const ajv = new Ajv();
const validate = ajv.compile(AuthenticationRequestOptsSchema);

export class RP {
  private readonly _authRequestOpts: AuthenticationRequestOpts;
  private readonly _verifyAuthResponseOpts: Partial<VerifyAuthenticationResponseOpts>;

  public constructor(opts: {
    builder?: RPBuilder;
    requestOpts?: AuthenticationRequestOpts;
    verifyOpts?: VerifyAuthenticationResponseOpts;
  }) {
    this._authRequestOpts = { ...createRequestOptsFromBuilderOrExistingOpts(opts) };
    this._verifyAuthResponseOpts = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) };
  }

  get authRequestOpts(): AuthenticationRequestOpts {
    return this._authRequestOpts;
  }

  get verifyAuthResponseOpts(): Partial<VerifyAuthenticationResponseOpts> {
    return this._verifyAuthResponseOpts;
  }

  public createAuthenticationRequest(opts?: { nonce?: string; state?: string }): Promise<AuthenticationRequestURI> {
    return AuthenticationRequest.createURI(this.newAuthenticationRequestOpts(opts));
  }

  public verifyAuthenticationResponseJwt(
    jwt: string,
    opts?: {
      audience: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<VerifiedAuthenticationResponseWithJWT> {
    return AuthenticationResponse.verifyJWT(jwt, this.newVerifyAuthenticationResponseOpts(opts));
  }

  public newAuthenticationRequestOpts(opts?: { nonce?: string; state?: string }): AuthenticationRequestOpts {
    const state = opts?.state || State.getState(opts?.state);
    const nonce = opts?.nonce || State.getNonce(state, opts?.nonce);
    return {
      ...this._authRequestOpts,
      state,
      nonce,
    };
  }

  public newVerifyAuthenticationResponseOpts(opts?: {
    state?: string;
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    audience: string;
  }): VerifyAuthenticationResponseOpts {
    return {
      ...this._verifyAuthResponseOpts,
      audience: opts.audience,
      state: opts?.state || this._verifyAuthResponseOpts.state,
      nonce: opts?.nonce || this._verifyAuthResponseOpts.nonce,

      verification: opts?.verification || this._verifyAuthResponseOpts.verification,
    };
  }

  public static fromRequestOpts(opts: SIOP.AuthenticationRequestOpts): RP {
    return new RP({ requestOpts: opts });
  }

  public static builder() {
    return new RPBuilder();
  }
}

function createRequestOptsFromBuilderOrExistingOpts(opts: {
  builder?: RPBuilder;
  requestOpts?: AuthenticationRequestOpts;
}) {
  const requestOpts: AuthenticationRequestOpts = opts.builder
    ? {
        registration: opts.builder.requestRegistration as RequestRegistrationOpts,
        redirectUri: opts.builder.redirectUri,
        requestBy: opts.builder.requestObjectBy,
        signatureType: opts.builder.signatureType,
        responseMode: opts.builder.responseMode,
        responseContext: opts.builder.responseContext,
      }
    : opts.requestOpts;

  const valid = validate(requestOpts);
  if (!valid) {
    throw new Error('RP builder validation error: ' + JSON.stringify(validate.errors));
  }
  return requestOpts;
}

function createVerifyResponseOptsFromBuilderOrExistingOpts(opts: {
  builder?: RPBuilder;
  verifyOpts?: Partial<VerifyAuthenticationResponseOpts>;
}) {
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            didMethods: opts.builder.didMethods,
            resolver: getResolver({ didMethods: opts.builder.didMethods }),
          },
        },
      }
    : opts.verifyOpts;
}
